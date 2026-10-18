//go:build linux

// Functional test for the outcome journal source (geekdojo/geekdojo-brain#853,
// FN-1) against the real, pinned Alloy and Loki images, under the
// supervisor's own compose. It proves what the unit tests cannot: that the
// pinned Alloy reads the host's journal through the rendered config, ships
// the allowlisted identifiers' lines that were written BEFORE it ever ran,
// labelled as the plan says, ships nothing else, and after a recreate neither
// re-ships nor loses its place.
//
// What it does, in order:
//
//  1. Writes a per-run token line under each allowlisted identifier as the
//     stdout of a transient unit (systemd-run -p SyslogIdentifier=<id>), the
//     way the real oneshots write theirs, so the entry carries a
//     _SYSTEMD_UNIT as theirs do. Then
//     canary lines under rasputin-api, rasputin-seal-key (the kmsg copy's
//     identifier) and rasputin-firstboot.sh, then a marker line under an
//     allowlisted identifier. Each line is waited on in the journal before
//     the next is written, so the journal order is the write order.
//  2. Points JournalDir at the runner's journal root, read from
//     `journalctl --header`'s File path.
//  3. Starts the stack and waits for the marker to reach Loki.
//  4. Each allowlisted line is in {job="rasputin-outcome"} exactly once, with
//     job, syslog_identifier, unit and node_id; no canary is in any stream;
//     no rasputin-outcome stream has another identifier. (TC-853-21)
//  5. Removes the Alloy container, Starts again, writes and waits on a second
//     marker: every count is still 1, and Alloy's positions file is on the
//     host. (TC-853-22)
//
// Opt-in: runs only when RASPUTIN_JOURNAL_FUNCTIONAL is set, as root on a
// systemd host with docker. "required" turns every skip into a failure,
// which is what the grafana-obs-socket CI job sets. Opt-in for the same
// reason as grafana_functional_linux_test.go: the compose template pins
// container names, so it must never run beside another stack.
//
// Every wait is on a fact (a line in the journal, a line in Loki, a file on
// disk), each bounded by a deadline whose failure names that fact.

package obs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
)

const (
	journalFuncEnv     = "RASPUTIN_JOURNAL_FUNCTIONAL"
	journalFuncProject = "rasputin-obs-journalfunc"
	journalFuncNodeID  = "fn853-cp"
	// Ports nothing else on a runner is likely to hold, and none the Grafana
	// functional tests use.
	journalFuncVMAddr   = "127.0.0.1:19317"
	journalFuncLokiAddr = "127.0.0.1:19318"
	// One fact-wait's bound. Generous: CI runners are slow, and a wait that
	// is met returns at once.
	journalFuncWait = 3 * time.Minute
)

func journalSkipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	functest.SkipOrFail(t, journalFuncEnv, format, args...)
}

func requireJournalHost(t *testing.T) {
	t.Helper()
	if os.Getenv(journalFuncEnv) == "" {
		t.Skip("set " + journalFuncEnv + "=1 to run (root, systemd and docker; see file comment)")
	}
	if os.Geteuid() != 0 {
		journalSkipOrFail(t, "must run as root (transient units, and the journal's 0640 files)")
	}
	for _, bin := range []string{"docker", "journalctl", "systemd-run"} {
		if _, err := exec.LookPath(bin); err != nil {
			journalSkipOrFail(t, "%s not on PATH: %v", bin, err)
		}
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		journalSkipOrFail(t, "docker daemon unreachable: %v (%s)", err, strings.TrimSpace(string(out)))
	}
}

// journalRoot is the directory holding the host's <machine-id>/ journal
// directories, from the first File path `journalctl --header` prints.
func journalRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("journalctl", "--header", "--no-pager").CombinedOutput()
	if err != nil {
		t.Fatalf("journalctl --header: %v (%s)", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), "File path: "); ok {
			root := filepath.Dir(filepath.Dir(strings.TrimSpace(p)))
			t.Logf("journal root %s (from %s)", root, p)
			return root
		}
	}
	t.Fatalf("journalctl --header printed no File path:\n%s", out)
	return ""
}

// journalLine is one line the test writes, and what Loki must say about it.
type journalLine struct {
	id   string // SYSLOG_IDENTIFIER
	msg  string
	unit string // _SYSTEMD_UNIT journald recorded
}

// writeJournal writes msg under identifier id as the stdout of a transient
// unit, then waits until journald has recorded it, and returns the line with
// the unit journald attributed it to.
//
// The line goes out on the unit's own stdout, which systemd connects to
// journald and names the unit in the stream's header, as for the real
// oneshots (outcome.sh's outcome_log prints to stdout). Not systemd-cat: its
// stream carries no unit, so journald reads the writer's cgroup from /proc,
// and when echo has already exited the entry has no _SYSTEMD_UNIT. On
// systemd 255 that lost the unit on 22 of 300 writes; this way lost none.
func writeJournal(t *testing.T, unit, id, msg string) journalLine {
	t.Helper()
	cmd := exec.Command("systemd-run", "--quiet", "--wait", "--collect",
		"--unit="+unit, "--property=SyslogIdentifier="+id, "echo", msg)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("systemd-run %s: %v (%s)", unit, err, out)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		out, err := exec.Command("journalctl", "--no-pager", "-o", "json",
			"-t", id, "-n", "500").Output()
		if err != nil {
			t.Fatalf("journalctl -t %s: %v", id, err)
		}
		for _, l := range strings.Split(string(out), "\n") {
			var e struct {
				Message string `json:"MESSAGE"`
				Unit    string `json:"_SYSTEMD_UNIT"`
			}
			if json.Unmarshal([]byte(l), &e) == nil && e.Message == msg {
				return journalLine{id: id, msg: msg, unit: e.Unit}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("journald never recorded %q under SYSLOG_IDENTIFIER=%s within 30s", msg, id)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// lokiStream is one stream of a query_range answer.
type lokiStream struct {
	Labels map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

// lokiQuery runs a LogQL log query over the test's window and returns its
// streams.
func lokiQuery(t *testing.T, base, query string, since time.Time) []lokiStream {
	t.Helper()
	q := url.Values{}
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(since.UnixNano(), 10))
	q.Set("end", strconv.FormatInt(time.Now().Add(time.Minute).UnixNano(), 10))
	q.Set("limit", "5000")
	q.Set("direction", "forward")
	resp, err := http.Get(base + "/loki/api/v1/query_range?" + q.Encode())
	if err != nil {
		t.Fatalf("loki query %s: %v", query, err)
	}
	defer resp.Body.Close()
	var body struct {
		Status string `json:"status"`
		Data   struct {
			Result []lokiStream `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("loki query %s: HTTP %d, decode %v", query, resp.StatusCode, err)
	}
	return body.Data.Result
}

// lokiOccurrences returns how many entries carry exactly msg, and the label
// sets of the streams they are in.
func lokiOccurrences(streams []lokiStream, msg string) (int, []map[string]string) {
	n := 0
	var labels []map[string]string
	for _, s := range streams {
		hit := false
		for _, v := range s.Values {
			if v[1] == msg {
				n++
				hit = true
			}
		}
		if hit {
			labels = append(labels, s.Labels)
		}
	}
	return n, labels
}

// waitInLoki waits until msg is in {job="rasputin-outcome"}.
func waitInLoki(t *testing.T, base, msg string, since time.Time) {
	t.Helper()
	deadline := time.Now().Add(journalFuncWait)
	for {
		if n, _ := lokiOccurrences(lokiQuery(t, base, `{job="rasputin-outcome"} |= "`+msg+`"`, since), msg); n > 0 {
			return
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", "--tail", "100", "rasputin-alloy").CombinedOutput()
			t.Fatalf("marker %q never reached Loki in {job=\"rasputin-outcome\"} within %s\n--- alloy log ---\n%s",
				msg, journalFuncWait, logs)
		}
		time.Sleep(time.Second)
	}
}

// waitFileNonEmpty waits until path exists with content.
func waitFileNonEmpty(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(journalFuncWait)
	for {
		if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Alloy's positions file %s was never written within %s", path, journalFuncWait)
		}
		time.Sleep(time.Second)
	}
}

func journalComposeDown(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("docker", "compose", "-p", journalFuncProject, "down", "-v",
		"--remove-orphans").CombinedOutput(); err != nil {
		t.Logf("compose down: %v (%s)", err, out)
	}
}

// TC-853-21 and TC-853-22.
func TestOutcomeJournalPipe_AgainstRealAlloyAndLoki(t *testing.T) {
	requireJournalHost(t)
	root := journalRoot(t)

	stateDir, err := os.MkdirTemp("/tmp", "rjf")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })
	journalComposeDown(t)
	// Registered after the RemoveAll, so it runs first: the project comes
	// down, and nothing rasputin-* is left for the job's next step.
	t.Cleanup(func() {
		journalComposeDown(t)
		out, err := exec.Command("docker", "ps", "-a", "--filter", "name=rasputin-",
			"--format", "{{.Names}}").CombinedOutput()
		left := strings.TrimSpace(string(out))
		if err != nil || left != "" {
			t.Errorf("after compose down, docker ps -a rasputin-*: %q (err %v); want none", left, err)
		} else {
			t.Logf("after compose down, docker ps -a rasputin-*: none")
		}
	})

	tokBytes := make([]byte, 6)
	if _, err := rand.Read(tokBytes); err != nil {
		t.Fatal(err)
	}
	token := "fn853-" + hex.EncodeToString(tokBytes)
	since := time.Now().Add(-10 * time.Minute)
	n := 0
	write := func(id, msg string) journalLine {
		n++
		return writeJournal(t, fmt.Sprintf("%s-%d", token, n), id, msg)
	}

	// Step 1: everything is in the journal before Alloy ever runs.
	var allowed []journalLine
	for _, id := range outcomeJournalIdentifiers {
		l := write(id, fmt.Sprintf("%s: outcome=created token=%s-%s", strings.TrimSuffix(id, ".sh"), token, id))
		if l.unit == "" {
			t.Fatalf("journald recorded no _SYSTEMD_UNIT for %q", l.msg)
		}
		allowed = append(allowed, l)
	}
	var canaries []journalLine
	for _, id := range []string{"rasputin-api", "rasputin-seal-key", "rasputin-firstboot.sh"} {
		canaries = append(canaries, write(id, fmt.Sprintf("canary token=%s-%s", token, id)))
	}
	marker1 := write(outcomeJournalIdentifiers[0], "marker1 token="+token)

	// Step 2.
	off := false
	sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
		StateDir:           stateDir,
		ProjectName:        journalFuncProject,
		ControlPlaneNodeID: journalFuncNodeID,
		VMListenAddr:       journalFuncVMAddr,
		LokiListenAddr:     journalFuncLokiAddr,
		JournalDir:         root,
		EnableGrafana:      &off,
		EnableVMAlert:      &off,
		EnableCadvisor:     &off,
		HealthTimeout:      150 * time.Second,
		PullTimeout:        5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Step 3.
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	base := sup.LokiBaseURL()
	waitInLoki(t, base, marker1.msg, since)

	// Step 4 (TC-853-21).
	assertShippedOnce := func(stage string, lines []journalLine) {
		t.Helper()
		outcome := lokiQuery(t, base, `{job="rasputin-outcome"} |= "`+token+`"`, since)
		for _, l := range lines {
			cnt, labels := lokiOccurrences(outcome, l.msg)
			if cnt != 1 || len(labels) != 1 {
				t.Errorf("%s: %q occurs %d times in %d streams, want exactly once", stage, l.msg, cnt, len(labels))
				continue
			}
			want := map[string]string{
				"job":               "rasputin-outcome",
				"syslog_identifier": l.id,
				"unit":              l.unit,
				"node_id":           journalFuncNodeID,
			}
			for k, v := range want {
				if labels[0][k] != v {
					t.Errorf("%s: %q label %s = %q, want %q (labels %v)", stage, l.msg, k, labels[0][k], v, labels[0])
				}
			}
			t.Logf("%s: %q occurs 1 time, labels %v", stage, l.msg, labels[0])
		}
		for _, c := range canaries {
			// Every stream this Alloy writes carries node_id, so this is
			// every stream there is.
			cnt, labels := lokiOccurrences(lokiQuery(t, base, `{node_id="`+journalFuncNodeID+`"} |= "`+c.msg+`"`, since), c.msg)
			if cnt != 0 {
				t.Errorf("%s: canary %q (SYSLOG_IDENTIFIER=%s) shipped %d times, streams %v; want 0", stage, c.msg, c.id, cnt, labels)
			} else {
				t.Logf("%s: canary %q (SYSLOG_IDENTIFIER=%s) occurs 0 times in any stream", stage, c.msg, c.id)
			}
		}
		var foreign []string
		for _, s := range lokiQuery(t, base, `{job="rasputin-outcome"}`, since) {
			if !slices.Contains(outcomeJournalIdentifiers, s.Labels["syslog_identifier"]) {
				foreign = append(foreign, fmt.Sprint(s.Labels))
			}
		}
		if len(foreign) != 0 {
			t.Errorf("%s: rasputin-outcome streams outside the allowlist: %v", stage, foreign)
		} else {
			t.Logf("%s: no rasputin-outcome stream outside the allowlist", stage)
		}
	}
	assertShippedOnce("TC-853-21", append(slices.Clone(allowed), marker1))
	if t.Failed() {
		return
	}

	// Step 5 (TC-853-22). Wait for Alloy to have recorded its place, then
	// remove the container the way a recreate does (stop, then remove).
	positions := filepath.Join(stateDir, alloyDataDir, "loki.source.journal.outcomes", "positions.yml")
	waitFileNonEmpty(t, positions)
	for _, args := range [][]string{{"stop", "rasputin-alloy"}, {"rm", "rasputin-alloy"}} {
		if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
			t.Fatalf("docker %s: %v (%s)", strings.Join(args, " "), err, out)
		}
	}
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	marker2 := write(outcomeJournalIdentifiers[0], "marker2 token="+token)
	waitInLoki(t, base, marker2.msg, since)
	assertShippedOnce("TC-853-22", append(slices.Clone(allowed), marker1, marker2))
	fi, err := os.Stat(positions)
	if err != nil || fi.Size() == 0 {
		t.Errorf("TC-853-22: positions file %s after the recreate: %v (size %d); want present and non-empty", positions, err, sizeOf(fi))
	} else {
		t.Logf("TC-853-22: positions file %s is %d bytes", positions, fi.Size())
	}
}

func sizeOf(fi os.FileInfo) int64 {
	if fi == nil {
		return 0
	}
	return fi.Size()
}
