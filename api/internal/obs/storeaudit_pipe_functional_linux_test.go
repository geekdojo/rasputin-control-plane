//go:build linux

// Functional test for the secret store's audit source
// (geekdojo/geekdojo-brain#802) against the real, pinned Alloy and Loki
// images, under the supervisor's own compose. It proves what the unit tests
// cannot: that the pinned Alloy ships the live audit file through the
// rendered config, each entry at the time the store wrote it, follows the
// store's link-remove-reopen rotation, and ships nothing twice across a
// rotation or an Alloy recreate.
//
// One Loki serves three Alloy runs, each over its own audit directory, with
// Alloy's container and positions removed between runs:
//
//  1. The audit file is absent when Alloy starts. It is then created holding
//     line F, timed 8 days ago (past Loki's reject_old_samples_max_age), and
//     line G, timed now, and later line C is appended: G and C arrive once
//     each, F never does. (TC-802-10, absent; TC-802-13)
//  2. The audit file is empty when Alloy starts: once Alloy is tailing it,
//     nothing has been shipped and no component is unhealthy; a line then
//     appended arrives. (TC-802-10, empty)
//  3. The file holds line A, a line that is not JSON (M) and line E when Alloy
//     starts: A and E arrive at their own time, M 1ns after A. The
//     file is rotated as storeaudit does (hard link to audit.log.1, remove,
//     create anew) and B appended: B arrives, and every line is in Loki once,
//     under the one filename. Alloy is then recreated by a config change, as
//     an api upgrade does, and D appended: D arrives, and nothing is
//     there twice. (TC-802-09, TC-802-11, TC-802-12)
//
// Opt-in: runs only when RASPUTIN_STOREAUDIT_FUNCTIONAL is set, with docker.
// "required" turns every skip into a failure, which is what the
// grafana-obs-socket CI job sets. It must never run beside another stack: the
// compose template pins container names.
//
// Every wait is on a fact (a line in Loki, a gauge in VictoriaMetrics, a
// position on disk), each bounded by a deadline whose failure names that fact.

package obs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"maps"
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
	storeAuditFuncEnv     = "RASPUTIN_STOREAUDIT_FUNCTIONAL"
	storeAuditFuncProject = "rasputin-obs-storeauditfunc"
	storeAuditFuncNodeID  = "fn802-cp"
	// Ports none of the other functional tests use.
	storeAuditFuncVMAddr   = "127.0.0.1:19327"
	storeAuditFuncLokiAddr = "127.0.0.1:19328"
	// One fact-wait's bound. Generous: CI runners are slow, and a wait that
	// is met returns at once.
	storeAuditFuncWait = 3 * time.Minute
	// storeAuditJob is the stream's job label.
	storeAuditJob = `{job="rasputin-store-audit"}`
	// The store's uid and gid on an appliance (the at-rest inventory's
	// 0600 990:990). As root the test gives the audit files that owner, so
	// Alloy reads them as it does on the appliance.
	storeUID, storeGID = 990, 990
)

func requireStoreAuditHost(t *testing.T) {
	t.Helper()
	if os.Getenv(storeAuditFuncEnv) == "" {
		t.Skip("set " + storeAuditFuncEnv + "=1 to run (docker; see file comment)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		functest.SkipOrFail(t, storeAuditFuncEnv, "docker not on PATH: %v", err)
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		functest.SkipOrFail(t, storeAuditFuncEnv, "docker daemon unreachable: %v (%s)", err, strings.TrimSpace(string(out)))
	}
}

// auditLine is one v2.7.1-shaped audit response entry: msg is the exact line,
// at the time its "time" field holds.
type auditLine struct {
	msg string
	at  time.Time
}

// newAuditLine renders a response entry, timed at, whose path and job header
// carry token-label so a query finds exactly it.
func newAuditLine(t *testing.T, token, label string, at time.Time) auditLine {
	t.Helper()
	at = at.UTC()
	b, err := json.Marshal(map[string]any{
		"time": at.Format(time.RFC3339Nano),
		"type": "response",
		"auth": map[string]any{"accessor": "hmac-sha256:0a1b", "display_name": "cert-rasputin-api",
			"policies": []string{"rasputin-api"}, "token_type": "service"},
		"request": map[string]any{
			"id": token + "-" + label, "operation": "read", "mount_type": "kv",
			"path":    "rasputin-secrets/data/apps/" + token + "-" + label,
			"headers": map[string][]string{"x-rasputin-job-id": {token + "-" + label}},
		},
		"response": map[string]any{"data": map[string]any{"data": map[string]string{"password": "hmac-sha256:9f8e"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auditLine{msg: string(b), at: at}
}

// asStore gives path the store's owner when the test runs as root.
func asStore(t *testing.T, path string) {
	t.Helper()
	if os.Geteuid() != 0 {
		return
	}
	if err := os.Chown(path, storeUID, storeGID); err != nil {
		t.Fatalf("chown %s: %v", path, err)
	}
}

// mkAuditDir makes an audit directory as the store keeps it, 0700.
func mkAuditDir(t *testing.T, parent, name string) string {
	t.Helper()
	dir := filepath.Join(parent, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	asStore(t, dir)
	return dir
}

// appendAudit appends lines to path, creating it 0600 as the store does.
func appendAudit(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	for _, l := range lines {
		buf.WriteString(l + "\n")
	}
	if _, err := f.WriteString(buf.String()); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	asStore(t, path)
}

// auditEntries returns every entry of the store-audit stream holding token
// in [since, now].
func auditEntries(t *testing.T, base, token string, since time.Time) []lokiStream {
	t.Helper()
	return lokiQuery(t, base, storeAuditJob+` |= "`+token+`"`, since)
}

// entryTimes returns the Loki timestamp of every entry that is exactly msg.
func entryTimes(streams []lokiStream, msg string) []time.Time {
	var out []time.Time
	for _, s := range streams {
		for _, v := range s.Values {
			if v[1] == msg {
				ns, _ := strconv.ParseInt(v[0], 10, 64)
				out = append(out, time.Unix(0, ns).UTC())
			}
		}
	}
	return out
}

// waitLoki waits until query finds an entry that is exactly msg.
func waitLoki(t *testing.T, base, query, msg, what string, since time.Time) {
	t.Helper()
	deadline := time.Now().Add(storeAuditFuncWait)
	for {
		for _, s := range lokiQuery(t, base, query, since) {
			for _, v := range s.Values {
				if v[1] == msg {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", "--tail", "100", "rasputin-alloy").CombinedOutput()
			t.Fatalf("%s never reached Loki (%s) within %s\n--- alloy log ---\n%s", what, query, storeAuditFuncWait, logs)
		}
		time.Sleep(time.Second)
	}
}

// vmVector runs an instant PromQL query and returns each series' value by its
// instance label (the Alloy container that reported it).
func vmVector(t *testing.T, base, query string) map[string]float64 {
	t.Helper()
	resp, err := http.Get(base + "/api/v1/query?" + url.Values{"query": {query}}.Encode())
	if err != nil {
		t.Fatalf("vm query %s: %v", query, err)
	}
	defer resp.Body.Close()
	var body struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  [2]any            `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("vm query %s: HTTP %d, decode %v", query, resp.StatusCode, err)
	}
	out := map[string]float64{}
	for _, r := range body.Data.Result {
		s, _ := r.Value[1].(string)
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			t.Fatalf("vm query %s: value %q: %v", query, s, err)
		}
		out[r.Metric["instance"]] += v
	}
	return out
}

// waitVM waits until an Alloy scraped selector after since (a fact this Alloy
// reported, not one an earlier Alloy left in VictoriaMetrics) with a value
// want accepts. timestamp() is applied to the bare selector: VictoriaMetrics
// returns nothing for timestamp() of a comparison.
func waitVM(t *testing.T, vmBase, selector, what string, since time.Time, want func(float64) bool) {
	t.Helper()
	deadline := time.Now().Add(storeAuditFuncWait)
	for {
		values := vmVector(t, vmBase, selector)
		for inst, ts := range vmVector(t, vmBase, `max by (instance) (timestamp(`+selector+`))`) {
			if v, ok := values[inst]; ok && ts > float64(since.Unix()) && want(v) {
				return
			}
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", "--tail", "60", "rasputin-alloy").CombinedOutput()
			t.Fatalf("%s: no sample of %s scraped after %s within %s (values %v)\n--- alloy log ---\n%s",
				what, selector, since.Format(time.RFC3339), storeAuditFuncWait, values, logs)
		}
		time.Sleep(time.Second)
	}
}

// waitAlloyRunning waits until this Alloy has loaded its config and reports
// its components: its own self-scrape, which runs only once they are running.
func waitAlloyRunning(t *testing.T, vmBase string, since time.Time) {
	t.Helper()
	waitVM(t, vmBase, `alloy_component_controller_running_components`, "Alloy running its components", since,
		func(v float64) bool { return v > 0 })
}

// waitTailing waits until this Alloy reports the store audit source tailing
// one file: the fact that it has opened the file.
func waitTailing(t *testing.T, vmBase string, since time.Time) {
	t.Helper()
	waitVM(t, vmBase, `loki_source_file_files_active_total{component_id="loki.source.file.store_audit"}`,
		"loki.source.file.store_audit tailing one file", since, func(v float64) bool { return v == 1 })
}

// assertNoUnhealthy asserts this Alloy reports no unhealthy component.
func assertNoUnhealthy(t *testing.T, stage, vmBase string) {
	t.Helper()
	q := `alloy_component_controller_running_components{health_type="unhealthy"}`
	if v := vmVector(t, vmBase, q); len(v) != 0 && slices.Max(slices.Collect(maps.Values(v))) != 0 {
		t.Errorf("%s: Alloy reports unhealthy components %v, want none", stage, v)
	} else {
		t.Logf("%s: Alloy reports no unhealthy component", stage)
	}
}

func alloyContainerID(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "-f", "{{.Id}}", "rasputin-alloy").CombinedOutput()
	if err != nil {
		t.Fatalf("docker inspect rasputin-alloy: %v (%s)", err, out)
	}
	return strings.TrimSpace(string(out))
}

func storeAuditComposeDown(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("docker", "compose", "-p", storeAuditFuncProject, "down", "-v",
		"--remove-orphans").CombinedOutput(); err != nil {
		t.Logf("compose down: %v (%s)", err, out)
	}
}

// TC-802-09 to TC-802-13.
func TestStoreAuditPipe_AgainstRealAlloyAndLoki(t *testing.T) {
	requireStoreAuditHost(t)

	stateDir, err := os.MkdirTemp("/tmp", "rsaf")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })
	storeAuditComposeDown(t)
	// Registered after the RemoveAll, so it runs first.
	t.Cleanup(func() {
		storeAuditComposeDown(t)
		out, err := exec.Command("docker", "ps", "-a", "--filter", "name=rasputin-",
			"--format", "{{.Names}}").CombinedOutput()
		if left := strings.TrimSpace(string(out)); err != nil || left != "" {
			t.Errorf("after compose down, docker ps -a rasputin-*: %q (err %v); want none", left, err)
		}
	})
	auditParent := filepath.Join(stateDir, "audit")
	if err := os.Mkdir(auditParent, 0o755); err != nil {
		t.Fatal(err)
	}

	tokBytes := make([]byte, 6)
	if _, err := rand.Read(tokBytes); err != nil {
		t.Fatal(err)
	}
	token := "fn802-" + hex.EncodeToString(tokBytes)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	off := false
	// start builds a supervisor shipping auditLog (and, when idsDir is set,
	// the IDS pipe, which changes the rendered config) and Starts it.
	start := func(t *testing.T, auditLog, idsDir string) *DockerComposeSupervisor {
		t.Helper()
		sup, err := NewDockerComposeSupervisor(DockerComposeSupervisorConfig{
			StateDir:           stateDir,
			ProjectName:        storeAuditFuncProject,
			ControlPlaneNodeID: storeAuditFuncNodeID,
			VMListenAddr:       storeAuditFuncVMAddr,
			LokiListenAddr:     storeAuditFuncLokiAddr,
			StoreAuditLog:      auditLog,
			IDSLogDir:          idsDir,
			EnableGrafana:      &off,
			EnableVMAlert:      &off,
			EnableCadvisor:     &off,
			HealthTimeout:      150 * time.Second,
			PullTimeout:        5 * time.Minute,
		})
		if err != nil {
			t.Fatalf("constructor: %v", err)
		}
		if err := sup.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		return sup
	}
	// freshAlloy removes Alloy's container and positions, so the next Start
	// runs a new Alloy over the same Loki.
	freshAlloy := func(t *testing.T) {
		t.Helper()
		if out, err := exec.Command("docker", "rm", "-f", "rasputin-alloy").CombinedOutput(); err != nil {
			t.Fatalf("docker rm -f rasputin-alloy: %v (%s)", err, out)
		}
		if err := os.RemoveAll(filepath.Join(stateDir, alloyDataDir)); err != nil {
			t.Fatal(err)
		}
	}
	// once asserts each line is in Loki exactly once, and returns its time.
	once := func(t *testing.T, stage string, streams []lokiStream, lines map[string]auditLine) map[string]time.Time {
		t.Helper()
		got := map[string]time.Time{}
		for _, name := range slices.Sorted(maps.Keys(lines)) {
			ts := entryTimes(streams, lines[name].msg)
			if len(ts) != 1 {
				t.Errorf("%s: line %s is in Loki %d times, want once", stage, name, len(ts))
				continue
			}
			got[name] = ts[0]
			t.Logf("%s: line %s is in Loki once, at %s", stage, name, ts[0].Format(time.RFC3339Nano))
		}
		return got
	}

	// Run 1: absent at start; then F (too old) and G, then C.
	t.Run("TC-802-10 absent at start, TC-802-13 backfill", func(t *testing.T) {
		dir := mkAuditDir(t, auditParent, "run1")
		live := filepath.Join(dir, "audit.log")
		began := time.Now()
		sup := start(t, live, "")
		base := sup.LokiBaseURL()
		waitAlloyRunning(t, sup.VMBaseURL(), began)
		if _, err := os.Stat(live); !os.IsNotExist(err) {
			t.Fatalf("audit.log exists before the test created it: %v", err)
		}

		now := time.Now()
		f := newAuditLine(t, token, "F", now.Add(-8*24*time.Hour))
		g := newAuditLine(t, token, "G", now)
		appendAudit(t, live, f.msg, g.msg)
		waitLoki(t, base, storeAuditJob+` |= "`+token+`-G"`, g.msg, "line G", began)
		c := newAuditLine(t, token, "C", time.Now())
		appendAudit(t, live, c.msg)
		waitLoki(t, base, storeAuditJob+` |= "`+token+`-C"`, c.msg, "line C", began)

		streams := auditEntries(t, base, token, now.Add(-9*24*time.Hour))
		times := once(t, "run 1", streams, map[string]auditLine{"G": g, "C (H)": c})
		if !times["G"].Equal(g.at) {
			t.Errorf("TC-802-13: G at %s, want its time %s", times["G"], g.at)
		}
		if n := len(entryTimes(streams, f.msg)); n != 0 {
			t.Errorf("TC-802-13: line F, 8 days old, is in Loki %d times, want 0", n)
		} else {
			t.Logf("TC-802-13: line F, 8 days old, is not in Loki")
		}
		assertNoUnhealthy(t, "TC-802-10 absent", sup.VMBaseURL())
	})
	if t.Failed() {
		return
	}

	// Run 2: empty at start.
	t.Run("TC-802-10 empty at start", func(t *testing.T) {
		freshAlloy(t)
		dir := mkAuditDir(t, auditParent, "run2")
		live := filepath.Join(dir, "audit.log")
		appendAudit(t, live)
		began := time.Now()
		sup := start(t, live, "")
		base := sup.LokiBaseURL()
		waitTailing(t, sup.VMBaseURL(), began)
		if streams := lokiQuery(t, base, storeAuditJob, began); len(streams) != 0 {
			t.Errorf("an empty audit file shipped %v, want nothing", streams)
		}
		assertNoUnhealthy(t, "TC-802-10 empty", sup.VMBaseURL())
		k := newAuditLine(t, token, "K", time.Now())
		appendAudit(t, live, k.msg)
		waitLoki(t, base, storeAuditJob+` |= "`+token+`-K"`, k.msg, "line K", began)
		once(t, "run 2", auditEntries(t, base, token, began), map[string]auditLine{"K": k})
	})
	if t.Failed() {
		return
	}

	// Run 3: shipping, entry time, malformed line, rotation, recreate.
	t.Run("TC-802-09 TC-802-11 TC-802-12", func(t *testing.T) {
		freshAlloy(t)
		dir := mkAuditDir(t, auditParent, "run3")
		live := filepath.Join(dir, "audit.log")
		began := time.Now()
		a := newAuditLine(t, token, "A", began.Add(-2*time.Minute))
		m := auditLine{msg: `{"time":"` + began.UTC().Format(time.RFC3339Nano) + `","type":"resp ` + token + `-M`}
		e := newAuditLine(t, token, "E", began.Add(-time.Minute))
		appendAudit(t, live, a.msg, m.msg, e.msg)
		since := began.Add(-10 * time.Minute)

		sup := start(t, live, "")
		base := sup.LokiBaseURL()
		waitLoki(t, base, storeAuditJob+` |= "`+token+`-E"`, e.msg, "line E", since)
		streams := auditEntries(t, base, token, since)
		times := once(t, "TC-802-09/12", streams, map[string]auditLine{"A": a, "M": m, "E": e})
		if !times["A"].Equal(a.at) {
			t.Errorf("TC-802-09: A at %s, want its time %s", times["A"], a.at)
		}
		if !times["E"].Equal(e.at) {
			t.Errorf("TC-802-12: E at %s, want its time %s", times["E"], e.at)
		}
		// A line with no parsable time is not dropped. stage.timestamp's
		// default action_on_failure, "fudge", times it 1ns after the entry
		// before it in the stream (A), so it keeps its place in the trail.
		if mt, want := times["M"], a.at.Add(time.Nanosecond); !mt.Equal(want) {
			t.Errorf("TC-802-12: the malformed line is at %s, want 1ns after A (%s)", mt, want)
		}

		// Rotate as storeaudit does: link the live file to a copy, remove
		// it, and the store creates it anew.
		if err := os.Link(live, live+".1"); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(live); err != nil {
			t.Fatal(err)
		}
		b := newAuditLine(t, token, "B", time.Now())
		appendAudit(t, live, b.msg)
		waitLoki(t, base, storeAuditJob+` |= "`+token+`-B"`, b.msg, "line B after the rotation", since)
		all := map[string]auditLine{"A": a, "M": m, "E": e, "B": b}
		once(t, "TC-802-09 after rotation", auditEntries(t, base, token, since), all)

		// Recreate Alloy by a config change, once its position covers B.
		fi, err := os.Stat(live)
		if err != nil {
			t.Fatal(err)
		}
		positions := filepath.Join(stateDir, alloyDataDir, "loki.source.file.store_audit", "positions.yml")
		want := `"` + strconv.FormatInt(fi.Size(), 10) + `"`
		deadline := time.Now().Add(storeAuditFuncWait)
		for {
			if body, err := os.ReadFile(positions); err == nil && strings.Contains(string(body), want) {
				break
			}
			if time.Now().After(deadline) {
				body, _ := os.ReadFile(positions)
				t.Fatalf("Alloy's position for audit.log never reached %s within %s:\n%s", want, storeAuditFuncWait, body)
			}
			time.Sleep(time.Second)
		}
		before := alloyContainerID(t)
		start(t, live, mkAuditDir(t, auditParent, "ids"))
		if after := alloyContainerID(t); after == before {
			t.Fatalf("TC-802-11: the config change did not recreate Alloy (container %s)", after)
		}
		d := newAuditLine(t, token, "D", time.Now())
		appendAudit(t, live, d.msg)
		waitLoki(t, base, storeAuditJob+` |= "`+token+`-D"`, d.msg, "line D after the recreate", since)
		all["D"] = d
		once(t, "TC-802-11 after recreate", auditEntries(t, base, token, since), all)

		// Over every run: one filename, the live file's.
		var names []string
		for _, s := range lokiQuery(t, base, storeAuditJob, began.Add(-9*24*time.Hour)) {
			if n := s.Labels["filename"]; !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
		if !slices.Equal(names, []string{storeAuditContainerDir + "/audit.log"}) {
			t.Errorf("TC-802-09: filename values %v, want only %s/audit.log", names, storeAuditContainerDir)
		} else {
			t.Logf("TC-802-09: the only filename is %s/audit.log", storeAuditContainerDir)
		}
	})
}
