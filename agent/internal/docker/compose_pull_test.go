package docker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The pull-only verb and the outdated-container reading (geekdojo/geekdojo-brain#411),
// without a daemon. The live proof is in compose_docker_test.go.

const (
	livePullAppID  = "01J9ZK3Q0M8X7Y6W5V4T3S2R1P"
	liveComposeV1  = "services:\n  web:\n    image: e/kuma:1@sha256:1111111111111111111111111111111111111111111111111111111111111111\n"
	stagedCompose2 = "services:\n  web:\n    image: e/kuma:2@sha256:2222222222222222222222222222222222222222222222222222222222222222\n"
)

// pullRecorder is a docker CLI that records every invocation and, for the
// pull, what the -f file held at the moment compose would have read it.
type pullRecorder struct {
	calls      [][]string
	stagedPath string
	stagedYAML string
	err        error
	out        string
}

func (r *pullRecorder) run(_ context.Context, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	for i, a := range args {
		if a == "-f" && i+1 < len(args) {
			r.stagedPath = args[i+1]
			b, _ := os.ReadFile(args[i+1])
			r.stagedYAML = string(b)
		}
	}
	return []byte(r.out), r.err
}

// seedLiveCompose writes the app's live compose as a deploy would have, with an
// old mtime so a rewrite of the same bytes would still show.
func seedLiveCompose(t *testing.T, c *ComposeBackend) time.Time {
	t.Helper()
	if err := os.MkdirAll(c.appDir(livePullAppID), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.composePath(livePullAppID), []byte(liveComposeV1), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(c.composePath(livePullAppID), old, old); err != nil {
		t.Fatal(err)
	}
	return old
}

func assertLiveComposeUntouched(t *testing.T, c *ComposeBackend, mtime time.Time) {
	t.Helper()
	fi, err := os.Stat(c.composePath(livePullAppID))
	if err != nil {
		t.Fatalf("live compose: %v", err)
	}
	b, _ := os.ReadFile(c.composePath(livePullAppID))
	if string(b) != liveComposeV1 {
		t.Errorf("live compose changed:\n%s", b)
	}
	if !fi.ModTime().Equal(mtime) {
		t.Errorf("live compose was rewritten: mtime %s → %s", mtime, fi.ModTime())
	}
	leftovers, _ := filepath.Glob(filepath.Join(c.appDir(livePullAppID), ".pull-*"))
	if len(leftovers) != 0 {
		t.Errorf("staged compose left behind: %v", leftovers)
	}
}

// The done-means on the agent: a pull that fails leaves the app's live compose
// file byte-for-byte and mtime-for-mtime as it was, pulled from a staged copy
// of the NEW compose under the SAME project, and ran nothing but `pull`.
func TestPullFailureLeavesTheLiveComposeUntouched(t *testing.T) {
	rec := &pullRecorder{err: errExit("exit status 1"), out: `Error response from daemon: manifest for e/kuma:2 not found`}
	c := &ComposeBackend{dir: t.TempDir(), exec: rec.run}
	mtime := seedLiveCompose(t, c)

	detail, err := c.Pull(context.Background(), livePullAppID, stagedCompose2)
	if err == nil {
		t.Fatal("a failed pull must return its error")
	}
	if !strings.Contains(detail, "docker compose pull") || !strings.Contains(detail, "manifest for e/kuma:2 not found") {
		t.Errorf("detail %q must name the verb and carry the daemon's reason", detail)
	}
	assertLiveComposeUntouched(t, c, mtime)

	if len(rec.calls) != 1 {
		t.Fatalf("docker was invoked %d times, want exactly the one pull: %v", len(rec.calls), rec.calls)
	}
	if rec.stagedPath == c.composePath(livePullAppID) {
		t.Fatal("the pull was pointed at the live compose file")
	}
	if filepath.Dir(rec.stagedPath) != c.appDir(livePullAppID) {
		t.Errorf("staged compose %s is not in the app's directory, so the project directory would differ from a deploy's", rec.stagedPath)
	}
	if rec.stagedYAML != stagedCompose2 {
		t.Errorf("compose read the staged file as %q, want the new compose", rec.stagedYAML)
	}
	want := composeArgs(rec.stagedPath, "rasp_"+strings.ToLower(livePullAppID), "pull", "--quiet", "--policy", "missing", "--ignore-buildable")
	if got := strings.Join(rec.calls[0], " "); got != strings.Join(want, " ") {
		t.Errorf("pull argv = %s\nwant       %s", got, strings.Join(want, " "))
	}
	for _, a := range rec.calls[0] {
		if a == "up" || a == "down" || a == "create" || a == "start" || a == "stop" {
			t.Errorf("a pull invoked %q: %v", a, rec.calls[0])
		}
	}
}

// Success is no different to the live file, and the staged copy still goes.
func TestPullSuccessAlsoLeavesTheLiveComposeUntouched(t *testing.T) {
	rec := &pullRecorder{}
	c := &ComposeBackend{dir: t.TempDir(), exec: rec.run}
	mtime := seedLiveCompose(t, c)

	if detail, err := c.Pull(context.Background(), livePullAppID, stagedCompose2); err != nil || detail != "" {
		t.Fatalf("Pull = %q, %v", detail, err)
	}
	assertLiveComposeUntouched(t, c, mtime)
}

// An app with no state directory yet (never deployed on this node) can be
// pulled for, and still gets no compose file.
func TestPullForAnUndeployedAppWritesNoComposeFile(t *testing.T) {
	rec := &pullRecorder{}
	c := &ComposeBackend{dir: t.TempDir(), exec: rec.run}
	if _, err := c.Pull(context.Background(), livePullAppID, stagedCompose2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.composePath(livePullAppID)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a pull created the app's compose file (stat err = %v)", err)
	}
	if status, _, _ := c.Status(context.Background(), livePullAppID); status != proto.AppStatusStopped {
		t.Errorf("status after a pull = %q, want stopped", status)
	}
}

// The id names a directory the pull writes into, and it arrives off the bus.
func TestPullRefusesAnAppIDThatIsNotOnePathElement(t *testing.T) {
	for _, id := range []string{"", ".", "..", "../escape", "a/b", `a\b`} {
		rec := &pullRecorder{}
		root := t.TempDir()
		c := &ComposeBackend{dir: filepath.Join(root, "apps"), exec: rec.run}
		if _, err := c.Pull(context.Background(), id, stagedCompose2); err == nil {
			t.Errorf("app id %q: want a refusal", id)
		}
		if len(rec.calls) != 0 {
			t.Errorf("app id %q: docker was invoked: %v", id, rec.calls)
		}
		if ents, _ := os.ReadDir(root); len(ents) != 0 {
			t.Errorf("app id %q: a refused pull created %v", id, ents)
		}
	}
}

func TestParseConfigHashesIgnoresWarnings(t *testing.T) {
	out := []byte(`time="2026-09-12T12:58:09-07:00" level=warning msg="No services to build"
web 05dd866af7213daf4b6685629c137480a17ff98b087aad66071395bf7d4bb1f0
db 6b0c5ce4c00d6c217499d2851895f7d3879e982aba1e9a38bc4aad9cf3ba4cc4
not-a-hash deadbeef
`)
	got := parseConfigHashes(out)
	if len(got) != 2 || got["web"] != "05dd866af7213daf4b6685629c137480a17ff98b087aad66071395bf7d4bb1f0" ||
		got["db"] != "6b0c5ce4c00d6c217499d2851895f7d3879e982aba1e9a38bc4aad9cf3ba4cc4" {
		t.Fatalf("parseConfigHashes = %v", got)
	}
}

func TestConfigHashLabel(t *testing.T) {
	// The Labels string as compose v5.0.1 emits it.
	labels := "com.docker.compose.version=5.0.1,com.docker.compose.project=rasp_x,com.docker.compose.service=app," +
		"com.docker.compose.config-hash=fbefb564066a13072cfe3a1a8699842d03408ca96d0f5d36d0c9249755006f8b,com.docker.compose.oneoff=False"
	if got := configHashLabel(labels); got != "fbefb564066a13072cfe3a1a8699842d03408ca96d0f5d36d0c9249755006f8b" {
		t.Errorf("configHashLabel = %q", got)
	}
	for _, l := range []string{"", "com.docker.compose.project=rasp_x", "com.docker.compose.config-hash=short"} {
		if got := configHashLabel(l); got != "" {
			t.Errorf("configHashLabel(%q) = %q, want unknown", l, got)
		}
	}
}

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hashC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// fakeComposeOnPath is fakeDockerOnPath that also answers `config --hash`
// with hashOut (and exits hashExit).
func fakeComposeOnPath(t *testing.T, psJSON, hashOut string, hashExit int) {
	t.Helper()
	binDir := t.TempDir()
	var script bytes.Buffer
	script.WriteString("#!/bin/sh\nfor a in \"$@\"; do\n")
	script.WriteString("  if [ \"$a\" = \"ps\" ]; then\n    cat <<'PSEOF'\n" + psJSON + "PSEOF\n    exit 0\n  fi\n")
	script.WriteString("  if [ \"$a\" = \"config\" ]; then\n    cat <<'HASHEOF'\n" + hashOut + "HASHEOF\n    exit " + string(rune('0'+hashExit)) + "\n  fi\n")
	script.WriteString("done\nexit 0\n")
	if err := os.WriteFile(filepath.Join(binDir, "docker"), script.Bytes(), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func statusWith(t *testing.T, psJSON, hashOut string, hashExit int) (proto.AppStatus, map[string]proto.AppServiceStatus) {
	t.Helper()
	fakeComposeOnPath(t, psJSON, hashOut, hashExit)
	c := &ComposeBackend{dir: t.TempDir()}
	seedLiveComposeFor(t, c, "01TESTAPP")
	status, services, err := c.Status(context.Background(), "01TESTAPP")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	byName := map[string]proto.AppServiceStatus{}
	for _, s := range services {
		byName[s.Name] = s
	}
	return status, byName
}

func seedLiveComposeFor(t *testing.T, c *ComposeBackend, appID string) {
	t.Helper()
	if err := os.MkdirAll(c.appDir(appID), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.composePath(appID), []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func psLine(service, state, hash string) string {
	return `{"Service":"` + service + `","State":"` + state + `","ExitCode":0,"Labels":"com.docker.compose.project=rasp_x,com.docker.compose.config-hash=` + hash + `"}` + "\n"
}

// The reading reconcile needs: a running container created from a definition
// the live file no longer has is outdated; one that matches is not; and the
// app's STATUS is unchanged by it — the containers really are running.
func TestStatusMarksRunningContainersFromAnotherComposeOutdated(t *testing.T) {
	ps := psLine("web", "running", hashA) + // current
		psLine("db", "running", hashB) + // file now says hashC
		psLine("gone", "running", hashA) + // the file no longer declares it
		psLine("seed", "exited", hashB) // not running: never judged
	status, got := statusWith(t, ps, "web "+hashA+"\ndb "+hashC+"\nseed "+hashC+"\n", 0)
	if status != proto.AppStatusRunning {
		t.Errorf("status = %q, want running", status)
	}
	if got["web"].Outdated {
		t.Error("web matches the live file and must not be outdated")
	}
	if !got["db"].Outdated {
		t.Error("db was created from another definition and must be outdated")
	}
	if !got["gone"].Outdated {
		t.Error("a running service the live file does not declare must be outdated")
	}
	if got["seed"].Outdated {
		t.Error("an exited container is not judged")
	}
}

// Unknown is never outdated: a failed hash listing, an empty one, or a
// container without the label all read as the status did before the field.
func TestStatusOutdatedIsFalseWhenTheComparisonCannotBeMade(t *testing.T) {
	cases := []struct {
		name     string
		ps       string
		hashOut  string
		hashExit int
	}{
		{"config --hash fails", psLine("web", "running", hashB), "no such flag\n", 1},
		{"config --hash prints nothing usable", psLine("web", "running", hashB), "level=warning msg=x\n", 0},
		{"container has no config-hash label", `{"Service":"web","State":"running","ExitCode":0,"Labels":"com.docker.compose.project=rasp_x"}` + "\n", "web " + hashA + "\n", 0},
		{"older ps output without Labels", `{"Service":"web","State":"running","ExitCode":0}` + "\n", "web " + hashA + "\n", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, got := statusWith(t, c.ps, c.hashOut, c.hashExit)
			if got["web"].Outdated {
				t.Error("an unmade comparison must not read as outdated")
			}
		})
	}
}
