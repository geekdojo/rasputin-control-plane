package docker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// compose.go helpers — pure, testable without docker. These used to live in
// mock_test.go under a "compose.go helpers" banner, which is how the tail-vs-head
// truncation bug stayed invisible: nobody looking at compose.go found a test file
// next to it.

func TestProjectNameNormalizesAppID(t *testing.T) {
	// Same input -> same name (idempotent). Mixed case folded.
	if got := projectName("AbC123"); got != "rasp_abc123" {
		t.Errorf("projectName: %q want rasp_abc123", got)
	}
	if projectName("a") != "rasp_a" {
		t.Errorf("projectName('a') should be rasp_a")
	}
}

// pullChatter is what compose actually wrote to the bench on 2026-08-23 when the
// pi-hole tile failed: per-layer progress first, the daemon's verdict last. The
// old head-keeping cap kept exactly the wrong half, so the operator saw seventeen
// lines of "Pulling fs layer" and no reason, and the tile was pulled from the
// catalog undiagnosed.
const daemonErrLine = `Error response from daemon: pull access denied for pihole/pihole, repository does not exist or may require 'docker login': denied: requested access to the resource is denied`

func pullChatter() string {
	var b strings.Builder
	layers := []string{
		"a1b2c3d4e5f6", "b2c3d4e5f6a1", "c3d4e5f6a1b2", "d4e5f6a1b2c3",
		"e5f6a1b2c3d4", "f6a1b2c3d4e5", "0a1b2c3d4e5f", "1b2c3d4e5f6a",
	}
	b.WriteString(" pihole Pulling \n")
	for _, l := range layers {
		b.WriteString(" " + l + " Pulling fs layer \n")
	}
	for _, l := range layers[:8] {
		b.WriteString(" " + l + " Downloading  [==============>  ]  41.2MB/58.7MB\n")
	}
	b.WriteString(" pihole Error \n")
	b.WriteString(daemonErrLine + "\n")
	return b.String()
}

func TestFormatCmdErr(t *testing.T) {
	cases := []struct {
		name        string
		out         string
		wantContain []string
		wantAbsent  []string
		wantSuffix  string
	}{
		{
			// Empty stdout — short format, no separator, no ellipsis.
			name:        "empty output falls back to the exit error",
			out:         "",
			wantContain: []string{"docker compose up", "rc=1"},
			wantAbsent:  []string{"…"},
		},
		{
			name:        "whitespace-only output takes the empty path",
			out:         "   \n  ",
			wantContain: []string{"docker compose up", "rc=1"},
			wantAbsent:  []string{"…"},
		},
		{
			// Short enough to survive whole — nothing is dropped and no
			// truncation marker is invented.
			name:        "output under the cap is kept verbatim",
			out:         daemonErrLine,
			wantContain: []string{daemonErrLine},
			wantAbsent:  []string{"…"},
		},
		{
			// The regression that matters. Under the cap here, but this is
			// the shape the bench produced.
			name:        "pull chatter plus a daemon error keeps the error",
			out:         pullChatter(),
			wantContain: []string{"Error response from daemon", "pull access denied"},
		},
		{
			// Over the cap: the daemon error is the LAST line, so it is the
			// one line that must survive. A head-keeping cap fails here.
			name:        "over-cap chatter still keeps the trailing daemon error",
			out:         strings.Repeat(pullChatter(), 40),
			wantContain: []string{"…", "Error response from daemon", "pull access denied"},
			wantSuffix:  daemonErrLine,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatCmdErr("docker compose up", []byte(tc.out), errExit("rc=1"))
			for _, want := range tc.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("detail missing %q\n--- got ---\n%s", want, got)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("detail should not contain %q\n--- got ---\n%s", absent, got)
				}
			}
			if tc.wantSuffix != "" && !strings.HasSuffix(got, tc.wantSuffix) {
				t.Errorf("detail should end at the real end of the output\n--- got ---\n%s", got)
			}
			// The cap is a budget, not a suggestion: label + exit error +
			// separator ride on top of maxDetailBytes, so allow a little slack.
			if len(got) > maxDetailBytes+256 {
				t.Errorf("detail not capped: len=%d (max %d + label slack)", len(got), maxDetailBytes)
			}
		})
	}
}

func TestFormatCmdErrKeepsTailNotHead(t *testing.T) {
	// Two distinct markers, one at each end, well past the cap apart. Only the
	// tail may survive — an operator reading a compose failure needs the last
	// line, never the first.
	out := "HEAD-MARKER\n" + strings.Repeat("filler line of pull progress\n", 400) + "TAIL-MARKER"
	if len(out) <= maxDetailBytes {
		t.Fatalf("fixture must exceed the cap: len=%d cap=%d", len(out), maxDetailBytes)
	}
	got := formatCmdErr("docker compose up", []byte(out), errExit("rc=1"))
	if !strings.Contains(got, "TAIL-MARKER") {
		t.Errorf("tail dropped — this is the bug\n--- got ---\n%s", got)
	}
	if strings.Contains(got, "HEAD-MARKER") {
		t.Errorf("head kept — the cap is slicing the wrong end\n--- got ---\n%s", got)
	}
	if !strings.HasSuffix(got, "TAIL-MARKER") {
		t.Errorf("truncated detail should end at the real end of the output\n--- got ---\n%s", got)
	}
	if !strings.Contains(got, "…") {
		t.Error("truncation must be visible — no ellipsis in the detail")
	}
}

func TestFormatCmdErrCutsOnALineBoundary(t *testing.T) {
	// Compose writes one status per line. Restarting mid-line reads like
	// corruption, so the cut lands on a newline whenever one is in budget.
	out := strings.Repeat("2026-08-23 layer sha256:deadbeef Extracting\n", 300) + daemonErrLine
	got := formatCmdErr("docker compose up", []byte(out), errExit("rc=1"))
	body := got[strings.Index(got, "…"):]
	for _, line := range strings.Split(body, "\n")[1:] {
		if line == "" || line == daemonErrLine {
			continue
		}
		if !strings.HasPrefix(line, "2026-08-23 layer") {
			t.Errorf("kept a partial line after the cut: %q", line)
		}
	}
}

func TestFormatCmdErrNeverSplitsARune(t *testing.T) {
	// A byte slice through a multi-byte sequence produces mojibake in the task
	// detail. Pad lengths shift where the cut lands so at least one case has a
	// wide character straddling it, whatever maxDetailBytes is set to.
	for pad := 0; pad < 4; pad++ {
		out := strings.Repeat("あ", maxDetailBytes) + strings.Repeat("!", pad)
		got := formatCmdErr("docker compose up", []byte(out), errExit("rc=1"))
		if !utf8.ValidString(got) {
			t.Errorf("pad=%d: detail is not valid UTF-8 — a rune was split by the cap", pad)
		}
		if !strings.HasSuffix(got, strings.Repeat("!", pad)) {
			t.Errorf("pad=%d: tail lost", pad)
		}
	}
}

// errExit is a tiny error helper for formatCmdErr coverage.
type errExit string

func (e errExit) Error() string { return string(e) }

func TestComposeArgs(t *testing.T) {
	got := composeArgs("/var/lib/rasputin/apps/a1/docker-compose.yml", "rasp_a1", "ps", "--format", "json")
	want := []string{
		"compose",
		"-f", "/var/lib/rasputin/apps/a1/docker-compose.yml",
		"-p", "rasp_a1",
		"ps", "--format", "json",
	}
	if len(got) != len(want) {
		t.Fatalf("composeArgs: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("composeArgs[%d] = %q want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestComposeUpArgsSuppressesPullProgress(t *testing.T) {
	// --quiet-pull is the other half of the fix: it stops compose emitting the
	// per-layer progress at the source, so the cap rarely has to fire at all.
	// Narrower than a root `--progress quiet`, which would also mute the
	// diagnostic we are trying to keep.
	args := composeArgs("/x/docker-compose.yml", "rasp_a1", composeUpArgs()...)
	for _, want := range []string{"up", "-d", "--remove-orphans", "--quiet-pull"} {
		found := false
		for _, a := range args {
			if a == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("compose up arg vector missing %q: %v", want, args)
		}
	}
	// --quiet-pull is an `up` flag, not a root flag: it must come after the
	// subcommand or the CLI rejects it.
	up, quiet := -1, -1
	for i, a := range args {
		switch a {
		case "up":
			up = i
		case "--quiet-pull":
			quiet = i
		}
	}
	if up < 0 || quiet < up {
		t.Errorf("--quiet-pull must follow the `up` subcommand: %v", args)
	}
}

func TestParsePsOutput_NDJSON(t *testing.T) {
	// Docker compose v2+ default — NDJSON, one container per line.
	ndjson := `{"Name":"a_web_1","Service":"web","State":"running","Health":"healthy"}
{"Name":"a_db_1","Service":"db","State":"exited","Health":""}
`
	svcs, err := parsePsOutput([]byte(ndjson))
	if err != nil {
		t.Fatalf("parsePsOutput: %v", err)
	}
	if len(svcs) != 2 {
		t.Fatalf("svcs: want 2, got %d", len(svcs))
	}
	if svcs[0].Name != "web" || svcs[0].State != "running" || svcs[0].Health != "healthy" {
		t.Errorf("svc[0]: %+v", svcs[0])
	}
	if svcs[1].State != "exited" {
		t.Errorf("svc[1].State: %q", svcs[1].State)
	}
}

func TestParsePsOutput_LegacyArray(t *testing.T) {
	// Older docker CLI emits a JSON array on a single line; the parser
	// must handle both shapes — that's the actual point of the array
	// branch.
	arr := `[{"Name":"a","Service":"web","State":"running"},{"Name":"b","Service":"db","State":"running"}]`
	svcs, err := parsePsOutput([]byte(arr))
	if err != nil {
		t.Fatalf("parsePsOutput: %v", err)
	}
	if len(svcs) != 2 {
		t.Fatalf("svcs: want 2, got %d", len(svcs))
	}
}

func TestParsePsOutput_Empty(t *testing.T) {
	svcs, err := parsePsOutput([]byte(""))
	if err != nil {
		t.Fatalf("parsePsOutput: %v", err)
	}
	if len(svcs) != 0 {
		t.Errorf("empty output: want 0 svcs, got %d", len(svcs))
	}
}

func TestParsePsOutput_BadLine(t *testing.T) {
	_, err := parsePsOutput([]byte(`{"bogus":` + "\n"))
	if err == nil {
		t.Error("expected parse error on truncated JSON")
	}
}

func TestAggregateStatus(t *testing.T) {
	cases := []struct {
		name string
		in   []proto.AppServiceStatus
		want proto.AppStatus
	}{
		{
			name: "all running",
			in:   []proto.AppServiceStatus{{State: "running"}, {State: "running"}},
			want: proto.AppStatusRunning,
		},
		{
			// No exit code on the wire at all — an agent older than the field,
			// or any producer that omits it. We cannot prove a clean finish,
			// so it stays a failure exactly as it was before exit codes
			// existed. This case is the whole reason ExitCode is a pointer.
			name: "exited with an unknown exit code",
			in:   []proto.AppServiceStatus{{State: "running"}, {State: "exited"}},
			want: proto.AppStatusFailed,
		},
		{
			name: "dead is failed",
			in:   []proto.AppServiceStatus{{State: "dead"}},
			want: proto.AppStatusFailed,
		},
		{
			name: "removing is failed",
			in:   []proto.AppServiceStatus{{State: "removing"}, {State: "running"}},
			want: proto.AppStatusFailed,
		},
		{
			name: "transient state is deploying",
			in:   []proto.AppServiceStatus{{State: "created"}},
			want: proto.AppStatusDeploying,
		},
		{
			name: "case-insensitive — Running counts",
			in:   []proto.AppServiceStatus{{State: "RUNNING"}},
			want: proto.AppStatusRunning,
		},
		{
			// The bug, in the exact shape that took the v11 home-assistant
			// tile down on e3bench: the app is up, its config-seed one-shot
			// has written configuration.yaml and exited 0. Before the fix
			// this returned "failed" on sight of the exited container.
			name: "init container that completed — home-assistant shape",
			in: []proto.AppServiceStatus{
				{Name: "home-assistant", State: "running", ExitCode: intp(0)},
				{Name: "home-assistant-config-seed", State: "exited", ExitCode: intp(0)},
			},
			want: proto.AppStatusRunning,
		},
		{
			// A live container also reports ExitCode 0 — confirmed against
			// compose v5.0.1. If anything ever reads the exit code without
			// the state, this is the case that catches it.
			name: "running services carry ExitCode 0 and are still running",
			in: []proto.AppServiceStatus{
				{Name: "web", State: "running", ExitCode: intp(0)},
				{Name: "db", State: "running", ExitCode: intp(0)},
			},
			want: proto.AppStatusRunning,
		},
		{
			name: "exited non-zero is failed",
			in: []proto.AppServiceStatus{
				{Name: "web", State: "running", ExitCode: intp(0)},
				{Name: "seed", State: "exited", ExitCode: intp(3)},
			},
			want: proto.AppStatusFailed,
		},
		{
			// Regression guard: an app that deployed and later crashed must
			// keep reading as failed, not get excused as a finished one-shot.
			name: "the only service crashed",
			in:   []proto.AppServiceStatus{{Name: "web", State: "exited", ExitCode: intp(137)}},
			want: proto.AppStatusFailed,
		},
		{
			// Regression guard the other way: nothing is up, so nothing may
			// claim to be running. `docker compose stop` leaves this shape
			// behind, and a stopped app must stay stopped.
			name: "every service completed cleanly",
			in: []proto.AppServiceStatus{
				{Name: "seed", State: "exited", ExitCode: intp(0)},
				{Name: "migrate", State: "exited", ExitCode: intp(0)},
			},
			want: proto.AppStatusStopped,
		},
		{
			name: "no services at all",
			in:   []proto.AppServiceStatus{},
			want: proto.AppStatusStopped,
		},
		{
			name: "completed one-shot alongside a still-settling service",
			in: []proto.AppServiceStatus{
				{Name: "seed", State: "exited", ExitCode: intp(0)},
				{Name: "web", State: "created"},
			},
			want: proto.AppStatusDeploying,
		},
		{
			// Failure outranks transience: a crashed container is a broken
			// app however busy its siblings look.
			name: "a crash outranks a transient service",
			in: []proto.AppServiceStatus{
				{Name: "web", State: "restarting"},
				{Name: "seed", State: "exited", ExitCode: intp(1)},
			},
			want: proto.AppStatusFailed,
		},
		{
			name: "case-insensitive — EXITED with code 0 counts as complete",
			in: []proto.AppServiceStatus{
				{Name: "web", State: "Running"},
				{Name: "seed", State: "EXITED", ExitCode: intp(0)},
			},
			want: proto.AppStatusRunning,
		},
		{
			name: "dead outranks a completed one-shot",
			in: []proto.AppServiceStatus{
				{Name: "seed", State: "exited", ExitCode: intp(0)},
				{Name: "web", State: "dead"},
			},
			want: proto.AppStatusFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := aggregateStatus(tc.in); got != tc.want {
				t.Errorf("aggregateStatus(%+v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestToServiceStatus(t *testing.T) {
	in := composePsLine{Name: "a_web_1", Service: "web", State: "running", Health: "healthy"}
	got := toServiceStatus(in)
	if got.Name != "web" || got.State != "running" || got.Health != "healthy" {
		t.Errorf("toServiceStatus: %+v", got)
	}
}

// intp is here because ExitCode is a *int — nil has to stay distinguishable
// from an explicit 0, so the tests need addressable literals.
func intp(i int) *int { return &i }

func TestParsePsOutputCarriesExitCode(t *testing.T) {
	// Verbatim field set from `docker compose ps --format json --all` under
	// compose v5.0.1 (trimmed of the fields we don't read). Note `web`: a
	// container that is UP still reports ExitCode 0, which is why nothing may
	// read the exit code without the state.
	ndjson := `{"Name":"a-web-1","Service":"web","State":"running","ExitCode":0,"Status":"Up Less than a second"}
{"Name":"a-seed-1","Service":"seed","State":"exited","ExitCode":0,"Status":"Exited (0) Less than a second ago"}
{"Name":"a-crasher-1","Service":"crasher","State":"exited","ExitCode":3,"Status":"Exited (3) Less than a second ago"}
`
	svcs, err := parsePsOutput([]byte(ndjson))
	if err != nil {
		t.Fatalf("parsePsOutput: %v", err)
	}
	if len(svcs) != 3 {
		t.Fatalf("svcs: want 3, got %d", len(svcs))
	}
	for i, want := range []int{0, 0, 3} {
		if svcs[i].ExitCode == nil {
			t.Fatalf("svc[%d] (%s): ExitCode is nil, want %d", i, svcs[i].Name, want)
		}
		if *svcs[i].ExitCode != want {
			t.Errorf("svc[%d] (%s): ExitCode = %d, want %d", i, svcs[i].Name, *svcs[i].ExitCode, want)
		}
	}
	if aggregateStatus(svcs[:2]) != proto.AppStatusRunning {
		t.Errorf("running + completed one-shot should aggregate to running")
	}
	if aggregateStatus(svcs) != proto.AppStatusFailed {
		t.Errorf("a crasher in the stack should aggregate to failed")
	}
}

func TestParsePsOutputLegacyArrayCarriesExitCode(t *testing.T) {
	// The single-line JSON-array shape older CLIs emit has to preserve the
	// exit code too — it goes through a different unmarshal branch.
	arr := `[{"Name":"a","Service":"web","State":"running","ExitCode":0},{"Name":"b","Service":"seed","State":"exited","ExitCode":0},{"Name":"c","Service":"bad","State":"exited","ExitCode":7}]`
	svcs, err := parsePsOutput([]byte(arr))
	if err != nil {
		t.Fatalf("parsePsOutput: %v", err)
	}
	if len(svcs) != 3 {
		t.Fatalf("svcs: want 3, got %d", len(svcs))
	}
	for i, want := range []int{0, 0, 7} {
		if svcs[i].ExitCode == nil || *svcs[i].ExitCode != want {
			t.Errorf("svc[%d] (%s): ExitCode = %v, want %d", i, svcs[i].Name, svcs[i].ExitCode, want)
		}
	}
}

func TestParsePsOutputAbsentExitCodeStaysUnknown(t *testing.T) {
	// The trap: output with no ExitCode key must NOT come back as a clean
	// zero. nil means "we were not told", and an exited container we were not
	// told about is a failure.
	svcs, err := parsePsOutput([]byte(`{"Name":"a-seed-1","Service":"seed","State":"exited"}` + "\n"))
	if err != nil {
		t.Fatalf("parsePsOutput: %v", err)
	}
	if svcs[0].ExitCode != nil {
		t.Fatalf("absent ExitCode came back as %d — absent must not read as 0", *svcs[0].ExitCode)
	}
	if got := aggregateStatus(svcs); got != proto.AppStatusFailed {
		t.Errorf("exited with unknown exit code = %q, want %q", got, proto.AppStatusFailed)
	}
}

func TestDeployDetail(t *testing.T) {
	cases := []struct {
		name   string
		status proto.AppStatus
		in     []proto.AppServiceStatus
		// wantHas are substrings the message must carry; wantHead is what the
		// first 36 chars (the Apps-table tooltip clip) must start with.
		wantHas  []string
		wantHead string
	}{
		{
			name:   "crashed service is named with its exit code",
			status: proto.AppStatusFailed,
			in: []proto.AppServiceStatus{
				{Name: "web", State: "running", ExitCode: intp(0)},
				{Name: "seed", State: "exited", ExitCode: intp(3)},
			},
			wantHas:  []string{"seed", "code 3", "1/2 services running"},
			wantHead: "seed exited (code 3)",
		},
		{
			name:    "unknown exit code says so rather than inventing one",
			status:  proto.AppStatusFailed,
			in:      []proto.AppServiceStatus{{Name: "seed", State: "exited"}},
			wantHas: []string{"seed", "exit code unknown"},
		},
		{
			name:     "dead service is named",
			status:   proto.AppStatusFailed,
			in:       []proto.AppServiceStatus{{Name: "db", State: "dead"}},
			wantHas:  []string{"db", "dead"},
			wantHead: "db dead",
		},
		{
			name:   "a stack of finished one-shots reads as completed, not failed",
			status: proto.AppStatusStopped,
			in: []proto.AppServiceStatus{
				{Name: "seed", State: "exited", ExitCode: intp(0)},
			},
			wantHas: []string{"seed", "completed (exit 0)", "stopped"},
		},
		{
			name:    "still settling names the transient service",
			status:  proto.AppStatusDeploying,
			in:      []proto.AppServiceStatus{{Name: "web", State: "created"}},
			wantHas: []string{"web", "created", "deploying"},
		},
		{
			name:    "no containers at all",
			status:  proto.AppStatusStopped,
			in:      nil,
			wantHas: []string{"no containers"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := deployDetail(tc.status, tc.in)
			if got == "" {
				t.Fatal("deployDetail returned an empty string — that is the bug")
			}
			for _, want := range tc.wantHas {
				if !strings.Contains(got, want) {
					t.Errorf("detail %q is missing %q", got, want)
				}
			}
			if tc.wantHead != "" && !strings.HasPrefix(got, tc.wantHead) {
				t.Errorf("detail %q must lead with %q — the table tooltip clips to ~36 chars", got, tc.wantHead)
			}
		})
	}
}

// fakeDockerOnPath installs a stub `docker` executable that answers
// `compose ... up` with success and `compose ... ps --format json --all` with
// psJSON. It lets the Deploy wiring be tested end-to-end without a daemon;
// the real-compose proof lives in the `docker`-tagged functional test.
func fakeDockerOnPath(t *testing.T, psJSON string) {
	t.Helper()
	binDir := t.TempDir()
	script := "#!/bin/sh\nfor a in \"$@\"; do\n  if [ \"$a\" = \"ps\" ]; then\n    cat <<'PSEOF'\n" +
		psJSON + "PSEOF\n    exit 0\n  fi\ndone\nexit 0\n"
	if err := os.WriteFile(filepath.Join(binDir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestDeployNonRunningReturnsDetailNamingTheService(t *testing.T) {
	// This is the second bug: Deploy used to return "" for every non-running
	// outcome, so the operator got a bare FAILED chip and the drawer — which
	// only renders its failure block when lastDetail is non-empty — showed
	// nothing at all.
	fakeDockerOnPath(t, `{"Name":"x-web-1","Service":"web","State":"running","ExitCode":0}
{"Name":"x-seed-1","Service":"seed","State":"exited","ExitCode":3}
`)
	c, err := NewComposeBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewComposeBackend: %v", err)
	}
	status, detail, err := c.Deploy(context.Background(), "01TESTAPP", "test", "services: {}\n")
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if status != proto.AppStatusFailed {
		t.Fatalf("status = %q, want %q", status, proto.AppStatusFailed)
	}
	if detail == "" {
		t.Fatal("Deploy returned an empty detail for a non-running status — the failure is invisible to the operator")
	}
	if !strings.Contains(detail, "seed") || !strings.Contains(detail, "3") {
		t.Errorf("detail %q must name the offending service and its exit code", detail)
	}
	t.Logf("detail: %s", detail)
}

func TestDeployOneShotStackReportsRunningWithNoDetail(t *testing.T) {
	// The home-assistant case, through the whole Deploy path: a running app
	// plus a one-shot that finished is a successful deploy, and a successful
	// deploy carries no failure detail.
	fakeDockerOnPath(t, `{"Name":"x-ha-1","Service":"home-assistant","State":"running","ExitCode":0}
{"Name":"x-seed-1","Service":"home-assistant-config-seed","State":"exited","ExitCode":0}
`)
	c, err := NewComposeBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewComposeBackend: %v", err)
	}
	status, detail, err := c.Deploy(context.Background(), "01TESTAPP", "home-assistant", "services: {}\n")
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if status != proto.AppStatusRunning {
		t.Fatalf("status = %q, want %q (detail: %q)", status, proto.AppStatusRunning, detail)
	}
	if detail != "" {
		t.Errorf("a successful deploy should carry no detail, got %q", detail)
	}
}
