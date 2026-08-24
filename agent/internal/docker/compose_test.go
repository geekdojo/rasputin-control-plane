package docker

import (
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
			name: "one exited",
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
