package docker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func newDockerMock(t *testing.T) *MockBackend {
	t.Helper()
	mb, err := NewMockBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	return mb
}

func TestMockBackend_NameIsMock(t *testing.T) {
	if got := newDockerMock(t).Name(); got != "mock" {
		t.Errorf("Name: %q want mock", got)
	}
}

func TestMockBackend_DeployWritesComposeAndState(t *testing.T) {
	dir := t.TempDir()
	mb, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	status, detail, err := mb.Deploy(context.Background(), "a1", "minecraft", "services:\n  m: {}\n")
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if status != proto.AppStatusRunning {
		t.Errorf("status: %q want running", status)
	}
	if !strings.Contains(detail, "mock") {
		t.Errorf("detail should mention mock backend, got %q", detail)
	}

	// Compose file landed.
	compose, err := os.ReadFile(filepath.Join(dir, "a1", "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read compose: %v", err)
	}
	if !strings.Contains(string(compose), "services:") {
		t.Errorf("compose content lost: %q", string(compose))
	}

	// State file landed and reflects running.
	st, err := os.ReadFile(filepath.Join(dir, "a1", "state.json"))
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var ms mockState
	if err := json.Unmarshal(st, &ms); err != nil {
		t.Fatalf("parse state: %v", err)
	}
	if ms.AppID != "a1" || ms.Name != "minecraft" {
		t.Errorf("state fields: %+v", ms)
	}
	if ms.Status != string(proto.AppStatusRunning) {
		t.Errorf("status: %q want running", ms.Status)
	}
}

func TestMockBackend_StopAfterDeploy(t *testing.T) {
	mb := newDockerMock(t)
	ctx := context.Background()
	if _, _, err := mb.Deploy(ctx, "a1", "minecraft", "services: {}"); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	status, detail, err := mb.Stop(ctx, "a1")
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if status != proto.AppStatusStopped {
		t.Errorf("status: %q want stopped", status)
	}
	if !strings.Contains(detail, "stopped") {
		t.Errorf("detail: %q", detail)
	}
}

func TestMockBackend_StopUnknownAppIsClean(t *testing.T) {
	// Regression: stopping an app that was never deployed should land
	// silently on "stopped" — the mock's loadState falls through to default
	// stopped state, and Stop just persists that. This mirrors what the
	// real backend does when the compose file is missing.
	mb := newDockerMock(t)
	status, _, err := mb.Stop(context.Background(), "never-deployed")
	if err != nil {
		t.Fatalf("Stop on missing app: %v", err)
	}
	if status != proto.AppStatusStopped {
		t.Errorf("status: %q want stopped", status)
	}
}

func TestMockBackend_StatusReturnsLastWrittenStatus(t *testing.T) {
	mb := newDockerMock(t)
	ctx := context.Background()
	if _, _, err := mb.Deploy(ctx, "a1", "x", "services: {}"); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	st, svcs, err := mb.Status(ctx, "a1")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st != proto.AppStatusRunning {
		t.Errorf("status: %q want running", st)
	}
	if svcs != nil {
		t.Errorf("mock should report nil services, got %+v", svcs)
	}
	// After Stop, Status flips.
	if _, _, err := mb.Stop(ctx, "a1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	st, _, err = mb.Status(ctx, "a1")
	if err != nil {
		t.Fatalf("Status after stop: %v", err)
	}
	if st != proto.AppStatusStopped {
		t.Errorf("status after stop: %q", st)
	}
}

func TestMockBackend_StatusForUnknownAppIsStopped(t *testing.T) {
	mb := newDockerMock(t)
	st, _, err := mb.Status(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st != proto.AppStatusStopped {
		t.Errorf("status: %q want stopped", st)
	}
}

func TestMockBackend_LoadStateCorruptFile(t *testing.T) {
	mb := newDockerMock(t)
	// Deploy once to make appDir exist, then corrupt state.json directly.
	ctx := context.Background()
	if _, _, err := mb.Deploy(ctx, "a1", "x", "services: {}"); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mb.dir, "a1", "state.json"), []byte("not-json"), 0o644); err != nil {
		t.Fatalf("corrupt state: %v", err)
	}
	// loadState() bubbles up the unmarshal error via Status() -> AppStatusUnknown + err.
	st, _, err := mb.Status(ctx, "a1")
	if err == nil {
		t.Error("expected error from corrupt state file")
	}
	if st != proto.AppStatusUnknown {
		t.Errorf("status on corrupt state: %q want unknown", st)
	}
}

// ----- compose.go helpers — pure, testable without docker ---------------------

func TestProjectNameNormalizesAppID(t *testing.T) {
	// Same input -> same name (idempotent). Mixed case folded.
	if got := projectName("AbC123"); got != "rasp_abc123" {
		t.Errorf("projectName: %q want rasp_abc123", got)
	}
	if projectName("a") != "rasp_a" {
		t.Errorf("projectName('a') should be rasp_a")
	}
}

func TestFormatCmdErr(t *testing.T) {
	// Empty stdout — short format.
	short := formatCmdErr("docker compose up", []byte(""), errExit("rc=1"))
	if !strings.Contains(short, "docker compose up") || !strings.Contains(short, "rc=1") {
		t.Errorf("short err missing context: %q", short)
	}
	// Long stdout — truncated.
	big := strings.Repeat("X", 1000)
	long := formatCmdErr("docker compose up", []byte(big), errExit("rc=1"))
	if !strings.Contains(long, "…") {
		t.Errorf("long err should be truncated with ellipsis: %q", long)
	}
	if len(long) > 700 {
		t.Errorf("long err not actually truncated: len=%d", len(long))
	}
	// Whitespace-only stdout — same path as empty.
	ws := formatCmdErr("label", []byte("   \n  "), errExit("e"))
	if !strings.Contains(ws, "label") {
		t.Errorf("whitespace stdout dropped label: %q", ws)
	}
}

// errExit is a tiny error helper for formatCmdErr coverage.
type errExit string

func (e errExit) Error() string { return string(e) }

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
