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
