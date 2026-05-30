package tailscale

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func newTSMock(t *testing.T) *MockBackend {
	t.Helper()
	mb, err := NewMockBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	return mb
}

func TestMockBackend_NameIsMock(t *testing.T) {
	if got := newTSMock(t).Name(); got != "mock" {
		t.Errorf("Name: %q want mock", got)
	}
}

func TestMockBackend_EnrollHappyPath(t *testing.T) {
	mb := newTSMock(t)
	st, err := mb.Enroll(context.Background(), EnrollInput{
		LoginServer:     "https://headscale.local",
		AuthKey:         "tskey-abc",
		Hostname:        "n1",
		AdvertiseRoutes: []string{"10.0.0.0/24"},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if !st.Enrolled {
		t.Errorf("Enrolled should be true after enroll")
	}
	if st.Hostname != "n1" {
		t.Errorf("Hostname: %q", st.Hostname)
	}
	if len(st.Routes) != 1 || st.Routes[0] != "10.0.0.0/24" {
		t.Errorf("Routes: %+v", st.Routes)
	}
}

func TestMockBackend_EnrollRejectsEmptyAuthKey(t *testing.T) {
	mb := newTSMock(t)
	_, err := mb.Enroll(context.Background(), EnrollInput{
		LoginServer: "https://headscale.local",
		AuthKey:     "",
		Hostname:    "n1",
	})
	if err == nil {
		t.Errorf("expected error on empty auth key")
	}
}

func TestMockBackend_StatusReflectsEnrollState(t *testing.T) {
	mb := newTSMock(t)
	// Before enroll — not enrolled.
	st, err := mb.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Enrolled {
		t.Errorf("fresh mock should not be enrolled")
	}

	// After enroll.
	if _, err := mb.Enroll(context.Background(), EnrollInput{AuthKey: "k", Hostname: "n"}); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	st, err = mb.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Enrolled || st.Hostname != "n" {
		t.Errorf("status after enroll: %+v", st)
	}
}

func TestMockBackend_LeaveClearsState(t *testing.T) {
	mb := newTSMock(t)
	if _, err := mb.Enroll(context.Background(), EnrollInput{AuthKey: "k", Hostname: "n"}); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := mb.Leave(context.Background()); err != nil {
		t.Fatalf("Leave: %v", err)
	}
	st, _ := mb.Status(context.Background())
	if st.Enrolled || st.Hostname != "" {
		t.Errorf("after leave, expected empty status, got %+v", st)
	}
}

func TestMockBackend_StatePersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	mb, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	if _, err := mb.Enroll(context.Background(), EnrollInput{AuthKey: "k", Hostname: "n-1"}); err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Reopen — state file should drive a Status call.
	mb2, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	st, _ := mb2.Status(context.Background())
	if !st.Enrolled || st.Hostname != "n-1" {
		t.Errorf("state lost on reopen: %+v", st)
	}

	// And check the on-disk JSON shape so a refactor doesn't silently
	// change the persisted format.
	buf, err := os.ReadFile(filepath.Join(dir, "tailscale.json"))
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(buf, &v); err != nil {
		t.Errorf("on-disk state is not JSON: %v", err)
	}
	if v["enrolled"] != true {
		t.Errorf("on-disk enrolled key wrong shape: %v", v)
	}
}

func TestNewMockBackend_RejectsBadStateDir(t *testing.T) {
	// Pre-create a file where stateDir would be; MkdirAll should fail.
	tmp := t.TempDir()
	clash := filepath.Join(tmp, "file-not-dir")
	if err := os.WriteFile(clash, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed clashing file: %v", err)
	}
	if _, err := NewMockBackend(clash); err == nil {
		t.Errorf("expected error when state dir is a file")
	}
}

func TestNewMockBackend_CorruptStateFileErrs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tailscale.json"), []byte("garbage"), 0o600); err != nil {
		t.Fatalf("seed bad state: %v", err)
	}
	if _, err := NewMockBackend(dir); err == nil {
		t.Errorf("expected error on corrupt state")
	}
}

// TestNewRealBackend_NameOrLookupErr exercises the real-backend constructor.
// It either returns an error (no tailscale on PATH) or a backend whose Name
// is "tailscale". We accept both — this is the contract.
func TestNewRealBackend_NameOrLookupErr(t *testing.T) {
	b, err := NewRealBackend()
	if err != nil {
		// No tailscale on PATH — expected on CI / dev boxes without it.
		return
	}
	if b.Name() != "tailscale" {
		t.Errorf("real backend Name: %q want tailscale", b.Name())
	}
}
