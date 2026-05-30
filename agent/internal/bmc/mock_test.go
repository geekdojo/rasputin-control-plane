package bmc

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// newMock returns a MockBackend rooted at a tempdir.
func newMock(t *testing.T) *MockBackend {
	t.Helper()
	mb, err := NewMockBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	return mb
}

func TestMockBackend_NameIsMock(t *testing.T) {
	mb := newMock(t)
	if mb.Name() != "mock" {
		t.Errorf("Name: %q, want mock", mb.Name())
	}
}

func TestMockBackend_PowerVerbsAndTransitions(t *testing.T) {
	cases := []struct {
		verb      proto.BMCPowerVerb
		wantState proto.BMCPowerState
		wantInDet string
	}{
		{proto.BMCPowerOn, proto.BMCStateOn, "powered on"},
		{proto.BMCPowerOff, proto.BMCStateOff, "powered off"},
		{proto.BMCPowerCycle, proto.BMCStateOn, "cycled"},
		{proto.BMCPowerReset, proto.BMCStateOn, "reset signal sent"},
	}
	for _, tc := range cases {
		t.Run(string(tc.verb), func(t *testing.T) {
			mb := newMock(t)
			state, detail, err := mb.Power(context.Background(), "t1", tc.verb)
			if err != nil {
				t.Fatalf("Power(%s): %v", tc.verb, err)
			}
			if state != tc.wantState {
				t.Errorf("state: got %q, want %q", state, tc.wantState)
			}
			if !strings.Contains(detail, tc.wantInDet) {
				t.Errorf("detail %q should contain %q", detail, tc.wantInDet)
			}
		})
	}
}

func TestMockBackend_QueryDoesNotMutate(t *testing.T) {
	mb := newMock(t)
	// First, power off so state is non-default.
	if _, _, err := mb.Power(context.Background(), "t1", proto.BMCPowerOff); err != nil {
		t.Fatalf("seed off: %v", err)
	}
	// Now query — must return off, must not change state.
	state, detail, err := mb.Power(context.Background(), "t1", proto.BMCPowerQuery)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if state != proto.BMCStateOff {
		t.Errorf("state: got %q, want off", state)
	}
	if detail != "queried" {
		t.Errorf("detail: %q, want 'queried'", detail)
	}
	// Re-query to confirm idempotence.
	state2, _, _ := mb.Power(context.Background(), "t1", proto.BMCPowerQuery)
	if state2 != state {
		t.Errorf("query changed state: was %q, now %q", state, state2)
	}
}

func TestMockBackend_QueryUnknownTargetReturnsUnknown(t *testing.T) {
	// Regression: blank string from a missing-key map lookup must be coerced
	// to BMCStateUnknown — otherwise the api gets "" and renders nothing.
	mb := newMock(t)
	state, _, err := mb.Power(context.Background(), "never-seen", proto.BMCPowerQuery)
	if err != nil {
		t.Fatalf("query unknown: %v", err)
	}
	if state != proto.BMCStateUnknown {
		t.Errorf("unknown target: got %q, want unknown", state)
	}
}

func TestMockBackend_UnsupportedVerbErrs(t *testing.T) {
	mb := newMock(t)
	_, _, err := mb.Power(context.Background(), "t1", proto.BMCPowerVerb("nuke"))
	if err == nil {
		t.Errorf("expected error for unsupported verb")
	}
}

func TestMockBackend_StatePersistedToDisk(t *testing.T) {
	dir := t.TempDir()
	mb, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	if _, _, err := mb.Power(context.Background(), "t1", proto.BMCPowerOn); err != nil {
		t.Fatalf("power on: %v", err)
	}
	if _, _, err := mb.Power(context.Background(), "t2", proto.BMCPowerOff); err != nil {
		t.Fatalf("power off t2: %v", err)
	}

	// Reopen — second instance should see the persisted state.
	mb2, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	s1, _, _ := mb2.Power(context.Background(), "t1", proto.BMCPowerQuery)
	s2, _, _ := mb2.Power(context.Background(), "t2", proto.BMCPowerQuery)
	if s1 != proto.BMCStateOn {
		t.Errorf("t1 after reopen: %q want on", s1)
	}
	if s2 != proto.BMCStateOff {
		t.Errorf("t2 after reopen: %q want off", s2)
	}

	// Sanity: file exists and parses as the expected shape.
	buf, err := os.ReadFile(filepath.Join(dir, "bmc.json"))
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	var st mockState
	if err := json.Unmarshal(buf, &st); err != nil {
		t.Fatalf("parse state file: %v", err)
	}
	if st.Power["t1"] != proto.BMCStateOn {
		t.Errorf("on-disk t1: %q want on", st.Power["t1"])
	}
}

func TestNewMockBackend_LoadsCorruptStateAsError(t *testing.T) {
	dir := t.TempDir()
	// Pre-write a bogus state file.
	if err := os.WriteFile(filepath.Join(dir, "bmc.json"), []byte("not-json"), 0o600); err != nil {
		t.Fatalf("seed bad json: %v", err)
	}
	if _, err := NewMockBackend(dir); err == nil {
		t.Errorf("expected error for corrupt state file")
	}
}

func TestMockBackend_HandlesEmptyPowerMapInLoadedState(t *testing.T) {
	dir := t.TempDir()
	// State file with an explicit null Power map — should be replaced with
	// an empty map so Power() doesn't nil-deref on assignment.
	if err := os.WriteFile(filepath.Join(dir, "bmc.json"), []byte(`{"power":null}`), 0o600); err != nil {
		t.Fatalf("seed null map: %v", err)
	}
	mb, err := NewMockBackend(dir)
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	if _, _, err := mb.Power(context.Background(), "t1", proto.BMCPowerOn); err != nil {
		t.Errorf("Power after null-map load: %v", err)
	}
}

// ----- SOL --------------------------------------------------------------------

// readWithTimeout pulls one chunk from out within the deadline; returns ("",
// false) on timeout. Uses a deterministic short timeout, no real-clock sleeps.
func readWithTimeout(t *testing.T, out <-chan []byte, d time.Duration) (string, bool) {
	t.Helper()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case b := <-out:
		return string(b), true
	case <-timer.C:
		return "", false
	}
}

func TestMockBackend_OpenSOLEmitsBannerAndClose(t *testing.T) {
	mb := newMock(t)
	sid := "abcdef-0123-4567-8901"
	sol, err := mb.OpenSOL(context.Background(), "target-1", sid)
	if err != nil {
		t.Fatalf("OpenSOL: %v", err)
	}
	if sol.SessionID() != sid {
		t.Errorf("SessionID: got %q, want %q", sol.SessionID(), sid)
	}
	// The banner is emitted immediately. Don't wait for the 2s uptime
	// ticker — would make the test flaky and would violate the test budget.
	got, ok := readWithTimeout(t, sol.Out(), 50*time.Millisecond)
	if !ok {
		t.Fatalf("did not receive banner within 50ms")
	}
	if !strings.Contains(got, "mock-bmc") || !strings.Contains(got, "target-1") {
		t.Errorf("banner missing expected markers: %q", got)
	}
	// Close must be clean — covers cancel + done channel handshake.
	if err := sol.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Out() will eventually drain; calling Close twice should not deadlock
	// (the underlying cancel is idempotent for our purposes here).
}

func TestMockSOL_WriteEchoesBack(t *testing.T) {
	mb := newMock(t)
	sol, err := mb.OpenSOL(context.Background(), "target-x", "012345678901-abc")
	if err != nil {
		t.Fatalf("OpenSOL: %v", err)
	}
	defer func() { _ = sol.Close() }()

	// Drain the banner first so the next received line is our echo.
	if _, ok := readWithTimeout(t, sol.Out(), 50*time.Millisecond); !ok {
		t.Fatalf("did not drain banner in time")
	}

	if err := sol.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, ok := readWithTimeout(t, sol.Out(), 50*time.Millisecond)
	if !ok {
		t.Fatalf("did not receive echo within 50ms")
	}
	if !strings.Contains(got, "mock-echo: hello") {
		t.Errorf("echo missing payload: %q", got)
	}
}

func TestMockSOL_AccessorsOnRunningSession(t *testing.T) {
	// Regression-flavored: Out() returns the same channel across calls, and
	// SessionID() returns the id we opened with. If either drifts the
	// handler's pump goroutine starts reading from the wrong channel.
	mb := newMock(t)
	sol, err := mb.OpenSOL(context.Background(), "tt", "session-id-very-long")
	if err != nil {
		t.Fatalf("OpenSOL: %v", err)
	}
	defer func() { _ = sol.Close() }()
	if sol.Out() == nil {
		t.Error("Out() channel is nil")
	}
	if sol.SessionID() != "session-id-very-long" {
		t.Errorf("session id: %q", sol.SessionID())
	}
}
