package setup

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(context.Background(), filepath.Join(dir, "setup.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// ============================================================================
// Store: Get / Set / GetTime / SetTime
// ============================================================================

func TestStore_GetUnknownIsEmpty(t *testing.T) {
	s := newStore(t)
	v, err := s.Get(context.Background(), "no.such.key")
	if err != nil {
		t.Fatalf("Get unknown: %v", err)
	}
	if v != "" {
		t.Errorf("want empty string, got %q", v)
	}
}

func TestStore_SetGet_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.Set(ctx, "ui.theme", "rasputin"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get(ctx, "ui.theme")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "rasputin" {
		t.Errorf("want %q, got %q", "rasputin", got)
	}
}

func TestStore_Set_UpsertsExistingKey(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.Set(ctx, "ui.theme", "dark"); err != nil {
		t.Fatalf("first Set: %v", err)
	}
	if err := s.Set(ctx, "ui.theme", "rasputin"); err != nil {
		t.Fatalf("second Set: %v", err)
	}
	got, _ := s.Get(ctx, "ui.theme")
	if got != "rasputin" {
		t.Errorf("upsert lost: got %q", got)
	}
}

func TestStore_GetTime_UnsetIsNil(t *testing.T) {
	s := newStore(t)
	got, err := s.GetTime(context.Background(), "absent")
	if err != nil {
		t.Fatalf("GetTime absent: %v", err)
	}
	if got != nil {
		t.Errorf("want nil, got %v", got)
	}
}

func TestStore_SetTimeGetTime_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	// Use a value with a clean ms boundary so the round-trip equals exactly.
	t0 := time.UnixMilli(1717000000000).UTC()
	if err := s.SetTime(ctx, KeyWizardCompletedAt, t0); err != nil {
		t.Fatalf("SetTime: %v", err)
	}
	got, err := s.GetTime(ctx, KeyWizardCompletedAt)
	if err != nil {
		t.Fatalf("GetTime: %v", err)
	}
	if got == nil {
		t.Fatal("GetTime returned nil for a set key")
	}
	if !got.Equal(t0) {
		t.Errorf("round trip: got %v want %v", got, t0)
	}
}

func TestStore_GetTime_GarbageValueErrors(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	// Manually plant a non-numeric value to exercise the parse-error path.
	if err := s.Set(ctx, "rogue.time", "not-a-number"); err != nil {
		t.Fatalf("Set garbage: %v", err)
	}
	_, err := s.GetTime(ctx, "rogue.time")
	if err == nil {
		t.Error("expected error parsing garbage time value")
	}
}

// ============================================================================
// Service: GetState across the various probe combinations.
//
// The Probes pattern lets each test close over local state without rebuilding
// the Service — mirrors the alerts test fixture.
// ============================================================================

type probesState struct {
	hasUsers        bool
	trustConfigured bool
	meshEnrolled    bool
	hasUsersErr     error
	meshErr         error
}

func buildService(t *testing.T, ps *probesState, selfNodeID string) *Service {
	t.Helper()
	store := newStore(t)
	probes := Probes{
		HasUsers: func(ctx context.Context) (bool, error) {
			return ps.hasUsers, ps.hasUsersErr
		},
		TrustConfigured: func() bool { return ps.trustConfigured },
		MeshEnrolled: func(ctx context.Context, nodeID string) (bool, error) {
			return ps.meshEnrolled, ps.meshErr
		},
	}
	return NewService(store, probes, selfNodeID)
}

func findStep(steps []Step, id string) (Step, bool) {
	for _, s := range steps {
		if s.ID == id {
			return s, true
		}
	}
	return Step{}, false
}

func TestService_GetState_EmptyShowsAllStepsUndone(t *testing.T) {
	ps := &probesState{}
	svc := buildService(t, ps, "self-1")
	state, err := svc.GetState(context.Background())
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if state.Completed {
		t.Error("brand-new install should not report Completed")
	}
	if state.InstallName != "" {
		t.Errorf("InstallName should be empty, got %q", state.InstallName)
	}
	if state.SelfNodeID != "self-1" {
		t.Errorf("SelfNodeID: got %q", state.SelfNodeID)
	}
	for _, id := range []string{"passkey", "install_name", "remote_access", "trust"} {
		st, ok := findStep(state.Steps, id)
		if !ok {
			t.Errorf("missing step %q", id)
			continue
		}
		if st.Done {
			t.Errorf("step %q should not be done", id)
		}
	}
}

func TestService_GetState_StepDoneFlagsTrackProbes(t *testing.T) {
	ctx := context.Background()
	ps := &probesState{hasUsers: true, trustConfigured: true, meshEnrolled: true}
	svc := buildService(t, ps, "self")
	// SetInstallName flips the install_name step to done.
	if err := svc.SetInstallName(ctx, "My Cluster"); err != nil {
		t.Fatalf("SetInstallName: %v", err)
	}

	state, err := svc.GetState(ctx)
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	for _, id := range []string{"passkey", "install_name", "remote_access", "trust"} {
		st, _ := findStep(state.Steps, id)
		if !st.Done {
			t.Errorf("step %q should be done", id)
		}
	}
	if state.Completed {
		// Still not Completed because MarkCompleted hasn't been called.
		t.Error("Completed should remain false until MarkCompleted is recorded")
	}
}

func TestService_GetState_CompletedOnlyAfterMarkCompleted(t *testing.T) {
	ctx := context.Background()
	ps := &probesState{hasUsers: true}
	svc := buildService(t, ps, "self")
	if err := svc.SetInstallName(ctx, "X"); err != nil {
		t.Fatalf("SetInstallName: %v", err)
	}
	// At this point both required steps are done but MarkCompleted is not yet
	// recorded — Completed must stay false to give the operator the chance
	// to click Finish.
	pre, _ := svc.GetState(ctx)
	if pre.Completed {
		t.Error("pre-Completed should be false")
	}
	if err := svc.MarkCompleted(ctx); err != nil {
		t.Fatalf("MarkCompleted: %v", err)
	}
	post, _ := svc.GetState(ctx)
	if !post.Completed {
		t.Errorf("post-MarkCompleted Completed should be true")
	}
	if post.CompletedAt == nil {
		t.Error("CompletedAt should be populated after MarkCompleted")
	}
}

func TestService_GetState_RequiredStepStillUndoneKeepsCompletedFalse(t *testing.T) {
	ctx := context.Background()
	// passkey probe is false → required step "passkey" is undone.
	ps := &probesState{hasUsers: false}
	svc := buildService(t, ps, "self")
	if err := svc.SetInstallName(ctx, "X"); err != nil {
		t.Fatalf("SetInstallName: %v", err)
	}
	if err := svc.MarkCompleted(ctx); err != nil {
		t.Fatalf("MarkCompleted: %v", err)
	}
	st, _ := svc.GetState(ctx)
	if st.Completed {
		t.Error("Completed must remain false while required steps are undone")
	}
}

func TestService_GetState_NoSelfNodeIDSkipsMeshProbe(t *testing.T) {
	ps := &probesState{meshEnrolled: true} // probe would return true
	svc := buildService(t, ps, "")         // …but selfNodeID is empty.
	st, err := svc.GetState(context.Background())
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if st.MeshEnrolled {
		t.Errorf("MeshEnrolled should be false when selfNodeID is empty")
	}
}

func TestService_GetState_NilProbesAreSafe(t *testing.T) {
	// Probes that the wiring code doesn't populate must default to false,
	// not panic. main wires them all in prod; tests shouldn't depend on it.
	store := newStore(t)
	svc := NewService(store, Probes{}, "self")
	st, err := svc.GetState(context.Background())
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if st.HasUsers || st.TrustConfigured || st.MeshEnrolled {
		t.Errorf("nil probes should produce false flags, got %+v", st)
	}
}

func TestService_SetInstallName_RejectsEmpty(t *testing.T) {
	ps := &probesState{}
	svc := buildService(t, ps, "self")
	err := svc.SetInstallName(context.Background(), "   ")
	if !errors.Is(err, ErrInstallNameEmpty) {
		t.Errorf("want ErrInstallNameEmpty, got %v", err)
	}
}

func TestService_SetInstallName_TrimsWhitespace(t *testing.T) {
	ctx := context.Background()
	ps := &probesState{}
	svc := buildService(t, ps, "self")
	if err := svc.SetInstallName(ctx, "  Rasputin Prime  "); err != nil {
		t.Fatalf("SetInstallName: %v", err)
	}
	st, _ := svc.GetState(ctx)
	if st.InstallName != "Rasputin Prime" {
		t.Errorf("want trimmed, got %q", st.InstallName)
	}
}

func TestService_SelfNodeIDAccessor(t *testing.T) {
	store := newStore(t)
	svc := NewService(store, Probes{}, "self-x")
	if svc.SelfNodeID() != "self-x" {
		t.Errorf("SelfNodeID: %q", svc.SelfNodeID())
	}
}
