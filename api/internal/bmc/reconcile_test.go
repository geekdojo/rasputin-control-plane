package bmc

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

func desiredMock(t *testing.T, st *setup.Store) string {
	t.Helper()
	ctx := context.Background()
	cfg := `{"targets":["node-1"]}`
	if err := st.Set(ctx, setup.KeyBMCBackend, "mock"); err != nil {
		t.Fatal(err)
	}
	if err := st.Set(ctx, setup.KeyBMCHostNode, "host-1"); err != nil {
		t.Fatal(err)
	}
	if err := st.Set(ctx, setup.KeyBMCConfig, cfg); err != nil {
		t.Fatal(err)
	}
	return ConfigHash("mock", json.RawMessage(cfg), "")
}

func regEvt(t *testing.T, nodeID string, meta map[string]any) []byte {
	t.Helper()
	buf, err := json.Marshal(proto.NodeRegisteredEvt{NodeID: nodeID, Metadata: meta, Ts: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func newReconciler(t *testing.T, st *setup.Store, busy bool) (*reconciler, *int) {
	t.Helper()
	submitted := 0
	r := &reconciler{
		st:     st,
		busy:   func(context.Context) (bool, error) { return busy, nil },
		submit: func(context.Context, string, json.RawMessage, string) error { submitted++; return nil },
	}
	return r, &submitted
}

func TestReconcile_RepushesStaleHost(t *testing.T) {
	st := newSetupStore(t)
	desiredMock(t, st)
	r, n := newReconciler(t, st, false)
	r.onRegistered(regEvt(t, "host-1", nil)) // no hash advertised — stale
	if *n != 1 {
		t.Errorf("submitted %d, want 1", *n)
	}
}

func TestReconcile_MatchingHashNoop(t *testing.T) {
	st := newSetupStore(t)
	hash := desiredMock(t, st)
	r, n := newReconciler(t, st, false)
	r.onRegistered(regEvt(t, "host-1", map[string]any{proto.MetadataBMCConfigHash: hash}))
	if *n != 0 {
		t.Errorf("submitted %d, want 0", *n)
	}
}

func TestReconcile_StandsDownWhileConfigureInFlight(t *testing.T) {
	// The race the bench caught: a configure push re-registers the host
	// BEFORE the record step writes settings — mid-job "drift" must not
	// resurrect the old selection.
	st := newSetupStore(t)
	desiredMock(t, st)
	r, n := newReconciler(t, st, true)
	r.onRegistered(regEvt(t, "host-1", nil))
	if *n != 0 {
		t.Errorf("submitted %d, want 0 while a configure job is in flight", *n)
	}
}

func TestReconcile_SkipsPinnedOffAndOtherNodes(t *testing.T) {
	st := newSetupStore(t)
	desiredMock(t, st)
	r, n := newReconciler(t, st, false)

	r.onRegistered(regEvt(t, "host-1", map[string]any{proto.MetadataBMCConfigPinned: true}))
	r.onRegistered(regEvt(t, "other-node", nil))
	if *n != 0 {
		t.Errorf("pinned/other-node submitted %d, want 0", *n)
	}

	// BMC off in settings: nothing to converge toward.
	if err := st.Set(context.Background(), setup.KeyBMCBackend, ""); err != nil {
		t.Fatal(err)
	}
	r.onRegistered(regEvt(t, "host-1", nil))
	if *n != 0 {
		t.Errorf("off submitted %d, want 0", *n)
	}
}

func TestReconcile_DebouncesSameHash(t *testing.T) {
	st := newSetupStore(t)
	desiredMock(t, st)
	r, n := newReconciler(t, st, false)
	r.onRegistered(regEvt(t, "host-1", nil))
	r.onRegistered(regEvt(t, "host-1", nil)) // reconnect burst
	if *n != 1 {
		t.Errorf("submitted %d, want 1 (debounced)", *n)
	}
}
