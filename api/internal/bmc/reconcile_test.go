package bmc

import (
	"context"
	"encoding/json"
	"strings"
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

// regMsg is regEvt as it arrives off the bus: on the node's own registered
// subject.
func regMsg(t *testing.T, nodeID string, meta map[string]any) (string, []byte) {
	t.Helper()
	return proto.NodeRegisteredSubject(nodeID), regEvt(t, nodeID, meta)
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
	r.onRegistered(regMsg(t, "host-1", nil)) // no hash advertised — stale
	if *n != 1 {
		t.Errorf("submitted %d, want 1", *n)
	}
}

func TestReconcile_MatchingHashNoop(t *testing.T) {
	st := newSetupStore(t)
	hash := desiredMock(t, st)
	r, n := newReconciler(t, st, false)
	r.onRegistered(regMsg(t, "host-1", map[string]any{proto.MetadataBMCConfigHash: hash}))
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
	r.onRegistered(regMsg(t, "host-1", nil))
	if *n != 0 {
		t.Errorf("submitted %d, want 0 while a configure job is in flight", *n)
	}
}

func TestReconcile_SkipsPinnedOffAndOtherNodes(t *testing.T) {
	st := newSetupStore(t)
	desiredMock(t, st)
	r, n := newReconciler(t, st, false)

	r.onRegistered(regMsg(t, "host-1", map[string]any{proto.MetadataBMCConfigPinned: true}))
	r.onRegistered(regMsg(t, "other-node", nil))
	if *n != 0 {
		t.Errorf("pinned/other-node submitted %d, want 0", *n)
	}

	// BMC off in settings: nothing to converge toward.
	if err := st.Set(context.Background(), setup.KeyBMCBackend, ""); err != nil {
		t.Fatal(err)
	}
	r.onRegistered(regMsg(t, "host-1", nil))
	if *n != 0 {
		t.Errorf("off submitted %d, want 0", *n)
	}
}

func TestReconcile_DebouncesSameHash(t *testing.T) {
	st := newSetupStore(t)
	desiredMock(t, st)
	r, n := newReconciler(t, st, false)
	r.onRegistered(regMsg(t, "host-1", nil))
	r.onRegistered(regMsg(t, "host-1", nil)) // reconnect burst
	if *n != 1 {
		t.Errorf("submitted %d, want 1 (debounced)", *n)
	}
}

// The configured host is recognised by the subject a registration arrives on,
// not by the payload's nodeId: a registration from another node whose payload
// names the host is dropped and triggers no re-push.
func TestReconcile_IgnoresMismatchedPayloadNodeID(t *testing.T) {
	st := newSetupStore(t)
	desiredMock(t, st)
	r, n := newReconciler(t, st, false)
	r.onRegistered(proto.NodeRegisteredSubject("other-node"), regEvt(t, "host-1", nil))
	if *n != 0 {
		t.Errorf("submitted %d for a registration on other-node's subject naming host-1, want 0", *n)
	}
	// The host's own registration with an empty payload id still converges.
	r.onRegistered(proto.NodeRegisteredSubject("host-1"), regEvt(t, "", nil))
	if *n != 1 {
		t.Errorf("submitted %d for host-1's own registration, want 1", *n)
	}
}

func TestStatusSeed_IgnoresMismatchedPayloadNodeID(t *testing.T) {
	// No bus: a sweep would only log failed requests, but it would still mark
	// the seeder sweeping (and then lastDone), which is what this checks.
	s := &statusSeeder{}
	meta := map[string]any{proto.MetadataBMCTargets: []any{"node-2"}}
	s.onRegistered(proto.NodeRegisteredSubject("other-node"), regEvt(t, "host-1", meta))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sweeping || !s.lastDone.IsZero() {
		t.Errorf("a registration with a mismatched payload node id started a sweep")
	}
}

// A config recorded before the credential had its own settings key carries it
// inline. The re-push spec — persisted in the job ledger — must not, so the
// credential moves to its key and the spec goes without it
// (geekdojo/geekdojo-brain#493, gate 6).
func TestReconcile_MovesALegacyInlineCredentialOutOfTheSpec(t *testing.T) {
	const secret = "SENTINEL-LEGACY-UNLOCK"
	ctx := context.Background()
	st := newSetupStore(t)
	for k, v := range map[string]string{
		setup.KeyBMCBackend:  "bitscope",
		setup.KeyBMCHostNode: "host-1",
		setup.KeyBMCConfig:   `{"targets":[{"pos":"A-0","node_id":"node-1"}],"unlock":"` + secret + `"}`,
	} {
		if err := st.Set(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	var spec json.RawMessage
	r := &reconciler{
		st:   st,
		busy: func(context.Context) (bool, error) { return false, nil },
		submit: func(_ context.Context, _ string, s json.RawMessage, _ string) error {
			spec = s
			return nil
		},
	}
	r.onRegistered(regMsg(t, "host-1", nil))
	if spec == nil {
		t.Fatal("no re-push submitted")
	}
	if strings.Contains(string(spec), secret) {
		t.Errorf("re-push spec carries the credential: %s", spec)
	}
	if got := StoredCredential(ctx, st, "bitscope"); got != secret {
		t.Errorf("credential key = %q, want the legacy inline value moved there", got)
	}
	var cs ConfigureSpec
	if err := json.Unmarshal(spec, &cs); err != nil {
		t.Fatal(err)
	}
	if err := refuseInlineCredential(cs.Kind, cs.Config); err != nil {
		t.Errorf("the validate step would refuse the re-push: %v", err)
	}
}
