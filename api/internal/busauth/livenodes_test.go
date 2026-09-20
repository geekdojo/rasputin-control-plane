package busauth

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// recordingRegistry is a NodeRegistry that keeps the live token hashes pushed
// per node and counts pushes. It answers TokenAdmits from what it was pushed,
// exactly as the real registry does.
type recordingRegistry struct {
	mu       sync.Mutex
	live     map[string]map[string]bool
	pushes   int
	replaces int
	queries  int
}

func newRecordingRegistry() *recordingRegistry {
	return &recordingRegistry{live: map[string]map[string]bool{}}
}

func (r *recordingRegistry) ReplaceLiveTokens(live map[string][]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.replaces++
	r.live = map[string]map[string]bool{}
	for k, v := range live {
		r.setLocked(k, v)
	}
}

func (r *recordingRegistry) SetLiveTokens(nodeID string, hashes []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pushes++
	r.setLocked(nodeID, hashes)
}

func (r *recordingRegistry) setLocked(nodeID string, hashes []string) {
	delete(r.live, nodeID)
	if len(hashes) == 0 {
		return
	}
	set := map[string]bool{}
	for _, h := range hashes {
		set[h] = true
	}
	r.live[nodeID] = set
}

func (r *recordingRegistry) TokenAdmits(nodeID, hash string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries++
	return r.live[nodeID][hash]
}

// get reports whether the node holds any live token.
func (r *recordingRegistry) get(nodeID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.live[nodeID]) > 0
}

// Attaching the sink pushes the whole set, read once: backfilled roles count,
// role-less and revoked rows do not. Nothing is pushed before a sink exists.
func TestSetNodeRegistry_PushesTheWholeSet(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "bus.db")
	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.MintBound(ctx, "compute", "a", proto.RoleCompute); err != nil { // no sink yet: no push, no panic
		t.Fatal(err)
	}
	_, idGone, _ := s.MintBound(ctx, "compute", "gone", proto.RoleCompute)
	if _, err := s.Revoke(ctx, idGone); err != nil {
		t.Fatal(err)
	}
	for node, label := range map[string]string{"b": "firewall", "c": "laptop agent"} {
		_, id, _ := GenerateToken()
		if _, err := s.db.ExecContext(ctx, `INSERT INTO bus_tokens (token_hash, label, created_at, node_id) VALUES (?, ?, ?, ?)`,
			id, label, ms(time.Now().UTC()), node); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Close()
	s, err = OpenStore(ctx, path) // backfills b's role from its label
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	sink := newRecordingRegistry()
	if err := s.SetNodeRegistry(ctx, sink); err != nil {
		t.Fatal(err)
	}
	if sink.replaces != 1 || sink.pushes != 0 {
		t.Fatalf("attach: %d replaces, %d pushes; want 1, 0", sink.replaces, sink.pushes)
	}
	for node, want := range map[string]bool{"a": true, "b": true, "c": false, "gone": false} {
		if got := sink.get(node); got != want {
			t.Errorf("after attach, %q live = %v, want %v", node, got, want)
		}
	}
}

// Every token event pushes the nodes it touched: mint, preload, revoke of one
// of two tokens (still live), revoke of the last (not live), node removal's
// revoke-all, and the controlplane agent's token.
func TestNodeRegistry_FollowsTokenEvents(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	sink := newRecordingRegistry()
	if err := s.SetNodeRegistry(ctx, sink); err != nil {
		t.Fatal(err)
	}
	_, id1, _ := s.MintBound(ctx, "compute", "c1", proto.RoleCompute)
	_, id2, _ := s.MintBound(ctx, "compute", "c1", proto.RoleCompute)
	if !sink.get("c1") {
		t.Fatal("mint did not push c1 live")
	}
	if _, err := s.Revoke(ctx, id1); err != nil {
		t.Fatal(err)
	}
	if !sink.get("c1") {
		t.Fatal("revoking one of two tokens pushed c1 not live")
	}
	if _, err := s.Revoke(ctx, id2); err != nil {
		t.Fatal(err)
	}
	if sink.get("c1") {
		t.Fatal("revoking the last token left c1 live")
	}

	_, h, _ := GenerateToken()
	if _, err := s.PreloadHashes(ctx, []PreseedToken{{Hash: h, NodeID: "c2", Label: "compute"}}); err != nil {
		t.Fatal(err)
	}
	if !sink.get("c2") {
		t.Fatal("preload did not push c2 live")
	}
	if _, _, err := s.RevokeByNodeID(ctx, "c2"); err != nil {
		t.Fatal(err)
	}
	if sink.get("c2") {
		t.Fatal("RevokeByNodeID left c2 live")
	}

	path := agentTokenPath(t)
	if _, err := s.EnsureAgentToken(ctx, path, "cp-1"); err != nil {
		t.Fatal(err)
	}
	if !sink.get("cp-1") {
		t.Fatal("the controlplane agent's token did not push cp-1 live")
	}
}

// A revoke re-applied from the tombstone file (a lost or restored database)
// is pushed to the node registry too, so a node revoked only by its tombstone
// is not admitted.
func TestNodeRegistry_FollowsTombstoneReapply(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	sink := newRecordingRegistry()
	if err := s.SetNodeRegistry(ctx, sink); err != nil {
		t.Fatal(err)
	}
	_, id, _ := s.MintBound(ctx, "compute", "c1", proto.RoleCompute)
	if !sink.get("c1") {
		t.Fatal("not live after mint")
	}
	path := filepath.Join(t.TempDir(), "bus", TombstoneFileName)
	if err := writeTombstoneFile(path, map[string]Tombstone{id: {Hash: id, NodeID: "c1", RevokedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	if _, n, err := s.UseTombstoneFile(ctx, path); err != nil || n != 1 {
		t.Fatalf("UseTombstoneFile = (%d, %v), want 1 re-applied", n, err)
	}
	if sink.get("c1") {
		t.Error("a node revoked by its tombstone is still live in the registry")
	}
}
