package busauth

import (
	"context"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The live-node set follows the token events that change it — mint, preload,
// adoption, revoke, node removal, rotation — and a node's leaving it fires
// OnNodeRevoked exactly once. Revoking one of two live tokens does not.
func TestLiveNodes_FollowTokenEvents(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	var mu sync.Mutex
	var left []string
	s.OnNodeRevoked(func(n string) { mu.Lock(); left = append(left, n); mu.Unlock() })
	gone := func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(left) }

	if s.NodeLive("c1") {
		t.Fatal("a node with no token is live")
	}
	_, id1, _ := s.MintBound(ctx, "compute", "c1", proto.RoleCompute)
	_, id2, _ := s.MintBound(ctx, "compute", "c1", proto.RoleCompute)
	if !s.NodeLive("c1") {
		t.Fatal("mint did not make the node live")
	}
	if _, err := s.Revoke(ctx, id1); err != nil {
		t.Fatal(err)
	}
	if !s.NodeLive("c1") || len(gone()) != 0 {
		t.Fatalf("revoking one of two tokens: live=%v, left=%v; want live, no event", s.NodeLive("c1"), gone())
	}
	if _, err := s.Revoke(ctx, id2); err != nil {
		t.Fatal(err)
	}
	if s.NodeLive("c1") || !slices.Equal(gone(), []string{"c1"}) {
		t.Fatalf("revoking the last token: live=%v, left=%v; want not live, [c1]", s.NodeLive("c1"), gone())
	}

	// Preload, then node removal's revoke-all.
	_, h, _ := GenerateToken()
	if _, err := s.PreloadHashes(ctx, []PreseedToken{{Hash: h, NodeID: "c2", Label: "compute"}}); err != nil {
		t.Fatal(err)
	}
	if !s.NodeLive("c2") {
		t.Fatal("preload did not make the node live")
	}
	if _, _, err := s.RevokeByNodeID(ctx, "c2"); err != nil {
		t.Fatal(err)
	}
	if s.NodeLive("c2") || !slices.Equal(gone(), []string{"c1", "c2"}) {
		t.Fatalf("RevokeByNodeID: live=%v, left=%v", s.NodeLive("c2"), gone())
	}

	// The controlplane agent's rotation keeps the node live throughout.
	path := agentTokenPath(t)
	if _, err := s.EnsureAgentToken(ctx, path, "cp-1"); err != nil {
		t.Fatal(err)
	}
	if !s.NodeLive("cp-1") {
		t.Fatal("the controlplane agent is not live")
	}
	if len(gone()) != 2 {
		t.Fatalf("minting the agent token fired %v", gone())
	}
}

// The set is loaded once at OpenStore — backfilled roles count, role-less and
// revoked rows do not — and NodeLive never touches the database: it still
// answers with the database closed.
func TestLiveNodes_LoadedAtOpenAndServedFromMemory(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "bus.db")
	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.MintBound(ctx, "compute", "a", proto.RoleCompute); err != nil {
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
	_ = s.Close()
	for node, want := range map[string]bool{"a": true, "b": true, "c": false, "gone": false, "none": false} {
		if got := s.NodeLive(node); got != want {
			t.Errorf("NodeLive(%q) = %v with the database closed, want %v", node, got, want)
		}
	}
}
