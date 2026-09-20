package busauth

import (
	"context"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The bus admission path reads the node registry and NOTHING else: with the
// token table closed, a token the registry holds still admits its node, one
// it does not hold is refused, and the same token presented as another node
// is refused. A closed database is the strongest available form of "no read
// on this path" — any query would error rather than answer.
func TestAdmit_AnswersFromTheRegistryWithTheDatabaseClosed(t *testing.T) {
	ctx := context.Background()
	s := newTokenStoreNoRegistry(t)
	reg := newRecordingRegistry()
	good, _, err := s.MintBound(ctx, "compute", "c1", proto.RoleCompute)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := s.MintBound(ctx, "compute", "c2", proto.RoleCompute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeRegistry(ctx, reg); err != nil {
		t.Fatal(err)
	}
	bus := newFakeBus(1, 2)
	s.TrackSessions(bus)

	// Nothing is readable from here on.
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}

	before := reg.queries
	if ok, err := s.Admit(ctx, Conn{ServerID: testServer, CID: 1, Host: testHost}, good, "c1"); !ok || err != nil {
		t.Fatalf("Admit of a live token with the database closed = (%v, %v), want (true, nil)", ok, err)
	}
	if reg.queries == before {
		t.Error("Admit did not ask the registry")
	}
	if ok, _ := s.Admit(ctx, Conn{ServerID: testServer, CID: 2, Host: testHost}, good, "c2"); ok {
		t.Error("a token bound to c1 admitted c2")
	}
	if ok, _ := s.Admit(ctx, Conn{ServerID: testServer, CID: 3, Host: testHost}, other+"x", "c2"); ok {
		t.Error("an unknown token was admitted")
	}
}

// A store with no registry attached admits nobody, whatever the token table
// says: an api whose registry load failed refuses every node rather than
// falling back to a per-connection database read.
func TestAdmit_FailsClosedWithoutARegistry(t *testing.T) {
	ctx := context.Background()
	s := newTokenStoreNoRegistry(t)
	tok, _, err := s.MintBound(ctx, "compute", "c1", proto.RoleCompute)
	if err != nil {
		t.Fatal(err)
	}
	// The row is live: Validate, which does read the table, says so.
	if ok, err := s.Validate(ctx, tok, "c1"); err != nil || !ok {
		t.Fatalf("Validate = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := s.Admit(ctx, Conn{ServerID: testServer, CID: 1, Host: testHost}, tok, "c1"); ok || err != nil {
		t.Errorf("Admit with no registry = (%v, %v), want (false, nil)", ok, err)
	}
}

// Revoking a token stops the next connection immediately — the registry push
// is part of the revoke, not something a later refresh catches up on.
func TestAdmit_RevokeRefusesTheNextConnectionImmediately(t *testing.T) {
	ctx := context.Background()
	s := newTokenStoreNoRegistry(t)
	if err := s.SetNodeRegistry(ctx, newRecordingRegistry()); err != nil {
		t.Fatal(err)
	}
	s.TrackSessions(newFakeBus(1, 2))
	tok, id, err := s.MintBound(ctx, "compute", "c1", proto.RoleCompute)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Admit(ctx, Conn{ServerID: testServer, CID: 1, Host: testHost}, tok, "c1"); !ok {
		t.Fatal("a freshly minted token was refused")
	}
	if _, err := s.Revoke(ctx, id); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Admit(ctx, Conn{ServerID: testServer, CID: 2, Host: testHost}, tok, "c1"); ok {
		t.Error("a revoked token was admitted on the next connection")
	}
}

// The session table is driven by the registry: whatever excludes a node —
// here, an inventory removal that revokes nothing — closes its bus sessions
// through the exclusion hook main wires to DisconnectNode.
func TestDisconnectNode_ClosesEverySessionOfTheNode(t *testing.T) {
	ctx := context.Background()
	s := newTokenStoreNoRegistry(t)
	if err := s.SetNodeRegistry(ctx, newRecordingRegistry()); err != nil {
		t.Fatal(err)
	}
	bus := newFakeBus(1, 2)
	s.TrackSessions(bus)
	a, _, err := s.MintBound(ctx, "compute", "c1", proto.RoleCompute)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := s.MintBound(ctx, "compute", "c2", proto.RoleCompute)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Admit(ctx, Conn{ServerID: testServer, CID: 1, Host: testHost}, a, "c1"); !ok {
		t.Fatal("c1 refused")
	}
	if ok, _ := s.Admit(ctx, Conn{ServerID: testServer, CID: 2, Host: testHost}, b, "c2"); !ok {
		t.Fatal("c2 refused")
	}
	if n := s.DisconnectNode("c1"); n != 1 {
		t.Errorf("DisconnectNode(c1) = %d, want 1", n)
	}
	if bus.ClientOpen(testServer, 1) {
		t.Error("c1's session is still open")
	}
	if !bus.ClientOpen(testServer, 2) {
		t.Error("c2's session was closed too")
	}
	if n := s.DisconnectNode("c1"); n != 0 {
		t.Errorf("a second DisconnectNode(c1) closed %d, want 0", n)
	}
}

// A revoke reports the sessions it closed even when the registry's exclusion
// hook is what closed them — the count is taken before the push.
func TestRevoke_CountsSessionsTheExclusionHookClosed(t *testing.T) {
	ctx := context.Background()
	s := newTokenStoreNoRegistry(t)
	reg := &hookedRegistry{recordingRegistry: newRecordingRegistry(), onEmpty: s.DisconnectNode}
	if err := s.SetNodeRegistry(ctx, reg); err != nil {
		t.Fatal(err)
	}
	bus := newFakeBus(1, 2)
	s.TrackSessions(bus)
	tok, id, err := s.MintBound(ctx, "compute", "c1", proto.RoleCompute)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Admit(ctx, Conn{ServerID: testServer, CID: 1, Host: testHost}, tok, "c1"); !ok {
		t.Fatal("c1 refused")
	}
	n, err := s.Revoke(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("Revoke reported %d closed connection(s), want 1", n)
	}
	if bus.ClientOpen(testServer, 1) {
		t.Error("the revoked node's session is still open")
	}
}

// hookedRegistry is a recordingRegistry that runs an exclusion hook when a
// node's live set empties — what inventory.Registry.OnNodeExcluded does, and
// what main wires to Store.DisconnectNode.
type hookedRegistry struct {
	*recordingRegistry
	onEmpty func(nodeID string) int
}

func (h *hookedRegistry) SetLiveTokens(nodeID string, hashes []string) {
	was := h.get(nodeID)
	h.recordingRegistry.SetLiveTokens(nodeID, hashes)
	if was && !h.get(nodeID) && h.onEmpty != nil {
		h.onEmpty(nodeID)
	}
}

// A connection recorded AFTER a revoke snapshotted the live sessions — the
// reconnect that raced it — is closed by the revoke too, and counted. This
// drives the two halves of the count directly: what was live when the revoke
// started, and what arrived after.
func TestCloseRemaining_CountsASessionRecordedAfterTheSnapshot(t *testing.T) {
	ctx := context.Background()
	s := newTokenStoreNoRegistry(t)
	if err := s.SetNodeRegistry(ctx, newRecordingRegistry()); err != nil {
		t.Fatal(err)
	}
	bus := newFakeBus(1, 2)
	s.TrackSessions(bus)
	tok, _, err := s.MintBound(ctx, "compute", "c1", proto.RoleCompute)
	if err != nil {
		t.Fatal(err)
	}
	match := func(g grant) bool { return g.nodeID == "c1" }

	// Nothing live yet: the snapshot is empty.
	held := s.liveSessions(match)
	if len(held) != 0 {
		t.Fatalf("snapshot = %v, want empty", held)
	}
	// The racer connects after the snapshot.
	if ok, _ := s.Admit(ctx, Conn{ServerID: testServer, CID: 1, Host: testHost}, tok, "c1"); !ok {
		t.Fatal("the racing connection was refused")
	}
	if n := s.closeRemaining(match, held); n != 1 {
		t.Errorf("closeRemaining counted %d, want 1 (the session that arrived after the snapshot)", n)
	}
	if bus.ClientOpen(testServer, 1) {
		t.Error("the racing session is still open")
	}
}
