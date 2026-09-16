package busauth

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"
)

// Unit tests for revoke = force-disconnect (sessions.go) against a fake
// Disconnector. The real embedded server is driven in revoke_bus_test.go and,
// through the HTTP handlers, in api/internal/api/bus_revoke_test.go.

// fakeBus is a Disconnector over a set of "open" connection ids.
type fakeBus struct {
	mu     sync.Mutex
	open   map[uint64]bool
	kicked []uint64
}

func newFakeBus(cids ...uint64) *fakeBus {
	b := &fakeBus{open: make(map[uint64]bool)}
	for _, c := range cids {
		b.open[c] = true
	}
	return b
}

func (b *fakeBus) ClientOpen(cid uint64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.open[cid]
}

func (b *fakeBus) DisconnectClient(cid uint64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.kicked = append(b.kicked, cid)
	was := b.open[cid]
	delete(b.open, cid)
	return was
}

// closeByPeer simulates a connection closing on its own (the node went away).
func (b *fakeBus) closeByPeer(cid uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.open, cid)
}

func (b *fakeBus) kickedIDs() []uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := slices.Clone(b.kicked)
	slices.Sort(out)
	return out
}

func mustAdmit(t *testing.T, s *Store, cid uint64, token, nodeID string, want bool) {
	t.Helper()
	ok, err := s.Admit(context.Background(), cid, token, nodeID)
	if err != nil {
		t.Fatalf("Admit(cid=%d, %s): %v", cid, nodeID, err)
	}
	if ok != want {
		t.Fatalf("Admit(cid=%d, %s) = %v, want %v", cid, nodeID, ok, want)
	}
}

func TestRevoke_ClosesOnlyThatTokensConnections(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	bus := newFakeBus(1, 2, 3, 4)
	s.TrackSessions(bus)

	tokA, idA, _ := s.MintBound(ctx, "a", "node-a")
	tokB, idB, _ := s.MintBound(ctx, "b", "node-b")
	tokC, idC, _ := s.MintBound(ctx, "c", "node-c")

	mustAdmit(t, s, 1, tokA, "node-a", true)
	mustAdmit(t, s, 2, tokB, "node-b", true)
	mustAdmit(t, s, 3, tokC, "node-c", true)
	mustAdmit(t, s, 4, tokC, "node-c", true) // a second session on the same token

	n, err := s.Revoke(ctx, idA)
	if err != nil {
		t.Fatalf("Revoke(A): %v", err)
	}
	if n != 1 {
		t.Errorf("Revoke(A) disconnected %d, want 1", n)
	}
	if got := bus.kickedIDs(); !slices.Equal(got, []uint64{1}) {
		t.Fatalf("Revoke(A) closed %v, want [1] only", got)
	}

	// The revoked token's reconnect is refused, and the refusal records nothing.
	mustAdmit(t, s, 5, tokA, "node-a", false)

	// Revoking a token closes every session it authenticated.
	n, err = s.Revoke(ctx, idC)
	if err != nil {
		t.Fatalf("Revoke(C): %v", err)
	}
	if n != 2 {
		t.Errorf("Revoke(C) disconnected %d, want 2", n)
	}
	if got := bus.kickedIDs(); !slices.Equal(got, []uint64{1, 3, 4}) {
		t.Fatalf("after Revoke(C) closed %v, want [1 3 4]", got)
	}
	if !bus.ClientOpen(2) {
		t.Error("node-b's connection was closed by revokes of other tokens")
	}

	// A token whose connection already went away reports zero closed: the
	// count is what the revoke actually cut, not how many grants it found.
	bus.closeByPeer(2)
	n, err = s.Revoke(ctx, idB)
	if err != nil {
		t.Fatalf("Revoke(B): %v", err)
	}
	if n != 0 {
		t.Errorf("Revoke(B) of an already-closed connection disconnected %d, want 0", n)
	}
}

func TestRevoke_RecordIsConsumed(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	bus := newFakeBus(1)
	s.TrackSessions(bus)
	tok, id, _ := s.MintBound(ctx, "a", "node-a")
	mustAdmit(t, s, 1, tok, "node-a", true)

	if n, _ := s.Revoke(ctx, id); n != 1 {
		t.Fatalf("Revoke disconnected %d, want 1", n)
	}
	if len(s.sess.grants) != 0 {
		t.Errorf("grants after revoke = %v, want empty", s.sess.grants)
	}
	// Revoking again is ErrNoRows and closes nothing more.
	if n, err := s.Revoke(ctx, id); err == nil || n != 0 {
		t.Errorf("second Revoke = (%d, %v), want (0, ErrNoRows)", n, err)
	}
	if got := bus.kickedIDs(); !slices.Equal(got, []uint64{1}) {
		t.Errorf("closed %v, want [1]", got)
	}
}

func TestRevokeByNodeID_ClosesEveryTokenSessionOfTheNode(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	bus := newFakeBus(1, 2, 3)
	s.TrackSessions(bus)

	tokA, _, _ := s.MintBound(ctx, "a", "node-a")
	tokA2, _, _ := s.MintBound(ctx, "a re-mint", "node-a") // a node can hold two
	tokB, _, _ := s.MintBound(ctx, "b", "node-b")

	mustAdmit(t, s, 1, tokA, "node-a", true)
	mustAdmit(t, s, 2, tokA2, "node-a", true)
	mustAdmit(t, s, 3, tokB, "node-b", true)

	revoked, disconnected, err := s.RevokeByNodeID(ctx, "node-a")
	if err != nil {
		t.Fatalf("RevokeByNodeID: %v", err)
	}
	if revoked != 2 || disconnected != 2 {
		t.Errorf("RevokeByNodeID = (revoked %d, disconnected %d), want (2, 2)", revoked, disconnected)
	}
	if got := bus.kickedIDs(); !slices.Equal(got, []uint64{1, 2}) {
		t.Fatalf("closed %v, want [1 2]", got)
	}
	if !bus.ClientOpen(3) {
		t.Error("node-b's connection was closed by node-a's removal")
	}
	// Neither of the removed node's tokens can reconnect.
	mustAdmit(t, s, 4, tokA, "node-a", false)
	mustAdmit(t, s, 5, tokA2, "node-a", false)
}

// The #247 removal gap was a node whose session used an UNBOUND token: removal
// closed the session but could not revoke a token bound to no node, so it
// reconnected. With every token bound, the only unbound tokens are legacy
// rows, and Admit refuses them outright — no session is admitted, none is
// recorded, so there is nothing for a removal to miss.
func TestAdmit_RefusesLegacyUnboundToken(t *testing.T) {
	s := newTokenStore(t)
	bus := newFakeBus(1, 2)
	s.TrackSessions(bus)
	legacy, _ := insertLegacyUnbound(t, s, "legacy")

	mustAdmit(t, s, 1, legacy, "node-a", false)
	mustAdmit(t, s, 2, legacy, "node-b", false)

	s.sess.mu.Lock()
	recorded := len(s.sess.grants)
	s.sess.mu.Unlock()
	if recorded != 0 {
		t.Errorf("a refused unbound token recorded %d grants; want 0", recorded)
	}
}

func TestAdmit_RefusedTokensAreNotRecorded(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	bus := newFakeBus(1, 2, 3)
	s.TrackSessions(bus)
	tok, _, _ := s.MintBound(ctx, "a", "node-a")

	mustAdmit(t, s, 1, "not-a-token", "node-a", false)
	mustAdmit(t, s, 2, tok, "node-b", false) // bound to a different node
	mustAdmit(t, s, 3, "", "node-a", false)
	if len(s.sess.grants) != 0 {
		t.Errorf("refused admissions were recorded: %v", s.sess.grants)
	}
	if _, disconnected, _ := s.RevokeByNodeID(ctx, "node-a"); disconnected != 0 {
		t.Errorf("removal closed %d connections that were never admitted", disconnected)
	}
	if got := bus.kickedIDs(); len(got) != 0 {
		t.Errorf("closed %v, want nothing", got)
	}
}

func TestAdmit_UntrackedStoreRecordsNothing(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t) // no TrackSessions: bus auth off
	tok, id, _ := s.MintBound(ctx, "a", "node-a")
	mustAdmit(t, s, 1, tok, "node-a", true)
	if len(s.sess.grants) != 0 {
		t.Errorf("untracked store recorded %v", s.sess.grants)
	}
	if n, err := s.Revoke(ctx, id); err != nil || n != 0 {
		t.Errorf("Revoke on untracked store = (%d, %v), want (0, nil)", n, err)
	}
	mustAdmit(t, s, 2, tok, "node-a", false)
}

func TestAdmit_PrunesClosedConnections(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	bus := newFakeBus(1, 2)
	s.TrackSessions(bus)
	tok, _, _ := s.MintBound(ctx, "a", "node-a")

	mustAdmit(t, s, 1, tok, "node-a", true)
	bus.closeByPeer(1) // the node dropped and is reconnecting
	mustAdmit(t, s, 2, tok, "node-a", true)

	if _, ok := s.sess.grants[1]; ok {
		t.Error("record for closed connection 1 survived the next admission")
	}
	if _, ok := s.sess.grants[2]; !ok {
		t.Error("live connection 2 is not recorded")
	}
}

// TestRevoke_RacingAnInFlightAdmission opens the exact window a naive
// implementation loses: the callout has validated the token (not yet revoked)
// but not yet recorded the connection, and the operator revokes right then.
// If the revoke could commit and snapshot inside that window, its snapshot
// would miss the connection, which would then go live on a revoked token.
//
// Two checks. The window must be covered by the session lock — asserted
// directly with TryLock, because whether an unlocked revoke actually wins the
// race depends on the scheduler, and a test that only sometimes notices a
// missing lock proves nothing. And a revoke started inside the window must end
// up closing the connection.
func TestRevoke_RacingAnInFlightAdmission(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	bus := newFakeBus(7)
	s.TrackSessions(bus)
	tok, id, _ := s.MintBound(ctx, "a", "node-a")

	type result struct {
		n   int
		err error
	}
	revokeDone := make(chan result, 1)
	s.sess.afterValidate = func() {
		if s.sess.mu.TryLock() {
			s.sess.mu.Unlock()
			t.Error("the admission validated the token without holding the session lock: " +
				"a concurrent revoke can commit and snapshot before this connection is recorded")
		}
		go func() {
			n, err := s.Revoke(ctx, id)
			revokeDone <- result{n, err}
		}()
	}

	mustAdmit(t, s, 7, tok, "node-a", true) // validated before the revoke committed

	select {
	case r := <-revokeDone:
		if r.err != nil {
			t.Fatalf("Revoke: %v", r.err)
		}
		if r.n != 1 {
			t.Errorf("Revoke disconnected %d, want 1: the in-flight connection survived", r.n)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Revoke did not return within 10s of the admission finishing")
	}
	if bus.ClientOpen(7) {
		t.Error("connection admitted concurrently with the revoke is still open")
	}
}

// TestSessionLockReleasedOnErrors: every error path must release the session
// lock, or the next callout (and every revoke) hangs forever.
func TestSessionLockReleasedOnErrors(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	s.TrackSessions(newFakeBus())
	if n, err := s.Revoke(ctx, "no-such-token"); err == nil || n != 0 {
		t.Errorf("Revoke(missing) = (%d, %v), want (0, ErrNoRows)", n, err)
	}
	_ = s.db.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := s.Revoke(ctx, "x"); err == nil {
			t.Error("Revoke on a closed DB returned no error")
		}
		if _, _, err := s.RevokeByNodeID(ctx, "node-a"); err == nil {
			t.Error("RevokeByNodeID on a closed DB returned no error")
		}
		if _, err := s.Admit(ctx, 1, "tok", "node-a"); err == nil {
			t.Error("Admit on a closed DB returned no error")
		}
		s.TrackSessions(newFakeBus()) // would deadlock if any path above leaked the lock
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("session lock leaked on an error path: calls did not return within 10s")
	}
}

// recordingValidator captures what the responder hands the token store.
type recordingValidator struct {
	calls []uint64
}

func (v *recordingValidator) Admit(_ context.Context, cid uint64, _, _ string) (bool, error) {
	v.calls = append(v.calls, cid)
	return true, nil
}

// The responder must hand the store the server's connection id — that id is
// what a revoke closes — and must not admit (record) a loopback connection,
// which holds no token for a revoke to act on.
func TestResponder_AdmitsTokenConnectionsByConnectionID(t *testing.T) {
	v := &recordingValidator{}
	r := &Responder{tokens: v}

	if ok, reason := r.authorize(42, "node-a", "some-token", "192.168.1.50"); !ok {
		t.Fatalf("remote token connection denied: %s", reason)
	}
	if !slices.Equal(v.calls, []uint64{42}) {
		t.Fatalf("Admit called with cids %v, want [42]", v.calls)
	}
	if ok, reason := r.authorize(43, "cp-1", "", "127.0.0.1"); !ok {
		t.Fatalf("loopback connection denied: %s", reason)
	}
	if ok, _ := r.authorize(44, "cp-1", "", "192.168.1.50"); ok {
		t.Fatal("tokenless remote connection admitted")
	}
	if !slices.Equal(v.calls, []uint64{42}) {
		t.Errorf("Admit called with cids %v; loopback and tokenless connections must not reach the store", v.calls)
	}
}
