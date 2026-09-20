package busauth

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// One live session per token, newest wins (takeover.go). The real embedded
// server drives the same rule end to end in takeover_bus_test.go.

// pinClock makes the takeover records deterministic.
func pinClock(s *Store, at time.Time) {
	s.tk.mu.Lock()
	s.tk.now = func() time.Time { return at }
	s.tk.mu.Unlock()
}

func TestAdmit_NewestSessionWinsAndTheOlderIsDisconnected(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	bus := newFakeBus(1, 2, 3)
	s.TrackSessions(bus)
	tok, id, _ := s.MintBound(ctx, "a", "node-a", "compute")
	other, _, _ := s.MintBound(ctx, "b", "node-b", "compute")

	mustAdmit(t, s, 1, tok, "node-a", true)
	mustAdmit(t, s, 3, other, "node-b", true)

	// A second connection with the same token: it is admitted, and the first
	// is closed rather than refused — the node's own reconnect must always win.
	mustAdmit(t, s, 2, tok, "node-a", true)
	if got := bus.kickedIDs(); !slices.Equal(got, []uint64{1}) {
		t.Fatalf("admitting a second session on one token closed %v, want [1]: the newest session wins", got)
	}
	if bus.ClientOpen(testServer, 1) {
		t.Error("the superseded connection is still open")
	}
	if !bus.ClientOpen(testServer, 2) {
		t.Error("the newest connection was closed; it must be the one that survives")
	}
	if bus.ClientOpen(testServer, 3) == false {
		t.Error("another node's session was closed by a takeover that was not its")
	}

	// The store now records exactly the surviving session, so a revoke closes
	// that one and not a stale record of the old.
	n, err := s.Revoke(ctx, id)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if n != 1 {
		t.Fatalf("Revoke closed %d connection(s), want 1 (the surviving session)", n)
	}
	if got := bus.kickedIDs(); !slices.Equal(got, []uint64{1, 2}) {
		t.Fatalf("after the revoke, closed %v, want [1 2]", got)
	}
}

// An ordinary reconnect — the node's previous connection is already gone — is
// not a takeover: Admit prunes closed sessions before it looks for one to
// evict, so nothing is disconnected and nothing is recorded.
func TestAdmit_AReconnectAfterTheOldSessionClosedIsNotATakeover(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	bus := newFakeBus(1, 2)
	s.TrackSessions(bus)
	tok, _, _ := s.MintBound(ctx, "a", "node-a", "compute")

	mustAdmit(t, s, 1, tok, "node-a", true)
	bus.closeByPeer(1) // the node dropped off
	mustAdmit(t, s, 2, tok, "node-a", true)

	if got := bus.kickedIDs(); len(got) != 0 {
		t.Fatalf("a reconnect after the old session closed disconnected %v, want nothing", got)
	}
	if alerts := s.SessionAlerts(time.Now()); len(alerts) != 0 {
		t.Fatalf("a plain reconnect raised %+v, want no alert", alerts)
	}
	if n := len(s.tk.byToken); n != 0 {
		t.Errorf("a plain reconnect recorded %d takeover(s), want 0", n)
	}
}

// Two presenters alternating is the alert: each takes the session back from
// the other. One-way churn from a single host is not.
func TestSessionAlerts_FireOnlyWhenTwoPresentersAlternate(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	bus := newFakeBus(1, 2, 3, 4)
	s.TrackSessions(bus)
	at := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	pinClock(s, at)
	tok, id, _ := s.MintBound(ctx, "a", "node-a", "compute")

	const nodeHost, thiefHost = "10.0.0.9", "10.0.0.77"
	mustAdmitFrom(t, s, testServer, nodeHost, 1, tok, "node-a", true)

	// The thief takes the session. One takeover on its own says nothing
	// certain — the node may simply have reconnected through a new address.
	mustAdmitFrom(t, s, testServer, thiefHost, 2, tok, "node-a", true)
	if alerts := s.SessionAlerts(at); len(alerts) != 0 {
		t.Fatalf("a single takeover raised %+v, wanted nothing until the presenters alternate", alerts)
	}

	// The node takes it back: the session is now being traded.
	mustAdmitFrom(t, s, testServer, nodeHost, 3, tok, "node-a", true)
	alerts := s.SessionAlerts(at)
	if len(alerts) != 1 {
		t.Fatalf("alternating presenters raised %d alert(s), want 1: %+v", len(alerts), alerts)
	}
	a := alerts[0]
	if a.ID != "bus-session-alternating:node-a" {
		t.Errorf("alert id = %q", a.ID)
	}
	if a.Severity != proto.AlertCrit || a.Source != proto.AlertSourceSecurity {
		t.Errorf("alert = (%s, %s), want (crit, security)", a.Severity, a.Source)
	}
	if a.RelatedKind != "node" || a.RelatedID != "node-a" {
		t.Errorf("alert related = (%q, %q), want (node, node-a)", a.RelatedKind, a.RelatedID)
	}
	if !a.Since.Equal(at) {
		t.Errorf("Since = %s, want the first alternation at %s", a.Since, at)
	}
	for _, want := range []string{nodeHost, thiefHost} {
		if !strings.Contains(a.Detail, want) {
			t.Errorf("detail does not name presenter %s: %q", want, a.Detail)
		}
	}
	if strings.Contains(a.Detail, tok) {
		t.Fatal("the alert text contains the join token itself")
	}

	// A second read is the same alert, not a second one.
	if again := s.SessionAlerts(at); len(again) != 1 || again[0].ID != a.ID {
		t.Fatalf("a second read = %+v, want the same single alert", again)
	}

	// Revoking the token is the fact that ends it: the registry excludes the
	// node, which calls ForgetNode (wired in main).
	if _, err := s.Revoke(ctx, id); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	s.ForgetNode("node-a")
	if alerts := s.SessionAlerts(at); len(alerts) != 0 {
		t.Fatalf("the alert survived the revoke: %+v", alerts)
	}
}

// A node that keeps reconnecting from its own address while the api has not
// yet reaped the previous connection evicts itself over and over. That is
// churn, not two presenters, and it must never raise the alert.
func TestSessionAlerts_SameHostChurnIsNotAnAlternation(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	bus := newFakeBus(1, 2, 3, 4, 5)
	s.TrackSessions(bus)
	tok, _, _ := s.MintBound(ctx, "a", "node-a", "compute")

	for cid := uint64(1); cid <= 5; cid++ {
		mustAdmitFrom(t, s, testServer, "10.0.0.9", cid, tok, "node-a", true)
	}
	if got := bus.kickedIDs(); !slices.Equal(got, []uint64{1, 2, 3, 4}) {
		t.Fatalf("closed %v, want each previous session closed by the next", got)
	}
	if alerts := s.SessionAlerts(time.Now()); len(alerts) != 0 {
		t.Fatalf("same-host churn raised %+v, want no alert", alerts)
	}
}

// ForgetNode clears one node and leaves the others.
func TestForgetNode_ClearsOnlyThatNode(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	bus := newFakeBus(1, 2, 3, 4, 5, 6)
	s.TrackSessions(bus)
	tokA, _, _ := s.MintBound(ctx, "a", "node-a", "compute")
	tokB, _, _ := s.MintBound(ctx, "b", "node-b", "compute")

	alternate := func(tok, node string, cids ...uint64) {
		t.Helper()
		hosts := []string{"10.0.0.1", "10.0.0.2", "10.0.0.1"}
		for i, cid := range cids {
			mustAdmitFrom(t, s, testServer, hosts[i], cid, tok, node, true)
		}
	}
	alternate(tokA, "node-a", 1, 2, 3)
	alternate(tokB, "node-b", 4, 5, 6)
	if got := len(s.SessionAlerts(time.Now())); got != 2 {
		t.Fatalf("got %d alerts, want one per contested node", got)
	}

	s.ForgetNode("node-a")
	alerts := s.SessionAlerts(time.Now())
	if len(alerts) != 1 || alerts[0].RelatedID != "node-b" {
		t.Fatalf("after forgetting node-a: %+v, want node-b's alert only", alerts)
	}
	s.ForgetNode("") // a no-op, not a wipe
	if len(s.SessionAlerts(time.Now())) != 1 {
		t.Error("ForgetNode(\"\") cleared records")
	}
}

// With no Disconnector (bus auth off) nothing is tracked and nothing is
// evicted — the store records no sessions at all.
func TestAdmit_UntrackedStoreEvictsNothing(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	tok, _, _ := s.MintBound(ctx, "a", "node-a", "compute")
	for cid := uint64(1); cid <= 3; cid++ {
		ok, err := s.Admit(ctx, Conn{ServerID: testServer, CID: cid, Host: "10.0.0.9"}, tok, "node-a")
		if err != nil || !ok {
			t.Fatalf("Admit(cid=%d) = (%v, %v), want admitted", cid, ok, err)
		}
	}
	if alerts := s.SessionAlerts(time.Now()); len(alerts) != 0 {
		t.Fatalf("an untracked store raised %+v", alerts)
	}
}
