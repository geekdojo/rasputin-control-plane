package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// newStore opens a fresh, file-backed sqlite store in a per-test temp dir.
// We deliberately avoid :memory: — the WAL pragma the store applies has
// surprising semantics with in-memory connections, per the project's test
// rules.
func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(context.Background(), filepath.Join(dir, "inv.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// makeNode builds a fully-populated test node so we can also exercise the
// JSON encode/decode paths for capabilities + metadata.
func makeNode(id string, role proto.NodeRole, lastSeenAgo time.Duration) *proto.Node {
	now := time.Now().UTC()
	return &proto.Node{
		ID:           id,
		Role:         role,
		Hostname:     id + ".test",
		AgentVersion: "v0.1.0",
		Capabilities: []string{"docker", "x86_64"},
		Metadata:     map[string]any{"arch": "amd64", "cores": float64(4)},
		FirstSeen:    now.Add(-1 * time.Hour),
		LastSeen:     now.Add(-lastSeenAgo),
	}
}

// ============================================================================
// Store CRUD
// ============================================================================

func TestStore_InsertAndGet(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	want := makeNode("n-1", proto.RoleCompute, 5*time.Second)

	if err := s.Insert(ctx, want); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	got, err := s.Get(ctx, "n-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatalf("Get returned nil for known id")
	}
	if got.ID != want.ID || got.Role != want.Role || got.Hostname != want.Hostname || got.AgentVersion != want.AgentVersion {
		t.Errorf("scalar mismatch: got=%+v want=%+v", got, want)
	}
	if len(got.Capabilities) != 2 || got.Capabilities[0] != "docker" {
		t.Errorf("capabilities not round-tripped: %v", got.Capabilities)
	}
	if got.Metadata["arch"] != "amd64" {
		t.Errorf("metadata not round-tripped: %v", got.Metadata)
	}
	// Status is not persisted — every consumer recomputes it.
	if got.Status != "" {
		t.Errorf("Status should be empty when read from store, got %q", got.Status)
	}
}

func TestStore_GetUnknownReturnsNilNil(t *testing.T) {
	s := newStore(t)
	got, err := s.Get(context.Background(), "nope")
	if err != nil {
		t.Fatalf("Get unknown: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for missing node, got %+v", got)
	}
}

func TestStore_InsertDuplicateIsError(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	n := makeNode("dup", proto.RoleControlPlane, 0)
	if err := s.Insert(ctx, n); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := s.Insert(ctx, n); err == nil {
		t.Error("duplicate insert: expected error, got nil")
	}
}

func TestStore_Update(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	n := makeNode("n-up", proto.RoleCompute, 0)
	if err := s.Insert(ctx, n); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	n.Hostname = "renamed.test"
	n.AgentVersion = "v0.2.0"
	n.Role = proto.RoleStorage
	n.Capabilities = []string{"zfs"}
	n.Metadata = map[string]any{"pool": "tank"}
	newLastSeen := time.Now().Add(-1 * time.Second).UTC()
	n.LastSeen = newLastSeen

	if err := s.Update(ctx, n); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.Get(ctx, "n-up")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Hostname != "renamed.test" || got.AgentVersion != "v0.2.0" || got.Role != proto.RoleStorage {
		t.Errorf("update fields not persisted: %+v", got)
	}
	if len(got.Capabilities) != 1 || got.Capabilities[0] != "zfs" {
		t.Errorf("capabilities not updated: %v", got.Capabilities)
	}
}

func TestStore_TouchLastSeen(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	n := makeNode("hb", proto.RoleCompute, 0)
	if err := s.Insert(ctx, n); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	bump := time.Now().Add(-10 * time.Millisecond).UTC()
	if err := s.TouchLastSeen(ctx, "hb", bump); err != nil {
		t.Fatalf("TouchLastSeen: %v", err)
	}
	got, _ := s.Get(ctx, "hb")
	// Stored at ms precision — compare via UnixMilli.
	if got.LastSeen.UnixMilli() != bump.UnixMilli() {
		t.Errorf("LastSeen: got %v want %v", got.LastSeen, bump)
	}
}

func TestStore_TouchLastSeen_UnknownNode(t *testing.T) {
	s := newStore(t)
	err := s.TouchLastSeen(context.Background(), "ghost", time.Now())
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("want sql.ErrNoRows, got %v", err)
	}
}

func TestStore_List_OrdersByFirstSeen(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	a := makeNode("a", proto.RoleCompute, 0)
	a.FirstSeen = time.Now().Add(-2 * time.Hour).UTC()
	b := makeNode("b", proto.RoleCompute, 0)
	b.FirstSeen = time.Now().Add(-1 * time.Hour).UTC()
	c := makeNode("c", proto.RoleCompute, 0)
	c.FirstSeen = time.Now().Add(-30 * time.Minute).UTC()

	// Insert out of order to confirm ORDER BY is what's doing the sorting.
	for _, n := range []*proto.Node{c, a, b} {
		if err := s.Insert(ctx, n); err != nil {
			t.Fatalf("Insert %s: %v", n.ID, err)
		}
	}

	got, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3, got %d", len(got))
	}
	if got[0].ID != "a" || got[1].ID != "b" || got[2].ID != "c" {
		t.Errorf("List order: got %s, %s, %s", got[0].ID, got[1].ID, got[2].ID)
	}
}

func TestStore_ListByRole(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	for i, role := range []proto.NodeRole{proto.RoleCompute, proto.RoleFirewall, proto.RoleCompute, proto.RoleControlPlane} {
		n := makeNode(string(role)+"-"+string(rune('0'+i)), role, 0)
		if err := s.Insert(ctx, n); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}

	got, err := s.ListByRole(ctx, proto.RoleCompute)
	if err != nil {
		t.Fatalf("ListByRole: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("compute count: want 2, got %d", len(got))
	}
	for _, n := range got {
		if n.Role != proto.RoleCompute {
			t.Errorf("ListByRole returned wrong role: %q", n.Role)
		}
	}

	none, err := s.ListByRole(ctx, proto.RoleStorage)
	if err != nil {
		t.Fatalf("ListByRole storage: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("storage count: want 0, got %d", len(none))
	}
}

func TestStore_Empty(t *testing.T) {
	s := newStore(t)
	got, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty, got %+v", got)
	}
}

// ============================================================================
// ComputeStatus thresholds
// ============================================================================

func TestComputeStatus(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		gap  time.Duration
		want proto.NodeStatus
	}{
		{"fresh", 0, proto.StatusOnline},
		{"just under stale", 25 * time.Second, proto.StatusOnline},
		// Exactly 30s falls into the "stale" bucket because the cutoff is "<staleAfter".
		{"stale lower edge", 30 * time.Second, proto.StatusStale},
		{"middle of stale", 90 * time.Second, proto.StatusStale},
		{"stale upper edge", 2 * time.Minute, proto.StatusOffline},
		{"offline", 5 * time.Minute, proto.StatusOffline},
		{"very old", 48 * time.Hour, proto.StatusOffline},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeStatus(now.Add(-tc.gap))
			if got != tc.want {
				t.Errorf("ComputeStatus(gap=%v) = %q, want %q", tc.gap, got, tc.want)
			}
		})
	}
}

// ============================================================================
// scanForTransitions — store-driven path without a real NATS bus.
//
// The Service.emit method dereferences s.nc, so we can't safely exercise the
// "transition fires emit" branch with a nil bus. Instead we seed the
// statusByNode cache to match what ComputeStatus will return — that makes
// cur == prev for every node, and the loop short-circuits before reaching
// emit. This still exercises the List, ComputeStatus, and bookkeeping
// lines under the race detector.
// ============================================================================

func TestService_ScanForTransitions_NoTransition_NoEmit(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	// One node per status bucket so we cover all three cases.
	for id, gap := range map[string]time.Duration{
		"online":  1 * time.Second,
		"stale":   45 * time.Second,
		"offline": 5 * time.Minute,
	} {
		n := makeNode(id, proto.RoleCompute, gap)
		if err := store.Insert(ctx, n); err != nil {
			t.Fatalf("Insert %s: %v", id, err)
		}
	}

	// nc is nil — that's fine as long as no branch attempts to publish.
	svc := NewService(store, nil)
	svc.ctx = ctx

	// Pre-populate the in-memory cache so cur == prev for every node and
	// the emit branch is unreachable.
	nodes, _ := store.List(ctx)
	for _, n := range nodes {
		svc.statusByNode[n.ID] = ComputeStatus(n.LastSeen)
	}

	// Should be a no-op: doesn't panic, doesn't change anything.
	svc.scanForTransitions()

	if got := svc.statusByNode["online"]; got != proto.StatusOnline {
		t.Errorf("online cache: got %q", got)
	}
	if got := svc.statusByNode["stale"]; got != proto.StatusStale {
		t.Errorf("stale cache: got %q", got)
	}
	if got := svc.statusByNode["offline"]; got != proto.StatusOffline {
		t.Errorf("offline cache: got %q", got)
	}
}

func TestService_ScanForTransitions_EmptyStore(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	svc := NewService(store, nil)
	svc.ctx = ctx
	// No nodes, no transitions, no emit, no panic.
	svc.scanForTransitions()
}

// ============================================================================
// Service.Seed — also nil-bus safe (only reads, no publishes).
// ============================================================================

func TestService_Seed_PopulatesCache(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	if err := store.Insert(ctx, makeNode("warm", proto.RoleCompute, 1*time.Second)); err != nil {
		t.Fatalf("insert warm: %v", err)
	}
	if err := store.Insert(ctx, makeNode("cold", proto.RoleCompute, 10*time.Minute)); err != nil {
		t.Fatalf("insert cold: %v", err)
	}

	svc := NewService(store, nil)
	svc.ctx = ctx
	if err := svc.seed(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if svc.statusByNode["warm"] != proto.StatusOnline {
		t.Errorf("warm: got %q", svc.statusByNode["warm"])
	}
	if svc.statusByNode["cold"] != proto.StatusOffline {
		t.Errorf("cold: got %q", svc.statusByNode["cold"])
	}
}

// ============================================================================
// nodeIDFromSubject — pure helper.
// ============================================================================

func TestNodeIDFromSubject(t *testing.T) {
	cases := []struct {
		subject string
		wantID  string
		wantOK  bool
	}{
		{"rasputin.node.cp-1.heartbeat", "cp-1", true},
		{"rasputin.node.fw-x.evt.registered", "fw-x", true},
		{"rasputin.node.x.cmd.something.deep", "x", true},
		// Negative cases:
		{"", "", false},
		{"rasputin.node", "", false},
		{"rasputin.node.x", "", false}, // only 3 parts — needs at least 4.
		{"other.node.x.heartbeat", "", false},
		{"rasputin.other.x.heartbeat", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.subject, func(t *testing.T) {
			id, ok := nodeIDFromSubject(tc.subject)
			if ok != tc.wantOK || id != tc.wantID {
				t.Errorf("nodeIDFromSubject(%q) = (%q, %v), want (%q, %v)",
					tc.subject, id, ok, tc.wantID, tc.wantOK)
			}
		})
	}
}

// ============================================================================
// Service.Store accessor.
// ============================================================================

func TestService_StoreAccessor(t *testing.T) {
	store := newStore(t)
	svc := NewService(store, nil)
	if svc.Store() != store {
		t.Errorf("Store() did not return the wrapped store")
	}
}

// ============================================================================
// Service.handleHeartbeat / handleRegistered — early-exit branches.
//
// These handlers eventually call s.emit(), which dereferences s.nc. With nc
// nil, the only branches we can exercise are the ones that return *before*
// reaching emit:
//   - bad subject (heartbeat)
//   - invalid JSON (both)
//   - unknown node id (heartbeat → TouchLastSeen ErrNoRows path)
//   - empty nodeID (registered)
//   - invalid role (registered)
//
// These cover the validation prelude of each handler, which is real
// production logic worth pinning.
// ============================================================================

func TestService_HandleHeartbeat_EarlyExits(t *testing.T) {
	store := newStore(t)
	svc := NewService(store, nil) // nc is nil; safe as long as no emit() is reached.
	svc.ctx = context.Background()

	// These cases all return before emit():
	//   1. subject doesn't match the rasputin.node.<id>.<rest> pattern
	//   2. payload isn't valid JSON
	//   3. node id is unknown to the store (TouchLastSeen ErrNoRows path)
	cases := []struct {
		name    string
		subject string
		data    []byte
	}{
		{"bad subject", "garbage.subject", []byte(`{}`)},
		{"invalid json", "rasputin.node.n.heartbeat", []byte("not-json")},
		{"unknown node id", "rasputin.node.ghost.heartbeat", mustJSON(t, proto.HeartbeatEvt{NodeID: "ghost"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Should not panic and should not touch the bus.
			svc.handleHeartbeat(&nats.Msg{Subject: tc.subject, Data: tc.data})
		})
	}
}

func TestService_HandleRegistered_EarlyExits(t *testing.T) {
	store := newStore(t)
	svc := NewService(store, nil)
	svc.ctx = context.Background()

	cases := []struct {
		name string
		data []byte
	}{
		{"invalid json", []byte("not-json")},
		{"empty node id", mustJSON(t, proto.NodeRegisteredEvt{Role: proto.RoleCompute})},
		{"invalid role", mustJSON(t, proto.NodeRegisteredEvt{NodeID: "n", Role: proto.NodeRole("bogus")})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc.handleRegistered(&nats.Msg{Subject: "rasputin.node.n.evt.registered", Data: tc.data})
		})
	}
}

// mustJSON marshals v or fails the test — keeps fixture set-up readable.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
