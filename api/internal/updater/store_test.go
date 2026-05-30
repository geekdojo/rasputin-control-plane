package updater

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

type storeFixture struct {
	ctx   context.Context
	dir   string
	store *Store
}

func newStoreFixture(t *testing.T) *storeFixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := OpenStore(ctx, filepath.Join(dir, "updater.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &storeFixture{ctx: ctx, dir: dir, store: st}
}

func sampleBundle(sha string) *Bundle {
	return &Bundle{
		SHA256:       sha,
		Version:      "2026.05.30",
		Compatible:   "rasputin-pi5-cm5",
		Architecture: "arm64",
		Description:  "test bundle",
		BuildDate:    "2026-05-30",
		SizeBytes:    1024,
		SignedBy:     "Test Signer",
		StoragePath:  "/var/lib/test/" + sha,
		UploadedAt:   time.Now().UTC().Truncate(time.Millisecond),
		UploadedBy:   "tester",
	}
}

// ============================================================================
// Bundle CRUD
// ============================================================================

func TestStore_CreateAndGetBundle(t *testing.T) {
	f := newStoreFixture(t)
	b := sampleBundle("abc123")
	if err := f.store.CreateBundle(f.ctx, b); err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}
	got, err := f.store.GetBundle(f.ctx, "abc123")
	if err != nil {
		t.Fatalf("GetBundle: %v", err)
	}
	if got == nil {
		t.Fatal("bundle not found")
	}
	if got.Version != b.Version || got.Compatible != b.Compatible {
		t.Errorf("mismatch: %+v", got)
	}
}

func TestStore_GetBundle_NotFound(t *testing.T) {
	f := newStoreFixture(t)
	got, err := f.store.GetBundle(f.ctx, "missing")
	if err != nil {
		t.Fatalf("GetBundle: %v", err)
	}
	if got != nil {
		t.Errorf("want nil, got %+v", got)
	}
}

func TestStore_ListBundles_OrderedByUploadDesc(t *testing.T) {
	f := newStoreFixture(t)
	older := sampleBundle("older")
	older.UploadedAt = time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	newer := sampleBundle("newer")
	if err := f.store.CreateBundle(f.ctx, older); err != nil {
		t.Fatalf("CreateBundle older: %v", err)
	}
	if err := f.store.CreateBundle(f.ctx, newer); err != nil {
		t.Fatalf("CreateBundle newer: %v", err)
	}

	all, err := f.store.ListBundles(f.ctx)
	if err != nil {
		t.Fatalf("ListBundles: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("want 2 bundles, got %d", len(all))
	}
	if all[0].SHA256 != "newer" {
		t.Errorf("ordering: want newer first, got %s", all[0].SHA256)
	}
}

func TestStore_DeleteBundle(t *testing.T) {
	f := newStoreFixture(t)
	if err := f.store.CreateBundle(f.ctx, sampleBundle("victim")); err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}
	if err := f.store.DeleteBundle(f.ctx, "victim"); err != nil {
		t.Fatalf("DeleteBundle: %v", err)
	}
	if got, _ := f.store.GetBundle(f.ctx, "victim"); got != nil {
		t.Error("bundle not deleted")
	}
}

func TestStore_DeleteBundle_NotFound(t *testing.T) {
	f := newStoreFixture(t)
	if err := f.store.DeleteBundle(f.ctx, "ghost"); err == nil {
		t.Error("want error for deleting unknown bundle")
	}
}

// ============================================================================
// NodeUpdate CRUD
// ============================================================================

func sampleNodeUpdate(jobID, nodeID string) *NodeUpdate {
	return &NodeUpdate{
		JobID:        jobID,
		NodeID:       nodeID,
		BundleSHA256: "bundle-1",
		FromSlot:     proto.SlotA,
		ToSlot:       proto.SlotB,
		FromVersion:  "v1",
		ToVersion:    "v2",
		Status:       NodeUpdateInProgress,
		StartedAt:    time.Now().UTC().Truncate(time.Millisecond),
	}
}

func TestStore_CreateAndGetNodeUpdate(t *testing.T) {
	f := newStoreFixture(t)
	u := sampleNodeUpdate("job-1", "node-1")
	if err := f.store.CreateNodeUpdate(f.ctx, u); err != nil {
		t.Fatalf("CreateNodeUpdate: %v", err)
	}
	got, err := f.store.GetNodeUpdate(f.ctx, "job-1")
	if err != nil {
		t.Fatalf("GetNodeUpdate: %v", err)
	}
	if got == nil {
		t.Fatal("not found")
	}
	if got.Status != NodeUpdateInProgress {
		t.Errorf("Status: got %q", got.Status)
	}
	if got.FromSlot != proto.SlotA || got.ToSlot != proto.SlotB {
		t.Errorf("slots: %s → %s", got.FromSlot, got.ToSlot)
	}
}

func TestStore_GetNodeUpdate_NotFound(t *testing.T) {
	f := newStoreFixture(t)
	got, err := f.store.GetNodeUpdate(f.ctx, "missing")
	if err != nil {
		t.Fatalf("GetNodeUpdate: %v", err)
	}
	if got != nil {
		t.Errorf("want nil, got %+v", got)
	}
}

func TestStore_UpdateNodeUpdate(t *testing.T) {
	f := newStoreFixture(t)
	u := sampleNodeUpdate("job-1", "node-1")
	_ = f.store.CreateNodeUpdate(f.ctx, u)

	finished := time.Now().UTC().Truncate(time.Millisecond)
	if err := f.store.UpdateNodeUpdate(f.ctx, "job-1", NodeUpdateCommitted,
		proto.SlotB, "v2", "", finished); err != nil {
		t.Fatalf("UpdateNodeUpdate: %v", err)
	}
	got, _ := f.store.GetNodeUpdate(f.ctx, "job-1")
	if got.Status != NodeUpdateCommitted {
		t.Errorf("Status: got %q", got.Status)
	}
	if got.FinishedAt == nil || !got.FinishedAt.Equal(finished) {
		t.Errorf("FinishedAt: want %v got %v", finished, got.FinishedAt)
	}
}

func TestStore_SetNodeUpdateSlots(t *testing.T) {
	f := newStoreFixture(t)
	u := sampleNodeUpdate("job-1", "node-1")
	u.FromSlot = proto.SlotUnknown
	u.ToSlot = proto.SlotUnknown
	_ = f.store.CreateNodeUpdate(f.ctx, u)

	if err := f.store.SetNodeUpdateSlots(f.ctx, "job-1",
		proto.SlotA, proto.SlotB, "v1", "v2"); err != nil {
		t.Fatalf("SetNodeUpdateSlots: %v", err)
	}
	got, _ := f.store.GetNodeUpdate(f.ctx, "job-1")
	if got.FromSlot != proto.SlotA || got.ToSlot != proto.SlotB {
		t.Errorf("slots: %s → %s", got.FromSlot, got.ToSlot)
	}
	if got.FromVersion != "v1" || got.ToVersion != "v2" {
		t.Errorf("versions: %s → %s", got.FromVersion, got.ToVersion)
	}
}

func TestStore_ListNodeUpdates_FilterByNode(t *testing.T) {
	f := newStoreFixture(t)
	// Two for node-A, one for node-B.
	_ = f.store.CreateNodeUpdate(f.ctx, sampleNodeUpdate("j1", "node-A"))
	time.Sleep(2 * time.Millisecond)
	_ = f.store.CreateNodeUpdate(f.ctx, sampleNodeUpdate("j2", "node-A"))
	_ = f.store.CreateNodeUpdate(f.ctx, sampleNodeUpdate("j3", "node-B"))

	gotA, err := f.store.ListNodeUpdates(f.ctx, "node-A", 0)
	if err != nil {
		t.Fatalf("ListNodeUpdates: %v", err)
	}
	if len(gotA) != 2 {
		t.Errorf("filter node-A: want 2, got %d", len(gotA))
	}

	gotAll, _ := f.store.ListNodeUpdates(f.ctx, "", 0)
	if len(gotAll) != 3 {
		t.Errorf("all: want 3, got %d", len(gotAll))
	}
}

func TestStore_ListNodeUpdates_LimitDefault(t *testing.T) {
	f := newStoreFixture(t)
	_ = f.store.CreateNodeUpdate(f.ctx, sampleNodeUpdate("j1", "x"))
	got, err := f.store.ListNodeUpdates(f.ctx, "", -1) // negative → 50 default
	if err != nil {
		t.Fatalf("ListNodeUpdates: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("want 1, got %d", len(got))
	}
}

func TestStore_LatestNodeUpdate(t *testing.T) {
	f := newStoreFixture(t)
	older := sampleNodeUpdate("j1", "n")
	older.StartedAt = time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	newer := sampleNodeUpdate("j2", "n")

	_ = f.store.CreateNodeUpdate(f.ctx, older)
	_ = f.store.CreateNodeUpdate(f.ctx, newer)

	got, err := f.store.LatestNodeUpdate(f.ctx, "n")
	if err != nil {
		t.Fatalf("LatestNodeUpdate: %v", err)
	}
	if got == nil || got.JobID != "j2" {
		t.Errorf("want j2, got %+v", got)
	}
}

func TestStore_LatestNodeUpdate_None(t *testing.T) {
	f := newStoreFixture(t)
	got, err := f.store.LatestNodeUpdate(f.ctx, "no-such-node")
	if err != nil {
		t.Fatalf("LatestNodeUpdate: %v", err)
	}
	if got != nil {
		t.Errorf("want nil, got %+v", got)
	}
}

// ============================================================================
// planTargets (system_jobs helper, pure function)
// ============================================================================

func node(id string, role proto.NodeRole, lastSeenAgo time.Duration) *proto.Node {
	return &proto.Node{
		ID:       id,
		Role:     role,
		LastSeen: time.Now().Add(-lastSeenAgo).UTC(),
	}
}

func TestPlanTargets_OrderingByRole(t *testing.T) {
	nodes := []*proto.Node{
		node("fw-1", proto.RoleFirewall, time.Second),
		node("cp-1", proto.RoleControlPlane, time.Second),
		node("cmp-1", proto.RoleCompute, time.Second),
		node("st-1", proto.RoleStorage, time.Second),
	}
	got, _ := planTargets(nodes, nil)
	wantOrder := []string{"cmp-1", "st-1", "cp-1", "fw-1"}
	if len(got) != len(wantOrder) {
		t.Fatalf("want %d targets, got %d", len(wantOrder), len(got))
	}
	for i, n := range got {
		if n.ID != wantOrder[i] {
			t.Errorf("idx %d: want %s, got %s", i, wantOrder[i], n.ID)
		}
	}
}

func TestPlanTargets_SkipsExcluded(t *testing.T) {
	nodes := []*proto.Node{
		node("a", proto.RoleCompute, time.Second),
		node("b", proto.RoleCompute, time.Second),
	}
	excl := map[string]struct{}{"a": {}}
	got, skipped := planTargets(nodes, excl)
	if len(got) != 1 || got[0].ID != "b" {
		t.Errorf("targets: %+v", got)
	}
	if len(skipped) != 1 || skipped[0] != "a (excluded)" {
		t.Errorf("skipped: %+v", skipped)
	}
}

func TestPlanTargets_SkipsOfflineNodes(t *testing.T) {
	nodes := []*proto.Node{
		node("on", proto.RoleCompute, time.Second),
		node("off", proto.RoleCompute, 10*time.Minute),
	}
	got, skipped := planTargets(nodes, nil)
	if len(got) != 1 || got[0].ID != "on" {
		t.Errorf("targets: %+v", got)
	}
	if len(skipped) != 1 {
		t.Errorf("skipped: %+v", skipped)
	}
}

// ============================================================================
// computeStatus (system_jobs helper, pure function)
// ============================================================================

func TestComputeStatus(t *testing.T) {
	cases := []struct {
		ago  time.Duration
		want proto.NodeStatus
	}{
		{0, proto.StatusOnline},
		{15 * time.Second, proto.StatusOnline},
		{45 * time.Second, proto.StatusStale},
		{90 * time.Second, proto.StatusStale},
		{5 * time.Minute, proto.StatusOffline},
	}
	for _, tc := range cases {
		got := computeStatus(time.Now().Add(-tc.ago))
		if got != tc.want {
			t.Errorf("ago=%v: want %q got %q", tc.ago, tc.want, got)
		}
	}
}

// ============================================================================
// Helpers (jobs.go)
// ============================================================================

func TestShort(t *testing.T) {
	if got := short("0123456789abcdef"); got != "0123456789ab" {
		t.Errorf("short long: got %q", got)
	}
	if got := short("abc"); got != "abc" {
		t.Errorf("short short: got %q", got)
	}
}

func TestParseSpec(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"valid", `{"nodeId":"n","bundleSha256":"s"}`, false},
		{"bad json", `{not json`, true},
		{"missing nodeId", `{"bundleSha256":"s"}`, true},
		{"missing sha", `{"nodeId":"n"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSpec([]byte(tc.raw))
			if (err != nil) != tc.wantErr {
				t.Errorf("err=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestMustJSON(t *testing.T) {
	got := mustJSON(map[string]string{"x": "y"})
	if string(got) != `{"x":"y"}` {
		t.Errorf("mustJSON: got %q", got)
	}
}

// ============================================================================
// ms / fromMs round-trip
// ============================================================================

func TestMsRoundTrip_Updater(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	got := fromMs(ms(now))
	if !got.Equal(now) {
		t.Errorf("round-trip: want %v got %v", now, got)
	}
}

// ============================================================================
// Compile sanity (re-used by system_jobs)
// ============================================================================

// Touch inventory.Store path: planTargets uses it indirectly through callers
// but the pure helper takes a slice. Make sure the inventory package still
// compiles in our import set.
var _ = inventory.OpenStore
