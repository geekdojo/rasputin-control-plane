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
		Compatible:   "rasputin-rpi-arm64",
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
	got, _ := planTargets(nodes, nil, "")
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
	got, skipped := planTargets(nodes, excl, "")
	if len(got) != 1 || got[0].ID != "b" {
		t.Errorf("targets: %+v", got)
	}
	if len(skipped) != 1 || skipped[0].NodeID != "a" || skipped[0].Reason != proto.SkipExcluded {
		t.Errorf("skipped: %+v", skipped)
	}
}

func TestPlanTargets_SkipsOfflineNodes(t *testing.T) {
	nodes := []*proto.Node{
		node("on", proto.RoleCompute, time.Second),
		node("off", proto.RoleCompute, 10*time.Minute),
	}
	got, skipped := planTargets(nodes, nil, "")
	if len(got) != 1 || got[0].ID != "on" {
		t.Errorf("targets: %+v", got)
	}
	if len(skipped) != 1 || skipped[0].Reason != proto.SkipOffline {
		t.Errorf("skipped: %+v", skipped)
	}
}

// A system.update carries ONE bundle, so planTargets must skip nodes whose SKU
// doesn't match it — the safety valve that stops an OS bundle from ever reaching
// the firewall's real openwrt-ab backend (and vice-versa).
func TestPlanTargets_SkipsSKUMismatch(t *testing.T) {
	amd64Node := func(id string, role proto.NodeRole) *proto.Node {
		n := node(id, role, time.Second)
		n.Architecture = "amd64"
		return n
	}
	nodes := []*proto.Node{
		amd64Node("cmp-1", proto.RoleCompute),
		node("fw-1", proto.RoleFirewall, time.Second),
	}

	// OS bundle → updates the compute node, skips the firewall. The firewall
	// skip is DESIGNED, so it must not read as stranded.
	got, skipped := planTargets(nodes, nil, "rasputin-n100")
	if len(got) != 1 || got[0].ID != "cmp-1" {
		t.Errorf("OS bundle targets = %+v, want [cmp-1]", got)
	}
	if len(skipped) != 1 || skipped[0].NodeID != "fw-1" {
		t.Fatalf("OS bundle should skip fw-1, skipped = %+v", skipped)
	}
	if skipped[0].Reason != proto.SkipFirewallSKU || skipped[0].Reason.Stranded() {
		t.Errorf("fw-1 skip reason = %q (stranded=%v), want firewall-sku and NOT stranded",
			skipped[0].Reason, skipped[0].Reason.Stranded())
	}

	// Firewall bundle → updates the firewall, skips the compute node. Same
	// direction, same designed reason.
	got, skipped = planTargets(nodes, nil, "rasputin-fw-n100")
	if len(got) != 1 || got[0].ID != "fw-1" {
		t.Errorf("fw bundle targets = %+v, want [fw-1]", got)
	}
	if len(skipped) != 1 || skipped[0].NodeID != "cmp-1" {
		t.Fatalf("fw bundle should skip cmp-1, skipped = %+v", skipped)
	}
	if skipped[0].Reason != proto.SkipFirewallSKU || skipped[0].Reason.Stranded() {
		t.Errorf("cmp-1 skip reason = %q (stranded=%v), want firewall-sku and NOT stranded",
			skipped[0].Reason, skipped[0].Reason.Stranded())
	}
}

// The whole point of ADR-0005 Decision 11: on a mixed arm64/amd64 cluster a
// single-bundle run leaves the other arch behind, and that skip is NOT the
// same thing as the firewall being filtered out. Eleven updated, eleven
// stranded, reported green is the failure this test exists to prevent.
func TestPlanTargets_OtherArchIsStrandedNotDesigned(t *testing.T) {
	withArch := func(id, arch string) *proto.Node {
		n := node(id, proto.RoleCompute, time.Second)
		n.Architecture = arch
		return n
	}
	nodes := []*proto.Node{
		withArch("n100-1", "amd64"),
		withArch("pi-1", "arm64"),
		node("fw-1", proto.RoleFirewall, time.Second),
	}

	got, skipped := planTargets(nodes, nil, "rasputin-n100")
	if len(got) != 1 || got[0].ID != "n100-1" {
		t.Fatalf("targets = %+v, want [n100-1]", got)
	}

	byID := map[string]proto.SkippedNode{}
	for _, sk := range skipped {
		byID[sk.NodeID] = sk
	}
	if r := byID["pi-1"].Reason; r != proto.SkipNoArtifactForArch || !r.Stranded() {
		t.Errorf("pi-1 skip reason = %q (stranded=%v), want no-artifact-for-arch and stranded", r, r.Stranded())
	}
	if r := byID["fw-1"].Reason; r != proto.SkipFirewallSKU || r.Stranded() {
		t.Errorf("fw-1 skip reason = %q (stranded=%v), want firewall-sku and NOT stranded", r, r.Stranded())
	}
}

// #67: a node that never reported its architecture was classified amd64 with
// full confidence. On a mixed cluster that plans an arch-unknown arm64 node
// into an amd64 cascade, where it fails at install and eats maxFailures budget
// for a node that was never a valid target. It is stranded, not planned.
func TestPlanTargets_EmptyArchIsStrandedNotAssumedAmd64(t *testing.T) {
	n := node("never-said", proto.RoleCompute, time.Second) // Architecture == ""
	got, skipped := planTargets([]*proto.Node{n}, nil, "rasputin-n100")
	if len(got) != 0 {
		t.Errorf("targets = %+v, want none — an unreported arch is not amd64", got)
	}
	if len(skipped) != 1 || skipped[0].Reason != proto.SkipNoArtifactForArch {
		t.Fatalf("skipped = %+v, want one no-artifact-for-arch skip", skipped)
	}
	if !skipped[0].Reason.Stranded() {
		t.Error("an unreported arch is a stranding — nobody asked for this node to be left out")
	}
}

// The firewall's artifact is selected by its own SKU, never by arch, so the
// #67 change must not make a firewall node undeterminable. It has no
// Architecture in most fixtures and still has exactly one valid image.
func TestPlanTargets_FirewallIsUnaffectedByEmptyArch(t *testing.T) {
	fw := node("fw-1", proto.RoleFirewall, time.Second) // Architecture == ""
	got, skipped := planTargets([]*proto.Node{fw}, nil, "rasputin-fw-n100")
	if len(got) != 1 || got[0].ID != "fw-1" {
		t.Fatalf("targets = %+v, want [fw-1]; the firewall is selected by SKU, not arch", got)
	}
	if len(skipped) != 0 {
		t.Errorf("skipped = %+v, want none", skipped)
	}
}

// A node whose arch cannot be resolved to an artifact used to fall straight
// through the SKU filter and be planned into whatever bundle the run carried —
// the `known` return was computed and then only consulted in the mismatch
// branch. It must be skipped as stranded instead.
func TestPlanTargets_UnknownArchIsStrandedNotPlanned(t *testing.T) {
	n := node("weird-1", proto.RoleCompute, time.Second)
	n.Architecture = "riscv64"
	got, skipped := planTargets([]*proto.Node{n}, nil, "rasputin-n100")
	if len(got) != 0 {
		t.Errorf("targets = %+v, want none — an unresolvable arch is not a valid target", got)
	}
	if len(skipped) != 1 || !skipped[0].Reason.Stranded() {
		t.Errorf("skipped = %+v, want one stranded skip", skipped)
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

// ⚠️ THE #86 REGRESSION. The api writes the authoritative to_version from the
// release manifest at step 1, and this statement used to overwrite it with the
// agent's echo unconditionally. On RAUC that is invisible — `rauc info` returns
// the same string — but openwrt-ab's raw squashfs carries no manifest, so the
// echo is "" and a good version was replaced with nothing on EVERY firewall
// update. verify reads this exact column as conjunct (c)'s expected side, so
// blanking it made the check permanently unevaluable on that backend.
//
// The issue and the wiki both originally proposed shipping a `.version` sidecar
// in the firewall image. No sidecar is needed: the api held the answer the
// whole time and was throwing it away here.
func TestStore_SetNodeUpdateSlots_EmptyVersionDoesNotEraseTheManifestVersion(t *testing.T) {
	f := newStoreFixture(t)
	u := sampleNodeUpdate("job-1", "firewall1")
	u.FromSlot = proto.SlotUnknown
	u.ToSlot = proto.SlotUnknown
	// Step 1: the api records what the RELEASE MANIFEST says it is installing,
	// before the node has been asked to do anything.
	u.ToVersion = "2026.08.2-dev.84"
	_ = f.store.CreateNodeUpdate(f.ctx, u)

	// Step 4: openwrt-ab installed it fine but has no manifest to read, so it
	// echoes back "" — "I have nothing to add", not "nobody knows".
	if err := f.store.SetNodeUpdateSlots(f.ctx, "job-1",
		proto.SlotA, proto.SlotB, "2026.08.2-dev.83", ""); err != nil {
		t.Fatalf("SetNodeUpdateSlots: %v", err)
	}

	got, _ := f.store.GetNodeUpdate(f.ctx, "job-1")
	if got.ToVersion != "2026.08.2-dev.84" {
		t.Errorf("to_version = %q, want the manifest version kept — verify reads this as conjunct (c)'s expected side, "+
			"so erasing it degrades every openwrt-ab update forever (#86)", got.ToVersion)
	}
	// The slots and the version it DID know are still recorded normally.
	if got.FromSlot != proto.SlotA || got.ToSlot != proto.SlotB {
		t.Errorf("slots: %s → %s, want a → b", got.FromSlot, got.ToSlot)
	}
	if got.FromVersion != "2026.08.2-dev.83" {
		t.Errorf("from_version = %q, want it written — a non-empty echo must still land", got.FromVersion)
	}
}

// The other direction, so the fix cannot degenerate into "never write versions":
// a backend that DOES know (RAUC reads RAUC_MF_VERSION from the bundle) must
// still refine the value. A slot-aware version is stronger evidence than a
// manifest the api is holding.
func TestStore_SetNodeUpdateSlots_KnownVersionStillRefines(t *testing.T) {
	f := newStoreFixture(t)
	u := sampleNodeUpdate("job-1", "compute1")
	u.ToVersion = "2026.08.3-dev.160"
	_ = f.store.CreateNodeUpdate(f.ctx, u)

	if err := f.store.SetNodeUpdateSlots(f.ctx, "job-1",
		proto.SlotA, proto.SlotB, "2026.08.3-dev.158", "2026.08.3-dev.160-rauc"); err != nil {
		t.Fatalf("SetNodeUpdateSlots: %v", err)
	}
	got, _ := f.store.GetNodeUpdate(f.ctx, "job-1")
	if got.ToVersion != "2026.08.3-dev.160-rauc" {
		t.Errorf("to_version = %q, want the agent's value — an agent that knows better must be allowed to say so", got.ToVersion)
	}
}

// An empty from_version must not erase either. Nothing writes from_version
// before the install step today, so this is a guard rather than a live bug —
// stated because the two columns are set by the same statement and treating
// them differently is exactly the kind of asymmetry that rots.
func TestStore_SetNodeUpdateSlots_EmptyFromVersionDoesNotErase(t *testing.T) {
	f := newStoreFixture(t)
	u := sampleNodeUpdate("job-1", "node-1")
	u.FromVersion = "2026.08.2-dev.83"
	_ = f.store.CreateNodeUpdate(f.ctx, u)

	if err := f.store.SetNodeUpdateSlots(f.ctx, "job-1",
		proto.SlotA, proto.SlotB, "", "v2"); err != nil {
		t.Fatalf("SetNodeUpdateSlots: %v", err)
	}
	got, _ := f.store.GetNodeUpdate(f.ctx, "job-1")
	if got.FromVersion != "2026.08.2-dev.83" {
		t.Errorf("from_version = %q, want it kept", got.FromVersion)
	}
}
