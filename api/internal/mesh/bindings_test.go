package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// fakeLedger is an EnrolLedger with fixed records.
type fakeLedger struct {
	recs  []EnrolRecord
	err   error
	calls int
}

func (l *fakeLedger) Records(context.Context) ([]EnrolRecord, error) {
	l.calls++
	return l.recs, l.err
}

// seedLegacyBinding writes a bound row the way a release before enrol-only
// binding did: bound, with no enrol job recorded.
func seedLegacyBinding(t *testing.T, st *Store, hsID, nodeID string, routes ...string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := st.db.ExecContext(context.Background(), `DROP INDEX IF EXISTS ux_mesh_devices_bound_node`); err != nil {
		t.Fatalf("drop index: %v", err)
	}
	if err := upsertDevice(context.Background(), st.db, &Device{HSID: hsID, Hostname: nodeID, RasputinNodeID: nodeID, Kind: "rasputin",
		Tags: []string{meshNodeTag}, AdvertisedRoutes: routes, FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatalf("seed %s: %v", hsID, err)
	}
}

func bindingOf(t *testing.T, st *Store, hsID string) (node, job string) {
	t.Helper()
	devs, _ := st.ListDevices(context.Background())
	for _, d := range devs {
		if d.HSID == hsID {
			return d.RasputinNodeID, d.EnrolJobID
		}
	}
	t.Fatalf("no device %s", hsID)
	return "", ""
}

// The upgrade split: a binding the ledger proves is kept (and records its
// job), one it does not is cleared, and of two bindings for one node only
// the newest enrolled device keeps it. The device rows stay.
func TestVerifyBindings_KeepsLedgerProvenClearsTheRest(t *testing.T) {
	f := newMeshFixture(t)
	seedLegacyBinding(t, f.store, "hs-1", "node-a") // proven
	seedLegacyBinding(t, f.store, "hs-2", "node-b") // no enrol recorded it
	seedLegacyBinding(t, f.store, "hs-3", "node-c") // enrolled as a different device
	seedLegacyBinding(t, f.store, "hs-4", "node-d") // proven, older
	seedLegacyBinding(t, f.store, "hs-5", "node-d") // proven, newer: wins
	seedLegacyBinding(t, f.store, "hs-6", "node-e") // hostname-named, never enrolled
	now := time.Now().UTC()
	ledger := &fakeLedger{recs: []EnrolRecord{
		{JobID: "j5", NodeID: "node-d", HSID: "hs-5", Finished: now},
		{JobID: "j1", NodeID: "node-a", HSID: "hs-1", Finished: now.Add(-time.Hour)},
		{JobID: "j4", NodeID: "node-d", HSID: "hs-4", Finished: now.Add(-2 * time.Hour)},
		{JobID: "j3", NodeID: "node-c", HSID: "hs-99", Finished: now.Add(-3 * time.Hour)},
	}}
	rep, err := VerifyBindings(f.ctx, f.store, ledger)
	if err != nil {
		t.Fatalf("VerifyBindings: %v", err)
	}
	if want := []string{"node-a=hs-1", "node-d=hs-5"}; !slices.Equal(rep.Kept, want) {
		t.Errorf("kept %v, want %v", rep.Kept, want)
	}
	if want := []string{"node-b=hs-2", "node-c=hs-3", "node-d=hs-4", "node-e=hs-6"}; !slices.Equal(rep.Cleared, want) {
		t.Errorf("cleared %v, want %v", rep.Cleared, want)
	}
	for hs, want := range map[string][2]string{"hs-1": {"node-a", "j1"}, "hs-5": {"node-d", "j5"}, "hs-2": {}, "hs-3": {}, "hs-4": {}, "hs-6": {}} {
		if n, j := bindingOf(t, f.store, hs); n != want[0] || j != want[1] {
			t.Errorf("%s bound to %q by %q, want %q by %q", hs, n, j, want[0], want[1])
		}
	}
	if devs, _ := f.store.ListDevices(f.ctx); len(devs) != 6 {
		t.Errorf("clearing must keep the device rows; have %d", len(devs))
	}

	// Idempotent: a second run reads nothing from the ledger and changes nothing.
	calls := ledger.calls
	rep, err = VerifyBindings(f.ctx, f.store, ledger)
	if err != nil || len(rep.Kept) != 0 || len(rep.Cleared) != 0 || ledger.calls != calls {
		t.Errorf("second run: %+v, %v, ledger read %d more time(s)", rep, err, ledger.calls-calls)
	}
}

// No job history at all (a wiped ledger): every binding no enrol recorded
// is cleared, so every node re-enrols. An unreadable ledger fails the same
// way — closed.
func TestVerifyBindings_NoHistoryClearsEverything(t *testing.T) {
	for name, ledger := range map[string]EnrolLedger{
		"empty ledger":      &fakeLedger{},
		"unreadable ledger": &fakeLedger{err: errors.New("disk")},
		"no ledger":         nil,
	} {
		t.Run(name, func(t *testing.T) {
			f := newMeshFixture(t)
			seedLegacyBinding(t, f.store, "hs-1", "node-a")
			seedLegacyBinding(t, f.store, "hs-2", "node-b")
			rep, err := VerifyBindings(f.ctx, f.store, ledger)
			if err != nil {
				t.Fatalf("VerifyBindings: %v", err)
			}
			if len(rep.Kept) != 0 || len(rep.Cleared) != 2 {
				t.Errorf("report %+v; want both cleared", rep)
			}
		})
	}
}

// Through the real jobs store: a succeeded enrol's record step is the proof.
func TestJobsLedger_ReadsSucceededRecordSteps(t *testing.T) {
	f := newConvergeFixture(t)
	f.addNode(t, "good", proto.RoleCompute, time.Now().UTC())
	f.addNode(t, "bad", proto.RoleCompute, time.Now().UTC())
	fakeAgent(t, f.nc, "good", proto.MeshEnrollAck{OK: true, TailnetID: "hs-9", TailnetIP: "100.64.0.9", Backend: "test"})
	fakeAgent(t, f.nc, "bad", proto.MeshEnrollAck{OK: false, Backend: "test", Detail: "no"})
	jst, err := jobs.OpenStore(f.ctx, filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatalf("jobs.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = jst.Close() })
	runner := jobs.NewRunner(jst, f.nc)
	runner.Register(EnrollNodeWorkflow(f.svc, f.inv, f.nc))
	for _, n := range []string{"good", "bad"} {
		spec, _ := json.Marshal(EnrollSpec{NodeID: n, AdvertiseRoutes: []string{"10.9.0.0/24"}})
		if _, err := runner.Submit(f.ctx, "mesh.enroll_node", spec, "test"); err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}
	runner.Wait()
	recs, err := JobsLedger{Store: jst}.Records(f.ctx)
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(recs) != 1 || recs[0].NodeID != "good" || recs[0].HSID != "hs-9" || !slices.Equal(recs[0].Routes, []string{"10.9.0.0/24"}) {
		t.Fatalf("records = %+v; want the one succeeded enrol", recs)
	}
	// And the enrol bound the device on the authority of that job.
	if n, j := bindingOf(t, f.store, "hs-9"); n != "good" || j != recs[0].JobID {
		t.Errorf("hs-9 bound to %q by %q, want good by %s", n, j, recs[0].JobID)
	}
	// Which VerifyBindings then trusts without re-deriving it.
	rep, err := VerifyBindings(f.ctx, f.store, JobsLedger{Store: jst})
	if err != nil || len(rep.Cleared) != 0 {
		t.Errorf("VerifyBindings after a real enrol: %+v, %v", rep, err)
	}
}

// One device per node, going forward: a second binding for a node is
// refused by the store, and readers refuse a node that still has two.
func TestStore_RefusesASecondBindingForANode(t *testing.T) {
	f := newMeshFixture(t)
	if _, err := VerifyBindings(f.ctx, f.store, nil); err != nil {
		t.Fatalf("VerifyBindings: %v", err)
	}
	now := time.Now().UTC()
	if _, err := f.store.BindDevice(f.ctx, &Device{HSID: "hs-1", RasputinNodeID: "node-a", Kind: "rasputin", FirstSeen: now, LastSeen: now}, "j1"); err != nil {
		t.Fatalf("BindDevice: %v", err)
	}
	err := f.store.UpsertDevice(f.ctx, &Device{HSID: "hs-2", RasputinNodeID: "node-a", Kind: "rasputin", FirstSeen: now, LastSeen: now})
	if !errors.Is(err, ErrDuplicateBinding) {
		t.Fatalf("second binding for node-a: err=%v, want ErrDuplicateBinding", err)
	}
	// The enrol itself moves the binding, and says which device it left.
	unbound, err := f.store.BindDevice(f.ctx, &Device{HSID: "hs-3", RasputinNodeID: "node-a", Kind: "rasputin", FirstSeen: now, LastSeen: now}, "j2")
	if err != nil || !slices.Equal(unbound, []string{"hs-1"}) {
		t.Fatalf("re-enrol bind: unbound=%v err=%v", unbound, err)
	}
	d, err := f.store.GetDeviceByRasputinNodeID(f.ctx, "node-a")
	if err != nil || d == nil || d.HSID != "hs-3" || d.EnrolJobID != "j2" {
		t.Fatalf("node-a resolves to %+v, %v; want hs-3 by j2", d, err)
	}
	if n, _ := bindingOf(t, f.store, "hs-1"); n != "" {
		t.Errorf("hs-1 still bound to %q", n)
	}
}

// A database that still holds two bindings for one node (the index could
// not be created over them): every reader refuses rather than picks.
func TestReaders_RefuseANodeBoundToTwoDevices(t *testing.T) {
	f := newMeshFixture(t)
	seedLegacyBinding(t, f.store, "hs-1", "node-a", "10.1.0.0/24")
	seedLegacyBinding(t, f.store, "hs-2", "node-a", "10.1.0.0/24")
	f.client.mu.Lock()
	f.client.nodes["hs-1"] = HSNode{ID: "hs-1"}
	f.client.nodes["hs-2"] = HSNode{ID: "hs-2"}
	f.client.mu.Unlock()

	_, err := f.store.GetDeviceByRasputinNodeID(f.ctx, "node-a")
	var dup *DuplicateBindingError
	if !errors.As(err, &dup) || dup.NodeID != "node-a" || !slices.Equal(dup.HSIDs, []string{"hs-1", "hs-2"}) {
		t.Fatalf("GetDeviceByRasputinNodeID: %v; want a DuplicateBindingError naming both", err)
	}

	now := time.Now().UTC()
	_ = f.store.CreateIntent(f.ctx, &Intent{ID: "r1", Kind: string(proto.IntentSubnetRoute), Name: "lan", Enabled: true,
		Spec: mustMarshal(t, proto.SubnetRouteSpec{NodeID: "node-a", CIDR: "10.1.0.0/24"}), CreatedAt: now, UpdatedAt: now})
	var logs []string
	sc := stepCtx(f.ctx, f.nc, struct{}{})
	sc.Log = func(_, m string) { logs = append(logs, m) }
	out, err := applyPushRoutes(f.svc, nil)(sc)
	if err != nil {
		t.Fatalf("push_routes: %v", err)
	}
	if f.client.setRoutesCalls != 0 {
		t.Errorf("push_routes approved routes on one of two devices bound to node-a")
	}
	if !strings.Contains(string(out), `"refusedDuplicateBinding":["node-a"]`) ||
		!slices.ContainsFunc(logs, func(m string) bool { return strings.Contains(m, "bound to 2 devices") }) {
		t.Errorf("the refusal must be surfaced: result %s, logs %v", out, logs)
	}

	sup := &capturingSupervisor{}
	svc := NewService(Config{ClusterID: "home1"}, f.store, f.client, sup)
	svc.SetAppLister(func() []AppDNS { return []AppDNS{{Name: "web", TargetNode: "node-a"}} })
	if err := svc.ReconcileAppDNS(f.ctx); err != nil {
		t.Fatalf("ReconcileAppDNS: %v", err)
	}
	if sup.calls != 1 || len(sup.got) != 0 {
		t.Errorf("app DNS published %v for a node bound to two devices", sup.got)
	}
}

// ----- routes carried by automatic re-enrols -----------------------------

// The firewall case: a node advertising a subnet route is re-enrolled by
// converge_trust (CA re-delivery) — the enrol names the route, so the
// agent's `tailscale up --reset` keeps it.
func TestConvergeTrust_ReenrolKeepsAdvertisedRoutes(t *testing.T) {
	f := newTrustFixture(t).convergeFixture
	now := time.Now().UTC()
	if err := f.inv.Insert(f.ctx, &proto.Node{ID: "fw", Role: proto.RoleFirewall, Hostname: "fw", FirstSeen: now, LastSeen: now,
		Metadata: map[string]any{proto.MetadataMeshCAFingerprint: "stale-fingerprint"}}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := f.store.BindDevice(f.ctx, &Device{HSID: "hs-fw", RasputinNodeID: "fw", Kind: "rasputin",
		AdvertisedRoutes: []string{"192.168.1.0/24"}, FirstSeen: now, LastSeen: now}, "j-fw"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if _, err := reconcileConvergeTrust(f.svc, f.inv, f.jstore, f.runner)(stepCtx(f.ctx, f.nc, struct{}{})); err != nil {
		t.Fatalf("converge_trust: %v", err)
	}
	specs := f.submittedSpecs(t)
	if len(specs) != 1 || specs[0].NodeID != "fw" || !slices.Equal(specs[0].AdvertiseRoutes, []string{"192.168.1.0/24"}) {
		t.Fatalf("re-delivery specs %+v; want fw advertising 192.168.1.0/24", specs)
	}
}

// converge_enrollment for a node with no bound device (a binding cleared at
// upgrade): routes come from its last succeeded enrol, else its subnet
// route intents; the enrol then carries them.
func TestConvergeEnrollment_ReenrolCarriesRoutes(t *testing.T) {
	f := newConvergeFixture(t)
	now := time.Now().UTC()
	f.addNode(t, "fw", proto.RoleFirewall, now)
	f.addNode(t, "c1", proto.RoleCompute, now)
	f.addNode(t, "c2", proto.RoleCompute, now)
	// fw's last succeeded enrol advertised the LAN.
	seedSucceededEnrol(t, f, "job-fw", "fw", "hs-old", []string{"192.168.1.0/24"}, now.Add(-time.Hour))
	// c1 has no enrol history but an operator-declared subnet route.
	_ = f.store.CreateIntent(f.ctx, &Intent{ID: "r1", Kind: string(proto.IntentSubnetRoute), Name: "lab", Enabled: true,
		Spec: mustMarshal(t, proto.SubnetRouteSpec{NodeID: "c1", CIDR: "10.20.0.0/16"}), CreatedAt: now, UpdatedAt: now})
	before := len(f.submittedSpecs(t))
	if _, err := reconcileConvergeEnrollment(f.svc, f.inv, f.jstore, f.runner)(stepCtx(f.ctx, f.nc, struct{}{})); err != nil {
		t.Fatalf("converge: %v", err)
	}
	got := map[string][]string{}
	for _, s := range f.submittedSpecs(t)[before:] {
		got[s.NodeID] = s.AdvertiseRoutes
	}
	if !slices.Equal(got["fw"], []string{"192.168.1.0/24"}) || !slices.Equal(got["c1"], []string{"10.20.0.0/16"}) || len(got["c2"]) != 0 {
		t.Fatalf("submitted routes %v; want fw from its last enrol, c1 from its intent, c2 none", got)
	}
	if _, ok := got["c2"]; !ok {
		t.Error("c2 was not enrolled")
	}
}

func TestReenrolRoutes_DropsWhatValidateWouldRefuse(t *testing.T) {
	d := &Device{AdvertisedRoutes: []string{"192.168.1.0/24", "fd7a::/48", "192.168.1.149/24", "192.168.1.0/24"}}
	got, source := ReenrolRoutes(context.Background(), nil, "n", d, nil)
	if source != "device" || !slices.Equal(got, []string{"192.168.1.0/24"}) {
		t.Errorf("routes %v from %s; want only the canonical IPv4 route, once", got, source)
	}
}

// seedSucceededEnrol writes a succeeded mesh.enroll_node job with its record
// step into the converge fixture's ledger.
func seedSucceededEnrol(t *testing.T, f *convergeFixture, jobID, nodeID, hsID string, routes []string, at time.Time) {
	t.Helper()
	spec, _ := json.Marshal(EnrollSpec{NodeID: nodeID, AdvertiseRoutes: routes})
	if err := f.jstore.CreateJob(f.ctx, &jobs.Job{ID: jobID, Kind: "mesh.enroll_node", Spec: spec, Status: jobs.StatusQueued, CreatedBy: "test", CreatedAt: at}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if err := f.jstore.CreateStep(f.ctx, &jobs.JobStep{JobID: jobID, Seq: 0, Name: "record", Status: jobs.StepPending}); err != nil {
		t.Fatalf("CreateStep: %v", err)
	}
	res, _ := json.Marshal(enrollSession{EnrollSpec: EnrollSpec{NodeID: nodeID, AdvertiseRoutes: routes}, HSID: hsID})
	if err := f.jstore.MarkStepSucceeded(f.ctx, jobID, 0, 1, res, at); err != nil {
		t.Fatalf("MarkStepSucceeded: %v", err)
	}
	if err := f.jstore.MarkJobSucceeded(f.ctx, jobID, at); err != nil {
		t.Fatalf("MarkJobSucceeded: %v", err)
	}
}

// submittedSpecs is every enroll spec in the converge fixture's ledger,
// oldest first.
func (f *convergeFixture) submittedSpecs(t *testing.T) []EnrollSpec {
	t.Helper()
	f.runner.Wait()
	all, err := f.jstore.ListAllJobsByKind(f.ctx, "mesh.enroll_node")
	if err != nil {
		t.Fatalf("ListAllJobsByKind: %v", err)
	}
	var out []EnrollSpec
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].CreatedBy == "test" {
			continue // seeded history, not a submission
		}
		var spec EnrollSpec
		_ = json.Unmarshal(all[i].Spec, &spec)
		out = append(out, spec)
	}
	return out
}

// CA re-delivery skips a node bound to two devices rather than re-enrol it
// with routes read off one of them.
func TestConvergeTrust_SkipsANodeBoundToTwoDevices(t *testing.T) {
	f := newTrustFixture(t).convergeFixture
	now := time.Now().UTC()
	if err := f.inv.Insert(f.ctx, &proto.Node{ID: "fw", Role: proto.RoleFirewall, Hostname: "fw", FirstSeen: now, LastSeen: now,
		Metadata: map[string]any{proto.MetadataMeshCAFingerprint: "stale-fingerprint"}}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	seedLegacyBinding(t, f.store, "hs-1", "fw", "192.168.1.0/24")
	seedLegacyBinding(t, f.store, "hs-2", "fw")
	out, err := reconcileConvergeTrust(f.svc, f.inv, f.jstore, f.runner)(stepCtx(f.ctx, f.nc, struct{}{}))
	if err != nil {
		t.Fatalf("converge_trust: %v", err)
	}
	if specs := f.submittedSpecs(t); len(specs) != 0 {
		t.Errorf("re-delivered to a node bound twice: %+v", specs)
	}
	if !strings.Contains(string(out), `"duplicate_binding":1`) {
		t.Errorf("the skip must be counted: %s", out)
	}
}

// Node removal reads every bound device, so a duplicate binding is removed
// whole instead of blocking the removal or picking one device.
func TestDevicesBoundTo_ReturnsEveryBoundDevice(t *testing.T) {
	f := newMeshFixture(t)
	seedLegacyBinding(t, f.store, "hs-2", "node-a")
	seedLegacyBinding(t, f.store, "hs-1", "node-a")
	seedLegacyBinding(t, f.store, "hs-3", "node-b")
	devs, err := f.store.DevicesBoundTo(f.ctx, "node-a")
	if err != nil {
		t.Fatalf("DevicesBoundTo: %v", err)
	}
	var ids []string
	for _, d := range devs {
		ids = append(ids, d.HSID)
	}
	if !slices.Equal(ids, []string{"hs-1", "hs-2"}) {
		t.Errorf("bound to node-a: %v, want [hs-1 hs-2]", ids)
	}
	if devs, _ := f.store.DevicesBoundTo(f.ctx, ""); len(devs) != 0 {
		t.Errorf("an empty node id matched %d unbound devices", len(devs))
	}
}
