package mesh

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The e3bench 2026-09-04 case, as data: the api holds the restored CA
// ("original"); compute1, enrolled during the interim, still reports the
// interim one. Only the fingerprints travel — no PEM appears in a spec, a
// log line or a step result.
var (
	trustOriginalCA = []byte("-----BEGIN CERTIFICATE-----\nORIGINAL\n-----END CERTIFICATE-----\n")
	trustInterimCA  = []byte("-----BEGIN CERTIFICATE-----\nINTERIM\n-----END CERTIFICATE-----\n")
)

// trustFixture is a convergeFixture whose Service ships a mesh CA.
type trustFixture struct {
	*convergeFixture
	want string
}

func newTrustFixture(t *testing.T) *trustFixture {
	t.Helper()
	f := newConvergeFixture(t)
	f.svc = NewService(Config{MeshCAPEM: trustOriginalCA}, f.store, f.client, NewNoopSupervisor())
	return &trustFixture{convergeFixture: f, want: proto.MeshCAFingerprint(trustOriginalCA)}
}

// addTrustNode inserts an online node reporting fp (or nothing when fp is
// ""), enrolled (a rasputin device row) unless enrolled is false.
func (f *trustFixture) addTrustNode(t *testing.T, id string, role proto.NodeRole, fp string, enrolled bool, lastSeen time.Time) {
	t.Helper()
	n := &proto.Node{ID: id, Role: role, Hostname: id, AgentVersion: "2026.09.1-dev.150", FirstSeen: lastSeen, LastSeen: lastSeen}
	if fp != "" {
		n.Metadata = map[string]any{proto.MetadataMeshCAFingerprint: fp}
	}
	if err := f.inv.Insert(f.ctx, n); err != nil {
		t.Fatalf("inv.Insert(%s): %v", id, err)
	}
	if enrolled {
		if err := f.store.UpsertDevice(f.ctx, &Device{
			HSID: "hs-" + id, User: "u", Hostname: id, Kind: "rasputin", RasputinNodeID: id,
			Tags: []string{meshNodeTag}, FirstSeen: lastSeen, LastSeen: lastSeen,
		}); err != nil {
			t.Fatalf("UpsertDevice(%s): %v", id, err)
		}
	}
}

// addTerminalEnroll seeds a finished enroll job for nodeID at `at`.
func (f *trustFixture) addTerminalEnroll(t *testing.T, id, nodeID string, status jobs.Status, at time.Time) {
	t.Helper()
	spec, _ := json.Marshal(EnrollSpec{NodeID: nodeID})
	j := &jobs.Job{ID: id, Kind: "mesh.enroll_node", Spec: spec, Status: jobs.StatusQueued, CreatedBy: "test", CreatedAt: at}
	if err := f.jstore.CreateJob(f.ctx, j); err != nil {
		t.Fatalf("CreateJob(%s): %v", id, err)
	}
	switch status {
	case jobs.StatusFailed:
		if err := f.jstore.MarkJobFailed(f.ctx, id, "boom", at); err != nil {
			t.Fatal(err)
		}
	case jobs.StatusSucceeded:
		if err := f.jstore.MarkJobSucceeded(f.ctx, id, at); err != nil {
			t.Fatal(err)
		}
	}
}

// run executes converge_trust and returns its result plus the node ids it
// submitted re-deliveries for (the jobs it created, by creator).
func (f *trustFixture) run(t *testing.T) (TrustConvergeResult, []string) {
	t.Helper()
	step := reconcileConvergeTrust(f.svc, f.inv, f.jstore, f.runner)
	raw, err := step(stepCtx(f.ctx, f.nc, struct{}{}))
	if err != nil {
		t.Fatalf("converge_trust: %v", err)
	}
	var res TrustConvergeResult
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("result: %v", err)
	}
	f.runner.Wait()
	recent, err := f.jstore.ListJobsByKind(f.ctx, "mesh.enroll_node", 100)
	if err != nil {
		t.Fatalf("ListJobsByKind: %v", err)
	}
	var submitted []string
	for _, j := range recent {
		if j.CreatedBy != "converge-trust" {
			continue
		}
		var spec EnrollSpec
		_ = json.Unmarshal(j.Spec, &spec)
		submitted = append(submitted, spec.NodeID)
	}
	slices.Sort(submitted)
	return res, submitted
}

func TestConvergeTrust_RedeliversToStaleEnrolledNodesOnly(t *testing.T) {
	f := newTrustFixture(t)
	now := time.Now().UTC()
	interim := proto.MeshCAFingerprint(trustInterimCA)
	f.addTrustNode(t, "compute1", proto.RoleCompute, interim, true, now)                   // stale → re-deliver
	f.addTrustNode(t, "fw", proto.RoleFirewall, proto.MeshCAFingerprintNone, true, now)    // trusts nothing → re-deliver
	f.addTrustNode(t, "controlplane", proto.RoleControlPlane, interim, true, now)          // the CP is a node too → re-deliver
	f.addTrustNode(t, "compute2", proto.RoleCompute, f.want, true, now)                    // current → nothing
	f.addTrustNode(t, "compute3", proto.RoleCompute, "", true, now)                        // unreported → left alone
	f.addTrustNode(t, "compute4", proto.RoleCompute, interim, false, now)                  // stale but unenrolled → converge_enrollment's
	f.addTrustNode(t, "compute5", proto.RoleCompute, interim, true, now.Add(-2*time.Hour)) // stale but offline → wait

	res, submitted := f.run(t)
	if want := []string{"compute1", "controlplane", "fw"}; !slices.Equal(submitted, want) {
		t.Errorf("submitted = %v, want %v", submitted, want)
	}
	if !slices.Equal(res.Redelivered, submitted) {
		t.Errorf("result.redelivered = %v, want %v", res.Redelivered, submitted)
	}
	if want := []string{"compute1", "compute5", "controlplane", "fw"}; !slices.Equal(res.Stale, want) {
		t.Errorf("result.stale = %v, want %v", res.Stale, want)
	}
	if !slices.Equal(res.Current, []string{"compute2"}) || !slices.Equal(res.Unreported, []string{"compute3"}) {
		t.Errorf("current = %v unreported = %v", res.Current, res.Unreported)
	}
	if res.Skipped["offline"] != 1 {
		t.Errorf("skipped = %v, want offline:1", res.Skipped)
	}
	if res.CAFingerprint != f.want {
		t.Errorf("result names CA %s, want %s", res.CAFingerprint, f.want)
	}
	// A second pass with the same data submits nothing more: the first
	// pass's job is in flight (or, once it runs under the no-op workflow,
	// succeeded inside the cooldown).
	if _, again := f.run(t); len(again) != len(submitted) {
		t.Errorf("second pass submitted %d, want the first pass's %d and no more", len(again), len(submitted))
	}
}

func TestConvergeTrust_SubmitsOncePerNodeAndHonoursGuards(t *testing.T) {
	interim := proto.MeshCAFingerprint(trustInterimCA)
	now := time.Now().UTC()
	cases := []struct {
		name   string
		seed   func(f *trustFixture)
		want   []string
		reason string
	}{
		{"inflight", func(f *trustFixture) {
			f.addTerminalEnroll(t, "job-q", "n1", jobs.StatusQueued, now)
		}, nil, "inflight"},
		{"recent failure is in backoff", func(f *trustFixture) {
			f.addTerminalEnroll(t, "job-f", "n1", jobs.StatusFailed, now.Add(-5*time.Second))
		}, nil, "backoff"},
		{"old failure is retried", func(f *trustFixture) {
			f.addTerminalEnroll(t, "job-f", "n1", jobs.StatusFailed, now.Add(-enrollRetryMax-time.Minute))
		}, []string{"n1"}, ""},
		{"repeated failures stay paced", func(f *trustFixture) {
			for i := range 6 {
				f.addTerminalEnroll(t, "job-f"+string(rune('a'+i)), "n1", jobs.StatusFailed, now.Add(-time.Duration(5+i*10)*time.Minute))
			}
		}, nil, "backoff"},
		{"a delivery that just succeeded is not repeated", func(f *trustFixture) {
			f.addTerminalEnroll(t, "job-ok", "n1", jobs.StatusSucceeded, now.Add(-time.Minute))
		}, nil, "delivered_recently"},
		{"a still-stale node is delivered to again after the cooldown", func(f *trustFixture) {
			f.addTerminalEnroll(t, "job-ok", "n1", jobs.StatusSucceeded, now.Add(-trustRedeliverCooldown-time.Minute))
		}, []string{"n1"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTrustFixture(t)
			f.addTrustNode(t, "n1", proto.RoleCompute, interim, true, now)
			tc.seed(f)
			res, submitted := f.run(t)
			if !slices.Equal(submitted, tc.want) {
				t.Errorf("submitted = %v, want %v", submitted, tc.want)
			}
			if tc.reason != "" && res.Skipped[tc.reason] != 1 {
				t.Errorf("skipped = %v, want %s:1", res.Skipped, tc.reason)
			}
		})
	}
}

// With no CA shipped (mock mesh, plain-HTTP dev, external Headscale with a
// public cert) there is nothing to compare against and nothing to deliver —
// a node reporting "none" is not stale, it is right.
func TestConvergeTrust_NoCAConfiguredDoesNothing(t *testing.T) {
	f := newTrustFixture(t)
	f.svc = NewService(Config{}, f.store, f.client, NewNoopSupervisor())
	f.want = ""
	f.addTrustNode(t, "n1", proto.RoleCompute, proto.MeshCAFingerprintNone, true, time.Now().UTC())
	res, submitted := f.run(t)
	if len(submitted) != 0 || len(res.Stale) != 0 || res.CAFingerprint != "" {
		t.Errorf("no CA: submitted=%v result=%+v", submitted, res)
	}
}

// The reconcile carries the step, after enrollment (a node must be enrolled
// before its trust can be stale) and before the DNS projection.
func TestReconcileWorkflow_HasConvergeTrustAfterEnrollment(t *testing.T) {
	f := newMeshFixture(t)
	wf := ReconcileWorkflow(f.svc, nil, nil, nil, f.nc)
	var names []string
	for _, s := range wf.Steps {
		names = append(names, s.Name)
	}
	want := []string{"fetch_observed", "compare", "converge_enrollment", "converge_trust", "reconcile_app_dns"}
	if !slices.Equal(names, want) {
		t.Errorf("steps = %v, want %v", names, want)
	}
}

func TestNodeTrustFor(t *testing.T) {
	want := proto.MeshCAFingerprint(trustOriginalCA)
	cases := []struct {
		name     string
		want     string
		node     *proto.Node
		state    NodeTrustState
		predates bool
	}{
		{"current", want, &proto.Node{ID: "a", Metadata: map[string]any{proto.MetadataMeshCAFingerprint: want}}, TrustCurrent, false},
		{"stale", want, &proto.Node{ID: "a", Metadata: map[string]any{proto.MetadataMeshCAFingerprint: "other"}}, TrustStale, false},
		{"none is stale", want, &proto.Node{ID: "a", Metadata: map[string]any{proto.MetadataMeshCAFingerprint: proto.MeshCAFingerprintNone}}, TrustStale, false},
		{"unreported, new agent", want, &proto.Node{ID: "a", AgentVersion: "2026.09.1-dev.150"}, TrustUnreported, false},
		{"unreported, agent predates the field", want, &proto.Node{ID: "a", AgentVersion: "2026.08.4-dev.130"}, TrustUnreported, true},
		{"unreported, unparseable version", want, &proto.Node{ID: "a", AgentVersion: "dev"}, TrustUnreported, false},
		{"no CA shipped", "", &proto.Node{ID: "a", Metadata: map[string]any{proto.MetadataMeshCAFingerprint: "other"}}, TrustCurrent, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NodeTrustFor(tc.want, tc.node)
			if got.State != tc.state || got.AgentPredatesField != tc.predates {
				t.Errorf("got %+v, want state=%s predates=%v", got, tc.state, tc.predates)
			}
		})
	}
}

// A node that re-registers with a NEW machine key (its tailscaled state was
// wiped — the re-flashed controlplane after a restore puts back a Headscale
// database that remembers the old machine) leaves Headscale holding two
// nodes under one hostname. The record step removes the one that is not the
// live registration; it leaves everything alone when the live one cannot be
// found under the id the agent reported.
func TestEnrollRecord_PrunesSupersededRegistrations(t *testing.T) {
	f := newMeshFixture(t)
	old := HSNode{ID: "hs-old", Hostname: "controlplane", IPv4: "100.64.0.1", Tags: []string{meshNodeTag}}
	live := HSNode{ID: "hs-new", Hostname: "controlplane", IPv4: "100.64.0.9", Tags: []string{meshNodeTag}}
	other := HSNode{ID: "hs-c1", Hostname: "compute1", IPv4: "100.64.0.2", Tags: []string{meshNodeTag}}
	laptop := HSNode{ID: "hs-lap", Hostname: "controlplane", IPv4: "100.64.0.3"} // a user device that happens to share the name
	for _, n := range []HSNode{old, live, other, laptop} {
		f.client.nodes[n.ID] = n
	}
	_ = f.store.UpsertDevice(f.ctx, &Device{HSID: "hs-old", Hostname: "controlplane", Kind: "rasputin", RasputinNodeID: "controlplane"})

	sc := stepCtx(f.ctx, f.nc, struct{}{})
	sc.PriorResults = map[string]json.RawMessage{}
	prior, _ := json.Marshal(enrollSession{EnrollSpec: EnrollSpec{NodeID: "controlplane"}, HSID: "hs-new", HSIP: "100.64.0.9"})
	sc.PriorResults["dispatch"] = prior
	if _, err := enrollRecord(f.svc, f.nc)(sc); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, gone := f.client.nodes["hs-old"]; gone {
		t.Error("superseded registration hs-old still in Headscale")
	}
	for _, keep := range []string{"hs-new", "hs-c1", "hs-lap"} {
		if _, ok := f.client.nodes[keep]; !ok {
			t.Errorf("%s was pruned and must not be", keep)
		}
	}
	devices, _ := f.store.ListDevices(f.ctx)
	for _, d := range devices {
		if d.HSID == "hs-old" {
			t.Error("superseded device row hs-old still in mesh_devices")
		}
	}

	// Live id not found under Headscale's ids → nothing pruned.
	f.client.nodes["hs-old"] = old
	prior, _ = json.Marshal(enrollSession{EnrollSpec: EnrollSpec{NodeID: "controlplane"}, HSID: "nodeid:unknown-format", HSIP: "100.64.0.9"})
	sc.PriorResults["dispatch"] = prior
	before := f.client.deleteNodeCalls
	if _, err := enrollRecord(f.svc, f.nc)(sc); err != nil {
		t.Fatalf("record: %v", err)
	}
	if f.client.deleteNodeCalls != before {
		t.Error("pruned without finding the live registration")
	}
}
