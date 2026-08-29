package api

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TestApplyMeshMembership_NilMapLeavesUndetermined is the load-bearing case.
// A nil map means we could not establish membership at all — no mesh service,
// or no reconcile yet. Painting those nodes "absent" would be the same unchecked
// assertion as the green 24/24, just pointing the other way.
func TestApplyMeshMembership_NilMapLeavesUndetermined(t *testing.T) {
	nodes := []*proto.Node{{ID: "c01"}, {ID: "c02"}}
	applyMeshMembership(nodes, nil)
	for _, n := range nodes {
		if n.Mesh != nil {
			t.Errorf("%s: Mesh = %+v, want nil (undetermined)", n.ID, n.Mesh)
		}
	}
}

// TestApplyMeshMembership_MissingNodeIsAbsent covers the other half: given a
// map we actually built, a node with no device row has genuinely never enrolled.
// We looked, and it was not there.
func TestApplyMeshMembership_MissingNodeIsAbsent(t *testing.T) {
	nodes := []*proto.Node{{ID: "c01"}, {ID: "never-enrolled"}}
	applyMeshMembership(nodes, map[string]*proto.MeshMembership{
		"c01": {State: proto.MeshJoined, TailnetIP: "100.64.0.1"},
	})
	if nodes[0].Mesh == nil || nodes[0].Mesh.State != proto.MeshJoined {
		t.Errorf("c01: want joined, got %+v", nodes[0].Mesh)
	}
	if nodes[1].Mesh == nil || nodes[1].Mesh.State != proto.MeshAbsent {
		t.Errorf("never-enrolled: want absent, got %+v", nodes[1].Mesh)
	}
}

func TestApplyMeshMembership_ToleratesNilNodes(t *testing.T) {
	applyMeshMembership([]*proto.Node{nil, {ID: "c01"}}, map[string]*proto.MeshMembership{})
}

// TestKnownAbsent_DefaultsOppositeToDisplay pins the asymmetry that the install
// gate depends on. Undetermined must NOT block an install (an operator with no
// mesh service configured is not broken), while the UI must never render
// undetermined as healthy. Same field, opposite safe default.
func TestKnownAbsent_DefaultsOppositeToDisplay(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    *proto.MeshMembership
		want bool
	}{
		{"nil is not a determination", nil, false},
		{"explicit unknown is not a determination", &proto.MeshMembership{State: proto.MeshUnknown}, false},
		{"joined", &proto.MeshMembership{State: proto.MeshJoined}, false},
		{"absent is the only blocking state", &proto.MeshMembership{State: proto.MeshAbsent}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.m.KnownAbsent(); got != tc.want {
				t.Errorf("KnownAbsent() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestTailnetOnlyOffMeshMsg_NamesTheDurationAndTheWayOut: the refusal has to
// answer the two questions the old reporting made unanswerable — how long has
// this been broken, and what do I do now.
func TestTailnetOnlyOffMeshMsg_NamesTheDurationAndTheWayOut(t *testing.T) {
	old := time.Now().UTC().Add(-5 * 7 * 24 * time.Hour)
	msg := tailnetOnlyOffMeshMsg("c07", &proto.MeshMembership{State: proto.MeshAbsent, LastSeen: &old})

	for _, want := range []string{"c07", "last seen on the mesh", "exposeLan"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal missing %q:\n%s", want, msg)
		}
	}
	// It must not let the operator conclude the node is simply down.
	if !strings.Contains(msg, "reachable on the LAN") {
		t.Errorf("refusal does not distinguish LAN reachability from mesh membership:\n%s", msg)
	}
}

// A node we have never seen on the mesh has no timestamp; the message must
// still be usable rather than emitting a zero date.
func TestTailnetOnlyOffMeshMsg_NoLastSeen(t *testing.T) {
	msg := tailnetOnlyOffMeshMsg("c07", &proto.MeshMembership{State: proto.MeshAbsent})
	if strings.Contains(msg, "last seen on the mesh") {
		t.Errorf("claimed a last-seen it does not have:\n%s", msg)
	}
	if !strings.Contains(msg, "exposeLan") {
		t.Errorf("refusal must still say how to proceed:\n%s", msg)
	}
}

// ---- meshMembership: the guard that decides "undetermined" -----------------
//
// These cover the branch mutation flagged as untested, and it is the one that
// matters most in the file: it is what stops an unconfigured or freshly-started
// mesh from painting the entire fleet as off-mesh. Getting it wrong would
// replace one confident falsehood with its mirror image.

func meshSvcWithStore(t *testing.T) (*mesh.Service, *mesh.Store) {
	t.Helper()
	st, err := mesh.OpenStore(context.Background(), filepath.Join(t.TempDir(), "mesh.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return mesh.NewService(mesh.Config{ClusterID: "home1"}, st, nil, nil), st
}

func TestMeshMembership_NoMeshServiceIsUndetermined(t *testing.T) {
	s := &Server{}
	if got := s.meshMembership(context.Background()); got != nil {
		t.Errorf("with no mesh service, want nil (undetermined), got %v", got)
	}
}

// The important one: devices exist in the table but no reconcile has completed.
// An empty or partial table means "we have not looked" just as readily as
// "nothing is enrolled", so membership must stay undetermined.
func TestMeshMembership_NeverReconciledIsUndetermined(t *testing.T) {
	svc, st := meshSvcWithStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.UpsertDevice(ctx, &mesh.Device{
		HSID: "hs-1", RasputinNodeID: "c01", Kind: "rasputin",
		FirstSeen: now, LastSeen: now, Online: true,
	}); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}

	s := &Server{mesh: svc}
	if got := s.meshMembership(ctx); got != nil {
		t.Errorf("no reconcile has completed, so membership is unknown; got %v", got)
	}
}

func TestMeshMembership_AfterReconcileReportsJoinedAndAbsent(t *testing.T) {
	svc, st := meshSvcWithStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	stale := now.Add(-5 * 7 * 24 * time.Hour)

	for _, d := range []*mesh.Device{
		{HSID: "hs-on", RasputinNodeID: "c04", Kind: "rasputin", TailnetIP: "100.64.0.8", FirstSeen: stale, LastSeen: stale, Online: true},
		{HSID: "hs-off", RasputinNodeID: "c13", Kind: "rasputin", TailnetIP: "100.64.0.3", FirstSeen: stale, LastSeen: stale, Online: false},
		// A laptop on the tailnet: on the mesh, but not a cluster node.
		{HSID: "hs-laptop", RasputinNodeID: "", Kind: "user", FirstSeen: now, LastSeen: now, Online: true},
	} {
		if err := st.UpsertDevice(ctx, d); err != nil {
			t.Fatalf("UpsertDevice %s: %v", d.HSID, err)
		}
	}
	if err := st.UpdateAfterReconcile(ctx, "obs", now); err != nil {
		t.Fatalf("UpdateAfterReconcile: %v", err)
	}

	got := (&Server{mesh: svc}).meshMembership(ctx)
	if got == nil {
		t.Fatal("after a reconcile, membership must be determined")
	}
	if len(got) != 2 {
		t.Errorf("map has %d entries, want 2 — user devices are not cluster nodes", len(got))
	}
	if m := got["c04"]; m == nil || m.State != proto.MeshJoined || m.TailnetIP != "100.64.0.8" {
		t.Errorf("c04: want joined with a tailnet IP, got %+v", m)
	}
	// The absent node must carry its real last-seen, which is what makes
	// "how long has this been broken?" answerable at all.
	m := got["c13"]
	if m == nil || m.State != proto.MeshAbsent {
		t.Fatalf("c13: want absent, got %+v", m)
	}
	if m.LastSeen == nil || !m.LastSeen.Equal(stale.Truncate(time.Millisecond)) {
		t.Errorf("c13: LastSeen = %v, want the stored %v", m.LastSeen, stale)
	}
}

// A store that cannot be read must yield undetermined, not an empty map — an
// empty map would mark every node absent.
func TestMeshMembership_StoreErrorIsUndetermined(t *testing.T) {
	svc, st := meshSvcWithStore(t)
	ctx := context.Background()
	if err := st.UpdateAfterReconcile(ctx, "obs", time.Now().UTC()); err != nil {
		t.Fatalf("UpdateAfterReconcile: %v", err)
	}
	_ = st.Close() // every subsequent query fails

	if got := (&Server{mesh: svc}).meshMembership(ctx); got != nil {
		t.Errorf("store unreadable: want nil (undetermined), got %v", got)
	}
}
