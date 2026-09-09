package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// applyMeshMembership moved to inventory.ApplyMesh (presence_test.go).

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

// ---- /api/nodes carries the join and the derived state ---------------------

// A node whose heartbeat lapsed while its mesh device is online — the
// e3bench 2026-09-04 shape — comes out of /api/nodes as off-bus with a mesh
// block saying enrolled + online + when; a node with both down stays offline
// (geekdojo/geekdojo-brain#401). Nothing on the nodes page fetches mesh
// itself: the row already says.
func TestHandleListNodes_OffBusOnMesh(t *testing.T) {
	f := newAPIFixture(t)
	now := time.Now().UTC()
	lapsed := now.Add(-3 * time.Hour)
	for _, id := range []string{"compute2", "compute3", "compute4"} {
		if err := f.inv.Insert(f.ctx, &proto.Node{ID: id, Role: proto.RoleCompute, Hostname: id, FirstSeen: lapsed, LastSeen: lapsed}); err != nil {
			t.Fatal(err)
		}
	}
	// compute2: enrolled and online. compute3: enrolled, dropped. compute4: never enrolled.
	for _, d := range []*mesh.Device{
		{HSID: "hs-2", RasputinNodeID: "compute2", Kind: "rasputin", TailnetIP: "100.64.0.2", FirstSeen: lapsed, LastSeen: lapsed, Online: true},
		{HSID: "hs-3", RasputinNodeID: "compute3", Kind: "rasputin", TailnetIP: "100.64.0.3", FirstSeen: lapsed, LastSeen: lapsed, Online: false},
	} {
		if err := f.mesh.Store().UpsertDevice(f.ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	observed := now.Add(-40 * time.Second)
	if err := f.mesh.Store().UpdateAfterReconcile(f.ctx, "obs", observed); err != nil {
		t.Fatal(err)
	}

	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/nodes", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var rows []struct {
		ID     string           `json:"id"`
		Status proto.NodeStatus `json:"status"`
		Mesh   *struct {
			State    string     `json:"state"`
			Enrolled bool       `json:"enrolled"`
			Online   bool       `json:"online"`
			LastSeen *time.Time `json:"lastSeen"`
		} `json:"mesh"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	byID := map[string]int{}
	for i, r := range rows {
		byID[r.ID] = i
	}
	r := rows[byID["compute2"]]
	if r.Status != proto.StatusOffBus || r.Mesh == nil || !r.Mesh.Enrolled || !r.Mesh.Online || r.Mesh.State != "joined" {
		t.Errorf("compute2: want off-bus with mesh enrolled+online, got status %q mesh %+v", r.Status, r.Mesh)
	}
	if r.Mesh != nil && (r.Mesh.LastSeen == nil || !r.Mesh.LastSeen.Equal(observed.Truncate(time.Millisecond))) {
		t.Errorf("compute2: mesh.lastSeen = %v, want the reconcile that saw it online (%v)", r.Mesh.LastSeen, observed)
	}
	r = rows[byID["compute3"]]
	if r.Status != proto.StatusOffline || r.Mesh == nil || !r.Mesh.Enrolled || r.Mesh.Online {
		t.Errorf("compute3: want offline, enrolled, not online; got status %q mesh %+v", r.Status, r.Mesh)
	}
	r = rows[byID["compute4"]]
	if r.Status != proto.StatusOffline || r.Mesh == nil || r.Mesh.Enrolled || r.Mesh.State != "absent" {
		t.Errorf("compute4: want offline and not enrolled; got status %q mesh %+v", r.Status, r.Mesh)
	}

	// The single-node handler agrees.
	w = f.do(t, http.MethodGet, "/api/nodes/compute2", "", c)
	var one proto.Node
	if err := json.Unmarshal(w.Body.Bytes(), &one); err != nil {
		t.Fatal(err)
	}
	if one.Status != proto.StatusOffBus {
		t.Errorf("GET /api/nodes/compute2: status %q, want off-bus", one.Status)
	}
}
