package inventory

import (
	"context"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The state rule (geekdojo/geekdojo-brain#401), one row per branch of
// DeriveStatus, with the heartbeat thresholds at their boundaries.
func TestDeriveStatus(t *testing.T) {
	now := time.Now()
	on := &proto.MeshMembership{State: proto.MeshJoined, Enrolled: true, Online: true}
	off := &proto.MeshMembership{State: proto.MeshAbsent, Enrolled: true, Online: false}
	// Joined as of the last reconcile, but that observation has aged past the
	// mesh service's bound: State stands, Online does not.
	aged := &proto.MeshMembership{State: proto.MeshJoined, Enrolled: true, Online: false}

	cases := []struct {
		name     string
		lastSeen time.Time
		mesh     *proto.MeshMembership
		want     proto.NodeStatus
	}{
		{"lapsed + mesh online → off-bus", now.Add(-3 * time.Hour), on, proto.StatusOffBus},
		{"lapsed + mesh offline → offline", now.Add(-3 * time.Hour), off, proto.StatusOffline},
		{"lapsed + mesh aged out → offline", now.Add(-3 * time.Hour), aged, proto.StatusOffline},
		{"lapsed + no device row → offline", now.Add(-3 * time.Hour), nil, proto.StatusOffline},
		{"live + mesh offline → online (unaffected)", now.Add(-5 * time.Second), off, proto.StatusOnline},
		{"live + no mesh → online", now.Add(-5 * time.Second), nil, proto.StatusOnline},
		{"stale + mesh online → stale (kept as is)", now.Add(-60 * time.Second), on, proto.StatusStale},
		// Threshold boundary: 2m is where offline begins, so at 2m-1s the
		// node is still stale whatever the mesh says, and at 2m+1s it is
		// off-bus.
		{"just under offline threshold + mesh online → stale", now.Add(-offlineAfter + time.Second), on, proto.StatusStale},
		{"just over offline threshold + mesh online → off-bus", now.Add(-offlineAfter - time.Second), on, proto.StatusOffBus},
		{"just over offline threshold + mesh offline → offline", now.Add(-offlineAfter - time.Second), off, proto.StatusOffline},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DeriveStatus(c.lastSeen, c.mesh); got != c.want {
				t.Errorf("DeriveStatus = %q, want %q", got, c.want)
			}
		})
	}
}

// A nil map means we could not establish membership at all — no mesh
// service, or no reconcile yet. Painting those nodes "absent" would be the
// same unchecked assertion as the green 24/24, just pointing the other way;
// and their status must be the heartbeat alone.
func TestApplyMesh_NilMapLeavesUndetermined(t *testing.T) {
	now := time.Now()
	nodes := []*proto.Node{{ID: "c01", LastSeen: now}, {ID: "c02", LastSeen: now.Add(-time.Hour)}}
	ApplyMesh(nodes, nil)
	for _, n := range nodes {
		if n.Mesh != nil {
			t.Errorf("%s: Mesh = %+v, want nil (undetermined)", n.ID, n.Mesh)
		}
	}
	if nodes[0].Status != proto.StatusOnline || nodes[1].Status != proto.StatusOffline {
		t.Errorf("statuses = %q, %q; want online, offline", nodes[0].Status, nodes[1].Status)
	}
}

// Given a map we actually built, a node with no device row has genuinely
// never enrolled — we looked, and it was not there — and a lapsed node whose
// row is online is off-bus.
func TestApplyMesh_JoinsAndDerives(t *testing.T) {
	now := time.Now()
	nodes := []*proto.Node{
		{ID: "c01", LastSeen: now},
		{ID: "c02", LastSeen: now.Add(-3 * time.Hour)},
		{ID: "never-enrolled", LastSeen: now.Add(-3 * time.Hour)},
	}
	ApplyMesh(nodes, map[string]*proto.MeshMembership{
		"c01": {State: proto.MeshJoined, Enrolled: true, Online: true, TailnetIP: "100.64.0.1"},
		"c02": {State: proto.MeshJoined, Enrolled: true, Online: true, TailnetIP: "100.64.0.2"},
	})
	if nodes[0].Mesh == nil || nodes[0].Mesh.State != proto.MeshJoined || nodes[0].Status != proto.StatusOnline {
		t.Errorf("c01: want joined+online, got mesh %+v status %q", nodes[0].Mesh, nodes[0].Status)
	}
	if nodes[1].Status != proto.StatusOffBus {
		t.Errorf("c02: want off-bus, got %q", nodes[1].Status)
	}
	m := nodes[2].Mesh
	if m == nil || m.State != proto.MeshAbsent || m.Enrolled {
		t.Errorf("never-enrolled: want absent and not enrolled, got %+v", m)
	}
	if nodes[2].Status != proto.StatusOffline {
		t.Errorf("never-enrolled: want offline, got %q", nodes[2].Status)
	}
}

func TestApplyMesh_ToleratesNilNodes(t *testing.T) {
	ApplyMesh([]*proto.Node{nil, {ID: "c01"}}, map[string]*proto.MeshMembership{})
}

// Store.Presence goes through the wired lookup; unwired, mesh stays
// undetermined.
func TestStorePresence_UsesTheWiredLookup(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	lapsed := time.Now().Add(-3 * time.Hour)
	if err := st.Insert(ctx, &proto.Node{ID: "c02", Role: proto.RoleCompute, FirstSeen: lapsed, LastSeen: lapsed}); err != nil {
		t.Fatal(err)
	}

	nodes, _ := st.List(ctx)
	st.Presence(ctx, nodes)
	if nodes[0].Mesh != nil || nodes[0].Status != proto.StatusOffline {
		t.Fatalf("unwired: want undetermined mesh and offline, got %+v %q", nodes[0].Mesh, nodes[0].Status)
	}

	st.SetMeshLookup(func(context.Context) map[string]*proto.MeshMembership {
		return map[string]*proto.MeshMembership{"c02": {State: proto.MeshJoined, Enrolled: true, Online: true}}
	})
	nodes, _ = st.List(ctx)
	st.Presence(ctx, nodes)
	if nodes[0].Status != proto.StatusOffBus {
		t.Fatalf("wired: want off-bus, got %q", nodes[0].Status)
	}
}
