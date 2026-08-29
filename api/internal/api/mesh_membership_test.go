package api

import (
	"strings"
	"testing"
	"time"

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
