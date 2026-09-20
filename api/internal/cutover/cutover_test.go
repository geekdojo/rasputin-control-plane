package cutover

import (
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// floorVersion is the release that first reports both keys, read from proto so
// this test moves with the table rather than pinning a copy of it.
func floorVersion(t *testing.T, key string) string {
	t.Helper()
	v, ok := proto.MetadataMinAgentVersion(key)
	if !ok {
		t.Fatalf("%s has no metadataMinAgentVersion floor", key)
	}
	return v
}

func node(id string, agentVersion string, meta map[string]any) *proto.Node {
	return &proto.Node{ID: id, Role: proto.RoleCompute, Status: proto.StatusOnline, AgentVersion: agentVersion, Metadata: meta}
}

func TestTokenOnFile_EveryNodeOnTheFile(t *testing.T) {
	v := floorVersion(t, proto.MetadataTokenSource)
	st := TokenOnFile([]*proto.Node{
		node("compute1", v, map[string]any{proto.MetadataTokenSource: proto.TokenSourceFile}),
		node("cp1", v, map[string]any{proto.MetadataTokenSource: proto.TokenSourceFile}),
	})
	if !st.Satisfied {
		t.Fatalf("satisfied = false, blockers = %v", st.Blockers)
	}
	if len(st.Blockers) != 0 {
		t.Errorf("blockers = %v, want none", st.Blockers)
	}
	if st.Want != proto.TokenSourceFile || st.Key != proto.MetadataTokenSource {
		t.Errorf("key/want = %q/%q", st.Key, st.Want)
	}
}

// One node still reading the variable holds the cutover, and the blocker says
// which node and which variable — that is the whole operator-facing value of
// the fact.
func TestTokenOnFile_OneNodeStillOnTheVariable(t *testing.T) {
	v := floorVersion(t, proto.MetadataTokenSource)
	st := TokenOnFile([]*proto.Node{
		node("compute1", v, map[string]any{proto.MetadataTokenSource: proto.TokenSourceFile}),
		node("fw1", v, map[string]any{proto.MetadataTokenSource: proto.TokenSourceEnv}),
	})
	if st.Satisfied {
		t.Fatal("satisfied = true with a node still on the environment variable")
	}
	if len(st.Blockers) != 1 || !strings.Contains(st.Blockers[0], "fw1") || !strings.Contains(st.Blockers[0], "RASPUTIN_CP_JOIN_TOKEN") {
		t.Errorf("blockers = %v, want one naming fw1 and the variable", st.Blockers)
	}
}

// A node whose agent predates the key reads as "could not report", with the
// floor named, and it still blocks. The two halves matter separately: the
// operator is told to update that node, and the cutover does not fire.
func TestTokenOnFile_AgentPredatesTheKey(t *testing.T) {
	v := floorVersion(t, proto.MetadataTokenSource)
	st := TokenOnFile([]*proto.Node{
		node("compute1", v, map[string]any{proto.MetadataTokenSource: proto.TokenSourceFile}),
		node("old1", "2026.08.5-dev.130", nil),
	})
	if st.Satisfied {
		t.Fatal("satisfied = true with an unreported node")
	}
	if len(st.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(st.Nodes))
	}
	var old NodeState
	for _, n := range st.Nodes {
		if n.NodeID == "old1" {
			old = n
		}
	}
	if old.Reported || old.Satisfied {
		t.Errorf("old1 reported=%v satisfied=%v, want both false", old.Reported, old.Satisfied)
	}
	if !old.AgentPredatesKey {
		t.Error("old1 should read as predating the key")
	}
	if len(st.Blockers) != 1 || !strings.Contains(st.Blockers[0], "old1") || !strings.Contains(st.Blockers[0], v) {
		t.Errorf("blockers = %v, want one naming old1 and the floor %s", st.Blockers, v)
	}
	if !strings.Contains(st.Blockers[0], "update the node") {
		t.Errorf("blocker %q should tell the operator to update the node", st.Blockers[0])
	}
}

// An agent at or above the floor that says nothing is a fault, not an old
// agent, and the sentence has to be different — the two send an operator to
// different places.
func TestTokenOnFile_NewEnoughButSilent(t *testing.T) {
	v := floorVersion(t, proto.MetadataTokenSource)
	st := TokenOnFile([]*proto.Node{node("quiet1", v, map[string]any{})})
	if st.Satisfied {
		t.Fatal("satisfied = true with a silent node")
	}
	if st.Nodes[0].AgentPredatesKey {
		t.Error("an agent at the floor does not predate the key")
	}
	if len(st.Blockers) != 1 || strings.Contains(st.Blockers[0], "update the node") {
		t.Errorf("blockers = %v, want one that does NOT read as an old agent", st.Blockers)
	}
}

// An empty inventory is not a satisfied cutover. A control plane that knows of
// no nodes has proved nothing about the fleet, and "no counter-examples" as a
// go signal would fire in exactly the window before inventory has loaded.
func TestEmptyInventoryIsNotSatisfied(t *testing.T) {
	if st := TokenOnFile(nil); st.Satisfied {
		t.Error("an empty inventory read as satisfied")
	}
	if st := HTTPSPinned([]*proto.Node{}); st.Satisfied {
		t.Error("an empty inventory read as satisfied")
	}
}

// A nil row in the slice is skipped rather than counted as a silent node — it
// is a hole in the caller's list, not a fact about the fleet.
func TestNilNodesAreSkipped(t *testing.T) {
	v := floorVersion(t, proto.MetadataTokenSource)
	st := TokenOnFile([]*proto.Node{nil, node("compute1", v, map[string]any{proto.MetadataTokenSource: proto.TokenSourceFile}), nil})
	if !st.Satisfied {
		t.Fatalf("satisfied = false, blockers = %v", st.Blockers)
	}
	if len(st.Nodes) != 1 {
		t.Errorf("nodes = %d, want 1", len(st.Nodes))
	}
}

func TestHTTPSPinned(t *testing.T) {
	v := floorVersion(t, proto.MetadataHTTPSPinned)
	t.Run("every node pinned", func(t *testing.T) {
		st := HTTPSPinned([]*proto.Node{
			node("compute1", v, map[string]any{proto.MetadataHTTPSPinned: true}),
			node("cp1", v, map[string]any{proto.MetadataHTTPSPinned: true}),
		})
		if !st.Satisfied {
			t.Fatalf("satisfied = false, blockers = %v", st.Blockers)
		}
	})
	t.Run("a reported false blocks and is named", func(t *testing.T) {
		st := HTTPSPinned([]*proto.Node{
			node("compute1", v, map[string]any{proto.MetadataHTTPSPinned: true}),
			node("compute2", v, map[string]any{proto.MetadataHTTPSPinned: false}),
		})
		if st.Satisfied {
			t.Fatal("satisfied = true with a node reporting false")
		}
		if len(st.Blockers) != 1 || !strings.Contains(st.Blockers[0], "compute2") {
			t.Errorf("blockers = %v, want one naming compute2", st.Blockers)
		}
		if !st.Nodes[1].Reported || st.Nodes[1].Value != "false" {
			t.Errorf("compute2 = %+v, want a reported false", st.Nodes[1])
		}
	})
}

// Nodes come back sorted by id whatever order the caller listed them in, so a
// status surface and a blocker list read the same twice running.
func TestNodesAreSortedByID(t *testing.T) {
	v := floorVersion(t, proto.MetadataTokenSource)
	st := TokenOnFile([]*proto.Node{
		node("zeta", v, map[string]any{proto.MetadataTokenSource: proto.TokenSourceEnv}),
		node("alpha", v, map[string]any{proto.MetadataTokenSource: proto.TokenSourceEnv}),
		node("mid", v, map[string]any{proto.MetadataTokenSource: proto.TokenSourceEnv}),
	})
	want := []string{"alpha", "mid", "zeta"}
	for i, w := range want {
		if st.Nodes[i].NodeID != w {
			t.Fatalf("nodes = %v, want sorted %v", st.Nodes, want)
		}
		if !strings.Contains(st.Blockers[i], w) {
			t.Errorf("blocker %d = %q, want it to name %s", i, st.Blockers[i], w)
		}
	}
}

// The floor the state reports is proto's, not a copy.
func TestStateCarriesTheFloorFromProto(t *testing.T) {
	for _, key := range []string{proto.MetadataTokenSource, proto.MetadataHTTPSPinned} {
		want := floorVersion(t, key)
		var got string
		if key == proto.MetadataTokenSource {
			got = TokenOnFile(nil).Floor
		} else {
			got = HTTPSPinned(nil).Floor
		}
		if got != want {
			t.Errorf("%s: floor = %q, want %q", key, got, want)
		}
	}
}
