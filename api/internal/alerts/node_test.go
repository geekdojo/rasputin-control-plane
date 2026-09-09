package alerts

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// meshOnline wires a membership lookup that reports the given nodes' devices
// online, seen at the given time.
func (f *fixture) meshOnline(seen time.Time, ids ...string) {
	f.svc.SetMeshMembership(func(context.Context) map[string]*proto.MeshMembership {
		out := map[string]*proto.MeshMembership{}
		for _, id := range ids {
			ls := seen
			out[id] = &proto.MeshMembership{State: proto.MeshJoined, Enrolled: true, Online: true, LastSeen: &ls}
		}
		return out
	})
}

// A lapsed node whose mesh device is online: the node-offline alert becomes
// OFF BUS — same id (it replaces, it does not duplicate), same severity, and
// the detail names both facts and the action (geekdojo/geekdojo-brain#401).
func TestNodeAlerts_OffBusReplacesOfflineUnderTheSameID(t *testing.T) {
	f := newFixture(t)
	f.insertNode(t, "compute2", 3*time.Hour)
	f.markSetupComplete(t)
	f.meshOnline(time.Now().Add(-40*time.Second), "compute2")

	alerts, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("want exactly one node alert (no duplicate), got %d: %+v", len(alerts), alerts)
	}
	got := alerts[0]
	if got.ID != "node-offline:compute2" {
		t.Errorf("id: want node-offline:compute2 (same id as OFFLINE), got %q", got.ID)
	}
	if got.Severity != proto.AlertCrit {
		t.Errorf("severity: want crit (what node-offline uses), got %q", got.Severity)
	}
	if got.Title != "Node compute2 is OFF BUS" {
		t.Errorf("title: %q", got.Title)
	}
	for _, want := range []string{"Reachable over the mesh", "seen 40s ago", "has not heartbeated for 3h", "restart the agent"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("detail %q lacks %q", got.Detail, want)
		}
	}
	if strings.Contains(strings.ToLower(got.Title), "offline") {
		t.Errorf("title %q must not say offline", got.Title)
	}
}

// Both down — heartbeat lapsed, mesh device not online — keeps the OFFLINE
// wording. And a mesh that reports the device online but has aged out
// (Online false, State joined) is the same case: not vouched for.
func TestNodeAlerts_BothDownKeepsOfflineWording(t *testing.T) {
	for _, tc := range []struct {
		name string
		mesh *proto.MeshMembership
	}{
		{"device not online", &proto.MeshMembership{State: proto.MeshAbsent, Enrolled: true}},
		{"observation aged out", &proto.MeshMembership{State: proto.MeshJoined, Enrolled: true, Online: false}},
		{"never enrolled", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.insertNode(t, "compute3", 3*time.Hour)
			f.markSetupComplete(t)
			f.svc.SetMeshMembership(func(context.Context) map[string]*proto.MeshMembership {
				m := map[string]*proto.MeshMembership{}
				if tc.mesh != nil {
					m["compute3"] = tc.mesh
				}
				return m
			})
			alerts, err := f.svc.List(f.ctx)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			got, ok := find(alerts, "node-offline:compute3")
			if !ok || len(alerts) != 1 {
				t.Fatalf("want one node-offline:compute3 alert, got %+v", alerts)
			}
			if got.Title != "Node compute3 is offline" || !strings.HasPrefix(got.Detail, "Last heartbeat ") {
				t.Errorf("want the OFFLINE wording, got %q / %q", got.Title, got.Detail)
			}
		})
	}
}

// A node with a live heartbeat is unaffected by the mesh, and a stale one
// stays a stale warn whatever the mesh says.
func TestNodeAlerts_LiveAndStaleAreUnaffectedByMesh(t *testing.T) {
	f := newFixture(t)
	f.insertNode(t, "live", 5*time.Second)
	f.insertNode(t, "stale", 60*time.Second)
	f.markSetupComplete(t)
	f.meshOnline(time.Now(), "live", "stale")

	alerts, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("want only the stale warn, got %+v", alerts)
	}
	if got := alerts[0]; got.ID != "node-stale:stale" || got.Severity != proto.AlertWarn {
		t.Errorf("got %+v", got)
	}
}
