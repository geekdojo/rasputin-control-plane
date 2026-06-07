package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
	"github.com/oklog/ulid/v2"
)

// seedNodeWithCascade plants a node + an app deployment + a mesh device
// (+ corresponding fake Headscale row) + a firewall_state row, returning
// the node id. Used by the cascade tests so each one starts from a known
// fully-wired state.
func seedNodeWithCascade(t *testing.T, f *apiFixture, nodeID string) (appID, hsID string) {
	t.Helper()
	ctx := context.Background()

	now := time.Now().UTC()
	if err := f.inv.Insert(ctx, &proto.Node{
		ID: nodeID, Role: proto.RoleControlPlane,
		Hostname: nodeID, AgentVersion: "test",
		FirstSeen: now, LastSeen: now, Status: proto.StatusOnline,
	}); err != nil {
		t.Fatalf("seed node: %v", err)
	}

	appID = ulid.Make().String()
	if err := f.appsStore.Create(ctx, &apps.App{
		ID: appID, Name: "seed-" + nodeID,
		ComposeYAML: "version: '3'", TargetNode: nodeID,
		LastStatus: proto.AppStatusStopped,
		CreatedAt:  now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed app: %v", err)
	}

	hsID = "hs-" + nodeID
	f.meshFake.nodes[hsID] = mesh.HSNode{ID: hsID, Hostname: nodeID, User: "rasputin-operator"}
	if err := f.mesh.Store().UpsertDevice(ctx, &mesh.Device{
		HSID: hsID, User: "rasputin-operator", Hostname: nodeID,
		TailnetIP: "100.64.0.10", RasputinNodeID: nodeID, Kind: "node",
		FirstSeen: now, LastSeen: now,
	}); err != nil {
		t.Fatalf("seed mesh device: %v", err)
	}

	if err := f.fw.UpdateAfterApply(ctx, nodeID, "abc123", now); err != nil {
		t.Fatalf("seed firewall state: %v", err)
	}

	return appID, hsID
}

func TestHandleGetNodeRemovalImpact(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	appID, hsID := seedNodeWithCascade(t, f, "node-impact")

	w := f.do(t, http.MethodGet, "/api/nodes/node-impact/removal-impact", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}

	var got nodeRemovalImpact
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.NodeID != "node-impact" {
		t.Errorf("nodeId: %q", got.NodeID)
	}
	if len(got.AppIDs) != 1 || got.AppIDs[0] != appID {
		t.Errorf("appIds: %#v want [%q]", got.AppIDs, appID)
	}
	if got.MeshDeviceHSID != hsID {
		t.Errorf("meshDeviceHsId: %q want %q", got.MeshDeviceHSID, hsID)
	}
	if !got.HasFirewallState {
		t.Errorf("hasFirewallState: want true")
	}
}

func TestHandleGetNodeRemovalImpact_NotFound(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/nodes/ghost/removal-impact", "", c)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestHandleDeleteNode_CascadesAndEmitsEvents(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	appID, hsID := seedNodeWithCascade(t, f, "node-rm")

	// Subscribe to inventory + apps events so we can confirm the cascade
	// publishes what the UI websocket bridges expect.
	invSub := subscribeOne(t, f.nc, proto.InventoryChangedSubject("node-rm", "removed"))
	appSub := subscribeOne(t, f.nc, proto.AppChangeSubject(appID, proto.AppDeleted))

	w := f.do(t, http.MethodDelete, "/api/nodes/node-rm", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}

	// Body should carry the impact summary.
	var impact nodeRemovalImpact
	if err := json.Unmarshal(w.Body.Bytes(), &impact); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if impact.MeshDeviceHSID != hsID {
		t.Errorf("impact.meshDeviceHsId: %q", impact.MeshDeviceHSID)
	}

	ctx := context.Background()
	if n, err := f.inv.Get(ctx, "node-rm"); err != nil || n != nil {
		t.Errorf("inventory: want nil, got %v err=%v", n, err)
	}
	if a, err := f.appsStore.Get(ctx, appID); err != nil || a != nil {
		t.Errorf("apps: want nil, got %v err=%v", a, err)
	}
	if _, ok := f.meshFake.nodes[hsID]; ok {
		t.Errorf("headscale still has node %s", hsID)
	}
	if d, err := f.mesh.Store().GetDeviceByRasputinNodeID(ctx, "node-rm"); err != nil || d != nil {
		t.Errorf("mesh device cache: want nil, got %v err=%v", d, err)
	}
	if ns, err := f.fw.GetNodeState(ctx, "node-rm"); err != nil || (ns != nil && ns.NodeID != "") {
		t.Errorf("firewall state: want gone, got %v err=%v", ns, err)
	}

	if !invSub.wait(2 * time.Second) {
		t.Error("inventory.removed event not received")
	}
	if !appSub.wait(2 * time.Second) {
		t.Error("apps.deleted event not received")
	}
}

func TestHandleDeleteNode_NoMeshDeviceSucceeds(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	// Seed a node + an app, but no mesh enrollment.
	ctx := context.Background()
	now := time.Now().UTC()
	if err := f.inv.Insert(ctx, &proto.Node{
		ID: "node-bare", Role: proto.RoleCompute, Hostname: "node-bare",
		AgentVersion: "test", FirstSeen: now, LastSeen: now,
	}); err != nil {
		t.Fatal(err)
	}
	w := f.do(t, http.MethodDelete, "/api/nodes/node-bare", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestHandleDeleteNode_NotFound(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodDelete, "/api/nodes/ghost", "", c)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestHandleDeleteNode_HeadscaleUnreachable_LeavesDBUntouched(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	appID, _ := seedNodeWithCascade(t, f, "node-hs-fail")
	f.meshFake.deleteErr = errors.New("connection refused")

	w := f.do(t, http.MethodDelete, "/api/nodes/node-hs-fail", "", c)
	if w.Code != http.StatusBadGateway {
		t.Errorf("want 502, got %d body=%s", w.Code, w.Body.String())
	}

	ctx := context.Background()
	// Inventory, apps, mesh device cache, and firewall state must all be intact.
	if n, _ := f.inv.Get(ctx, "node-hs-fail"); n == nil {
		t.Error("inventory row was deleted despite Headscale failure")
	}
	if a, _ := f.appsStore.Get(ctx, appID); a == nil {
		t.Error("app row was deleted despite Headscale failure")
	}
	if d, _ := f.mesh.Store().GetDeviceByRasputinNodeID(ctx, "node-hs-fail"); d == nil {
		t.Error("mesh device cache was cleared despite Headscale failure")
	}
	if ns, _ := f.fw.GetNodeState(ctx, "node-hs-fail"); ns == nil || ns.NodeID == "" {
		t.Error("firewall state was cleared despite Headscale failure")
	}
}

func TestHandleDeleteNode_ReRegistrationAfterDelete(t *testing.T) {
	// Per design (no v1 blocklist), a re-registered node id should
	// produce a fresh inventory row. The cascaded apps are NOT
	// auto-restored — the operator must redeploy.
	f := newAPIFixture(t)
	c := f.authenticate(t)
	appID, _ := seedNodeWithCascade(t, f, "node-comeback")

	if w := f.do(t, http.MethodDelete, "/api/nodes/node-comeback", "", c); w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}

	ctx := context.Background()
	// Simulate the node coming back online by inserting a fresh row the
	// way the inventory.Service.handleRegistered path would.
	now := time.Now().UTC()
	if err := f.inv.Insert(ctx, &proto.Node{
		ID: "node-comeback", Role: proto.RoleControlPlane, Hostname: "node-comeback",
		AgentVersion: "test", FirstSeen: now, LastSeen: now,
	}); err != nil {
		t.Fatalf("re-insert: %v", err)
	}

	if n, _ := f.inv.Get(ctx, "node-comeback"); n == nil {
		t.Error("re-registered node should exist in inventory")
	}
	if a, _ := f.appsStore.Get(ctx, appID); a != nil {
		t.Error("apps must not auto-resurrect after node removal")
	}
}

// subscription is a tiny one-shot NATS subscriber used to assert that the
// cascade emits the expected event subjects.
type subscription struct {
	mu  sync.Mutex
	got bool
	ch  chan struct{}
	sub *nats.Subscription
}

func subscribeOne(t *testing.T, nc *nats.Conn, subject string) *subscription {
	t.Helper()
	s := &subscription{ch: make(chan struct{}, 1)}
	sub, err := nc.Subscribe(subject, func(_ *nats.Msg) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.got {
			s.got = true
			close(s.ch)
		}
	})
	if err != nil {
		t.Fatalf("subscribe %s: %v", subject, err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	s.sub = sub
	return s
}

func (s *subscription) wait(d time.Duration) bool {
	select {
	case <-s.ch:
		return true
	case <-time.After(d):
		return false
	}
}
