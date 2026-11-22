package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalogsync"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// assertReservedSentence checks the coded body every reserved-name refusal
// carries: the code, and a sentence that names the name and the reason.
func assertReservedSentence(t *testing.T, body []byte, name string) {
	t.Helper()
	c := decodeCoded(t, body)
	if c.Code != codeAppNameReserved {
		t.Errorf("code = %q, want %q (body %s)", c.Code, codeAppNameReserved, body)
	}
	msg := c.Error
	if msg == "" || msg[0] < 'A' || msg[0] > 'Z' || !strings.HasSuffix(msg, ".") ||
		!strings.Contains(msg, " "+name+" ") || !strings.Contains(msg, "kept for the cluster's sign-in addresses") {
		t.Errorf("message %q is not the reserved-name sentence for %s", msg, name)
	}
}

// TC-983-04: reserved app names are refused with app_name_reserved and a
// sentence, through POST /api/apps and a catalog install, and no row is
// written; names that merely contain the label are accepted.
func TestReservedAppNames_AreRefused(t *testing.T) {
	f, cookie, _ := gateFixture(t)
	for in, name := range map[string]string{"radius": "radius", "signin": "signin", "SIGNIN": "signin"} {
		w := f.do(t, http.MethodPost, "/api/apps", createRequest(in, "services: {}\n", ""), cookie)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("create %s = %d %s, want 400", in, w.Code, w.Body.String())
		}
		assertReservedSentence(t, w.Body.Bytes(), name)
	}
	for _, name := range []string{"radius", "signin"} {
		w := f.do(t, http.MethodPost, "/api/catalog/jellyfin/install", `{"targetNode":"n1","name":"`+name+`"}`, cookie)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("install as %s = %d %s, want 400", name, w.Code, w.Body.String())
		}
		assertReservedSentence(t, w.Body.Bytes(), name)
	}
	list, err := f.appsStore.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("refused names wrote %d rows", len(list))
	}
	for _, ok := range []string{"signin2", "my-signin"} {
		w := f.do(t, http.MethodPost, "/api/apps", createRequest(ok, "services: {}\n", ""), cookie)
		if w.Code != http.StatusCreated {
			t.Errorf("create %s = %d %s, want 201", ok, w.Code, w.Body.String())
		}
	}
}

// TC-983-13: a join token for a reserved node id is refused with a sentence
// and stores nothing, while the bus's own node-id check still admits an
// existing node of that name.
func TestMintBusToken_RefusesReservedNodeIDs(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	for _, id := range []string{"signin", "radius"} {
		w := f.do(t, http.MethodPost, "/api/bus/tokens", fmt.Sprintf(`{"role":"compute","label":"t","nodeId":"%s"}`, id), cookie)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("mint %s = %d %s, want 400", id, w.Code, w.Body.String())
		}
		if body := w.Body.String(); !strings.Contains(body, "The node id "+id+" is kept for the cluster's sign-in addresses") {
			t.Errorf("mint %s body %s does not name the id and the rule", id, body)
		}
	}
	tokens, err := f.srv.busTokens.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 0 {
		t.Fatalf("refused mints stored %d tokens", len(tokens))
	}
	if !busauth.ValidNodeID("signin") || !busauth.ValidNodeID("radius") {
		t.Error("ValidNodeID refuses a reserved id: an existing node would be locked out")
	}
}

// capturingRecords records the projection the mesh service writes.
type capturingRecords struct {
	mesh.NoopSupervisor
	got   map[string]string
	calls int
}

func (c *capturingRecords) ReconcileAppRecords(m map[string]string) error {
	c.got, c.calls = m, c.calls+1
	return nil
}

// doorMesh swaps the fixture's mesh service for one with the app door
// configured, SelfNodeID n1, over the same store and fake Headscale, and binds
// n1's device hs-cp at 100.64.0.5.
func doorMesh(t *testing.T, f *apiFixture) *capturingRecords {
	t.Helper()
	sup := &capturingRecords{}
	svc := mesh.NewService(mesh.Config{
		ClusterID: "bench", AppDoorHost: proto.SignInFQDN("bench"), SelfNodeID: "n1",
		AppDoorWithheld: func() bool { return false },
	}, f.mesh.Store(), f.meshFake, sup)
	svc.SetAppLister(func() []mesh.AppDNS { return nil })
	f.srv.mesh = svc
	now := time.Now().UTC()
	f.meshFake.nodes["hs-cp"] = mesh.HSNode{ID: "hs-cp", Hostname: "n1"}
	if _, err := f.mesh.Store().BindDevice(context.Background(), &mesh.Device{
		HSID: "hs-cp", Hostname: "n1", RasputinNodeID: "n1", TailnetIP: "100.64.0.5", Kind: "rasputin",
		Tags: []string{}, AdvertisedRoutes: []string{}, FirstSeen: now, LastSeen: now,
	}, "j1"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := svc.ReconcileAppDNS(context.Background()); err != nil || sup.got["signin.bench.internal"] != "100.64.0.5" {
		t.Fatalf("door not projected before the delete: %v %v", sup.got, err)
	}
	return sup
}

// TC-983-08 (delete half): removing the control plane's device through
// DELETE /api/mesh/devices/{hsId}, or through the node-delete cascade, writes
// a projection without the door entry, with no reconcile tick.
func TestDeviceDelete_DropsTheAppDoor(t *testing.T) {
	t.Run("mesh device delete", func(t *testing.T) {
		f := newAPIFixture(t)
		c := f.authenticate(t)
		sup := doorMesh(t, f)
		before := sup.calls
		if w := f.do(t, http.MethodDelete, "/api/mesh/devices/hs-cp", "", c); w.Code != http.StatusNoContent {
			t.Fatalf("delete = %d %s", w.Code, w.Body.String())
		}
		if sup.calls != before+1 {
			t.Fatalf("projection writes = %d, want one more than %d", sup.calls, before)
		}
		if _, ok := sup.got["signin.bench.internal"]; ok {
			t.Errorf("door still projected: %v", sup.got)
		}
	})
	t.Run("node delete cascade", func(t *testing.T) {
		f := newAPIFixture(t)
		c := f.authenticate(t)
		now := time.Now().UTC()
		if err := f.inv.Insert(f.ctx, &proto.Node{ID: "n1", Role: proto.RoleCompute, Hostname: "n1", FirstSeen: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
		sup := doorMesh(t, f)
		before := sup.calls
		if w := f.do(t, http.MethodDelete, "/api/nodes/n1", "", c); w.Code != http.StatusOK {
			t.Fatalf("delete node = %d %s", w.Code, w.Body.String())
		}
		if sup.calls != before+1 {
			t.Fatalf("projection writes = %d, want one more than %d", sup.calls, before)
		}
		if _, ok := sup.got["signin.bench.internal"]; ok {
			t.Errorf("door still projected: %v", sup.got)
		}
	})
}

// TC-983-14 (route half): a reserved tile in a catalog the cluster loads is
// not served: GET /api/catalog/signin and /api/catalog/radius answer 404
// while jellyfin answers.
func TestCatalogTile_ReservedIDIsNotServed(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	b := gateTileBundle(7)
	b.Tiles = append(b.Tiles, oneTileBundle(7, "signin").Tiles[0], oneTileBundle(7, "radius").Tiles[0])
	cat, err := catalogsync.New(t.TempDir(), stubVerifier{}, b)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetCatalogSync(cat, nil)
	for id, want := range map[string]int{"jellyfin": http.StatusOK, "signin": http.StatusNotFound, "radius": http.StatusNotFound} {
		if w := f.do(t, http.MethodGet, "/api/catalog/"+id, "", cookie); w.Code != want {
			t.Errorf("GET /api/catalog/%s = %d, want %d", id, w.Code, want)
		}
	}
}
