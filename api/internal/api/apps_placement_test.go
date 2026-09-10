package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// design/storage.md §6.4's placement, on the api side.
//
// The api's job here is narrow and it is not the enforcement: §6.3 makes the
// marker on the platter the enforcement, and only the agent can read it. What
// the api owns is refusing a placement that could never work, at the moment the
// operator chooses it — because the alternative is a deploy job that fails on a
// node minutes later, for a reason nobody standing at the install screen could
// have seen.

// A node that cannot hold a data disk cannot host an app placed on one, and the
// refusal happens BEFORE the app is recorded.
//
// Every compute node is such a node today: the agent registers the storage
// verbs on the controlplane and storage roles only, so a data claim addressed
// to a compute node reaches no responder. Apps run on compute nodes only. So
// this is currently the answer for every placement, and that is the honest
// state of the contract rather than a bug in this test — see
// api/internal/storage.CanHoldTarget's header for the two moves that change it.
func TestInstall_RefusesAPlacementOnANodeThatHasNoDataDisk(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "pi-1", Role: proto.RoleCompute, Hostname: "pi", Architecture: "arm64",
	}); err != nil {
		t.Fatalf("seed compute node: %v", err)
	}

	w := f.do(t, http.MethodPost, "/api/catalog/jellyfin/install",
		`{"targetNode":"pi-1","dataDiskPartUuid":"9d0f4a2b-01"}`, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("placed install: want 400, got %d (%s)", w.Code, w.Body.String())
	}
	// The refusal is CanHoldTarget's sentence, so the installer and the disk
	// picker tell the operator one story rather than two.
	if !strings.Contains(w.Body.String(), "cannot hold app data") {
		t.Errorf("refusal should be the eligibility rule's own words, got %s", w.Body.String())
	}

	// Refused before it was recorded: nothing was created that a later deploy
	// could act on.
	if app, _ := f.appsStore.GetByName(f.ctx, "jellyfin"); app != nil {
		t.Errorf("a refused placement was still recorded: %+v", app)
	}
}

func TestCreateApp_RefusesAPlacementOnANodeThatHasNoDataDisk(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "pi-1", Role: proto.RoleCompute, Hostname: "pi", Architecture: "arm64",
	}); err != nil {
		t.Fatalf("seed compute node: %v", err)
	}

	body := `{"name":"custom","composeYaml":"services: {}","targetNode":"pi-1","dataDiskPartUuid":"9d0f4a2b-01"}`
	w := f.do(t, http.MethodPost, "/api/apps", body, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("placed custom app: want 400, got %d (%s)", w.Code, w.Body.String())
	}
	if app, _ := f.appsStore.GetByName(f.ctx, "custom"); app != nil {
		t.Errorf("a refused placement was still recorded: %+v", app)
	}
}

// A partition UUID is how a data disk is addressed (§6.2) and nothing else is.
// The value becomes a path segment on the node, so a shape that is not one is
// refused at the door as well as on the node.
func TestCreateApp_RefusesAPlacementThatIsNotAPartitionUUID(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "pi-1", Role: proto.RoleCompute, Hostname: "pi", Architecture: "arm64",
	}); err != nil {
		t.Fatalf("seed compute node: %v", err)
	}

	body := `{"name":"custom","composeYaml":"services: {}","targetNode":"pi-1","dataDiskPartUuid":"../../etc"}`
	w := f.do(t, http.MethodPost, "/api/apps", body, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "not a partition UUID") {
		t.Errorf("refusal should name the addressing rule, got %s", w.Body.String())
	}
}

// The refusal must not have cost the default. An app with NO placement installs
// exactly as it always has — that is every app in every existing cluster, and
// §6.4's opt-in is worth nothing if opting out stopped working.
func TestInstall_UnplacedAppIsUnaffected(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "pi-1", Role: proto.RoleCompute, Hostname: "pi", Architecture: "arm64",
	}); err != nil {
		t.Fatalf("seed compute node: %v", err)
	}

	w := f.do(t, http.MethodPost, "/api/catalog/jellyfin/install", `{"targetNode":"pi-1"}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("unplaced install: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	var got apps.App
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.DataDiskPartUUID != "" {
		t.Errorf("an unplaced install recorded a placement: %q", got.DataDiskPartUUID)
	}

	// And the deploy route's gate has nothing to say about it. Asserted on the
	// rule rather than on the route's status code, because this fixture's job
	// runner registers no app.deploy kind — a 202 here would be testing the
	// runner, and the thing that must not have changed is the gate.
	node, err := f.inv.Get(f.ctx, "pi-1")
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if refusal := dataPlacementRefusal(node, got.DataDiskPartUUID); refusal != "" {
		t.Errorf("an unplaced app was refused at deploy: %q", refusal)
	}
}

// The deploy route re-checks, because the one input the rule depends on — the
// target node's role — is inventory state that can change after an app is
// recorded. A placement recorded when it was legal must not silently become a
// job that fails on the agent.
func TestDeployApp_RefusesAPlacementTheNodeCanNoLongerHonour(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "pi-1", Role: proto.RoleCompute, Hostname: "pi", Architecture: "arm64",
	}); err != nil {
		t.Fatalf("seed compute node: %v", err)
	}
	// Seeded through the store rather than the install route, because the
	// install route is exactly what refuses this today — which is the point:
	// the deploy gate has to stand on its own, for a row that got past the
	// install gate under a different inventory.
	app := &apps.App{
		ID: "01J6ZK3Q9V8XKX2M5TQ7R4A9BF", Name: "placed", ComposeYAML: "services: {}",
		TargetNode: "pi-1", DataDiskPartUUID: "9d0f4a2b-01", LastStatus: proto.AppStatusStopped,
	}
	if err := f.appsStore.Create(f.ctx, app); err != nil {
		t.Fatalf("seed app: %v", err)
	}

	w := f.do(t, http.MethodPost, "/api/apps/"+app.ID+"/deploy", "", cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("placed deploy: want 400, got %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "cannot hold app data") {
		t.Errorf("refusal should be the eligibility rule's own words, got %s", w.Body.String())
	}
}

// A placement onto an eligible node is RECORDED and reaches the deploy path.
// The eligible roles are the controlplane and the storage role (§6, and
// CanHoldTarget), and no app can target either today — so this exercises the
// rule directly rather than through a route that would refuse for a different
// reason first, and it is what proves the api's gate is about the DISK and not
// a second spelling of "apps are compute-only".
func TestDataPlacementRefusal_AcceptsANodeThatCanHoldADataDisk(t *testing.T) {
	for _, role := range []proto.NodeRole{proto.RoleControlPlane, proto.RoleStorage} {
		node := &proto.Node{ID: "n-1", Role: role, Hostname: "shelf"}
		if refusal := dataPlacementRefusal(node, "9d0f4a2b-01"); refusal != "" {
			t.Errorf("role %s should be able to hold a data disk, got %q", role, refusal)
		}
	}
	// No placement is always allowed, on every node and with no node at all —
	// it means the boot medium.
	if refusal := dataPlacementRefusal(&proto.Node{ID: "n-1", Role: proto.RoleCompute}, ""); refusal != "" {
		t.Errorf("an unplaced app should never be refused, got %q", refusal)
	}
	if refusal := dataPlacementRefusal(nil, ""); refusal != "" {
		t.Errorf("an unplaced app should never be refused, got %q", refusal)
	}
}
