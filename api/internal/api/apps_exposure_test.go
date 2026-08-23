package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// PATCH /api/apps/{id} is the reverse edge LAN exposure never had (#197):
// before it, revoking LAN reachability meant DELETING the app, so any tile
// with volumes forced a choice between the LAN and its data.
func TestApps_ExposureIsRevocableInPlace(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	app := &apps.App{
		ID: "app-1", Name: "kuma", ComposeYAML: "services: {}", TargetNode: "n1",
		PublishedPort: 3001, ExposeLAN: true,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := f.appsStore.Create(f.ctx, app); err != nil {
		t.Fatal(err)
	}

	w := f.do(t, http.MethodPatch, "/api/apps/app-1", `{"exposeLan":false}`, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}

	got, err := f.appsStore.Get(f.ctx, "app-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ExposeLAN {
		t.Fatal("exposeLan must be false after the patch — this is the whole point of #197")
	}
	// And the record the caller got back agrees, so a UI that trusts the
	// response body does not show a stale toggle.
	var body apps.App
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.ExposeLAN {
		t.Fatal("response body still reports exposeLan true")
	}

	// And back on again — the direction that needs friction is the grant, but
	// neither direction may need a delete.
	w = f.do(t, http.MethodPatch, "/api/apps/app-1", `{"exposeLan":true}`, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("re-grant: want 200, got %d (%s)", w.Code, w.Body.String())
	}
	if got, _ := f.appsStore.Get(f.ctx, "app-1"); !got.ExposeLAN {
		t.Fatal("exposeLan must be true after re-granting")
	}
}

// Only exposeLan is patchable. The compose was signed and installed; an
// exposure toggle has no business rewriting it, and a general "update the app"
// route is how it would grow the ability to.
func TestApps_PatchRejectsEverythingElse(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	app := &apps.App{
		ID: "app-2", Name: "kuma", ComposeYAML: "signed: original", TargetNode: "n1",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := f.appsStore.Create(f.ctx, app); err != nil {
		t.Fatal(err)
	}

	// A body naming only unknown fields changes nothing and says so, rather
	// than reporting success for a no-op the caller thinks it made.
	w := f.do(t, http.MethodPatch, "/api/apps/app-2", `{"composeYaml":"evil: yes","name":"other"}`, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for a body with nothing patchable, got %d (%s)", w.Code, w.Body.String())
	}
	got, _ := f.appsStore.Get(f.ctx, "app-2")
	if got.ComposeYAML != "signed: original" || got.Name != "kuma" {
		t.Fatalf("patch must not touch compose or name, got %+v", got)
	}

	if w := f.do(t, http.MethodPatch, "/api/apps/app-2", `not json`, cookie); w.Code != http.StatusBadRequest {
		t.Errorf("malformed body: want 400, got %d", w.Code)
	}
	if w := f.do(t, http.MethodPatch, "/api/apps/nope", `{"exposeLan":true}`, cookie); w.Code != http.StatusNotFound {
		t.Errorf("unknown app: want 404, got %d", w.Code)
	}
}

// The .lan name is a SAN in the app's TLS leaf and a route on the proxy's LAN
// listener, so a database flip alone leaves the name resolving. The patch must
// run the app's leaf rotation immediately rather than waiting for the sweep.
func TestApps_ExposureChangeRotatesTheLeaf(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	app := &apps.App{
		ID: "app-3", Name: "kuma", ComposeYAML: "services: {}", TargetNode: "n1",
		PublishedPort: 3001, ExposeLAN: true,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := f.appsStore.Create(f.ctx, app); err != nil {
		t.Fatal(err)
	}

	var sawExpose []bool
	f.srv.SetAppLeafRotator(func(a *apps.App) (proto.AppLeafCmd, bool, func() error, error) {
		sawExpose = append(sawExpose, a.ExposeLAN)
		// renewed=false: nothing to ship, so the handler needs no online node.
		// What is being asserted is that the rotator is CONSULTED with the new
		// exposure, which is the input its SAN drift check reads.
		return proto.AppLeafCmd{}, false, func() error { return nil }, nil
	})

	if w := f.do(t, http.MethodPatch, "/api/apps/app-3", `{"exposeLan":false}`, cookie); w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}
	if len(sawExpose) != 1 {
		t.Fatalf("rotator should be consulted exactly once, got %d calls", len(sawExpose))
	}
	if sawExpose[0] {
		t.Fatal("rotator was handed the OLD exposure — the leaf would keep the .lan SAN")
	}

	// A no-op patch must not churn the leaf. Re-minting a cert to change
	// nothing is a needless re-ship to the node.
	sawExpose = nil
	if w := f.do(t, http.MethodPatch, "/api/apps/app-3", `{"exposeLan":false}`, cookie); w.Code != http.StatusOK {
		t.Fatalf("no-op patch: want 200, got %d", w.Code)
	}
	if len(sawExpose) != 0 {
		t.Fatalf("a no-op patch must not touch the leaf, got %d calls", len(sawExpose))
	}
}

// A rotator error must not lose the exposure change. The record is already
// authoritative for DNS and the rotation sweep is the backstop for the proxy
// half, so the caller is warned rather than told the revocation failed —
// reporting failure would invite a retry that cannot help.
func TestApps_ExposureSurvivesALeafFailure(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	app := &apps.App{
		ID: "app-4", Name: "kuma", ComposeYAML: "services: {}", TargetNode: "n1",
		PublishedPort: 3001, ExposeLAN: true,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := f.appsStore.Create(f.ctx, app); err != nil {
		t.Fatal(err)
	}
	f.srv.SetAppLeafRotator(func(_ *apps.App) (proto.AppLeafCmd, bool, func() error, error) {
		return proto.AppLeafCmd{}, false, nil, context.DeadlineExceeded
	})

	w := f.do(t, http.MethodPatch, "/api/apps/app-4", `{"exposeLan":false}`, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 with a warning, got %d (%s)", w.Code, w.Body.String())
	}
	if !jsonHas(w.Body.Bytes(), "leafWarning") {
		t.Errorf("a leaf failure must be surfaced, got %s", w.Body.String())
	}
	if got, _ := f.appsStore.Get(f.ctx, "app-4"); got.ExposeLAN {
		t.Fatal("the exposure change must persist even when the leaf could not be re-shipped")
	}
}

func jsonHas(b []byte, key string) bool {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}
