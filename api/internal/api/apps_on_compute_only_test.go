package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Apps run on COMPUTE nodes only.
//
// The controlplane node is refused because rasputin-api owns :443 there (the OS
// image's unit sets RASPUTIN_HTTPS_ADDR=:443, the wildcard), so the node-local
// Caddy that fronts apps can never bind the port it needs. None of that is
// visible from a deploy: the leaf is delivered, the saga logs "delivered TLS
// leaf + proxy route", the app reports RUNNING, and its name resolves to the
// control plane and serves the control plane's own cert and its 404. Measured
// on e3bench 2026-08-23 with a 12s deploy that never went near a timeout.
//
// So the install has to fail where the operator is standing, not five minutes
// later as an app that looks healthy and answers nothing.
func TestInstall_RefusesTheControlplaneNode(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "cp-1", Role: proto.RoleControlPlane, Hostname: "cp", Architecture: "amd64",
	}); err != nil {
		t.Fatalf("seed controlplane node: %v", err)
	}

	w := f.do(t, http.MethodPost, "/api/catalog/jellyfin/install", `{"targetNode":"cp-1"}`, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("install to controlplane: want 400, got %d (%s)", w.Code, w.Body.String())
	}
	// The operator has to learn WHY, or they will just try again.
	if !strings.Contains(w.Body.String(), "compute nodes only") {
		t.Errorf("refusal should say apps are compute-only, got %s", w.Body.String())
	}
}

func TestCreateApp_RefusesTheControlplaneNode(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "cp-1", Role: proto.RoleControlPlane, Hostname: "cp", Architecture: "amd64",
	}); err != nil {
		t.Fatalf("seed controlplane node: %v", err)
	}

	body := `{"name":"custom","composeYaml":"services: {}","targetNode":"cp-1"}`
	w := f.do(t, http.MethodPost, "/api/apps", body, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("hand-authored app on controlplane: want 400, got %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "compute nodes only") {
		t.Errorf("refusal should say apps are compute-only, got %s", w.Body.String())
	}
}

// The refusal must not have cost us the case it exists to allow. A compute node
// still installs — otherwise "compute only" would read as "nowhere".
func TestInstall_StillAcceptsACompatibleComputeNode(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "pi-1", Role: proto.RoleCompute, Hostname: "pi", Architecture: "arm64",
	}); err != nil {
		t.Fatalf("seed compute node: %v", err)
	}

	w := f.do(t, http.MethodPost, "/api/catalog/jellyfin/install", `{"targetNode":"pi-1"}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("install to compute: want 201, got %d (%s)", w.Code, w.Body.String())
	}
}
