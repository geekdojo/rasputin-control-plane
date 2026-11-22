package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
)

// A custom app's route (geekdojo/geekdojo-brain#1094): an app with no catalog
// tile that declared a web port gets the route a tile gets, and the .lan. name
// only while it is exposed to the LAN.
//
// The exposed-at-create case is TC-1089-16
// (TestCreateApp_WebPortReachesTheFirstDeploysLeaf, apps_webport_test.go).
// Turning exposure on or off later is not re-proved here: the PATCH handler
// passing the new exposure to the rotator is
// TestApps_ExposureChangeRotatesTheLeaf (apps_exposure_test.go), and the
// rotated leaf reaching the node with or without the .lan. name is
// TestRotateAppLeaf_RevokingExposureReachesTheNode
// (api/internal/apps/leaf_exposure_test.go).

// TC-1094-01: a custom app that is not exposed gets only the tailnet route,
// carrying its declared port over plain HTTP.
func TestCreateApp_TailnetOnlyCustomAppGetsOnlyTheTailnetRoute(t *testing.T) {
	f := newWebPortFixture(t)
	compose := `services: {web: {image: me/web:1, ports: ["127.0.0.1:8080:80"]}}` + "\n"
	body := strings.Replace(createRequest("web", compose, "8080"), `"exposeLan":true`, `"exposeLan":false`, 1)
	if !strings.Contains(body, `"exposeLan":false`) {
		t.Fatalf("request %s does not turn exposure off", body)
	}
	w := f.do(t, http.MethodPost, "/api/apps", body, f.cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	id := decodeBody[apps.App](t, w.Body.String()).ID

	row := f.row(t, id)
	if row.SourceTile != "" || row.PublishedPort != 8080 || row.ExposeLAN {
		t.Fatalf("stored row: tile %q, port %d, exposeLan %v; want no tile, 8080, false",
			row.SourceTile, row.PublishedPort, row.ExposeLAN)
	}

	d := f.do(t, http.MethodPost, "/api/apps/"+id+"/deploy", "", f.cookie)
	if d.Code != http.StatusAccepted {
		t.Fatalf("deploy: %d %s", d.Code, d.Body.String())
	}
	j := f.runJob(t, d.Body.String())
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("deploy %s: %s", j.Status, j.Error)
	}
	if log := f.jobLog(t, j.ID); strings.Contains(log, "no published port") {
		t.Fatalf("leaf step skipped:\n%s", log)
	}

	tailnet, _ := mesh.AppRouteHosts(webPortCluster, "web", false)
	if want := "web." + webPortCluster + ".internal"; tailnet != want {
		t.Fatalf("AppRouteHosts tailnet name %q, want %q", tailnet, want)
	}
	cmd := f.leaf(t)
	if cmd.TailnetFQDN != tailnet {
		t.Errorf("TailnetFQDN = %q, want %q", cmd.TailnetFQDN, tailnet)
	}
	if cmd.LANFQDN != "" {
		t.Errorf("LANFQDN = %q, want none: the app is not exposed to the LAN", cmd.LANFQDN)
	}
	if cmd.UpstreamPort != 8080 {
		t.Errorf("UpstreamPort = %d, want 8080", cmd.UpstreamPort)
	}
	if cmd.UpstreamTLS {
		t.Error("UpstreamTLS = true, want plain HTTP for a custom app")
	}
	select {
	case extra := <-f.leaves:
		t.Errorf("a second leaf reached n1: %+v", extra)
	default:
	}
}
