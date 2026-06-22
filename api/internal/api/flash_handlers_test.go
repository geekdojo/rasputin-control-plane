package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

func TestGetFlashScript(t *testing.T) {
	f := newAPIFixture(t)
	rec := f.do(t, http.MethodGet, "/flash.sh", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/x-shellscript") {
		t.Errorf("content-type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"rasputin flash.sh", "RASPUTIN_SEED_B64", "read-back"} {
		if !strings.Contains(body, want) {
			t.Errorf("flash.sh missing %q", want)
		}
	}
}

func TestClusterNodeImage(t *testing.T) {
	const version = "2026.06.0-dev.31"
	const img = "rasputin-os-n100-2026.06.0-dev.31.img.xz"
	const sha = "6b88e011deadbeef"

	mux := http.NewServeMux()
	mux.HandleFunc("/geekdojo/rasputin-releases/releases/download/os-"+version+"/manifest.json",
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(releases.Manifest{
				Version: version,
				Artifacts: []releases.ManifestArtifact{{
					Compatible: "rasputin-n100", Image: img, ImageSha256: sha,
				}},
			})
		})
	rel := httptest.NewServer(mux)
	defer rel.Close()

	f := newAPIFixture(t)
	f.srv.SetReleaseRepo("geekdojo/rasputin-releases", rel.URL)

	// 503 until a controlplane node has reported its OS version.
	if rec := f.do(t, http.MethodGet, "/api/cluster/node-image", "", nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 before cp version known, got %d", rec.Code)
	}

	if err := f.inv.Insert(f.ctx, &proto.Node{ID: "x", Role: proto.RoleControlPlane, ImageVersion: version}); err != nil {
		t.Fatalf("seed cp node: %v", err)
	}

	rec := f.do(t, http.MethodGet, "/api/cluster/node-image", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	var desc releases.NodeImageDescriptor
	if err := json.Unmarshal(rec.Body.Bytes(), &desc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if desc.Version != version || desc.SHA256 != sha {
		t.Fatalf("descriptor = %+v", desc)
	}
	if !strings.HasSuffix(desc.URL, "/os-"+version+"/"+img) {
		t.Fatalf("url = %q", desc.URL)
	}
}
