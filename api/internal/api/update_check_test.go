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

// fakeReleaseServer serves a GitHub-Releases-shaped API plus the manifest and
// bundle assets, so the github public source can be exercised end-to-end with
// RASPUTIN_RELEASE_API_BASE pointed at it.
func fakeReleaseServer(t *testing.T, bundle []byte, bundleSHA string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var base string // set after the server starts so asset URLs are absolute

	mux.HandleFunc("/repos/geekdojo/rasputin-releases/releases", func(w http.ResponseWriter, r *http.Request) {
		rels := []map[string]any{
			{
				"tag_name": "os-2026.06.0-dev.99", "prerelease": true,
				"assets": []map[string]any{
					{"name": "manifest.json", "browser_download_url": base + "/os-manifest"},
					{"name": "bundle.raspbundle", "browser_download_url": base + "/os-asset"},
				},
			},
			{
				"tag_name": "fw-2026.07.1-dev.20", "prerelease": true,
				"assets": []map[string]any{
					{"name": "manifest.json", "browser_download_url": base + "/fw-manifest"},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(rels)
	})
	mux.HandleFunc("/os-manifest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(releases.Manifest{
			Version: "2026.06.0-dev.99", Channel: "dev",
			Artifacts: []releases.ManifestArtifact{{
				SKU: "n100", Architecture: "amd64", Compatible: "rasputin-n100",
				Raucb: "bundle.raspbundle", SHA256: bundleSHA, SizeBytes: int64(len(bundle)),
				SignedBy: "Rasputin Release 2026.06.0-dev.99",
			}},
		})
	})
	mux.HandleFunc("/fw-manifest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(releases.Manifest{
			Version: "2026.07.1-dev.20", Channel: "dev",
			Artifacts: []releases.ManifestArtifact{{
				SKU: "fw-n100", Architecture: "amd64", Compatible: "rasputin-fw-n100", Kind: "combined-efi",
				Image: "rasputin-fw-n100-2026.07.1-dev.20-combined-efi.img.gz", SHA256: "deadbeef",
			}},
		})
	})
	mux.HandleFunc("/os-asset", func(w http.ResponseWriter, r *http.Request) {
		w.Write(bundle)
	})

	srv := httptest.NewServer(mux)
	base = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckAndPullUpdate(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	bundle, sha := buildBundleFixture(t, f) // also installs a real root CA on f.srv

	rel := fakeReleaseServer(t, bundle, sha)
	f.srv.SetReleaseSource(releases.NewGithubPublicSource(rel.URL, "geekdojo/rasputin-releases"), "dev")

	// Seed inventory: a controlplane node on an older OS, a firewall node.
	_ = f.inv.Insert(f.ctx, &proto.Node{ID: "x", Role: proto.RoleControlPlane, ImageVersion: "2026.06.0-dev.20", AgentVersion: "v0.8.4"})
	_ = f.inv.Insert(f.ctx, &proto.Node{ID: "n", Role: proto.RoleFirewall, ImageVersion: "2026.07.0"})

	// --- check ---
	rec := f.do(t, http.MethodPost, "/api/updates/check", `{"channel":"dev"}`, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("check: status %d, body %s", rec.Code, rec.Body.String())
	}
	var res releases.CheckResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode check: %v", err)
	}
	byID := map[string]releases.ComponentStatus{}
	for _, cs := range res.Components {
		byID[cs.Component] = cs
	}
	if os := byID["os"]; os.Status != releases.StatusUpdateAvailable || os.BundleSHA256 != sha || os.Staged {
		t.Fatalf("os check unexpected: %+v", os)
	}
	if fw := byID["fw"]; fw.Status != releases.StatusUpdateAvailable || fw.Deployable || fw.ManualInstructions == "" {
		t.Fatalf("fw check unexpected: %+v", fw)
	}

	// --- pull ---
	rec = f.do(t, http.MethodPost, "/api/updates/pull", `{"component":"os","channel":"dev"}`, c)
	if rec.Code != http.StatusCreated {
		t.Fatalf("pull: status %d, body %s", rec.Code, rec.Body.String())
	}
	if got, _ := f.srv.updater.GetBundle(f.ctx, sha); got == nil {
		t.Fatalf("pulled bundle %s not in store", sha)
	}

	// --- pull again: idempotent (200, not 201) ---
	rec = f.do(t, http.MethodPost, "/api/updates/pull", `{"component":"os","channel":"dev"}`, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("pull (repeat): status %d, want 200, body %s", rec.Code, rec.Body.String())
	}

	// --- check again: os now reports staged ---
	rec = f.do(t, http.MethodPost, "/api/updates/check", `{"channel":"dev"}`, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-check: status %d", rec.Code)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	for _, cs := range res.Components {
		if cs.Component == "os" && !cs.Staged {
			t.Errorf("os should be staged after pull: %+v", cs)
		}
	}
}

func TestCheckUpdatesNotConfigured(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	// No SetReleaseSource → 503.
	rec := f.do(t, http.MethodPost, "/api/updates/check", `{}`, c)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 when unconfigured, got %d (%s)", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}

func TestPullRejectsFirewall(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	bundle, sha := buildBundleFixture(t, f)
	rel := fakeReleaseServer(t, bundle, sha)
	f.srv.SetReleaseSource(releases.NewGithubPublicSource(rel.URL, "geekdojo/rasputin-releases"), "dev")

	rec := f.do(t, http.MethodPost, "/api/updates/pull", `{"component":"fw","channel":"dev"}`, c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("firewall pull should be 400, got %d (%s)", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}
