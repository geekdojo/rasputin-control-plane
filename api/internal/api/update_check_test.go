package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The firewall's deployable OTA artifact is a bare rootfs squashfs. This fixture
// stands in for it; its sha is what the fw manifest pins + the pull verifies.
var fwRootfsFixture = []byte("FW-ROOTFS-SQUASHFS-FIXTURE")

func fwRootfsSHA() string { s := sha256.Sum256(fwRootfsFixture); return hex.EncodeToString(s[:]) }

// fakeReleaseServer serves a GitHub-Releases-shaped API plus the manifest and
// bundle assets, so the github public source can be exercised end-to-end with
// RASPUTIN_RELEASE_API_BASE pointed at it. Each component is read from its own
// source repo (ADR-0002), tagged with the bare version — no os-/fw- mirror
// prefix.
func fakeReleaseServer(t *testing.T, bundle []byte, bundleSHA string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var base string // set after the server starts so asset URLs are absolute

	mux.HandleFunc("/repos/geekdojo/rasputin-os/releases", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"tag_name": "2026.06.0-dev.99", "prerelease": true,
			"assets": []map[string]any{
				{"name": "manifest.json", "browser_download_url": base + "/os-manifest"},
				{"name": "bundle.raspbundle", "browser_download_url": base + "/os-asset"},
			},
		}})
	})
	mux.HandleFunc("/repos/geekdojo/rasputin-openwrt-firewall/releases", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"tag_name": "2026.07.1-dev.20", "prerelease": true,
			"assets": []map[string]any{
				{"name": "manifest.json", "browser_download_url": base + "/fw-manifest"},
				{"name": "rasputin-fw-n100-2026.07.1-dev.20.rootfs", "browser_download_url": base + "/fw-asset"},
			},
		}})
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
				SKU: "fw-n100", Architecture: "amd64", Compatible: "rasputin-fw-n100", Kind: "ab",
				Image:  "rasputin-fw-n100-2026.07.1-dev.20-ab.img.gz",
				Rootfs: "rasputin-fw-n100-2026.07.1-dev.20.rootfs", RootfsSha256: fwRootfsSHA(),
				RootfsSizeBytes: int64(len(fwRootfsFixture)),
			}},
		})
	})
	mux.HandleFunc("/os-asset", func(w http.ResponseWriter, r *http.Request) {
		w.Write(bundle)
	})
	mux.HandleFunc("/fw-asset", func(w http.ResponseWriter, r *http.Request) {
		w.Write(fwRootfsFixture)
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
	f.srv.SetReleaseSource(releases.NewGithubPublicSource(rel.URL), "dev")

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
	if fw := byID["fw"]; fw.Status != releases.StatusUpdateAvailable || !fw.Deployable || fw.BundleSHA256 != fwRootfsSHA() || fw.ManualInstructions != "" {
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

// mixedArchReleaseServer publishes an OS release with TWO artifacts — the
// amd64 one downloadable, the arm64 one pointing at an asset the release does
// not carry. That is the shape of a real half-published release, and it is the
// one that used to leave the bundle store holding amd64 with the caller told
// only "release has no asset …".
func mixedArchReleaseServer(t *testing.T, bundle []byte, bundleSHA string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var base string

	mux.HandleFunc("/repos/geekdojo/rasputin-os/releases", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"tag_name": "2026.06.0-dev.99", "prerelease": true,
			"assets": []map[string]any{
				{"name": "manifest.json", "browser_download_url": base + "/os-manifest"},
				{"name": "bundle.raspbundle", "browser_download_url": base + "/os-asset"},
			},
		}})
	})
	mux.HandleFunc("/os-manifest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(releases.Manifest{
			Version: "2026.06.0-dev.99", Channel: "dev",
			Artifacts: []releases.ManifestArtifact{
				{
					SKU: "n100", Architecture: "amd64", Compatible: "rasputin-n100",
					Raucb: "bundle.raspbundle", SHA256: bundleSHA, SizeBytes: int64(len(bundle)),
					SignedBy: "Rasputin Release 2026.06.0-dev.99",
				},
				{
					SKU: "rpi", Architecture: "arm64", Compatible: "rasputin-rpi-arm64",
					Raucb: "missing-arm64.raspbundle", SHA256: strings.Repeat("b", 64), SizeBytes: 4096,
				},
			},
		})
	})
	mux.HandleFunc("/os-asset", func(w http.ResponseWriter, r *http.Request) { w.Write(bundle) })

	srv := httptest.NewServer(mux)
	base = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

// A pull where one arch lands and another does not is neither a success nor a
// failure, and reporting it as either is the bug. It answers 207 and names
// both outcomes — previously the first error aborted the loop, so the amd64
// bundle was already in the store with nothing saying so.
func TestPullUpdate_PartialStagingIsReportedNotSwallowed(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	bundle, sha := buildBundleFixture(t, f)
	rel := mixedArchReleaseServer(t, bundle, sha)
	f.srv.SetReleaseSource(releases.NewGithubPublicSource(rel.URL), "dev")

	rec := f.do(t, http.MethodPost, "/api/updates/pull", `{"component":"os","channel":"dev"}`, c)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("partial pull: status %d, want 207; body %s", rec.Code, rec.Body.String())
	}

	var res struct {
		Version string `json:"version"`
		Staged  []struct {
			Architecture string `json:"architecture"`
		} `json:"staged"`
		Failed []struct {
			Architecture string `json:"architecture"`
			Error        string `json:"error"`
		} `json:"failed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode pull result: %v", err)
	}
	if len(res.Staged) != 1 || res.Staged[0].Architecture != "amd64" {
		t.Errorf("staged = %+v, want [amd64]", res.Staged)
	}
	if len(res.Failed) != 1 || res.Failed[0].Architecture != "arm64" {
		t.Fatalf("failed = %+v, want [arm64]", res.Failed)
	}
	if res.Failed[0].Error == "" {
		t.Error("a failed artifact must say why")
	}
	// The amd64 bundle really is in the store — which is exactly why the
	// caller had to be told, rather than shown a bare error.
	if got, _ := f.srv.updater.GetBundle(f.ctx, sha); got == nil {
		t.Error("amd64 bundle should have been staged despite the arm64 failure")
	}
}

// When NOTHING lands the pull is an ordinary failure — but it still reports
// per-artifact detail rather than only the first error hit, which is the whole
// reason the loop stopped bailing out.
func TestPullUpdate_NothingStagedIsStillAFailureWithDetail(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)

	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/repos/geekdojo/rasputin-os/releases", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"tag_name": "2026.06.0-dev.99", "prerelease": true,
			"assets": []map[string]any{
				{"name": "manifest.json", "browser_download_url": base + "/os-manifest"},
			},
		}})
	})
	mux.HandleFunc("/os-manifest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(releases.Manifest{
			Version: "2026.06.0-dev.99", Channel: "dev",
			Artifacts: []releases.ManifestArtifact{
				{SKU: "n100", Architecture: "amd64", Compatible: "rasputin-n100",
					Raucb: "gone-amd64.raspbundle", SHA256: strings.Repeat("a", 64)},
				{SKU: "rpi", Architecture: "arm64", Compatible: "rasputin-rpi-arm64",
					Raucb: "gone-arm64.raspbundle", SHA256: strings.Repeat("b", 64)},
			},
		})
	})
	srv := httptest.NewServer(mux)
	base = srv.URL
	t.Cleanup(srv.Close)
	f.srv.SetReleaseSource(releases.NewGithubPublicSource(srv.URL), "dev")

	rec := f.do(t, http.MethodPost, "/api/updates/pull", `{"component":"os","channel":"dev"}`, c)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("total failure: status %d, want 502; body %s", rec.Code, rec.Body.String())
	}
	var res struct {
		Staged []struct{ Architecture string } `json:"staged"`
		Failed []struct {
			Architecture string `json:"architecture"`
			Error        string `json:"error"`
		} `json:"failed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(res.Staged) != 0 {
		t.Errorf("staged = %+v, want none", res.Staged)
	}
	// Both arches are named, not just whichever failed first.
	if len(res.Failed) != 2 {
		t.Fatalf("failed = %+v, want both arches reported", res.Failed)
	}
	for _, a := range res.Failed {
		if a.Error == "" {
			t.Errorf("%s failed with no reason", a.Architecture)
		}
	}
}

// The arch-set badge: a cluster with an arm64 node must not read STAGED when
// only the amd64 bundle is present, and a cluster with no arm64 hardware must
// not be nagged for a bundle it will never use.
func TestCheckUpdates_StagedIsPerArchNotPerComponent(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	bundle, sha := buildBundleFixture(t, f)
	rel := mixedArchReleaseServer(t, bundle, sha)
	f.srv.SetReleaseSource(releases.NewGithubPublicSource(rel.URL), "dev")

	// An all-amd64 cluster on an older image.
	_ = f.inv.Insert(f.ctx, &proto.Node{
		ID: "n100-1", Role: proto.RoleControlPlane, Architecture: "amd64",
		ImageVersion: "2026.06.0-dev.20",
	})
	// Stage the amd64 artifact only.
	f.do(t, http.MethodPost, "/api/updates/pull", `{"component":"os","channel":"dev"}`, c)

	osRow := func(t *testing.T) releases.ComponentStatus {
		t.Helper()
		rec := f.do(t, http.MethodPost, "/api/updates/check", `{"channel":"dev"}`, c)
		if rec.Code != http.StatusOK {
			t.Fatalf("check: status %d", rec.Code)
		}
		var res releases.CheckResult
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, cs := range res.Components {
			if cs.Component == "os" {
				return cs
			}
		}
		t.Fatal("no os component")
		return releases.ComponentStatus{}
	}

	got := osRow(t)
	if len(got.Artifacts) != 2 {
		t.Fatalf("want both arches enumerated, got %+v", got.Artifacts)
	}
	byArch := map[string]releases.ArtifactStatus{}
	for _, a := range got.Artifacts {
		byArch[a.Architecture] = a
	}
	if !byArch["amd64"].Staged || byArch["arm64"].Staged {
		t.Errorf("per-arch staged wrong: %+v", got.Artifacts)
	}
	if byArch["amd64"].NeededBy != 1 || byArch["arm64"].NeededBy != 0 {
		t.Errorf("neededBy wrong: amd64=%d arm64=%d",
			byArch["amd64"].NeededBy, byArch["arm64"].NeededBy)
	}
	if !got.Staged {
		t.Error("an all-amd64 cluster with the amd64 bundle staged IS fully staged")
	}

	// Add a Pi. The same store contents now describe a half-staged release.
	_ = f.inv.Insert(f.ctx, &proto.Node{
		ID: "pi-1", Role: proto.RoleCompute, Architecture: "arm64",
		ImageVersion: "2026.06.0-dev.20",
	})
	got = osRow(t)
	for _, a := range got.Artifacts {
		if a.Architecture == "arm64" && a.NeededBy != 1 {
			t.Errorf("arm64 neededBy = %d, want 1 once a Pi joins", a.NeededBy)
		}
	}
	if got.Staged {
		t.Error("a cluster with an arm64 node and no arm64 bundle must NOT read as staged")
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

// The firewall is now deployable (custom A/B via openwrt-ab) — pulling it stages
// the rootfs OTA artifact into the bundle store, same as an OS bundle.
func TestPullFirewall(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	bundle, sha := buildBundleFixture(t, f)
	rel := fakeReleaseServer(t, bundle, sha)
	f.srv.SetReleaseSource(releases.NewGithubPublicSource(rel.URL), "dev")

	rec := f.do(t, http.MethodPost, "/api/updates/pull", `{"component":"fw","channel":"dev"}`, c)
	if rec.Code != http.StatusCreated {
		t.Fatalf("firewall pull should be 201, got %d (%s)", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if got, _ := f.srv.updater.GetBundle(f.ctx, fwRootfsSHA()); got == nil {
		t.Fatalf("pulled firewall rootfs %s not in store", fwRootfsSHA())
	}
}
