package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The control-plane memory floor at pull and at the plan preview
// (geekdojo/geekdojo-brain#1011).

const memFloorBytes = int64(3758096384) // 3,584 MiB

// floorReleaseServer serves one OS release whose manifest is m, with each
// artifact's raucb asset serving the bytes in assets. opens counts asset
// downloads.
func floorReleaseServer(t *testing.T, m releases.Manifest, assets map[string][]byte) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	mux := http.NewServeMux()
	var base string
	opens := &atomic.Int32{}
	mux.HandleFunc("/repos/geekdojo/rasputin-os/releases", func(w http.ResponseWriter, r *http.Request) {
		list := []map[string]any{{"name": "manifest.json", "browser_download_url": base + "/os-manifest"}}
		for name := range assets {
			list = append(list, map[string]any{"name": name, "browser_download_url": base + "/asset/" + name})
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{"tag_name": m.Version, "prerelease": true, "assets": list}})
	})
	mux.HandleFunc("/os-manifest", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(m) })
	mux.HandleFunc("/asset/{name}", func(w http.ResponseWriter, r *http.Request) {
		opens.Add(1)
		_, _ = w.Write(assets[r.PathValue("name")])
	})
	srv := httptest.NewServer(mux)
	base = srv.URL
	t.Cleanup(srv.Close)
	return srv, opens
}

func shaOf(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// TC-1011-06: an OS release that carries the sign-in service and states no
// floor is never staged: 502 with the sentence, nothing downloaded, no row, no
// blob, and one WARN record naming the component and version.
func TestPullUpdate_IdentityReleaseWithNoFloorIsNotStaged(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	bundle, sha := buildBundleFixture(t, f)
	const version = "2026.06.0-dev.99"
	rel, opens := floorReleaseServer(t, releases.Manifest{
		Version: version, Channel: "dev", IdentityService: true,
		Artifacts: []releases.ManifestArtifact{{
			SKU: "n100", Architecture: "amd64", Compatible: "rasputin-n100",
			Raucb: "bundle.raucb", SHA256: sha, SizeBytes: int64(len(bundle)),
		}},
	}, map[string][]byte{"bundle.raucb": bundle})
	f.srv.SetReleaseSource(releases.NewGithubPublicSource(rel.URL, nil), "dev")

	rec := f.do(t, http.MethodPost, "/api/updates/pull", `{"component":"os","channel":"dev"}`, c)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502; body %s", rec.Code, rec.Body.String())
	}
	var body codedError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	const want = "Rasputin OS 2026.06.0-dev.99 carries the sign-in service but its signed manifest states no control-plane memory floor, so it was not staged."
	if body.Error != want {
		t.Errorf("error = %q\nwant    %q", body.Error, want)
	}
	if body.Code != codeMemoryFloorMissing || body.CorrelationID == "" {
		t.Errorf("code = %q, correlationId = %q; want %q and a non-empty id", body.Code, body.CorrelationID, codeMemoryFloorMissing)
	}
	if n := opens.Load(); n != 0 {
		t.Errorf("%d asset download(s), want none", n)
	}
	if all, err := f.srv.updater.ListBundles(f.ctx); err != nil || len(all) != 0 {
		t.Errorf("bundles = %d (%v), want none", len(all), err)
	}
	entries, err := os.ReadDir(f.bundleDir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read bundle dir: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			t.Errorf("bundle dir holds %s, want no blob", e.Name())
		}
	}
	recs := f.logs.withAttr("event", "updates.memory_floor_missing")
	if len(recs) != 1 {
		t.Fatalf("memory_floor_missing records = %d, want 1", len(recs))
	}
	if recs[0].Level.String() != "WARN" {
		t.Errorf("record level = %v, want WARN", recs[0].Level)
	}
	for k, v := range map[string]string{"component": "os", "version": version, "code": codeMemoryFloorMissing, "correlation_id": body.CorrelationID} {
		if got, _ := recAttr(recs[0], k); got != v {
			t.Errorf("record %s = %q, want %q", k, got, v)
		}
	}
}

// TC-1011-07 (a): a pull of a release with a floor stages both SKUs, each
// carrying the floor.
func TestPullUpdate_CarriesTheMemoryFloorOntoEveryBundle(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	amd, amdSHA := buildBundleFixture(t, f)
	arm := []byte("ARM64-BUNDLE-FIXTURE")
	armSHA := shaOf(arm)
	rel, _ := floorReleaseServer(t, releases.Manifest{
		Version: "2026.06.0-dev.99", Channel: "dev", ControlPlaneMemoryFloorBytes: memFloorBytes,
		Artifacts: []releases.ManifestArtifact{
			{SKU: "n100", Architecture: "amd64", Compatible: "rasputin-n100", Raucb: "amd.raucb", SHA256: amdSHA, SizeBytes: int64(len(amd))},
			{SKU: "rpi", Architecture: "arm64", Compatible: "rasputin-rpi-arm64", Raucb: "arm.raucb", SHA256: armSHA, SizeBytes: int64(len(arm))},
		},
	}, map[string][]byte{"amd.raucb": amd, "arm.raucb": arm})
	f.srv.SetReleaseSource(releases.NewGithubPublicSource(rel.URL, nil), "dev")

	rec := f.do(t, http.MethodPost, "/api/updates/pull", `{"component":"os","channel":"dev"}`, c)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	for _, sha := range []string{amdSHA, armSHA} {
		b, err := f.srv.updater.GetBundle(f.ctx, sha)
		if err != nil || b == nil || b.MemoryFloorBytes != memFloorBytes {
			t.Errorf("bundle %s = %+v (%v), want floor %d", sha, b, err, memFloorBytes)
		}
	}
}

// TC-1011-07 (b), (c): an OS release from before the field, and a firewall
// release, stage with floor 0 and answer as they always have (201).
func TestPullUpdate_ReleasesWithoutTheFieldStageWithNoFloor(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	bundle, sha := buildBundleFixture(t, f)
	rel := fakeReleaseServer(t, bundle, sha)
	f.srv.SetReleaseSource(releases.NewGithubPublicSource(rel.URL, nil), "dev")

	for _, p := range []struct{ comp, sha string }{{"os", sha}, {"fw", fwRootfsSHA()}} {
		rec := f.do(t, http.MethodPost, "/api/updates/pull", `{"component":"`+p.comp+`","channel":"dev"}`, c)
		if rec.Code != http.StatusCreated {
			t.Fatalf("%s pull: status %d, want 201; body %s", p.comp, rec.Code, rec.Body.String())
		}
		b, err := f.srv.updater.GetBundle(f.ctx, p.sha)
		if err != nil || b == nil || b.MemoryFloorBytes != 0 {
			t.Errorf("%s bundle = %+v (%v), want floor 0", p.comp, b, err)
		}
	}
}

// TC-1011-15: the pre-flight preview of a run whose release states a floor the
// control plane is below answers 400 with the plan's sentence, through the
// server's own metrics store, and submits no job.
func TestSystemUpdatePlan_PreviewShowsTheMemoryFloorRefusal(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	now := time.Now().UTC()
	for _, n := range []*proto.Node{
		{ID: "cp-1", Hostname: "s4c-cp1", Role: proto.RoleControlPlane, Architecture: "arm64"},
		{ID: "c-1", Hostname: "c-1", Role: proto.RoleCompute, Architecture: "arm64"},
		{ID: "c-2", Hostname: "c-2", Role: proto.RoleCompute, Architecture: "arm64"},
	} {
		n.FirstSeen, n.LastSeen = now, now
		if err := f.inv.Insert(f.ctx, n); err != nil {
			t.Fatalf("inv %s: %v", n.ID, err)
		}
	}
	if err := f.srv.updater.CreateBundle(f.ctx, bundleRow("sha-arm64", "2026.11.9", "rasputin-rpi-arm64", memFloorBytes)); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if err := f.metricsStore.Insert(f.ctx, &proto.MetricsEvt{
		NodeID: "cp-1", Ts: now, Metrics: map[string]float64{proto.MetricMemTotalBytes: 900 * (1 << 20)},
	}); err != nil {
		t.Fatalf("metrics: %v", err)
	}

	rec := f.do(t, http.MethodPost, "/api/updates/system/plan", `{"version":"2026.11.9","component":"os"}`, c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	const want = "This update needs at least 3.5 GiB of memory on the control plane; s4c-cp1 has 900.0 MiB. No node was updated."
	if body["error"] != want {
		t.Errorf("error = %q\nwant    %q", body["error"], want)
	}
	if js, err := f.jobsStore.ListJobs(f.ctx, 10); err != nil || len(js) != 0 {
		t.Errorf("jobs = %d (%v), want none submitted", len(js), err)
	}
}

func bundleRow(sha, version, compat string, floor int64) *updater.Bundle {
	return &updater.Bundle{
		SHA256: sha, Version: version, Compatible: compat, UploadedAt: time.Now().UTC(),
		StoragePath: "/nonexistent/" + strings.ToLower(sha), MemoryFloorBytes: floor,
	}
}

// A release whose manifest states a negative floor is refused the same way,
// with its own sentence, rather than read as "no floor".
func TestPullUpdate_NegativeMemoryFloorIsNotStaged(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	bundle, sha := buildBundleFixture(t, f)
	rel, opens := floorReleaseServer(t, releases.Manifest{
		Version: "2026.06.0-dev.99", Channel: "dev", ControlPlaneMemoryFloorBytes: -1,
		Artifacts: []releases.ManifestArtifact{{
			SKU: "n100", Architecture: "amd64", Compatible: "rasputin-n100",
			Raucb: "bundle.raucb", SHA256: sha, SizeBytes: int64(len(bundle)),
		}},
	}, map[string][]byte{"bundle.raucb": bundle})
	f.srv.SetReleaseSource(releases.NewGithubPublicSource(rel.URL, nil), "dev")

	rec := f.do(t, http.MethodPost, "/api/updates/pull", `{"component":"os","channel":"dev"}`, c)
	var body codedError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	const want = "Rasputin OS 2026.06.0-dev.99 states a control-plane memory floor that is not a positive number, so it was not staged."
	if rec.Code != http.StatusBadGateway || body.Error != want {
		t.Errorf("pull = %d %q, want 502 %q", rec.Code, body.Error, want)
	}
	if body.Code != codeMemoryFloorInvalid || body.CorrelationID == "" {
		t.Errorf("code = %q, correlationId = %q; want %q and a non-empty id", body.Code, body.CorrelationID, codeMemoryFloorInvalid)
	}
	if n := opens.Load(); n != 0 {
		t.Errorf("%d asset download(s), want none", n)
	}
	recs := f.logs.withAttr("event", "updates.memory_floor_invalid")
	if len(recs) != 1 {
		t.Fatalf("memory_floor_invalid records = %d, want 1", len(recs))
	}
	for k, v := range map[string]string{"component": "os", "version": "2026.06.0-dev.99", "code": codeMemoryFloorInvalid, "correlation_id": body.CorrelationID} {
		if got, _ := recAttr(recs[0], k); got != v {
			t.Errorf("record %s = %q, want %q", k, got, v)
		}
	}
}
