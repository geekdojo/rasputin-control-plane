package releases

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// fakeSource returns canned releases keyed by component id.
type fakeSource struct {
	rel map[string]*ReleaseInfo
	err error
}

func (f *fakeSource) LatestFor(_ context.Context, comp Component, _ string) (*ReleaseInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rel[comp.ID], nil
}
func (f *fakeSource) Open(context.Context, string) (io.ReadCloser, error) { return nil, nil }

func osRelease(version string) *ReleaseInfo {
	return &ReleaseInfo{
		Component: "os", Version: version, Channel: "dev",
		Manifest: Manifest{Version: version, Channel: "dev", Artifacts: []ManifestArtifact{{
			SKU: "n100", Architecture: "amd64", Compatible: "rasputin-n100",
			Raucb: "rasputin-os-n100-" + version + ".raucb", SHA256: "abc123", SizeBytes: 128, SignedBy: "Rasputin Release " + version,
		}}},
	}
}

func fwRelease(version string) *ReleaseInfo {
	return &ReleaseInfo{
		Component: "fw", Version: version, Channel: "dev",
		Manifest: Manifest{Version: version, Channel: "dev", Artifacts: []ManifestArtifact{{
			SKU: "fw-n100", Architecture: "amd64", Compatible: "rasputin-fw-n100", Kind: "combined-efi",
			Image: "rasputin-fw-n100-" + version + "-combined-efi.img.gz", SHA256: "def456",
		}}},
	}
}

func byComponent(res CheckResult) map[string]ComponentStatus {
	m := map[string]ComponentStatus{}
	for _, c := range res.Components {
		m[c.Component] = c
	}
	return m
}

func TestCheck(t *testing.T) {
	nodes := []*proto.Node{
		{ID: "x", Role: proto.RoleControlPlane, ImageVersion: "2026.06.0-dev.20", AgentVersion: "v0.8.4"},
		{ID: "n", Role: proto.RoleFirewall, ImageVersion: "2026.07.0"},
	}
	src := &fakeSource{rel: map[string]*ReleaseInfo{
		"os": osRelease("2026.06.0-dev.24"), // newer than installed dev.20
		"fw": fwRelease("2026.07.1-dev.15"), // newer than installed 2026.07.0
	}}

	got := byComponent(Check(context.Background(), src, "dev", nodes))

	os := got["os"]
	if os.Status != StatusUpdateAvailable {
		t.Errorf("os status = %q, want update_available", os.Status)
	}
	if os.BundleSHA256 != "abc123" || os.AssetName == "" || !os.Deployable {
		t.Errorf("os deploy metadata missing: %+v", os)
	}

	fw := got["fw"]
	if fw.Status != StatusUpdateAvailable {
		t.Errorf("fw status = %q, want update_available", fw.Status)
	}
	if fw.Deployable {
		t.Errorf("fw should not be deployable")
	}
	if fw.ManualInstructions == "" || fw.AssetName == "" {
		t.Errorf("fw should carry manual instructions + image asset name: %+v", fw)
	}
	if fw.BundleSHA256 != "" {
		t.Errorf("fw should not expose a bundle sha")
	}

	// The control-plane software is not a standalone row — it's folded into the
	// OS row as a display-only bundled detail (it ships inside the OS image).
	if _, ok := got["cp"]; ok {
		t.Errorf("cp should not be a standalone update row")
	}
	if len(os.Bundled) != 1 || os.Bundled[0].Version != "v0.8.4" || os.Bundled[0].Label != "Control-plane software" {
		t.Errorf("os.Bundled = %+v, want control-plane v0.8.4 (the controlplane node's agent version)", os.Bundled)
	}
}

// The control-plane version is folded into the OS row from the controlplane
// node's reported agent version, regardless of its format (a -dev.N pre-release
// here) — it's display-only, never compared or shown as its own status.
func TestCheckFoldsControlPlaneVersion(t *testing.T) {
	nodes := []*proto.Node{
		{ID: "x", Role: proto.RoleControlPlane, ImageVersion: "2026.06.0-dev.28", AgentVersion: "0.8.7-dev.3"},
	}
	src := &fakeSource{rel: map[string]*ReleaseInfo{
		"os": osRelease("2026.06.0-dev.28"), // OS up to date
	}}
	got := byComponent(Check(context.Background(), src, "dev", nodes))
	if _, ok := got["cp"]; ok {
		t.Fatalf("cp should not be a standalone row")
	}
	os := got["os"]
	if len(os.Bundled) != 1 || os.Bundled[0].Version != "0.8.7-dev.3" {
		t.Errorf("os.Bundled = %+v, want control-plane 0.8.7-dev.3 folded in", os.Bundled)
	}
}

// The OS row must read "update available" when ANY node running the OS image
// lags latest — even if the controlplane itself is current — so the operator
// can stage + deploy to the trailing node. Regression for a compute node stuck
// a version behind a freshly-updated controlplane.
func TestCheckOSBehindWhenComputeNodeLags(t *testing.T) {
	nodes := []*proto.Node{
		{ID: "bench-cp", Role: proto.RoleControlPlane, ImageVersion: "2026.06.0-dev.33", AgentVersion: "0.8.7-dev.7"},
		{ID: "bench-compute1", Role: proto.RoleCompute, ImageVersion: "2026.06.0-dev.32"},
		{ID: "bench-fw", Role: proto.RoleFirewall, ImageVersion: "2026.07.1-dev.15"},
	}
	src := &fakeSource{rel: map[string]*ReleaseInfo{
		"os": osRelease("2026.06.0-dev.33"), // controlplane already matches latest…
		"fw": fwRelease("2026.07.1-dev.15"),
	}}

	got := byComponent(Check(context.Background(), src, "dev", nodes))

	os := got["os"]
	if os.Status != StatusUpdateAvailable {
		t.Fatalf("os status = %q, want update_available (compute node behind)", os.Status)
	}
	if os.Installed != "2026.06.0-dev.32" {
		t.Errorf("os.Installed = %q, want the oldest node version 2026.06.0-dev.32", os.Installed)
	}
	if !strings.Contains(os.Note, "bench-compute1") {
		t.Errorf("os.Note = %q, want it to name the lagging compute node", os.Note)
	}
	if strings.Contains(os.Note, "dev.33") {
		t.Errorf("os.Note = %q, should not list the current controlplane", os.Note)
	}
	// The firewall is on latest → unaffected.
	if got["fw"].Status != StatusUpToDate {
		t.Errorf("fw status = %q, want up_to_date", got["fw"].Status)
	}
}

func TestCheckUpToDateAndNoFirewall(t *testing.T) {
	nodes := []*proto.Node{
		{ID: "x", Role: proto.RoleControlPlane, ImageVersion: "2026.06.0-dev.24", AgentVersion: "v0.8.5"},
		// no firewall node registered
	}
	src := &fakeSource{rel: map[string]*ReleaseInfo{
		"os": osRelease("2026.06.0-dev.24"), // same as installed
		"fw": fwRelease("2026.07.1-dev.15"),
	}}

	got := byComponent(Check(context.Background(), src, "dev", nodes))

	if got["os"].Status != StatusUpToDate {
		t.Errorf("os status = %q, want up_to_date", got["os"].Status)
	}
	// No firewall node → can't compare → unknown, but still shows latest.
	if got["fw"].Status != StatusUnknown {
		t.Errorf("fw status = %q, want unknown (no firewall node)", got["fw"].Status)
	}
	if got["fw"].Latest == "" {
		t.Errorf("fw should still report the latest available version")
	}
}

func TestCheckNoRelease(t *testing.T) {
	src := &fakeSource{rel: map[string]*ReleaseInfo{}} // LatestFor returns nil
	got := byComponent(Check(context.Background(), src, "stable", []*proto.Node{
		{ID: "x", Role: proto.RoleControlPlane, ImageVersion: "2026.06.0-dev.24"},
	}))
	if got["os"].Status != StatusNoRelease {
		t.Errorf("os status = %q, want no_release", got["os"].Status)
	}
}
