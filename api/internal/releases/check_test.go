package releases

import (
	"context"
	"io"
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
		"cp": {Component: "cp", Version: "v0.8.5", Manifest: Manifest{Version: "v0.8.5"}},
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

	cp := got["cp"]
	if cp.Status != StatusUpdateAvailable || cp.Deployable {
		t.Errorf("cp = %+v, want informational update_available, not deployable", cp)
	}
}

// Regression: the cp line ships -dev.N pre-releases, and the installed agent
// version has no "v" prefix while the release tag does. The semver scheme must
// compare the -dev.N suffix (not collapse dev.1 and dev.2 to the same 0.8.7 and
// report "up to date").
func TestCheckControlPlaneDevPrerelease(t *testing.T) {
	nodes := []*proto.Node{
		{ID: "x", Role: proto.RoleControlPlane, ImageVersion: "2026.06.0-dev.28", AgentVersion: "0.8.7-dev.1"},
	}
	src := &fakeSource{rel: map[string]*ReleaseInfo{
		"cp": {Component: "cp", Version: "v0.8.7-dev.2", Manifest: Manifest{Version: "v0.8.7-dev.2"}},
	}}
	cp := byComponent(Check(context.Background(), src, "dev", nodes))["cp"]
	if cp.Status != StatusUpdateAvailable {
		t.Errorf("cp status = %q, want update_available (dev.1 installed, dev.2 available)", cp.Status)
	}

	// Same dev build → up to date.
	src.rel["cp"] = &ReleaseInfo{Component: "cp", Version: "v0.8.7-dev.1", Manifest: Manifest{Version: "v0.8.7-dev.1"}}
	cp = byComponent(Check(context.Background(), src, "dev", nodes))["cp"]
	if cp.Status != StatusUpToDate {
		t.Errorf("cp status = %q, want up_to_date (dev.1 == dev.1)", cp.Status)
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
		"cp": {Component: "cp", Version: "v0.8.5", Manifest: Manifest{Version: "v0.8.5"}},
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
