package releases

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

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
			SKU: "fw-n100", Architecture: "amd64", Compatible: "rasputin-fw-n100", Kind: "ab",
			// Full-disk image for humans; the rootfs squashfs is the deployable OTA artifact.
			Image:  "rasputin-fw-n100-" + version + "-ab.img.gz",
			Rootfs: "rasputin-fw-n100-" + version + ".rootfs", RootfsSha256: "def456", RootfsSizeBytes: 200,
			SignedBy: "Rasputin Release " + version,
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

// confirmedNode builds a node whose image version carries a CONFIRMATION —
// the normal state of any row in inventory, since every registration stamps
// one (ADR-0005 Decision 4). Tests that care about the UNCONFIRMED case build
// their nodes by hand; everything else uses this, so the fixtures describe a
// real fleet rather than one that has been globally doubted.
func confirmedNode(n *proto.Node) *proto.Node {
	at := time.Now().UTC()
	n.ImageVersionConfirmedAt = &at
	return n
}

func TestCheck(t *testing.T) {
	nodes := []*proto.Node{
		confirmedNode(&proto.Node{ID: "x", Role: proto.RoleControlPlane, ImageVersion: "2026.06.0-dev.20", AgentVersion: "v0.8.4"}),
		confirmedNode(&proto.Node{ID: "n", Role: proto.RoleFirewall, ImageVersion: "2026.07.0"}),
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
	// Firewall is now deployable via the node.update saga (KindRootfsAB): it
	// exposes the rootfs OTA artifact + its sha, and carries no manual note.
	if !fw.Deployable {
		t.Errorf("fw should be deployable")
	}
	if fw.BundleSHA256 != "def456" || fw.AssetName == "" {
		t.Errorf("fw should expose the rootfs OTA asset + sha: %+v", fw)
	}
	if fw.ManualInstructions != "" {
		t.Errorf("fw should no longer carry manual instructions: %q", fw.ManualInstructions)
	}

	// The control-plane software is not a standalone row — it's folded into the
	// OS row as a display-only RUNNING detail (it ships inside the OS image, so
	// it has no update path, and the version we can see is the one running).
	if _, ok := got["cp"]; ok {
		t.Errorf("cp should not be a standalone update row")
	}
	if len(os.Running) != 1 || os.Running[0].Version != "v0.8.4" || os.Running[0].Label != "Control-plane software" {
		t.Errorf("os.Running = %+v, want control-plane v0.8.4 (the controlplane node's agent version)", os.Running)
	}
}

// The control-plane version is folded into the OS row from the controlplane
// node's reported agent version, regardless of its format (a -dev.N pre-release
// here) — it's display-only, never compared or shown as its own status.
func TestCheckFoldsControlPlaneVersion(t *testing.T) {
	nodes := []*proto.Node{
		confirmedNode(&proto.Node{ID: "x", Role: proto.RoleControlPlane, ImageVersion: "2026.06.0-dev.28", AgentVersion: "0.8.7-dev.3"}),
	}
	src := &fakeSource{rel: map[string]*ReleaseInfo{
		"os": osRelease("2026.06.0-dev.28"), // OS up to date
	}}
	got := byComponent(Check(context.Background(), src, "dev", nodes))
	if _, ok := got["cp"]; ok {
		t.Fatalf("cp should not be a standalone row")
	}
	os := got["os"]
	if len(os.Running) != 1 || os.Running[0].Version != "0.8.7-dev.3" {
		t.Errorf("os.Running = %+v, want control-plane 0.8.7-dev.3 folded in", os.Running)
	}
}

// The OS row must read "update available" when ANY node running the OS image
// lags latest — even if the controlplane itself is current — so the operator
// can stage + deploy to the trailing node. Regression for a compute node stuck
// a version behind a freshly-updated controlplane.
func TestCheckOSBehindWhenComputeNodeLags(t *testing.T) {
	nodes := []*proto.Node{
		confirmedNode(&proto.Node{ID: "bench-cp", Role: proto.RoleControlPlane, ImageVersion: "2026.06.0-dev.33", AgentVersion: "0.8.7-dev.7"}),
		confirmedNode(&proto.Node{ID: "bench-compute1", Role: proto.RoleCompute, ImageVersion: "2026.06.0-dev.32"}),
		confirmedNode(&proto.Node{ID: "bench-fw", Role: proto.RoleFirewall, ImageVersion: "2026.07.1-dev.15"}),
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
		confirmedNode(&proto.Node{ID: "x", Role: proto.RoleControlPlane, ImageVersion: "2026.06.0-dev.24", AgentVersion: "v0.8.5"}),
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
		confirmedNode(&proto.Node{ID: "x", Role: proto.RoleControlPlane, ImageVersion: "2026.06.0-dev.24"}),
	}))
	if got["os"].Status != StatusNoRelease {
		t.Errorf("os status = %q, want no_release", got["os"].Status)
	}
}

// ============================================================================
// Unconfirmed versions (ADR-0005 Decision 4)
//
// A node whose image version carries no confirmation is one an update outcome
// told us not to trust. The whole point of the column is that such a node must
// stop making its component read green.
// ============================================================================

// THE c08 SHAPE. Every node agrees it is on latest — but one of them is only
// SAYING so on the strength of a registration that an update outcome later
// failed to verify. Green would be a lie.
func TestCheck_UnconfirmedNodeBlocksUpToDate(t *testing.T) {
	nodes := []*proto.Node{
		confirmedNode(&proto.Node{ID: "cp", Role: proto.RoleControlPlane, ImageVersion: "2026.07.0-dev.104"}),
		// c08: reports latest, but nothing confirms it.
		{ID: "c08", Role: proto.RoleCompute, ImageVersion: "2026.07.0-dev.104"},
	}
	src := &fakeSource{rel: map[string]*ReleaseInfo{"os": osRelease("2026.07.0-dev.104")}}

	got := byComponent(Check(context.Background(), src, "dev", nodes))
	if got["os"].Status != StatusNeedsAttention {
		t.Errorf("os status = %q, want needs_attention", got["os"].Status)
	}
	if !strings.Contains(got["os"].Note, "c08") {
		t.Errorf("os.Note = %q, want it to name the unconfirmed node", got["os"].Note)
	}
}

// An update is already an action; an unconfirmed node is a different problem on
// (possibly) a different node. The status stays update_available — the operator
// is being sent to the Updates page either way — but both notes survive, since
// one silently replacing the other would hide a node.
func TestCheck_UnconfirmedNodeAnnotatesButDoesNotMaskUpdateAvailable(t *testing.T) {
	nodes := []*proto.Node{
		confirmedNode(&proto.Node{ID: "cp", Role: proto.RoleControlPlane, ImageVersion: "2026.07.0-dev.101"}),
		{ID: "c08", Role: proto.RoleCompute, ImageVersion: "2026.07.0-dev.104"},
	}
	src := &fakeSource{rel: map[string]*ReleaseInfo{"os": osRelease("2026.07.0-dev.104")}}

	got := byComponent(Check(context.Background(), src, "dev", nodes))
	if got["os"].Status != StatusUpdateAvailable {
		t.Errorf("os status = %q, want update_available to survive", got["os"].Status)
	}
	if !strings.Contains(got["os"].Note, "Behind latest") || !strings.Contains(got["os"].Note, "unconfirmed") {
		t.Errorf("os.Note = %q, want BOTH the lagging and the unconfirmed node named", got["os"].Note)
	}
}

// A fully confirmed fleet reads green, unchanged. The guard must cost nothing
// when every node is trustworthy — otherwise it is just a permanent yellow
// light and operators learn to ignore it.
func TestCheck_AllConfirmedStaysUpToDate(t *testing.T) {
	nodes := []*proto.Node{
		confirmedNode(&proto.Node{ID: "cp", Role: proto.RoleControlPlane, ImageVersion: "2026.07.0-dev.104"}),
		confirmedNode(&proto.Node{ID: "c01", Role: proto.RoleCompute, ImageVersion: "2026.07.0-dev.104"}),
	}
	src := &fakeSource{rel: map[string]*ReleaseInfo{"os": osRelease("2026.07.0-dev.104")}}

	got := byComponent(Check(context.Background(), src, "dev", nodes))
	if got["os"].Status != StatusUpToDate {
		t.Errorf("os status = %q, want up_to_date", got["os"].Status)
	}
	if got["os"].Note != "" {
		t.Errorf("os.Note = %q, want no note on a clean fleet", got["os"].Note)
	}
}

// A node whose version was unconfirmed AND is blank still has to be nameable —
// otherwise the note reads "Version unconfirmed: c08 ()" and an operator cannot
// tell an empty version from a rendering bug.
func TestCheck_UnconfirmedNodeWithNoVersionIsStillNamed(t *testing.T) {
	nodes := []*proto.Node{
		confirmedNode(&proto.Node{ID: "cp", Role: proto.RoleControlPlane, ImageVersion: "2026.07.0-dev.104"}),
		{ID: "c08", Role: proto.RoleCompute}, // never reported a version at all
	}
	src := &fakeSource{rel: map[string]*ReleaseInfo{"os": osRelease("2026.07.0-dev.104")}}

	got := byComponent(Check(context.Background(), src, "dev", nodes))
	if !strings.Contains(got["os"].Note, "c08 (no version reported)") {
		t.Errorf("os.Note = %q, want the empty version spelled out", got["os"].Note)
	}
}

// The version folded into the OS row is what is RUNNING, and the row it sits on
// describes what is OFFERED. Those diverge exactly when an update is pending,
// which is the only time anyone reads the row.
//
// It used to be labelled "ships in this image", so during the 2026-08-23 bench
// the OS row offered 2026.07.1-dev.178 and reported a control-plane version of
// dev.122 as if dev.178 carried it. dev.178 actually vendored dev.123; dev.122
// was simply what the node was still running. The only way to establish that
// was to read the OS build log.
//
// This test pins the semantics, not the wording: if someone ever tries to make
// this field mean "what the offered image bundles", it has to come from the
// release rather than from the node, and this fails first.
func TestRunningVersionComesFromTheNodeNotTheOfferedRelease(t *testing.T) {
	const running = "2026.07.1-dev.122"
	nodes := []*proto.Node{
		confirmedNode(&proto.Node{
			ID: "cp1", Role: proto.RoleControlPlane,
			ImageVersion: "2026.07.1-dev.170", AgentVersion: running,
		}),
	}
	// An OS update IS pending — the offered release is newer than what runs.
	src := &fakeSource{rel: map[string]*ReleaseInfo{
		"os": osRelease("2026.07.1-dev.178"),
	}}

	os := byComponent(Check(context.Background(), src, "dev", nodes))["os"]
	if len(os.Running) != 1 {
		t.Fatalf("want exactly one running detail on the OS row, got %+v", os.Running)
	}
	if os.Running[0].Version != running {
		t.Errorf("Running = %q, want the controlplane node's own version %q — this field "+
			"reports what is running, never what the offered image carries",
			os.Running[0].Version, running)
	}
	if os.Running[0].Version == os.Latest {
		t.Errorf("Running tracked the offered release (%q) instead of the node — that is the "+
			"exact confusion this field caused when it was called Bundled", os.Latest)
	}
}
