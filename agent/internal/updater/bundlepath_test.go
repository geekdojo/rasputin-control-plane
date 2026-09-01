package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The traversal payloads every test below shares. They are what a hostile or
// impersonated control plane would put in UpdateDownloadCmd.BundleID —
// remembering that the agent's state dir sits next to the trust root and the
// A/B slot devices, so "escapes the bundle store" is not an abstract worry.
var traversalIDs = []string{
	"../../../../etc/rasputin/trust/root-ca",
	"..",
	".",
	"a/b",
	`a\b`,
	"sub/../../escape",
	"/etc/passwd",
	"with space",
	"semi;colon",
	"nul\x00byte",
	"",
	strings.Repeat("a", maxBundleIDLen+1),
}

func TestValidBundleID_AcceptsWhatTheAPIActuallySends(t *testing.T) {
	// A sha256 hex digest is what api/internal/updater/jobs.go sends as
	// BundleID (spec.BundleSHA256); the others are ids the backends' own
	// tests and the CalVer release line use.
	for _, id := range []string{
		"7dc0657846367cec8c9f328e513e4d3af297864119186651605632e4f72e16ea",
		"2026.07.0",
		"2026.08.2-dev.83",
		"b1",
		"b-install",
		"bundle_v2",
	} {
		if !validBundleID(id) {
			t.Errorf("validBundleID(%q) = false, want true — this is a shape the api really sends", id)
		}
	}
}

func TestValidBundleID_RejectsAnythingThatIsNotOneFilename(t *testing.T) {
	for _, id := range traversalIDs {
		if validBundleID(id) {
			t.Errorf("validBundleID(%q) = true, want false", id)
		}
	}
}

func TestResolveBundlePath_DefaultsIntoTheStore(t *testing.T) {
	got, err := resolveBundlePath("/var/lib/rasputin", "b1", "", ".rootfs")
	if err != nil {
		t.Fatalf("resolveBundlePath: %v", err)
	}
	want := filepath.Join("/var/lib/rasputin", "bundles", "b1.rootfs")
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestResolveBundlePath_RejectsTraversalInTheBundleID(t *testing.T) {
	for _, id := range traversalIDs {
		if _, err := resolveBundlePath("/var/lib/rasputin", id, "", ".rootfs"); !errors.Is(err, errBadBundleID) {
			t.Errorf("bundleID %q: err = %v, want errBadBundleID", id, err)
		}
	}
}

// The id is validated even when localPath supplies the path, because the id is
// echoed into acks and log lines and drives pruneBundles' keep-set.
func TestResolveBundlePath_ValidatesTheIDEvenWhenLocalPathIsGiven(t *testing.T) {
	dir := t.TempDir()
	inside := filepath.Join(dir, "bundles", "ok.rootfs")
	if _, err := resolveBundlePath(dir, "../../etc/shadow", inside, ".rootfs"); !errors.Is(err, errBadBundleID) {
		t.Errorf("err = %v, want errBadBundleID", err)
	}
}

func TestResolveBundlePath_AcceptsALocalPathInsideTheStore(t *testing.T) {
	dir := t.TempDir()
	inside := filepath.Join(dir, "bundles", "staged.rootfs")
	got, err := resolveBundlePath(dir, "b1", inside, ".rootfs")
	if err != nil {
		t.Fatalf("resolveBundlePath: %v", err)
	}
	if got != inside {
		t.Errorf("got %q want %q", got, inside)
	}
}

func TestResolveBundlePath_RejectsALocalPathOutsideTheStore(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{
		"/etc/passwd",
		filepath.Join(dir, "not-bundles", "x.rootfs"),
		filepath.Join(dir, "bundles", "..", "..", "escape.rootfs"),
		filepath.Join(dir, "bundles"),                 // the store itself is a directory
		filepath.Join(dir, "bundlesevil", "x.rootfs"), // prefix match is not containment
	} {
		if _, err := resolveBundlePath(dir, "b1", p, ".rootfs"); !errors.Is(err, errBundlePathEscape) {
			t.Errorf("localPath %q: err = %v, want errBundlePathEscape", p, err)
		}
	}
}

// ── the same rule, proved at each backend rather than only at the helper ─────
//
// The helper is unexported and every backend calls it; these assert that none
// of them forgot to, which is the failure that would put the hole back.

func TestBackends_RejectTraversingBundleIDOnDownload(t *testing.T) {
	const evil = "../../../../etc/rasputin/trust/root-ca"

	t.Run("openwrt-ab", func(t *testing.T) {
		b, err := NewOpenWrtABBackend(t.TempDir())
		if err != nil {
			t.Fatalf("NewOpenWrtABBackend: %v", err)
		}
		_, _, err = b.Download(context.Background(), evil, "http://unused", "http://unused/sig", "", 0, nil)
		if !errors.Is(err, errBadBundleID) {
			t.Errorf("err = %v, want errBadBundleID", err)
		}
	})

	t.Run("rauc", func(t *testing.T) {
		fakeRAUC(t, "ok")
		b, err := NewRAUCBackend(t.TempDir())
		if err != nil {
			t.Fatalf("NewRAUCBackend: %v", err)
		}
		_, _, err = b.Download(context.Background(), evil, "http://unused", "", "", 0, nil)
		if !errors.Is(err, errBadBundleID) {
			t.Errorf("err = %v, want errBadBundleID", err)
		}
	})

	t.Run("mock", func(t *testing.T) {
		mb, err := NewMockBackend(t.TempDir())
		if err != nil {
			t.Fatalf("NewMockBackend: %v", err)
		}
		_, _, err = mb.Download(context.Background(), evil, "http://unused", "", "", 0, nil)
		if !errors.Is(err, errBadBundleID) {
			t.Errorf("err = %v, want errBadBundleID", err)
		}
	})
}

func TestBackends_RejectOutOfStoreLocalPathOnInstall(t *testing.T) {
	t.Run("openwrt-ab", func(t *testing.T) {
		b, err := NewOpenWrtABBackend(t.TempDir())
		if err != nil {
			t.Fatalf("NewOpenWrtABBackend: %v", err)
		}
		_, err = b.Install(context.Background(), "b1", "/etc/passwd", proto.SlotB, nil)
		if !errors.Is(err, errBundlePathEscape) {
			t.Errorf("err = %v, want errBundlePathEscape", err)
		}
	})

	t.Run("rauc", func(t *testing.T) {
		fakeRAUC(t, "ok")
		b, err := NewRAUCBackend(t.TempDir())
		if err != nil {
			t.Fatalf("NewRAUCBackend: %v", err)
		}
		_, err = b.Install(context.Background(), "b1", "/etc/passwd", proto.SlotB, nil)
		if !errors.Is(err, errBundlePathEscape) {
			t.Errorf("err = %v, want errBundlePathEscape", err)
		}
	})

	t.Run("mock", func(t *testing.T) {
		mb, err := NewMockBackend(t.TempDir())
		if err != nil {
			t.Fatalf("NewMockBackend: %v", err)
		}
		_, err = mb.Install(context.Background(), "b1", "/etc/passwd", proto.SlotB, nil)
		if !errors.Is(err, errBundlePathEscape) {
			t.Errorf("err = %v, want errBundlePathEscape", err)
		}
	})
}

// The whole point, end to end: the command arrives over the BUS, which is the
// only way these fields are ever populated in production. A refusal here has
// to be an ack with OK=false — never a panic, never a silent success, and
// never a file written outside the store.
func TestBusInstall_TraversingLocalPathIsRefusedAndWritesNothing(t *testing.T) {
	nc, mb := newRegistered(t)
	outside := filepath.Join(t.TempDir(), "pwned.bin")

	var ack proto.UpdateInstallAck
	request(t, nc, proto.UpdateInstallSubject("node-1"), proto.UpdateInstallCmd{
		BundleID: "b1", LocalPath: outside, TargetSlot: proto.SlotB,
	}, &ack)
	if ack.OK {
		t.Fatalf("install accepted an out-of-store LocalPath off the bus: %+v", ack)
	}
	if !strings.Contains(ack.Detail, "escapes the bundle store") {
		t.Errorf("detail should name the refusal, got %q", ack.Detail)
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Errorf("something touched %s", outside)
	}
	// And the store itself is untouched.
	ents, err := os.ReadDir(filepath.Join(mb.stateDir, "bundles"))
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	if len(ents) != 0 {
		t.Errorf("bundle store should be empty, holds %d entries", len(ents))
	}
}

func TestBusDownload_TraversingBundleIDIsRefused(t *testing.T) {
	nc, _ := newRegistered(t)

	var ack proto.UpdateDownloadAck
	request(t, nc, proto.UpdateDownloadSubject("node-1"), proto.UpdateDownloadCmd{
		BundleID: "../../../../etc/rasputin/trust/root-ca",
		URL:      "http://unused",
	}, &ack)
	if ack.OK {
		t.Fatalf("download accepted a traversing BundleID off the bus: %+v", ack)
	}
	if !strings.Contains(ack.Detail, "not a safe filename component") {
		t.Errorf("detail should name the refusal, got %q", ack.Detail)
	}
}
