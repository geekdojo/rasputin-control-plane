package tailscale

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Fail-closed table tests for the two resolvers this package declares in
// .github/security-resolvers.tsv (gate 4, geekdojo/geekdojo-brain#491).
//
// Both answer a question with a security consequence — where tailscaled's
// trust file lives, and whether this node trusts a mesh CA at all — from
// inputs that can be absent, empty, malformed or unreadable. Each case below
// asserts the CLOSED outcome for one of those shapes.

func TestCABundlePath_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	custom := filepath.Join(t.TempDir(), "elsewhere.pem")

	for _, tc := range []struct {
		name string
		set  bool
		env  string
		want string
	}{
		{"absent: the per-image default", false, "", defaultCABundlePath},
		{"empty: the per-image default", true, "", defaultCABundlePath},
		{"whitespace only: the per-image default, not a path that cannot exist",
			true, "   ", defaultCABundlePath},
		{"a tab: the per-image default", true, "\t", defaultCABundlePath},
		{"a real path is honoured", true, custom, custom},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("RASPUTIN_MESH_CA_BUNDLE", tc.env)
			} else {
				os.Unsetenv("RASPUTIN_MESH_CA_BUNDLE")
			}
			if got := caBundlePath(); got != tc.want {
				t.Fatalf("caBundlePath() = %q, want %q", got, tc.want)
			}
			if got := CABundlePath(); got != tc.want {
				t.Fatalf("CABundlePath() = %q, want %q — the exported accessor must "+
					"resolve identically, or the agent and tailscaled read different files", got, tc.want)
			}
		})
	}
}

func TestInstalledCAFingerprint_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	dir := t.TempDir()

	write := func(name string, data []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, mode); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	unreadable := write("unreadable.pem", []byte("-----BEGIN CERTIFICATE-----\n"), 0o600)
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	// "none" means this node trusts no mesh CA. Every shape that leaves the
	// agent without a usable bundle has to reach it, because the api's
	// converge step re-enrols a node whose report does not match its own CA,
	// and a node that answered anything else here would be left alone.
	none := []struct {
		name string
		path string
	}{
		{"absent", filepath.Join(dir, "missing.pem")},
		{"empty", write("empty.pem", nil, 0o600)},
		{"whitespace only", write("blank.pem", []byte("\n\n  \t\n"), 0o600)},
		{"a directory, not a file", dir},
	}
	if os.Geteuid() != 0 {
		none = append(none, struct {
			name string
			path string
		}{"unreadable", unreadable})
	} else {
		// Mode bits do not stop root, so asserting the unreadable case here
		// would pass for the wrong reason.
		t.Log("running as root: skipping the unreadable case")
	}

	for _, tc := range none {
		t.Run(tc.name, func(t *testing.T) {
			if got := InstalledCAFingerprint(tc.path); got != proto.MeshCAFingerprintNone {
				t.Fatalf("InstalledCAFingerprint(%s) = %q, want %q", tc.name, got,
					proto.MeshCAFingerprintNone)
			}
		})
	}

	// A file that holds SOMETHING is fingerprinted rather than rejected, which
	// is deliberate: this is a content fingerprint for comparison, not a
	// validity check. The property that matters is that a bundle which is not
	// the api's CA can never fingerprint equal to it, so the api re-enrols the
	// node instead of leaving it alone.
	realCA := []byte("-----BEGIN CERTIFICATE-----\nthe api's mesh CA\n-----END CERTIFICATE-----\n")
	want := proto.MeshCAFingerprint(realCA)
	for _, tc := range []struct {
		name    string
		content []byte
	}{
		{"not a certificate at all", []byte("this is not a certificate\n")},
		{"a truncated PEM", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n")},
		{"some other cluster's CA", []byte("-----BEGIN CERTIFICATE-----\nanother cluster\n-----END CERTIFICATE-----\n")},
	} {
		t.Run("does not pass for the api's CA: "+tc.name, func(t *testing.T) {
			p := write("case.pem", tc.content, 0o600)
			got := InstalledCAFingerprint(p)
			if got == proto.MeshCAFingerprintNone {
				t.Fatalf("InstalledCAFingerprint = %q for a non-empty bundle; the api "+
					"needs a fingerprint it can compare", got)
			}
			if got == want {
				t.Fatalf("InstalledCAFingerprint = the api's own fingerprint for %s — "+
					"the node would be left un-enrolled with a bundle that is not the CA",
					tc.name)
			}
		})
	}

	// And the CA itself fingerprints to exactly what the api computes, or
	// every node would be re-enrolled on every reconcile.
	t.Run("the real CA matches the api's fingerprint", func(t *testing.T) {
		p := write("real.pem", realCA, 0o600)
		if got := InstalledCAFingerprint(p); got != want {
			t.Fatalf("InstalledCAFingerprint = %q, want %q", got, want)
		}
	})
}
