package nodetrust

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/proto/tlstest"
)

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// TC-741-18: Install reports changed for new bytes and unchanged for
// identical ones, writes the bundle 0644 in a 0700 dir, and touches no other
// file; Fingerprint tracks it; BundlePath honours the override.
func TestStore_InstallFingerprintAndModes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mesh", "tailscaled-ca.pem")
	global := filepath.Join(dir, "ca-certificates.crt")
	if err := os.WriteFile(global, []byte("public roots\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewStore(path)
	if s.Path() != path {
		t.Fatalf("Path() %q", s.Path())
	}
	if got := s.Fingerprint(); got != proto.TrustFingerprintNone {
		t.Fatalf("no bundle: %q", got)
	}
	a, b := tlstest.NewCA(t, "a"), tlstest.NewCA(t, "b")

	changed, err := s.Install(a.PEM)
	if err != nil || !changed {
		t.Fatalf("first install: changed=%v err=%v", changed, err)
	}
	if got := mode(t, path); got != 0o644 {
		t.Errorf("bundle mode %o, want 644", got)
	}
	if got := mode(t, filepath.Dir(path)); got != 0o700 {
		t.Errorf("dir mode %o, want 700", got)
	}
	if got, want := s.Fingerprint(), proto.TrustFingerprint(a.PEM); got != want {
		t.Errorf("fingerprint %s, want the api's fingerprint of the same PEM %s", got, want)
	}
	if changed, err := s.Install(a.PEM); err != nil || changed {
		t.Errorf("identical install: changed=%v err=%v, want unchanged", changed, err)
	}
	if changed, err := s.Install(append(append(append([]byte{}, a.PEM...), '\n'), b.PEM...)); err != nil || !changed {
		t.Errorf("two-CA bundle: changed=%v err=%v", changed, err)
	}
	if b, _ := os.ReadFile(global); !bytes.Equal(b, []byte("public roots\n")) {
		t.Error("the global trust bundle was touched")
	}
	// An empty file reads as trusting nothing, not the fingerprint of nothing.
	if err := os.WriteFile(path, []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := s.Fingerprint(); got != proto.TrustFingerprintNone {
		t.Errorf("empty bundle: %q", got)
	}
}

// Validate refuses everything that is not a bundle of CA certificates, and
// Install leaves the file as it was when it does.
func TestStore_InstallRefusesAndLeavesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailscaled-ca.pem")
	s := NewStore(path)
	good := tlstest.NewCA(t, "good").PEM
	if _, err := s.Install(good); err != nil {
		t.Fatal(err)
	}
	for name, in := range refusedBundles(t) {
		if _, err := s.Install(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if b, _ := os.ReadFile(path); !bytes.Equal(b, append(bytes.TrimSpace(good), '\n')) {
			t.Errorf("%s: the bundle changed", name)
		}
	}
}

// refusedBundles is every input shape trust.install must refuse.
func refusedBundles(t *testing.T) map[string][]byte {
	good := tlstest.NewCA(t, "x").PEM
	return map[string][]byte{
		"empty":                             nil,
		"not PEM":                           []byte("not a certificate at all"),
		"no CERTIFICATE":                    []byte("   \n\t"),
		"a PRIVATE KEY block":               tlstest.KeyOnlyPEM(t),
		"a certificate and a key":           append(append(append([]byte{}, good...), '\n'), tlstest.KeyOnlyPEM(t)...),
		"a CERTIFICATE that does not parse": []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
		"bytes outside a block":             append([]byte("stray\n"), good...),
		"bytes after the last block":        append(append([]byte{}, good...), []byte("trailing junk\n")...),
	}
}

func TestBundlePath_Override(t *testing.T) {
	t.Setenv("RASPUTIN_MESH_CA_BUNDLE", "/custom/ca.pem")
	if got := BundlePath(); got != "/custom/ca.pem" {
		t.Errorf("override not honoured: %q", got)
	}
	t.Setenv("RASPUTIN_MESH_CA_BUNDLE", " \t")
	if got := BundlePath(); got != defaultBundlePath {
		t.Errorf("a whitespace override is not the default: %q", got)
	}
}
