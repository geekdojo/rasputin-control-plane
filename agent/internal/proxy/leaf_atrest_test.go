//go:build unix

package proxy

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The at-rest modes of an app's leaf directory (geekdojo/geekdojo-brain#832):
// everything LeafStore writes is owner-only whatever the umask, and an
// older agent's 0755/0644 leaves are corrected both by a rewrite and by
// TightenExisting at start. No test in this package runs in parallel, so the
// process-wide umask is safe to change here.

func zeroUmask(t *testing.T) {
	t.Helper()
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })
}

func leafPerm(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

var testMeta = RouteMeta{TailnetFQDN: "a1.home1.internal", UpstreamPort: 8080}

// seedOldLeaf lays down app's leaf directory the way an agent before #832 did:
// the directory 0755 and each file 0644, holding the given contents.
func seedOldLeaf(t *testing.T, s *LeafStore, app string, files map[string][]byte) {
	t.Helper()
	dir := s.appDir(app)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func assertLeafModes(t *testing.T, s *LeafStore, app string) {
	t.Helper()
	if got := leafPerm(t, s.appDir(app)); got != 0o700 {
		t.Errorf("%s dir: mode %#o, want 0700", app, got)
	}
	for _, p := range []string{s.CertPath(app), s.KeyPath(app), s.metaPath(app)} {
		if got := leafPerm(t, p); got != 0o600 {
			t.Errorf("%s: mode %#o, want 0600", p, got)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TC-832-01: a fresh Write under umask 0 gives a 0700 directory and 0600 for
// the certificate, the key and the route metadata.
func TestLeafStore_WriteIsOwnerOnly(t *testing.T) {
	zeroUmask(t)
	s := NewLeafStore(t.TempDir())
	if err := s.Write("a1", []byte("CERT"), []byte("KEY"), testMeta); err != nil {
		t.Fatal(err)
	}
	assertLeafModes(t, s, "a1")
}

// TC-832-02: a rewrite over an older agent's 0755/0644 leaf fixes every mode
// and holds the new contents.
func TestLeafStore_WriteTightensAnOldLeaf(t *testing.T) {
	zeroUmask(t)
	s := NewLeafStore(t.TempDir())
	seedOldLeaf(t, s, "a1", map[string][]byte{
		certFile: []byte("OLD CERT"), keyFile: []byte("OLD KEY"), metaFile: []byte("{}"),
	})
	if err := s.Write("a1", []byte("NEW CERT"), []byte("NEW KEY"), testMeta); err != nil {
		t.Fatal(err)
	}
	assertLeafModes(t, s, "a1")
	if got := readFile(t, s.CertPath("a1")); got != "NEW CERT" {
		t.Errorf("cert = %q, want NEW CERT", got)
	}
}

// TC-832-03: TightenExisting over an old install fixes the directory and the
// three leaf files without touching their contents, and leaves a file the
// agent did not write at its own mode.
func TestLeafStore_TightenExisting(t *testing.T) {
	zeroUmask(t)
	s := NewLeafStore(t.TempDir())
	seed := map[string][]byte{
		certFile: []byte("CERT"), keyFile: []byte("KEY"), metaFile: []byte(`{"upstreamPort":8080}`),
		"other": []byte("not ours"),
	}
	seedOldLeaf(t, s, "a1", seed)

	if err := s.TightenExisting(); err != nil {
		t.Fatalf("TightenExisting: %v", err)
	}
	assertLeafModes(t, s, "a1")
	for name, want := range seed {
		if got := readFile(t, filepath.Join(s.appDir("a1"), name)); got != string(want) {
			t.Errorf("%s contents = %q, want %q", name, got, want)
		}
	}
	if got := leafPerm(t, filepath.Join(s.appDir("a1"), "other")); got != 0o644 {
		t.Errorf("other: mode %#o, want 0644 (not an agent-written file)", got)
	}
}

// TC-832-04: a node with no published app has no certs/; TightenExisting
// returns nil and creates nothing.
func TestLeafStore_TightenExistingNoCerts(t *testing.T) {
	dir := t.TempDir()
	s := NewLeafStore(dir)
	if err := s.TightenExisting(); err != nil {
		t.Errorf("TightenExisting with no certs/: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "certs")); !os.IsNotExist(err) {
		t.Errorf("certs/ was created (Lstat: %v)", err)
	}
}

const (
	seededCert = "-----BEGIN CERTIFICATE-----\nTC832SEEDEDCERTBYTES\n"
	seededKey  = "-----BEGIN PRIVATE KEY-----\nTC832SEEDEDKEYBYTES\n"
)

// symlinkedLeafInstall is the TC-832-05 setup: a1/leaf.pem is a symlink to a
// 0644 file outside the tree, a1's key and meta are 0644, and a2/leaf.pem is
// 0644. It returns the store, the symlink's path and its target's path.
func symlinkedLeafInstall(t *testing.T) (*LeafStore, string, string) {
	t.Helper()
	zeroUmask(t)
	s := NewLeafStore(t.TempDir())
	target := filepath.Join(t.TempDir(), "elsewhere.pem")
	if err := os.WriteFile(target, []byte(seededCert), 0o644); err != nil {
		t.Fatal(err)
	}
	seedOldLeaf(t, s, "a1", map[string][]byte{keyFile: []byte(seededKey), metaFile: []byte("{}")})
	link := s.CertPath("a1")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	seedOldLeaf(t, s, "a2", map[string][]byte{certFile: []byte(seededCert)})
	return s, link, target
}

// TC-832-05: one bad entry does not stop the rest, and a symlinked leaf is
// refused, not followed.
func TestLeafStore_TightenExistingBestEffortRefusesSymlink(t *testing.T) {
	s, link, target := symlinkedLeafInstall(t)

	err := s.TightenExisting()
	if err == nil {
		t.Fatal("TightenExisting over a symlinked leaf returned nil")
	}
	if !strings.Contains(err.Error(), link) {
		t.Errorf("error %q does not name %s", err, link)
	}
	if got := leafPerm(t, target); got != 0o644 {
		t.Errorf("symlink target: mode %#o, want 0644 (followed)", got)
	}
	for _, p := range []string{s.KeyPath("a1"), s.metaPath("a1"), s.CertPath("a2")} {
		if got := leafPerm(t, p); got != 0o600 {
			t.Errorf("%s: mode %#o, want 0600", p, got)
		}
	}
}

// TC-832-11: the tighten reads no credential material, so its error carries
// paths and actions only, never the seeded certificate or key bytes.
func TestLeafStore_TightenExistingErrorCarriesNoCredential(t *testing.T) {
	s, _, _ := symlinkedLeafInstall(t)

	err := s.TightenExisting()
	if err == nil {
		t.Fatal("TightenExisting over a symlinked leaf returned nil")
	}
	for _, secret := range []string{"TC832SEEDEDCERTBYTES", "TC832SEEDEDKEYBYTES", "BEGIN"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error carries %q: %q", secret, err)
		}
	}
}

// TC-832-10: a Write after the start pass keeps the certificate 0600 and
// holds the new bytes.
func TestLeafStore_WriteAfterTightenExisting(t *testing.T) {
	zeroUmask(t)
	s := NewLeafStore(t.TempDir())
	seedOldLeaf(t, s, "a1", map[string][]byte{
		certFile: []byte("OLD CERT"), keyFile: []byte("OLD KEY"), metaFile: []byte("{}"),
	})
	if err := s.TightenExisting(); err != nil {
		t.Fatal(err)
	}
	if got := leafPerm(t, s.CertPath("a1")); got != 0o600 {
		t.Fatalf("after TightenExisting: cert mode %#o, want 0600", got)
	}
	if err := s.Write("a1", []byte("NEW CERT"), []byte("NEW KEY"), testMeta); err != nil {
		t.Fatal(err)
	}
	if got := leafPerm(t, s.CertPath("a1")); got != 0o600 {
		t.Errorf("after Write: cert mode %#o, want 0600", got)
	}
	if got := readFile(t, s.CertPath("a1")); got != "NEW CERT" {
		t.Errorf("cert = %q, want NEW CERT", got)
	}
}
