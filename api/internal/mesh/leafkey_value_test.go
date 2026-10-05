package mesh

import (
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-825-09: an app leaf's private key is a secret.Value from MintLeaf and
// PrepareAppLeaf to the file CommitAppLeaf writes through writeKey, and the
// file holds exactly the Value's bytes.
func TestAppLeaf_KeyIsAValueFromMintToDisk(t *testing.T) {
	ca := newCAForTest(t)
	dir := t.TempDir()

	certPEM, key, renewed, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin")
	if err != nil {
		t.Fatalf("first prepare: %v", err)
	}
	if !renewed || key.Len() == 0 {
		t.Fatalf("first prepare: renewed=%v key bytes=%d, want a fresh leaf with its key", renewed, key.Len())
	}
	if _, err := tls.X509KeyPair(certPEM, key.Reveal()); err != nil {
		t.Fatalf("the minted key does not pair with its certificate: %v", err)
	}
	if err := CommitAppLeaf(dir, certPEM, key); err != nil {
		t.Fatalf("commit: %v", err)
	}
	onDisk, err := os.ReadFile(LeafPathsIn(dir).KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, key.Reveal()) {
		t.Fatal("the committed key file is not the Value's bytes")
	}

	_, again, renewed, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin")
	if err != nil {
		t.Fatalf("second prepare: %v", err)
	}
	if renewed {
		t.Error("a committed, usable leaf came back renewed")
	}
	if !bytes.Equal(again.Reveal(), onDisk) {
		t.Error("the second prepare's key is not the file's bytes")
	}

	// The two Values own separate payloads: destroying one leaves the other.
	key.Destroy()
	if again.Len() == 0 {
		t.Error("destroying the minted key emptied the one read back from disk")
	}
}

// TC-825-09: the failure rows. A nil CA is an error with the zero Value from
// MintLeaf and PrepareAppLeaf, and writeKey under a path that is a file is an
// error. An unreadable key FILE is not an error: loadLeafIfUsable treats it as
// no usable leaf, so PrepareAppLeaf mints a fresh one (renewed) instead of
// returning bytes it could not read.
func TestAppLeaf_FailuresReturnAZeroValue(t *testing.T) {
	if _, key, err := MintLeaf(nil, LeafSpec{CommonName: "x", DNSNames: []string{"x"}}); err == nil || key.Len() != 0 {
		t.Errorf("MintLeaf(nil CA): err=%v key bytes=%d, want an error and the zero Value", err, key.Len())
	}
	if _, key, _, err := PrepareAppLeaf(nil, t.TempDir(), "home1", "app"); err == nil || key.Len() != 0 {
		t.Errorf("PrepareAppLeaf(nil CA): err=%v key bytes=%d, want an error and the zero Value", err, key.Len())
	}
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeKey(filepath.Join(notADir, "leaf.key"), secret.New([]byte("k"))); err == nil {
		t.Error("writeKey under a path that is a file succeeded")
	}

	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0000 file; the unreadable-key row needs an unprivileged user")
	}
	ca := newCAForTest(t)
	dir := t.TempDir()
	certPEM, key, _, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin")
	if err != nil {
		t.Fatal(err)
	}
	if err := CommitAppLeaf(dir, certPEM, key); err != nil {
		t.Fatal(err)
	}
	keyPath := LeafPathsIn(dir).KeyPath
	if err := os.Chmod(keyPath, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(keyPath, 0o600) })
	_, fresh, renewed, err := PrepareAppLeaf(ca, dir, "home1", "jellyfin")
	if err != nil {
		t.Fatalf("an unreadable key file must re-mint, not fail: %v", err)
	}
	if !renewed || fresh.Len() == 0 || bytes.Equal(fresh.Reveal(), key.Reveal()) {
		t.Errorf("an unreadable key file: renewed=%v key bytes=%d, want a freshly minted key", renewed, fresh.Len())
	}
}
