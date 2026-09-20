package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
)

// The bus certificate travels with the key in the identity set
// (geekdojo/geekdojo-brain#508). It is derivable from the key, so an archive
// without it still restores — but a client that pins its exact bytes (the
// collector's ca_pem) refuses a re-minted one, so it is captured and put back.
func TestIdentitySet_CarriesTheBusCertificate(t *testing.T) {
	busDir := t.TempDir()
	src := IdentitySources{BusDir: busDir, TrustDir: t.TempDir()}

	var cert *trustFile
	for i, f := range trustFiles(src) {
		if f.arc == busCertArchivePath {
			cert = &trustFiles(src)[i]
		}
	}
	if cert == nil {
		t.Fatalf("no %q in the identity set: %+v", busCertArchivePath, trustFiles(src))
	}
	if want := filepath.Join(busDir, bustls.CertFileName); cert.abs != want {
		t.Fatalf("captured from %q, want %q", cert.abs, want)
	}
	if !strings.Contains(cert.note, "pins its exact bytes") {
		t.Fatalf("the manifest note does not say why it is captured: %q", cert.note)
	}

	// A restore recognises it as part of the identity set, with the same note.
	note, ok := identityRestorePath(busCertArchivePath)
	if !ok || note != cert.note {
		t.Fatalf("identityRestorePath(%q) = (%q, %t), want the capture note", busCertArchivePath, note, ok)
	}

	// And it is measured like every other identity file, so the staging guard
	// and the target estimate size it rather than guess.
	key, _, err := bustls.EnsureKey(busDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bustls.EnsureCert(busDir, key); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(busDir, bustls.CertFileName))
	if err != nil {
		t.Fatal(err)
	}
	withCert := MeasureIdentitySet(src, 0)
	if err := os.Remove(filepath.Join(busDir, bustls.CertFileName)); err != nil {
		t.Fatal(err)
	}
	withoutCert := MeasureIdentitySet(src, 0)
	if withCert <= withoutCert {
		t.Fatalf("the certificate (%d bytes) is not measured: %d with it, %d without", fi.Size(), withCert, withoutCert)
	}
}
