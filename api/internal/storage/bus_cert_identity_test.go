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
// without it still restores, and the manifest note says so: no client pins the
// certificate, so a re-minted one changes nothing (geekdojo/geekdojo-brain#672).
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
	if !strings.Contains(cert.note, "no client pins the certificate") || strings.Contains(cert.note, "collector") {
		t.Fatalf("the manifest note does not say a re-minted certificate is harmless: %q", cert.note)
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
