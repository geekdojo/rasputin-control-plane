package artifactsig

import (
	"os"
	"path/filepath"
	"testing"
)

// A check against the REAL published release assets, kept in the tree so it can
// be re-run rather than described. Everything else in this package tests
// certificates minted by the test itself, which proves the logic and cannot
// prove that the shape it expects is the shape the pipeline actually produces.
//
//	gh release download <tag> --repo geekdojo/rasputin-os --pattern '*.raucb'
//	curl -fsSLO https://rasputin.geekdojo.com/rasputin-root-ca.pem   # as root-ca.pem
//	RASPUTIN_REAL_ASSETS=<that dir> go test ./artifactsig/ -run RealPublished -v
//
// Skipped without that directory, so it never runs in CI and never depends on
// the network.
func TestRealPublishedBundles(t *testing.T) {
	dir := os.Getenv("RASPUTIN_REAL_ASSETS")
	if dir == "" {
		t.Skip("set RASPUTIN_REAL_ASSETS to a directory holding root-ca.pem and published .raucb files")
	}
	root := filepath.Join(dir, "root-ca.pem")
	bundles, err := filepath.Glob(filepath.Join(dir, "*.raucb"))
	if err != nil || len(bundles) == 0 {
		t.Fatalf("no .raucb in %s: %v", dir, err)
	}
	for _, b := range bundles {
		res, err := VerifyRAUCBundleSignerForPurpose(b, root, OIDCodeSigningRelease)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(b), err)
			continue
		}
		t.Logf("%s: release-authorized, signer %q issued by %q, expires %s",
			filepath.Base(b), res.Signer, res.Issuer, res.NotAfter.UTC())
		// The same bundle must NOT satisfy the catalog purpose.
		if _, err := VerifyRAUCBundleSignerForPurpose(b, root, OIDCodeSigningCatalog); err == nil {
			t.Errorf("%s: a release bundle satisfied the CATALOG purpose", filepath.Base(b))
		}
	}
}
