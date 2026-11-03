//go:build release

package artifactsig

import (
	"path/filepath"
	"testing"
)

// TC-529-17: the compiled-in release branch. Run by CI's release-tag step
// (go test -tags release -run ReleaseBuild). A release binary is a release
// build, and TrustRootPath ignores a set RASPUTIN_TRUST_ROOT.
func TestReleaseBuild_TrustRootPathIgnoresTheEnvironment(t *testing.T) {
	if !ReleaseBuild() {
		t.Fatal("ReleaseBuild() = false in a build with -tags release")
	}
	t.Setenv(TrustRootEnv, filepath.Join(t.TempDir(), "root-ca.pem"))
	if got := TrustRootPath(); got != DefaultTrustRoot {
		t.Errorf("a release build honoured %s: got %q, want %q", TrustRootEnv, got, DefaultTrustRoot)
	}
}
