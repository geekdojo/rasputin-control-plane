//go:build !release

package artifactsig

import "testing"

// TC-529-17 (default build half): a binary built without -tags release is not
// a release build, so dev boxes and local stacks keep their overrides.
func TestReleaseBuild_FalseWithoutTheTag(t *testing.T) {
	if ReleaseBuild() {
		t.Fatal("ReleaseBuild() = true in a build without -tags release")
	}
	t.Setenv(TrustRootEnv, "/somewhere/else.pem")
	if got := TrustRootPath(); got != "/somewhere/else.pem" {
		t.Errorf("a non-release build must honour %s: got %q", TrustRootEnv, got)
	}
}
