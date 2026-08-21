package catalogsync

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// artifactsig's fixtures, reached across modules. Reusing them rather than
// minting a second set keeps one definition of "a correctly signed artifact".
func sigFixture(name string) string {
	return filepath.Join("..", "..", "..", "artifactsig", "testdata", name)
}

// The integration the fake verifier cannot prove: the REAL verifier, wired into
// the store, refusing an artifact signed by the release leaf.
//
// Both signatures below are cryptographically valid and both chain to the same
// trusted root. They differ only in what the signing certificate was authorized
// to do. A store that verified signatures generically would accept both, and
// nothing about the failure would look like a security problem.
func TestStore_RealVerifier_RefusesAReleaseSignedCatalog(t *testing.T) {
	v := NewVerifier(sigFixture("root-ca.pem"))
	s, err := New(t.TempDir(), v, bundle(1, "floor"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	payload := sigFixture("payload.bin")

	// Signed by the RELEASE leaf: must be refused on authorization, before the
	// content is ever parsed.
	err = s.Apply(payload, sigFixture("payload.bin.sig"))
	if err == nil {
		t.Fatal("a release-signed artifact must not be accepted as a catalog")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("want an authorization failure, got %v", err)
	}

	// Signed by the CATALOG leaf: authorization passes, so the failure moves on
	// to the content — which is a random payload, not a bundle. That the error
	// CHANGES is the proof the purpose gate ran and then got out of the way.
	err = s.Apply(payload, sigFixture("payload.bin.catalog.sig"))
	if err == nil {
		t.Fatal("a random payload must not parse as a bundle")
	}
	if strings.Contains(err.Error(), "signature") {
		t.Errorf("a catalog-signed artifact must clear authorization; got %v", err)
	}

	// Neither attempt disturbed the catalog in effect.
	if got := s.Current().Version; got != 1 {
		t.Fatalf("current = v%d, want the untouched floor v1", got)
	}
}

func TestNewVerifier_MissingTrustRootIsAFailureNotAPass(t *testing.T) {
	v := NewVerifier(filepath.Join(t.TempDir(), "absent-root.pem"))
	err := v.VerifyForPurpose(sigFixture("payload.bin"), sigFixture("payload.bin.catalog.sig"))
	if err == nil {
		t.Fatal("a missing trust root must fail the check, never skip it")
	}
}

// Guards the floor contract from the other direction: a floor that is not a
// valid bundle is a build defect, and starting on it would mean shipping a
// catalog the reader would reject.
func TestNew_RejectsAnInvalidFloor(t *testing.T) {
	if _, err := New(t.TempDir(), NewVerifier("x"), tileschema.Bundle{}); err == nil {
		t.Fatal("an invalid embedded floor must be refused at construction")
	}
}
