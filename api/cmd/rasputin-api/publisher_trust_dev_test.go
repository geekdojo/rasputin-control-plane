//go:build !release

package main

// These tests drive the wiring through artifactsig.TrustRootPath with
// RASPUTIN_TRUST_ROOT set, which only a non-release build honours. The release
// branch is TestReleaseBuild_* (release_on_test.go) and the pure resolver
// tables.

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/catalog/floor"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalogsync"
	"github.com/geekdojo/rasputin-control-plane/artifactsig"
)

// catalogStoreOn builds a catalog store on v over the real embedded floor, and
// returns it with the floor's version.
func catalogStoreOn(t *testing.T, v catalogsync.Verifier) (*catalogsync.Store, int) {
	t.Helper()
	fl, err := floor.Load()
	if err != nil {
		t.Fatalf("floor.Load: %v", err)
	}
	s, err := catalogsync.New(t.TempDir(), v, fl)
	if err != nil {
		t.Fatalf("catalogsync.New: %v", err)
	}
	return s, fl.Version
}

// trustDirHolding returns a trust dir with the named fixture root copied to
// <trustDir>/root-ca.pem, where the api read its publisher root before #529.
func trustDirHolding(t *testing.T, fixture string) string {
	t.Helper()
	dir := t.TempDir()
	copyFixture(t, fixture, filepath.Join(dir, "root-ca.pem"))
	return dir
}

// TC-529-08: one read path. The updater and catalog verifiers are both built on
// the root TrustRootPath resolved, both verify under it, and both fail closed
// together when that one file goes bad.
func TestPublisherTrust_OneReadPathFailsClosedTogether(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root-ca.pem")
	copyFixture(t, "root-ca.pem", root)
	t.Setenv(artifactsig.TrustRootEnv, root)
	logger := slog.New(slog.DiscardHandler)
	payload := sigFixture("payload.bin")

	upd, cat := wirePublisherTrust(logger, artifactsig.TrustRootPath())
	if got := upd.TrustRoot(); got != root {
		t.Fatalf("updater TrustRoot = %q, want %q", got, root)
	}
	if _, err := upd.VerifyArtifact(payload, sigFixture("payload.bin.sig")); err != nil {
		t.Fatalf("updater refused the release signature: %v", err)
	}
	if err := cat.VerifyForPurpose(payload, sigFixture("payload.bin.catalog.sig")); err != nil {
		t.Fatalf("catalog verifier refused the catalog signature: %v", err)
	}

	if err := os.WriteFile(root, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cat.VerifyForPurpose(payload, sigFixture("payload.bin.catalog.sig")); !errors.Is(err, artifactsig.ErrNoTrustRoot) {
		t.Errorf("catalog verifier on a garbage root: want ErrNoTrustRoot, got %v", err)
	}
	store, floorVersion := catalogStoreOn(t, cat)
	err := store.Apply(payload, sigFixture("payload.bin.catalog.sig"))
	if !errors.Is(err, artifactsig.ErrNoTrustRoot) {
		t.Errorf("Apply on a garbage root: want a signature refusal (ErrNoTrustRoot), got %v", err)
	}
	if got := store.Current().Version; got != floorVersion {
		t.Errorf("current = v%d, want the floor v%d", got, floorVersion)
	}
	if upd2, _ := wirePublisherTrust(logger, artifactsig.TrustRootPath()); upd2.Available() {
		t.Error("re-wiring on a garbage root gave an available updater verifier")
	}
}

// TC-529-09: the OS and firewall path never trusts <trustDir>/root-ca.pem. The
// Geekdojo fixture root sits there and RASPUTIN_TRUST_ROOT names the other
// root; only the root differs between the two signatures, so a refusal of the
// Geekdojo-signed one can only mean the trustDir file was not used.
func TestPublisherTrust_UpdaterNeverTrustsTheTrustDirRoot(t *testing.T) {
	trustDirHolding(t, "root-ca.pem")
	other, err := filepath.Abs(sigFixture("other-root-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(artifactsig.TrustRootEnv, other)

	upd, _ := wirePublisherTrust(slog.New(slog.DiscardHandler), artifactsig.TrustRootPath())
	if got := upd.TrustRoot(); got != other {
		t.Fatalf("TrustRoot = %q, want the env path %q", got, other)
	}
	if _, err := upd.VerifyArtifact(sigFixture("payload.bin"), sigFixture("payload.bin.sig")); err == nil {
		t.Error("a signature under the trustDir root was accepted")
	}
	if _, err := upd.VerifyArtifact(sigFixture("payload.bin"), sigFixture("payload.bin.other.sig")); err != nil {
		t.Errorf("a signature under the resolved root was refused: %v", err)
	}
}

// TC-529-10: with RASPUTIN_TRUST_ROOT unset the wiring resolves to the baked
// path and does not fall back to a valid root in the trust dir.
func TestPublisherTrust_UnsetEnvResolvesTheBakedPath(t *testing.T) {
	if _, err := os.Stat(artifactsig.DefaultTrustRoot); err == nil {
		t.Fatalf("this test needs a host without a baked root at %s", artifactsig.DefaultTrustRoot)
	}
	trustDirHolding(t, "root-ca.pem")
	setOrUnset(t, artifactsig.TrustRootEnv, true, "")

	upd, _ := wirePublisherTrust(slog.New(slog.DiscardHandler), artifactsig.TrustRootPath())
	if got := upd.TrustRoot(); got != artifactsig.DefaultTrustRoot {
		t.Errorf("TrustRoot = %q, want %q", got, artifactsig.DefaultTrustRoot)
	}
	if upd.Available() {
		t.Error("the verifier is available with no baked root: it loaded something else")
	}
}

// TC-529-11: the catalog never trusts <trustDir>/root-ca.pem. TC-529-08 is the
// positive control: the same catalog signature verifies under its own root.
func TestPublisherTrust_CatalogNeverTrustsTheTrustDirRoot(t *testing.T) {
	trustDirHolding(t, "root-ca.pem")
	other, err := filepath.Abs(sigFixture("other-root-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(artifactsig.TrustRootEnv, other)
	payload, sig := sigFixture("payload.bin"), sigFixture("payload.bin.catalog.sig")

	_, cat := wirePublisherTrust(slog.New(slog.DiscardHandler), artifactsig.TrustRootPath())
	if err := cat.VerifyForPurpose(payload, sig); err == nil {
		t.Error("a catalog signature under the trustDir root was accepted")
	}
	store, floorVersion := catalogStoreOn(t, cat)
	err = store.Apply(payload, sig)
	if err == nil || !strings.HasPrefix(err.Error(), "signature:") {
		t.Errorf("Apply: want a signature refusal, got %v", err)
	}
	if got := store.Current().Version; got != floorVersion {
		t.Errorf("current = v%d, want the floor v%d", got, floorVersion)
	}
}
