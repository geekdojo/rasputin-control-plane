//go:build release

package main

import (
	"log/slog"
	"slices"
	"sync/atomic"
	"testing"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/artifactsig"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-529-17: the compiled-in release branch of the api's catalog source. Run by
// CI's release-tag step (go test -tags release -run ReleaseBuild). With both
// catalog variables set, a release binary still fetches Geekdojo's catalog at
// the release API base, and names both as ignored.
func TestReleaseBuild_CatalogSourceIsFixed(t *testing.T) {
	if !artifactsig.ReleaseBuild() {
		t.Fatal("artifactsig.ReleaseBuild() = false in a build with -tags release")
	}
	t.Setenv(catalogRepoEnv, "evil/catalog")
	t.Setenv(catalogAPIBaseEnv, "https://evil.example")
	const releaseBase = "https://api.example.test"

	repo, base, ignored := catalogSource(releaseBase)
	if repo != "geekdojo/rasputin-app-catalog" {
		t.Errorf("repo = %q, want geekdojo/rasputin-app-catalog", repo)
	}
	if base != releaseBase {
		t.Errorf("apiBase = %q, want %q", base, releaseBase)
	}
	if want := []string{catalogRepoEnv, catalogAPIBaseEnv}; !slices.Equal(ignored, want) {
		t.Errorf("ignored = %v, want %v", ignored, want)
	}
}

// TC-982-06 (F-982-01): main's identity binding on a release binary. With
// RASPUTIN_IDENTITY_BACKEND=mock in the environment, wireIdentityFromEnv,
// the one call main makes, passes the compiled-in marker, so the mock is
// refused: identity is off with one configfault ERROR naming the value, every
// call refuses with ErrDisabled, and the api keeps starting.
func TestReleaseBuild_IdentityMockIsRefused(t *testing.T) {
	t.Setenv("RASPUTIN_IDENTITY_BACKEND", "mock")
	for _, k := range []string{"RASPUTIN_IDENTITY_ADDR", "RASPUTIN_IDENTITY_MGMT_ADDR"} {
		setOrUnset(t, k, true, "")
	}
	ca := ensureIdentityCA(t, t.TempDir(), tlscatest.Deps())
	log, rec := logkittest.New()
	w, err := wireIdentityFromEnv(t.Context(), log, ca, t.TempDir(), (&scriptedRun{}).run, noRunIn, &atomic.Pointer[restoredFunc]{})
	if err != nil {
		t.Fatalf("wireIdentityFromEnv: %v", err)
	}
	if w.mode != identityModeOff {
		t.Errorf("mode = %q, want off", w.mode)
	}
	recs := rec.Records()
	if len(recs) != 1 || recs[0].Level != slog.LevelError || recs[0].Message != "identity service off: configuration refused" {
		t.Fatalf("records:\n%s\nwant exactly one configfault ERROR", rec.Text())
	}
	if a := attrsOf(recs[0]); a["configfault"] != "true" || a["setting"] != "RASPUTIN_IDENTITY_BACKEND" || a["value"] != "mock" || a["reason"] == "" {
		t.Errorf("configfault record attrs = %v", a)
	}
	assertRefuses(t, w, idclient.ErrDisabled)
	assertKindUnknown(t, w)
}
