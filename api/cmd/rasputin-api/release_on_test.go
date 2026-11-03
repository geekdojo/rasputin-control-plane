//go:build release

package main

import (
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/artifactsig"
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
