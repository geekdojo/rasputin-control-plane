//go:build release

package artifactsig

// releaseBuild is true in a binary built with -tags release, which
// scripts/build-release.sh passes to every binary it ships and asserts after
// each build (geekdojo/geekdojo-brain#529).
const releaseBuild = true
