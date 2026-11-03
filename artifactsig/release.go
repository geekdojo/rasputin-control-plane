package artifactsig

// ReleaseBuild reports whether this binary was built with the release tag.
//
// It is fixed at compile time, deliberately. A runtime marker (a file on the
// image, an image-version string) can be absent or re-pointed through
// node.env, and either would turn a shipped binary back into one that honours
// development overrides. A build tag cannot change after the build, and
// scripts/build-release.sh refuses to package a binary that lacks it.
//
// A release build ignores the settings that exist only for development: the
// publisher trust root (trustRootPath) and, in the api, the app catalog's
// source.
func ReleaseBuild() bool { return releaseBuild }
