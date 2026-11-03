//go:build !release

package artifactsig

// releaseBuild is false in every build without -tags release: dev boxes, CI
// and local stacks. See release_on.go.
const releaseBuild = false
