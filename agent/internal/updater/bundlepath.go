package updater

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Bundle paths are built from values that arrive ON THE BUS — BundleID and
// LocalPath in proto.UpdateDownloadCmd and proto.UpdateInstallCmd — and until
// this file existed every backend interpolated them into a filesystem path
// with no validation whatsoever:
//
//	dest := filepath.Join(r.stateDir, "bundles", bundleID+".raucb")   // download WRITES here
//	if localPath == "" { localPath = ... }                            // install READS/EXECs this
//
// A `../` in either one escaped the state directory. Nothing was exploitable
// in the shipped flow — the api sends a bare sha256 as BundleID and
// deliberately leaves LocalPath empty (api/internal/updater/jobs.go, "LocalPath
// is empty") — but nothing at the agent ENFORCED that, and "the sender happens
// to be well-behaved" is not a property the receiving side gets to assume. A
// compromised or impersonated control plane is squarely in this path's threat
// model: it is the same threat artifactsig exists for
// (geekdojo/geekdojo-brain#154), which is what makes an unvalidated path here
// the wrong shape regardless of who can currently reach it.
//
// So the rule is enforced where the path is BUILT, in every backend, rather
// than trusted at the boundary where it is sent.

// errBadBundleID and errBundlePathEscape are distinct so a caller — and a test
// — can tell "you named a bundle that cannot be a filename" apart from "you
// named a file outside the bundle store".
var (
	errBadBundleID      = errors.New("bundle id is not a safe filename component")
	errBundlePathEscape = errors.New("bundle path escapes the bundle store")
)

// bundlesSubdir is the one place the bundle store's name is written.
const bundlesSubdir = "bundles"

// maxBundleIDLen keeps a pathological id off the filesystem well before any
// NAME_MAX. The real ids are 64-char sha256 hex or a CalVer string.
const maxBundleIDLen = 128

// validBundleID reports whether id is usable as a single filename component.
//
// An allowlist, not a "reject ../" denylist: a denylist has to anticipate every
// separator, encoding and platform quirk, and this only has to accept what the
// api actually sends — a sha256 hex digest, or a CalVer-ish version string.
// Everything outside [A-Za-z0-9._-] is refused, which incidentally makes the id
// safe to interpolate into the log lines and acks that echo it.
func validBundleID(id string) bool {
	if id == "" || len(id) > maxBundleIDLen || id == "." || id == ".." {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// resolveBundlePath returns the path a backend may touch for this command, or
// an error naming what was wrong with the request.
//
// bundleID is validated ALWAYS, even when localPath supplies the path, because
// the id is also echoed into acks, log lines and pruneBundles' keep-set.
//
// localPath empty — the normal flow, and the only one the api uses — means the
// agent resolves the path itself from the id. A non-empty localPath is honoured
// only if it lands inside <stateDir>/bundles; the wire type keeps the field for
// a future api that pre-stages content, and this is what makes that future
// change safe by default rather than by convention.
//
// TRIP-WIRE: containment is LEXICAL. A symlink inside the bundle store pointing
// out of it would defeat it. That holds because the store is created by the
// agent and is writable only by root on the appliance, so nothing reachable
// over the bus can plant one — if the store ever becomes writable by anything
// else, this needs filepath.EvalSymlinks and the cost of the store having to
// exist before a download can resolve its destination.
func resolveBundlePath(stateDir, bundleID, localPath, ext string) (string, error) {
	if !validBundleID(bundleID) {
		return "", fmt.Errorf("%w: %q", errBadBundleID, bundleID)
	}
	if localPath == "" {
		return filepath.Join(stateDir, bundlesSubdir, bundleID+ext), nil
	}

	store, err := filepath.Abs(filepath.Join(stateDir, bundlesSubdir))
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(localPath)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(store, abs)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q is not inside %s", errBundlePathEscape, localPath, store)
	}
	// Cleaned, not absolutised: a caller that passed a relative path gets a
	// relative path back, so error messages and logs keep saying what was sent.
	return filepath.Clean(localPath), nil
}
