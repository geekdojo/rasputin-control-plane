package releases

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/artifactsig"
)

// Signature checking for release manifests (geekdojo/geekdojo-brain#527).
//
// # What this closes
//
// A release manifest names the version, the asset filenames and the SHA-256 of
// every artifact. Everything downstream — the flasher's checksum check, the
// updater's staging decision, the version the UI shows — is derived from it.
// Until this, it was fetched over HTTPS and believed: the chain of custody for
// what a node boots started at "whatever GitHub served", and anyone who could
// replace a release asset could replace both the image and the checksum that
// was supposed to catch a replaced image (F39).
//
// The pipeline has published `manifest.json.sig` beside it all along. This is
// the code that reads it.
//
// # One verifier
//
// There is no signature code here. Verification is `updater.Verifier`, which is
// `artifactsig` bound to the RELEASE purpose — the same verifier that gates an
// OTA install, reached through the ManifestVerifier interface so this package
// does not depend on the api's wiring. A second implementation, even a careful
// one, would be a second thing to keep correct.
//
// # The ladder, and why it is a fact and not a date
//
// Not every published release can be verified. Releases signed before the
// release-purpose OID existed carry a signature made by a leaf that is not
// authorized for firmware, and requiring verification of those would strand
// every cluster still running one: it could no longer resolve the image for
// its OWN version, so it could not add a node. The firewall publishes no
// signed manifest at all until geekdojo/geekdojo-brain#526 ships.
//
// So each component names the first version whose release publishes a
// signature this api can accept (Component.SignedManifestFrom). At or above it,
// a signature is REQUIRED and a missing one is a hard failure — so nobody can
// downgrade a signed release by deleting its `.sig`. Below it, the `.sig` is
// not read at all, because the one that exists there cannot pass.
//
// That floor is a checkable fact about published artifacts, not a date and not
// a grace period: it moves when a release publishes a signature, and it is
// verified by TestSignedManifestFloorsMatchPublishedReleases against the real
// releases.

// ManifestVerifier verifies a detached CMS signature over a release manifest,
// requiring a leaf authorized to sign OS and firmware releases.
//
// Satisfied by *updater.Verifier. It is an interface here only so that this
// package does not import the api's; the release purpose is bound inside the
// implementation and is deliberately not a parameter.
type ManifestVerifier interface {
	VerifyArtifact(artifactPath, sigPath string) (*artifactsig.Result, error)
}

var (
	// ErrManifestUnsigned means a release at or above its component's signing
	// floor published no `manifest.json.sig`. Hard: the alternative is letting
	// anyone who can delete an asset turn verification off.
	ErrManifestUnsigned = errors.New("release manifest is not signed")

	// ErrManifestVersionMismatch means the verified manifest names a different
	// version than the tag it was fetched from. The signature covers the
	// manifest, not the tag, so without this check a signed manifest for one
	// release could be served under another release's tag — pairing a signed
	// checksum list with somebody else's assets.
	ErrManifestVersionMismatch = errors.New("release tag does not match the signed manifest's version")

	// ErrManifestSignerExpired means the signature is intact but the signing
	// certificate has aged out. Separated from a verification failure because
	// it is not a tampering report and has a different remedy — see dec 24
	// (geekdojo/geekdojo-brain#576).
	ErrManifestSignerExpired = errors.New("the release's signing certificate has expired")

	// ErrNoVerifier means this control plane has no usable trust root, so it
	// cannot check a signature it is required to check.
	ErrNoVerifier = errors.New("this control plane cannot verify release signatures")
)

// SignedManifestRequired reports whether a manifest for this component at this
// version must carry a verifiable signature.
//
// False for a version below the component's floor, and for a component with no
// floor set. An unparseable version is treated as BELOW the floor: it is
// already refused as a download path segment by ValidReleaseVersion, and
// failing here instead would turn a malformed version into an unverifiable one.
func SignedManifestRequired(comp Component, version string) bool {
	if comp.SignedManifestFrom == "" {
		return false
	}
	c, err := Compare(comp.Scheme, version, comp.SignedManifestFrom)
	if err != nil {
		return false
	}
	return c >= 0
}

// VerifyManifest checks sigDER over manifestJSON and returns who signed it.
//
// version is the release tag the manifest was fetched from; the verified
// manifest must name that same version. sigDER may be nil when the release
// published no signature, which is an error only when the component's floor
// requires one.
//
// The bytes are written to a private temp directory because the verifier works
// on paths: it streams artifacts off disk rather than buffering them, which is
// right for a 3 GB image and merely inconvenient for a 1 KB manifest. Paying
// two small writes is much better than growing a second, in-memory entry point
// into the signature code.
func VerifyManifest(v ManifestVerifier, comp Component, version string, manifestJSON, sigDER []byte) (*artifactsig.Result, error) {
	required := SignedManifestRequired(comp, version)
	if len(sigDER) == 0 {
		if !required {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %s %s publishes no manifest.json.sig, and every release from %s onward must",
			ErrManifestUnsigned, comp.ID, version, comp.SignedManifestFrom)
	}
	if !required {
		// Below the floor the signature that exists was made by a leaf with no
		// release purpose, so checking it could only ever fail. Ignoring it is
		// the ladder, not laxity — and the floor is what removes it.
		return nil, nil
	}
	if v == nil {
		return nil, fmt.Errorf("%w: no trust root is configured", ErrNoVerifier)
	}

	dir, err := os.MkdirTemp("", "rasputin-manifest-*")
	if err != nil {
		return nil, fmt.Errorf("verify %s manifest: %w", comp.ID, err)
	}
	defer os.RemoveAll(dir)
	manifestPath := filepath.Join(dir, "manifest.json")
	sigPath := artifactsig.SigPathFor(manifestPath)
	if err := os.WriteFile(manifestPath, manifestJSON, 0o600); err != nil {
		return nil, fmt.Errorf("verify %s manifest: %w", comp.ID, err)
	}
	if err := os.WriteFile(sigPath, sigDER, 0o600); err != nil {
		return nil, fmt.Errorf("verify %s manifest: %w", comp.ID, err)
	}

	res, err := v.VerifyArtifact(manifestPath, sigPath)
	if err != nil {
		// Ask why before reporting it. An aged-out leaf and a tampered asset
		// are indistinguishable here and call for opposite responses from an
		// operator (dec 24). The diagnostic decides nothing: this path has
		// already refused.
		if notAfter, expired := artifactsig.SignerExpiry(sigPath); expired {
			return nil, fmt.Errorf("%w on %s (%s %s): %v",
				ErrManifestSignerExpired, notAfter.UTC().Format("2006-01-02"), comp.ID, version, err)
		}
		return nil, fmt.Errorf("verify %s %s manifest signature: %w", comp.ID, version, err)
	}

	// The signature covers the manifest's bytes, which say which release they
	// describe. Binding that to the tag we fetched from is what stops a signed
	// manifest being replayed under another tag.
	var m struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return nil, fmt.Errorf("parse verified %s manifest: %w", comp.ID, err)
	}
	if m.Version != version {
		return nil, fmt.Errorf("%w: tag %q carries a manifest signed for %q", ErrManifestVersionMismatch, version, m.Version)
	}
	return res, nil
}
