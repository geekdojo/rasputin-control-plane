package updater

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/geekdojo/rasputin-control-plane/artifactsig"
)

// Verifier checks an OS/firmware update artifact against the DETACHED CMS
// signature published beside it, using the shared artifactsig package bound to
// the release signing purpose. It is the same verifier, the same trust root
// and the same purpose OID the agent applies on the node — one implementation,
// so the api and the device cannot come to different conclusions about the same
// pair of files.
//
// # What replaced what
//
// There used to be a second format here: the `.raspbundle` JSON envelope
// { manifest, payload, signature, certPem }, produced by scripts/build-bundle.sh
// --mock and verified by hand in this file. It is retired. Three of its
// properties are the reason, and none of them could be fixed without becoming
// this:
//
//   - **Its manifest was not signed.** The signature covered sha256(payload)
//     only, so version, architecture and compatible — the fields the fleet
//     plan reasons about — were attacker-chosen in a bundle that verified.
//   - **It accepted EKU Any.** The chain check passed
//     x509.ExtKeyUsageAny alongside codeSigning, so the purpose split that
//     keeps a catalog-signing leaf away from the OTA path was not enforced on
//     this route at all.
//   - **It had a permissive mode.** With no root CA and an explicit opt-in,
//     signatures were parsed and not checked, and the bundle was recorded
//     SignedBy "<unverified>".
//
// Operators now upload the artifact and its detached `.sig`, which is exactly
// what the release pipeline publishes and what a node verifies — so the format
// an operator hand-carries into an air-gapped cluster is the format everything
// else already speaks, rather than a dev-only envelope with its own verifier
// and its own weaknesses.
//
// # Fail closed
//
// This type guards the artifact that decides what code a node boots. Trust is
// REQUIRED: with no readable root CA the verifier is UNAVAILABLE and every
// Verify refuses with ErrTrustUnavailable, naming the file that is missing.
// There is no permissive mode to opt into — see catalogsync.NewVerifier, which
// has never had one. A dev box gets a real PKI from scripts/pki-init.sh, whose
// release leaf carries the same purpose OID the pipeline's does.
//
// Per #89 and api/internal/mesh.UnavailableClient the api still boots and
// serves everything else, because a control plane that will not start is a
// control plane nobody can fix.
//
// The zero value fails closed: no roots means refuse.
type Verifier struct {
	// rootPath is the publisher root CA file this verifier was built on,
	// whether or not it loaded. Kept so callers can log where trust comes from.
	rootPath string
	// trustRoot is the root CA file artifactsig verifies against. Empty when
	// none loaded.
	trustRoot string
	// reason says why no root CA was loaded, in the operator's terms. Carried
	// into every refusal so the fix does not require reading this file.
	reason string
}

// ErrTrustUnavailable is returned by every Verify when no trust root was
// loaded. A sentinel so callers can tell "this api cannot verify anything" (an
// installation problem, 503) apart from "this bundle's signature is bad" (a bad
// artifact, 400) — two different problems with two different fixes.
var ErrTrustUnavailable = errors.New("OS update signature verification is unavailable")

// Trust postures, as reported to the UI by Mode.
const (
	// TrustEnforced: a root CA is loaded and every artifact is verified.
	TrustEnforced = "enforced"
	// TrustUnavailable: no root CA — every artifact is refused.
	TrustUnavailable = "unavailable"
)

// NewVerifier loads the publisher root CA from rootPath, the file the
// composition root resolved through artifactsig.TrustRootPath — the same file
// the catalog verifier and the node's agent use (geekdojo/geekdojo-brain#529).
//
// It always returns a usable *Verifier and never an error, deliberately: there
// is no error path a caller can mishandle back into permissiveness. When the
// root CA is missing, unreadable or unparseable the verifier comes back
// UNAVAILABLE — it refuses every artifact, carrying the reason — instead of
// downgrading to an unverified mode or killing the process.
//
// The root is parsed here, through the same artifactsig.LoadTrustRoot every
// verification uses, so an unusable root is reported once, at startup, as a
// configuration fault — rather than once per upload as a verification failure,
// which reads like a bad artifact.
func NewVerifier(rootPath string) *Verifier {
	if _, err := artifactsig.LoadTrustRoot(rootPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &Verifier{rootPath: rootPath, reason: fmt.Sprintf(
				"no update trust root at %s. On Rasputin hardware it ships in the OS image at "+
					"%s — if this is an appliance, re-flash. On a dev box run scripts/pki-init.sh "+
					"and set %s to the root-ca.pem it writes",
				rootPath, artifactsig.DefaultTrustRoot, artifactsig.TrustRootEnv)}
		}
		return &Verifier{rootPath: rootPath, reason: fmt.Sprintf(
			"the update trust root at %s is unusable (%v). On Rasputin hardware it ships in the OS "+
				"image at %s — if this is an appliance, re-flash. On a dev box set %s to the "+
				"root-ca.pem scripts/pki-init.sh writes",
			rootPath, err, artifactsig.DefaultTrustRoot, artifactsig.TrustRootEnv)}
	}
	return &Verifier{rootPath: rootPath, trustRoot: rootPath}
}

// TrustConfigured reports whether the verifier was loaded with a real root
// CA. The UI surfaces this in a warning banner when false.
func (v *Verifier) TrustConfigured() bool { return v.trustRoot != "" }

// Available reports whether this verifier can produce a verdict on an artifact
// at all. False means every Verify refuses: no trust root was loaded.
//
// Kept distinct from TrustConfigured even though the two now answer the same
// question. They asked different questions while a permissive mode existed,
// and collapsing them at the call sites would quietly re-merge "we are not
// checking" with "we cannot check" — the distinction that mode blurred.
func (v *Verifier) Available() bool { return v.trustRoot != "" }

// UnavailableReason names what is missing, for logs and for the operator.
// Empty when the verifier is available.
func (v *Verifier) UnavailableReason() string {
	if v.Available() {
		return ""
	}
	if v.reason == "" {
		// A zero-value Verifier. Refuses like any other unavailable one.
		return "no update trust root was loaded"
	}
	return v.reason
}

// Mode is the posture, for the UI banner: TrustEnforced or TrustUnavailable.
func (v *Verifier) Mode() string {
	if v.Available() {
		return TrustEnforced
	}
	return TrustUnavailable
}

// TrustRoot is the publisher root CA file the verifier was built on, whether or
// not it loaded. For logs.
func (v *Verifier) TrustRoot() string { return v.rootPath }

// VerifyArtifact checks the artifact at artifactPath against the detached CMS
// signature at sigPath, requiring a leaf that chains to the loaded trust root
// AND carries the RELEASE signing purpose.
//
// The purpose is not a parameter, for the reason catalogsync.NewVerifier gives
// for binding its own: a check that takes "which purpose?" as an argument is
// one refactor away from being handed the catalog OID, and the two are
// indistinguishable at the call site.
//
// An unavailable verifier refuses before either file is opened.
func (v *Verifier) VerifyArtifact(artifactPath, sigPath string) (*artifactsig.Result, error) {
	if !v.Available() {
		return nil, fmt.Errorf("%w: %s", ErrTrustUnavailable, v.UnavailableReason())
	}
	return artifactsig.VerifyForPurpose(artifactPath, sigPath, v.trustRoot, artifactsig.OIDCodeSigningRelease)
}
