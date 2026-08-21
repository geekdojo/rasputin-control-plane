// Package artifactsig verifies the detached CMS signature that the Rasputin
// release pipeline publishes alongside every update artifact (`${artifact}.sig`)
// against the publisher trust root baked read-only into each image.
//
// Why this package exists at all: until 2026-08-18 the firewall's OTA path
// applied a rootfs artifact with NO publisher check — the only gate was a
// sha256 compare against a value the control plane handed down over mesh TLS.
// That authenticates the TRANSPORT, not the PUBLISHER: it proves the bytes
// arrived from the api unaltered and says nothing about whether the api was
// serving a genuine Rasputin artifact. Anything that could get an artifact into
// the bundle store reached the firewall unchallenged, and the firewall is the
// node that terminates the WAN. See geekdojo/geekdojo-brain#154.
//
// The pipeline signs with `openssl cms -sign -binary -outform DER`, leaf +
// intermediate, no `-nodetach` — so the artifact on the wire is a DER
// SignedData with an ABSENT eContent, carrying the leaf and intermediate certs
// and the standard authenticated attributes (contentType, signingTime,
// messageDigest). The chain terminates at the offline, YubiKey-backed root
// whose public half is baked to /etc/rasputin/trust/root-ca.pem.
//
// Two deliberate choices, both of which a future reader will want the reason for:
//
//  1. **The chain is verified at time.Now(), not at the signature's own
//     signingTime.** That matches Rasputin OS, where RAUC pins `[keyring]` to
//     the same root with no allow-expired escape and so rejects an expired
//     signer already (board/rasputin/n100/rauc-system.conf). The consequence is
//     real and intended: once a signing leaf expires, releases it signed stop
//     being installable OTA and must be re-signed. The alternative — trusting
//     the signingTime attribute — takes the verification instant from a value
//     inside the object being verified, which is the wrong direction.
//
//  2. **The artifact is never read into memory.** The firewall's `.rootfs` is a
//     full 512 MiB slot image today (geekdojo/geekdojo-brain#60 is the trim),
//     and an appliance mid-update is already holding a download and a raw slot
//     write. CMS binds content through the messageDigest authenticated
//     attribute rather than by signing the bytes directly, so the content only
//     ever needs to be HASHED — which streams. pkcs7.PKCS7.Hasher is the
//     library's documented seam for exactly that.
//
// Choice 2 has one sharp edge and it is guarded below: pkcs7 verifies the
// signature over p7.Content directly when a signer carries NO authenticated
// attributes. With the content held out of memory that would be a signature
// over nothing, so a signer without authenticated attributes is rejected
// outright before any verification runs.
package artifactsig

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/smallstep/pkcs7"
)

// DefaultTrustRoot is where every Rasputin image bakes the publisher root CA.
// Identical on both surfaces: Rasputin OS mounts it read-only in the squashfs
// and hands the same path to RAUC's keyring; the firewall ships it in
// files/etc/rasputin/trust/ and names it in RASPUTIN_TRUST_ROOT.
const DefaultTrustRoot = "/etc/rasputin/trust/root-ca.pem"

// TrustRootEnv is the environment variable both images set to the trust root.
// It has been set on the firewall since the agent's init script was written
// (files/etc/init.d/rasputin-agent) and, until #154, nothing read it.
const TrustRootEnv = "RASPUTIN_TRUST_ROOT"

// maxSigBytes caps the detached signature read. A real one is ~1.6 KiB (leaf +
// intermediate + attributes); a megabyte is four hundred times the headroom
// needed and still refuses to buffer a hostile "signature" the size of a disk.
const maxSigBytes = 1 << 20

var (
	// ErrNoSignature means the `.sig` companion is absent. It is a HARD failure
	// on every path that calls this package — the whole point of #154 is that a
	// missing signature must not degrade to the sha256 gate.
	ErrNoSignature = errors.New("artifact signature file is missing")
	// ErrNoTrustRoot means the baked root CA could not be read. Also hard: an
	// unreadable trust root is indistinguishable, from here, from one an
	// attacker removed.
	ErrNoTrustRoot = errors.New("publisher trust root is missing or unreadable")
	// ErrNotDetached means the CMS object carries its own content. The pipeline
	// never produces one, and honouring it would verify a signature over the
	// bytes INSIDE the .sig rather than over the artifact on disk.
	ErrNotDetached = errors.New("signature is not detached (it carries its own content)")
	// ErrNoSignedAttrs means a signer omitted its authenticated attributes —
	// see the package doc, choice 2's sharp edge.
	ErrNoSignedAttrs = errors.New("signer carries no authenticated attributes")
)

// Result describes a signature that verified. It exists so callers can log WHO
// signed rather than just "ok" — on a security gate, an unattributed pass is
// only marginally better than no gate.
type Result struct {
	// Signer is the leaf certificate's subject common name.
	Signer string
	// Issuer is the leaf's issuing CA common name (the intermediate).
	Issuer string
	// NotAfter is the leaf's expiry. Logged because the failure it eventually
	// causes ("chain does not verify") reads like tampering unless the operator
	// knows the leaf simply aged out.
	NotAfter time.Time
	// DigestHex is the artifact digest the signature actually committed to,
	// hex-encoded, and DigestAlg names the hash that produced it.
	DigestHex string
	DigestAlg string
}

// TrustRootPath returns the trust root to verify against: RASPUTIN_TRUST_ROOT
// when the image set it, DefaultTrustRoot otherwise. The fallback is what makes
// this work identically on Rasputin OS, whose systemd unit does not export the
// variable but bakes the file to the same path.
func TrustRootPath() string {
	if p := os.Getenv(TrustRootEnv); p != "" {
		return p
	}
	return DefaultTrustRoot
}

// SigPathFor is the pipeline's naming rule: the detached signature sits beside
// the artifact with `.sig` appended. One function so the agent, the api and the
// runbook cannot drift on it.
func SigPathFor(artifactPath string) string { return artifactPath + ".sig" }

// VerifyDefault verifies artifactPath against its `.sig` companion and the
// image's baked trust root, requiring a leaf authorized to sign OS and firmware
// releases. This is the form both OTA paths use.
//
// The purpose is not a parameter here on purpose: every caller of this function
// is installing an image, and an OTA path that could be talked into accepting a
// catalog-signing leaf is the bug geekdojo/geekdojo-brain#192 exists to close.
func VerifyDefault(artifactPath string) (*Result, error) {
	return VerifyForPurpose(artifactPath, SigPathFor(artifactPath), TrustRootPath(), OIDCodeSigningRelease)
}

// Verify checks the detached CMS signature at sigPath over the artifact at
// artifactPath, requiring a chain to a root in trustRootPath that is valid NOW.
//
// Every return path that is not a verified signature is an error. There is no
// "degraded" or "unverified but proceeding" outcome by construction — callers
// cannot accidentally treat a missing signature as a soft warning, because
// there is no value they could receive that says so.
func Verify(artifactPath, sigPath, trustRootPath string) (*Result, error) {
	return VerifyForPurpose(artifactPath, sigPath, trustRootPath, OIDCodeSigningRelease)
}

// VerifyForPurpose is Verify with the authorized signing purpose named
// explicitly. A leaf that chains to the trust root but was not issued for
// `purpose` is REJECTED.
//
// This is the check whose absence made ADR-0006 Decision 3 untrue: before it,
// authorization was chain-to-root alone, so every leaf under the intermediate
// could sign every artifact class and "a separate leaf for the catalog" bought
// nothing at all.
func VerifyForPurpose(artifactPath, sigPath, trustRootPath string, purpose asn1.ObjectIdentifier) (*Result, error) {
	roots, err := loadTrustRoot(trustRootPath)
	if err != nil {
		return nil, err
	}

	sigDER, err := readSignature(sigPath)
	if err != nil {
		return nil, err
	}

	p7, err := pkcs7.Parse(sigDER)
	if err != nil {
		return nil, fmt.Errorf("parse detached signature %s: %w", sigPath, err)
	}
	if len(p7.Content) > 0 {
		return nil, fmt.Errorf("%s: %w", sigPath, ErrNotDetached)
	}
	if len(p7.Signers) == 0 {
		return nil, fmt.Errorf("%s: signature has no signers", sigPath)
	}
	// See the package doc: without this, a signer stripped of its authenticated
	// attributes would have its signature checked against p7.Content — which is
	// deliberately empty here — instead of against the artifact's digest.
	for _, signer := range p7.Signers {
		if len(signer.AuthenticatedAttributes) == 0 {
			return nil, fmt.Errorf("%s: %w", sigPath, ErrNoSignedAttrs)
		}
	}

	// Hand the verifier a hasher that streams the artifact off disk instead of
	// the (absent) in-memory content. pkcs7 asks it for whatever digest the
	// signature names, so this stays correct if the pipeline ever moves off
	// sha256.
	hasher := &fileHasher{path: artifactPath}
	p7.Hasher = hasher
	p7.Content = nil

	if err := p7.VerifyWithChainAtTime(roots, time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("verify %s against %s: %w", artifactPath, sigPath, err)
	}

	leaf := p7.GetOnlySigner()
	if leaf == nil {
		// Unreachable in practice — VerifyWithChainAtTime already resolved a
		// signer cert — but returning a Result with empty attribution would be
		// a lie, and this is the one place that could tell it.
		return nil, fmt.Errorf("%s: verified but no signer certificate to attribute it to", sigPath)
	}
	// Chain-of-trust is necessary and NOT sufficient: ask what this leaf was
	// issued to do before accepting what it signed.
	if err := authorizePurpose(leaf, purpose); err != nil {
		return nil, err
	}

	return &Result{
		Signer:    leaf.Subject.CommonName,
		Issuer:    leaf.Issuer.CommonName,
		NotAfter:  leaf.NotAfter,
		DigestHex: hex.EncodeToString(hasher.digest),
		DigestAlg: hasher.alg,
	}, nil
}

func loadTrustRoot(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrNoTrustRoot, path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%w: %s: no certificates parsed", ErrNoTrustRoot, path)
	}
	return pool, nil
}

func readSignature(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNoSignature, path)
		}
		return nil, fmt.Errorf("open signature %s: %w", path, err)
	}
	defer f.Close()
	der, err := io.ReadAll(io.LimitReader(f, maxSigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read signature %s: %w", path, err)
	}
	if len(der) == 0 {
		return nil, fmt.Errorf("%w: %s is empty", ErrNoSignature, path)
	}
	if len(der) > maxSigBytes {
		return nil, fmt.Errorf("signature %s exceeds %d bytes", path, maxSigBytes)
	}
	return der, nil
}

// fileHasher implements pkcs7.Hasher by streaming a file off disk, so the
// artifact is never held in memory. The io.Reader pkcs7 passes is the (empty)
// in-memory content and is deliberately ignored — see the package doc for why
// that is safe here and what guards it.
type fileHasher struct {
	path   string
	digest []byte
	alg    string
}

func (h *fileHasher) Hash(hashFunc crypto.Hash, _ io.Reader) ([]byte, error) {
	if !hashFunc.Available() {
		return nil, fmt.Errorf("signature names hash %v, which this build does not have", hashFunc)
	}
	f, err := os.Open(h.path)
	if err != nil {
		return nil, fmt.Errorf("open artifact %s: %w", h.path, err)
	}
	defer f.Close()
	sum := hashFunc.New()
	if _, err := io.Copy(sum, f); err != nil {
		return nil, fmt.Errorf("read artifact %s: %w", h.path, err)
	}
	h.digest = sum.Sum(nil)
	h.alg = hashName(hashFunc)
	return h.digest, nil
}

func hashName(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	case crypto.SHA1:
		return "sha1"
	}
	return fmt.Sprintf("hash-%d", int(h))
}
