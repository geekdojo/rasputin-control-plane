package updater

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Verifier checks bundle signatures against the Rasputin Root CA. It supports
// two formats, and the CALLER says which one it is holding:
//
//  1. **RAUC bundle** (`.raucb`) — a squashfs filesystem with a PKCS#7
//     signature appended. The api cannot verify one host-side without the
//     `rauc` CLI, so it refuses; RAUC re-verifies on the node at install.
//
//  2. **Raspbundle** (`.raspbundle`) — a JSON envelope: { manifest, payload,
//     signature, certPem } where signature is over sha256(payload). This is
//     the dev / air-gapped format produced by scripts/build-bundle.sh --mock.
//
// In both cases the verifier returns the parsed manifest on success.
//
// # Fail closed
//
// This type guards OS UPDATE BUNDLES — the artifact that decides what code a
// node boots. It used to answer a missing <trustDir>/root-ca.pem by returning a
// "dev-permissive" verifier that parsed signatures without chain-verifying any
// of them and flagged every bundle SignedBy "<unverified>". That is a fail-OPEN
// on the most dangerous artifact in the system: deleting or failing to place one
// file silently downgraded update verification to none, and the only signal was
// a string in a manifest that nothing alerts on.
//
// Trust is now REQUIRED by default and permissiveness is opt-in by name
// (NewDevPermissiveVerifier, wired from RASPUTIN_UPDATE_TRUST=dev-permissive in
// the api's main). With no trust root the verifier is UNAVAILABLE: every Verify
// refuses with ErrTrustUnavailable, naming the file that is missing. Nothing is
// installed unverified, and — per #89 and api/internal/mesh.UnavailableClient —
// the api still boots and serves everything else, because a control plane that
// will not start is a control plane nobody can fix.
//
// The zero value fails closed: no roots and no explicit opt-in means refuse.
type Verifier struct {
	roots *x509.CertPool
	// trustDir is the directory we read the root CA from. Kept so callers can
	// log where trust came from.
	trustDir string
	// permissive records that an operator EXPLICITLY asked for the unverified
	// dev mode. Never set by inference — only NewDevPermissiveVerifier sets it.
	permissive bool
	// reason says why no root CA was loaded, in the operator's terms. Carried
	// into every refusal so the fix does not require reading this file.
	reason string
}

// ErrTrustUnavailable is returned by every Verify when no trust root was loaded
// and no dev opt-in was given. A sentinel so callers can tell "this api cannot
// verify anything" (an installation problem, 503) apart from "this bundle's
// signature is bad" (a bad artifact, 400) — two different problems with two
// different fixes.
var ErrTrustUnavailable = errors.New("OS update signature verification is unavailable")

// Trust postures, as reported to the UI by Mode.
const (
	// TrustEnforced: a root CA is loaded and every bundle is chain-verified.
	TrustEnforced = "enforced"
	// TrustUnavailable: no root CA, no opt-in — every bundle is refused.
	TrustUnavailable = "unavailable"
	// TrustDevPermissive: explicitly requested, and no root CA was found, so
	// signatures are parsed but not checked.
	TrustDevPermissive = "dev-permissive"
)

// Format names the bundle wire format.
//
// It is DECLARED BY THE CALLER and never inferred from the bytes being
// verified. The format used to be chosen by sniffing the first non-space byte
// for '{', which let the content select its own verification path: a JSON blob
// routed itself to the raspbundle verifier no matter what the operator or the
// release manifest said it was. Content that picks its own checker is the same
// shape of defect as trust that defaults to none — so the api names the format
// from something the bundle cannot forge (the endpoint it arrived at, or the
// asset name in the signed release manifest), and an unrecognised format is
// refused rather than guessed.
type Format string

const (
	// FormatRaspbundle is the JSON envelope from scripts/build-bundle.sh
	// --mock: dev boxes, CI and air-gapped operator uploads.
	FormatRaspbundle Format = ".raspbundle"
	// FormatRAUC is a real RAUC bundle. Not verifiable host-side.
	FormatRAUC Format = ".raucb"
)

// NewVerifier loads the root CA cert from <dir>/root-ca.pem.
//
// It always returns a usable *Verifier and never an error, deliberately: there
// is no error path a caller can mishandle back into permissiveness. When the
// root CA is missing, unreadable or unparseable the verifier comes back
// UNAVAILABLE — it refuses every bundle, carrying the reason — instead of
// downgrading to an unverified mode or killing the process.
func NewVerifier(dir string) *Verifier {
	path := filepath.Join(dir, "root-ca.pem")
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Verifier{trustDir: dir, reason: fmt.Sprintf(
				"no update trust root at %s. On Rasputin hardware it ships in the OS image at "+
					"/etc/rasputin/trust/root-ca.pem — if this is an appliance, re-flash. On a dev box "+
					"run scripts/pki-init.sh and copy root-ca.pem into %s", path, dir)}
		}
		return &Verifier{trustDir: dir, reason: fmt.Sprintf("cannot read the update trust root at %s: %v", path, err)}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return &Verifier{trustDir: dir, reason: fmt.Sprintf(
			"no certificates parsed from %s — the update trust root is present but not a PEM "+
				"certificate; replace it with the root-ca.pem from scripts/pki-init.sh", path)}
	}
	return &Verifier{roots: pool, trustDir: dir}
}

// NewDevPermissiveVerifier is the EXPLICIT opt-in to the old behaviour, for a
// dev box that has never run scripts/pki-init.sh: with no trust root present,
// bundle signatures are parsed but not chain-verified and every bundle is
// flagged SignedBy "<unverified>".
//
// It is reached only by naming it — RASPUTIN_UPDATE_TRUST=dev-permissive — and
// never by inference from a missing file. And it only ever DOWNGRADES nothing:
// when a root CA is present it is loaded and enforced exactly as NewVerifier
// would, so setting this on a provisioned box does not weaken it.
func NewDevPermissiveVerifier(dir string) *Verifier {
	v := NewVerifier(dir)
	v.permissive = true
	return v
}

// TrustConfigured reports whether the verifier was loaded with a real root
// CA. The UI surfaces this in a warning banner when false.
func (v *Verifier) TrustConfigured() bool { return v.roots != nil }

// Available reports whether this verifier can produce a verdict on a bundle at
// all. False means every Verify refuses: no trust root was loaded and no dev
// opt-in was given.
func (v *Verifier) Available() bool { return v.roots != nil || v.permissive }

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

// Mode is the posture, for the UI banner: TrustEnforced, TrustUnavailable or
// TrustDevPermissive. A bool cannot say the third thing, and "not enforced" and
// "not checked at all" need different words in front of an operator.
func (v *Verifier) Mode() string {
	switch {
	case v.roots != nil:
		return TrustEnforced
	case v.permissive:
		return TrustDevPermissive
	default:
		return TrustUnavailable
	}
}

// VerifyFile checks the bundle at path, in the format the caller declares, and
// returns its manifest and computed sha256.
func (v *Verifier) VerifyFile(path string, format Format) (*proto.BundleManifest, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	return v.Verify(f, format)
}

// Verify reads from r and returns the bundle manifest and the bundle's sha256.
//
// format is the caller's declaration of what the bytes are; it is never
// inferred from the bytes themselves. An unavailable verifier refuses before a
// single byte is read.
func (v *Verifier) Verify(r io.Reader, format Format) (*proto.BundleManifest, string, error) {
	// Fail closed FIRST — before the bundle is read, parsed or hashed. Nothing
	// an unverifiable bundle contains should reach the rest of this function.
	if !v.Available() {
		return nil, "", fmt.Errorf("%w: %s", ErrTrustUnavailable, v.UnavailableReason())
	}
	switch format {
	case FormatRaspbundle:
		// handled below
	case FormatRAUC:
		return nil, "", errors.New("real .raucb verification requires the rauc CLI on the api host; " +
			"build with scripts/build-bundle.sh --mock for dev")
	default:
		return nil, "", fmt.Errorf("bundle format %q is not one of %q or %q — the caller must declare "+
			"the format; it is never inferred from the bundle's own bytes", format, FormatRaspbundle, FormatRAUC)
	}

	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(buf)
	shaHex := hex.EncodeToString(sum[:])

	man, signedBy, err := v.verifyRaspbundle(buf)
	if err != nil {
		return nil, shaHex, err
	}
	man.SHA256 = shaHex
	man.SizeBytes = int64(len(buf))
	man.SignedBy = signedBy
	return man, shaHex, nil
}

type raspbundleEnvelope struct {
	Manifest  proto.BundleManifest `json:"manifest"`
	Payload   string               `json:"payload"`   // hex-encoded; the bundle contents
	Signature string               `json:"signature"` // hex; over sha256(payload bytes)
	CertPEM   string               `json:"certPem"`   // leaf cert that signed
}

func (v *Verifier) verifyRaspbundle(buf []byte) (*proto.BundleManifest, string, error) {
	var env raspbundleEnvelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return nil, "", fmt.Errorf("parse %s envelope: %w — the api verifies the JSON envelope from "+
			"scripts/build-bundle.sh --mock; a real RAUC or OpenWrt artifact is not verifiable host-side "+
			"and must be staged from the release channel", FormatRaspbundle, err)
	}
	if env.Manifest.Version == "" {
		return nil, "", errors.New("raspbundle: manifest.version is required")
	}

	if v.roots == nil {
		// Reachable only through the explicit dev opt-in. Re-checked here
		// rather than trusted from Verify so that a future caller reaching
		// this method directly cannot bypass the gate either.
		if !v.permissive {
			return nil, "", fmt.Errorf("%w: %s", ErrTrustUnavailable, v.UnavailableReason())
		}
		return &env.Manifest, "<unverified>", nil
	}

	// certPem may contain a chain: leaf first, then any intermediates.
	// Parse every PEM block.
	var leaf *x509.Certificate
	intermediates := x509.NewCertPool()
	rest := []byte(env.CertPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("parse cert in chain: %w", err)
		}
		if leaf == nil {
			leaf = cert
		} else {
			intermediates.AddCert(cert)
		}
	}
	if leaf == nil {
		return nil, "", errors.New("raspbundle: certPem contained no certificates")
	}
	opts := x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return nil, "", fmt.Errorf("leaf cert chain verify: %w", err)
	}

	// Verify the signature over the payload bytes.
	payloadBytes, err := hex.DecodeString(env.Payload)
	if err != nil {
		return nil, "", fmt.Errorf("decode payload: %w", err)
	}
	sig, err := hex.DecodeString(env.Signature)
	if err != nil {
		return nil, "", fmt.Errorf("decode signature: %w", err)
	}
	hashed := sha256.Sum256(payloadBytes)
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, hashed[:], sig); err != nil {
		// CheckSignature wants raw signed bytes, not the digest, for RSA
		// signatures — but since we don't know the leaf's algorithm at
		// build time, fall back to a manual RSA-PKCS1v15 check.
		if err2 := checkRSA(leaf, hashed[:], sig); err2 != nil {
			return nil, "", fmt.Errorf("signature verify: %w (fallback: %v)", err, err2)
		}
	}

	return &env.Manifest, leaf.Subject.CommonName, nil
}

// VerifyEnvelopeBytes is a helper exposed for tests / scripts: takes a
// raspbundle JSON byte slice and returns the manifest. Doesn't do any
// chain verification — pure parse.
//
// NOT a verification path, despite the name it has carried since v0: nothing
// that decides whether an artifact is installable may call it. The name is
// kept because scripts consume it; the guard is that no api handler does.
func VerifyEnvelopeBytes(buf []byte) (*proto.BundleManifest, error) {
	var env raspbundleEnvelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(buf, []byte("{")) && !bytes.HasPrefix(bytes.TrimSpace(buf), []byte("{")) {
		return nil, errors.New("not a raspbundle envelope")
	}
	return &env.Manifest, nil
}
