package artifactsig

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/smallstep/pkcs7"
)

// A RAUC bundle's signature is INLINE, not detached, so the rest of this
// package does not apply to it: RAUC embeds a CMS SignedData in the bundle file
// and verifies it itself, against the same root the api verifies detached
// signatures against.
//
// WHY THE AGENT CHECKS IT ANYWAY. RAUC's `[keyring] check-purpose=codesign`
// asks whether the signer carries the GENERIC codeSigning extended key usage.
// That is all it can ask — it is an OpenSSL X509 purpose, and OpenSSL has no
// notion of Rasputin's purpose arc. So codesign cannot tell a RELEASE leaf from
// any other leaf under the same intermediate that happens to carry codeSigning,
// and "the catalog leaf is refused" is true today only because that leaf
// deliberately omits codeSigning (ADR-0006 Decision 3). One future leaf minted
// with codeSigning for some unrelated purpose would silently become able to
// sign an OS image, and nothing on the node would notice.
//
// artifactsig already closes exactly that hole on the detached path, by
// authorizing on the Rasputin release OID rather than on chain-to-root
// (geekdojo/geekdojo-brain#192). This file asks the same question of the
// bundle's own inline signer, so the OTA path a node actually takes gets the
// same authorization the firewall rootfs path has had since #154.
//
// The two checks are a CONJUNCTION and neither replaces the other. RAUC proves
// the signature is cryptographically valid over the payload and that the signer
// chains to the baked root with a code-signing purpose; this proves the signer
// was issued to sign RELEASES. A bundle must pass both.

// raucSigSizeField is the size of the trailing big-endian uint64 that a RAUC
// "verity" bundle uses to record its signature length.
const raucSigSizeField = 8

// maxRAUCSigBytes is RAUC's own cap on a bundle signature
// (MAX_BUNDLE_SIGNATURE_SIZE, src/bundle.c). Matching it exactly matters: a
// bundle whose trailer claims more than this is one RAUC refuses to open, and
// reading it here would mean buffering something no installer would ever accept.
const maxRAUCSigBytes = 0x10000

var (
	// ErrNotRAUCBundle means the file does not carry a readable RAUC "verity"
	// bundle trailer. Hard, like every other failure here: a file the agent
	// cannot locate a signature in is not one it may hand to `rauc install`.
	ErrNotRAUCBundle = errors.New("file does not carry a RAUC bundle signature trailer")
)

// VerifyRAUCBundleSigner checks the signer of the RAUC bundle at bundlePath
// against the image's baked trust root, requiring a leaf authorized to sign OS
// and firmware releases. This is the form the agent's OTA path uses.
//
// The purpose is not a parameter, for the same reason it is not one on
// VerifyDefault: every caller is installing an image, and an OTA path that
// could be talked into accepting a leaf issued for something else is the bug
// this exists to close.
func VerifyRAUCBundleSigner(bundlePath string) (*Result, error) {
	return VerifyRAUCBundleSignerForPurpose(bundlePath, TrustRootPath(), OIDCodeSigningRelease)
}

// VerifyRAUCBundleSignerForPurpose reads the inline CMS signature out of a RAUC
// "verity" bundle, resolves the signer certificate, and requires that it chains
// to a root in trustRootPath valid NOW and carries `purpose`.
//
// It deliberately does NOT re-verify the signature over the payload. RAUC does
// that, over a bundle layout only RAUC can interpret, and reimplementing it
// here would mean a second verifier to keep in step with RAUC's format — the
// kind of near-duplicate that drifts and then disagrees. What is NOT duplicated
// is the question RAUC cannot express, and that is all this answers.
//
// The ordering that makes this safe: the agent runs this BEFORE `rauc install`,
// so an unauthorized signer stops the update before anything is written to the
// inactive slot, and `rauc install` then applies its own verification to the
// same bytes. Passing here is necessary and not sufficient.
func VerifyRAUCBundleSignerForPurpose(bundlePath, trustRootPath string, purpose asn1.ObjectIdentifier) (*Result, error) {
	roots, err := loadTrustRoot(trustRootPath)
	if err != nil {
		return nil, err
	}

	sigDER, err := readRAUCBundleSignature(bundlePath)
	if err != nil {
		return nil, err
	}

	p7, err := pkcs7.Parse(sigDER)
	if err != nil {
		return nil, fmt.Errorf("parse bundle signature in %s: %w", bundlePath, err)
	}
	if len(p7.Signers) == 0 {
		return nil, fmt.Errorf("%s: bundle signature has no signers", bundlePath)
	}
	// Note what is NOT checked here and is checked on the detached path:
	// ErrNotDetached. A RAUC bundle signature is inline BY DESIGN -- it carries
	// the signed manifest as its content -- so demanding a detached object
	// would refuse every bundle RAUC has ever produced.

	// GetOnlySigner resolves the certificate the SignerInfo actually names, by
	// issuer and serial, and returns nil when the object carries more than one
	// signer. Both halves matter. A CMS may embed any number of certificates,
	// so "the first certificate in the bag" is not the signer and picking it
	// would let an attacker park an authorized release leaf alongside the leaf
	// that really signed. And a multi-signer object has no single answer to
	// "what was this authorized to do", so it is refused rather than resolved
	// to whichever signer happens to pass.
	leaf := p7.GetOnlySigner()
	if leaf == nil {
		return nil, fmt.Errorf("%s: bundle signature has no single resolvable signer certificate", bundlePath)
	}

	// Chain the signer to the baked root, at time.Now() and not at the
	// signature's own signingTime — the same choice the detached path makes,
	// and for the same reason: taking the verification instant from a value
	// inside the object being verified is the wrong direction. RAUC's keyring
	// check enforces the identical rule, so this cannot be the thing that makes
	// an installable bundle uninstallable.
	intermediates := x509.NewCertPool()
	for _, c := range p7.Certificates {
		if c.Equal(leaf) {
			continue
		}
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now().UTC(),
		// ExtKeyUsageAny is how Go is told NOT to constrain the extended key
		// usage; leaving KeyUsages nil would default it to ServerAuth and
		// reject every signing leaf we issue. That is deliberate rather than
		// lax: the X509 purpose is RAUC's job, enforced on the device by
		// [keyring] check-purpose=codesign, and the Rasputin purpose is the
		// next check below. Duplicating RAUC's purpose here would couple this
		// function to which generic EKUs a leaf happens to carry, and those
		// are scheduled to change -- emailProtection comes out once no node
		// still enforcing the S/MIME default remains.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("verify %s bundle signer against %s: %w", bundlePath, trustRootPath, err)
	}

	// Chain-of-trust is necessary and NOT sufficient: ask what this leaf was
	// issued to do before accepting the image it signed.
	if err := authorizePurpose(leaf, purpose); err != nil {
		return nil, err
	}

	// DigestHex and DigestAlg are left empty, unlike the detached path's
	// Result: nothing here hashed the payload, because nothing here verified a
	// signature over it. Reporting a digest would imply a check that was not
	// made.
	return &Result{
		Signer:   leaf.Subject.CommonName,
		Issuer:   leaf.Issuer.CommonName,
		NotAfter: leaf.NotAfter,
	}, nil
}

// readRAUCBundleSignature returns the DER CMS blob out of a RAUC "verity"
// bundle, reading only the trailer and the signature — never the payload, which
// is a full rootfs image.
//
// The layout, from RAUC src/bundle.c open_local_bundle():
//
//	[ payload ][ CMS DER (sigsize bytes) ][ big-endian uint64 sigsize ]
//
// Every bound below is RAUC's own, so this reads a signature exactly when RAUC
// would and refuses exactly when RAUC would.
func readRAUCBundleSignature(bundlePath string) ([]byte, error) {
	f, err := os.Open(bundlePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNoSignature, bundlePath)
		}
		return nil, fmt.Errorf("open bundle %s: %w", bundlePath, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat bundle %s: %w", bundlePath, err)
	}
	if !st.Mode().IsRegular() {
		// RAUC refuses a non-regular file outright (R_BUNDLE_ERROR_UNSAFE).
		// A fifo would also make every size bound below meaningless.
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrNotRAUCBundle, bundlePath)
	}
	size := st.Size()
	if size <= raucSigSizeField {
		return nil, fmt.Errorf("%w: %s is %d bytes, too small to hold one", ErrNotRAUCBundle, bundlePath, size)
	}

	var trailer [raucSigSizeField]byte
	if _, err := f.ReadAt(trailer[:], size-raucSigSizeField); err != nil {
		return nil, fmt.Errorf("read bundle trailer %s: %w", bundlePath, err)
	}
	sigSize := binary.BigEndian.Uint64(trailer[:])

	payloadEnd := size - raucSigSizeField
	switch {
	case sigSize == 0:
		return nil, fmt.Errorf("%w: %s declares a zero-length signature", ErrNotRAUCBundle, bundlePath)
	case sigSize > uint64(payloadEnd):
		return nil, fmt.Errorf("%w: %s declares a %d-byte signature, larger than the bundle",
			ErrNotRAUCBundle, bundlePath, sigSize)
	case sigSize > maxRAUCSigBytes:
		return nil, fmt.Errorf("%w: %s declares a %d-byte signature, over RAUC's 64KiB cap",
			ErrNotRAUCBundle, bundlePath, sigSize)
	}

	der := make([]byte, sigSize)
	if _, err := io.ReadFull(io.NewSectionReader(f, payloadEnd-int64(sigSize), int64(sigSize)), der); err != nil {
		return nil, fmt.Errorf("read bundle signature %s: %w", bundlePath, err)
	}
	return der, nil
}
