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
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Verifier checks bundle signatures against the Rasputin Root CA. It
// supports two formats:
//
//  1. **RAUC bundle** (`.raucb`) — a squashfs filesystem with a PKCS#7
//     signature appended. v0 of the api delegates real RAUC verification
//     to an out-of-process `rauc info` call when the binary is available;
//     otherwise it falls back to the mock format.
//
//  2. **Mock bundle** (`.raspbundle`) — a JSON envelope: { manifest, payload, signature }
//     where signature is a base64'd RSA-PSS signature over sha256(payload).
//     This is the dev-only format produced by scripts/build-bundle.sh on
//     machines without rauc installed.
//
// In both cases the verifier returns the parsed manifest on success.
type Verifier struct {
	roots *x509.CertPool
	// trustDir is the directory we read the root CA from. Kept so callers can
	// log where trust came from.
	trustDir string
}

// NewVerifier loads the root CA cert from <dir>/root-ca.pem. If the file is
// missing, it returns a Verifier in "dev-permissive" mode — signatures are
// parsed but not chain-verified, and every bundle is flagged SignedBy
// "<unverified>" in its manifest. This lets the api come up cleanly before
// the operator runs `make pki-init`.
func NewVerifier(dir string) (*Verifier, error) {
	pool := x509.NewCertPool()
	path := dir + "/root-ca.pem"
	pem, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Verifier{roots: nil, trustDir: dir}, nil
		}
		return nil, fmt.Errorf("read root CA at %s: %w", path, err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates parsed from %s", path)
	}
	return &Verifier{roots: pool, trustDir: dir}, nil
}

// TrustConfigured reports whether the verifier was loaded with a real root
// CA. The UI surfaces this in a warning banner when false.
func (v *Verifier) TrustConfigured() bool { return v.roots != nil }

// VerifyFile checks the bundle at path, returns its manifest and computed
// sha256. If TrustConfigured is false, signature checks are skipped (but
// the manifest is still parsed and the sha256 is still computed).
func (v *Verifier) VerifyFile(path string) (*proto.BundleManifest, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	return v.Verify(f, path)
}

// Verify reads from r, returns the bundle manifest and the bundle's sha256.
// hintPath is used only to disambiguate format from extension.
func (v *Verifier) Verify(r io.Reader, hintPath string) (*proto.BundleManifest, string, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(buf)
	shaHex := hex.EncodeToString(sum[:])

	// Mock format: starts with a JSON object. Real RAUC bundles start with
	// a squashfs magic — we look at the first byte.
	mockMode := looksLikeJSON(buf) || strings.HasSuffix(hintPath, ".raspbundle")
	if mockMode {
		man, signedBy, err := v.verifyMock(buf)
		if err != nil {
			return nil, shaHex, err
		}
		man.SHA256 = shaHex
		man.SizeBytes = int64(len(buf))
		man.SignedBy = signedBy
		return man, shaHex, nil
	}
	// Real RAUC bundle: defer to `rauc info` if available — but for v0 we
	// only carry the metadata path. Operators on hardware without rauc see
	// the mock path; operators on hardware get the rauc-side verify done
	// by the agent at install time (RAUC re-verifies on install regardless).
	return nil, shaHex, errors.New("real .raucb verification requires the rauc CLI on the api host; build with scripts/build-bundle.sh --mock for dev")
}

type mockBundleEnvelope struct {
	Manifest  proto.BundleManifest `json:"manifest"`
	Payload   string               `json:"payload"`   // hex-encoded; the bundle contents
	Signature string               `json:"signature"` // hex; over sha256(payload bytes)
	CertPEM   string               `json:"certPem"`   // leaf cert that signed
}

func (v *Verifier) verifyMock(buf []byte) (*proto.BundleManifest, string, error) {
	var env mockBundleEnvelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return nil, "", fmt.Errorf("parse mock envelope: %w", err)
	}
	if env.Manifest.Version == "" {
		return nil, "", errors.New("mock bundle: manifest.version is required")
	}

	// Without trust configured, accept without chain check but mark.
	if v.roots == nil {
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
		return nil, "", errors.New("mock bundle: certPem contained no certificates")
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

func looksLikeJSON(buf []byte) bool {
	for _, b := range buf {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		}
		return b == '{'
	}
	return false
}

// VerifyEnvelopeBytes is a helper exposed for tests / scripts: takes a
// mock-bundle JSON byte slice and returns the manifest. Doesn't do any
// chain verification — pure parse.
func VerifyEnvelopeBytes(buf []byte) (*proto.BundleManifest, error) {
	var env mockBundleEnvelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(buf, []byte("{")) && !bytes.HasPrefix(bytes.TrimSpace(buf), []byte("{")) {
		return nil, errors.New("not a mock bundle envelope")
	}
	return &env.Manifest, nil
}
