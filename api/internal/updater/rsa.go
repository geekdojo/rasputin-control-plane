package updater

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
)

// checkRSA performs an RSA-PKCS1v15 / SHA-256 signature check against the
// leaf cert's public key. Used by the mock-bundle verifier as a fallback
// when x509.CheckSignature can't introspect the algorithm.
func checkRSA(leaf *x509.Certificate, hashed, sig []byte) error {
	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("leaf cert public key is not RSA")
	}
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed, sig)
}
