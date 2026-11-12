package signin

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// verifierBytes is the random input to a verifier: 32 bytes give the
// 43-character base64url verifier RFC 7636 §4.1 recommends.
const verifierBytes = 32

// Verifier is a PKCE code verifier (RFC 7636 §4.1): 32 bytes from r as
// unpadded base64url, 43 characters from the unreserved set.
func Verifier(r io.Reader) (string, error) {
	b := make([]byte, verifierBytes)
	defer clear(b)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("signin: PKCE verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Challenge is the S256 code challenge for verifier (RFC 7636 §4.2):
// BASE64URL(SHA256(ASCII(verifier))), unpadded.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
