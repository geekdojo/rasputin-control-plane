package backupxfer

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
)

// newX25519Public mints a throwaway recipient key for tests that only need
// something to seal TO.
func newX25519Public() (string, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}
