// Package credmactest gives tests a fixed fingerprinting key.
package credmactest

import (
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// KeyBytes is the fixed test key: 0x00, 0x01, … 0x1f. Pinned fingerprint
// vectors in tests are computed under it.
func KeyBytes() []byte {
	b := make([]byte, credmac.MinKeyLen)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// Key returns a *credmac.Key over KeyBytes.
func Key(t testing.TB) *credmac.Key {
	t.Helper()
	k, err := credmac.New(secret.New(KeyBytes()))
	if err != nil {
		t.Fatalf("credmac.New: %v", err)
	}
	return k
}
