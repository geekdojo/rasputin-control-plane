// Package credmac fingerprints state that includes a credential, under a key
// only the api holds (geekdojo/geekdojo-brain#827).
//
// A fingerprint is how the api tells whether two configurations are the same:
// the BMC selection a host advertises against the one in settings, and the
// firewall state the agent reports against the one the api last pushed. Both
// configurations carry a credential (the BMC unlock or password, the PPPoE
// password), and the fingerprint has to change when only the credential does,
// so the credential is part of what is fingerprinted. The fingerprint itself
// is written to the job ledger, the bus and inventory. Keying it with HMAC
// means that what is written there says nothing about the credential to
// anyone who does not hold the key.
//
// The key is derived from the app-secret seed (appsecret.Seed.MACKey) on every
// start, so it survives a restart and a restore and is never written anywhere
// of its own. The agent never holds it.
package credmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// MinKeyLen is the shortest key New accepts: the SHA-256 output size.
const MinKeyLen = 32

// prefix marks a keyed fingerprint. A fingerprint written by an earlier
// release (an unkeyed SHA-256, or its 16-hex prefix) never carries it, which is
// how a reader tells the two apart (IsKeyed). The 1 is the scheme version: a
// change to the MAC input is a new prefix, never an edit to this one.
const prefix = "k1-"

// Key is the fingerprinting key. It renders as "[redacted]" through every
// ordinary rendering path, because the only field is a secret.Value.
type Key struct{ k secret.Value }

// New wraps key. It refuses one shorter than MinKeyLen. The caller still owns
// key's own bytes.
func New(key secret.Value) (*Key, error) {
	if key.Len() < MinKeyLen {
		return nil, fmt.Errorf("credmac: the key is %d bytes, want at least %d", key.Len(), MinKeyLen)
	}
	return &Key{k: key}, nil
}

// Sum returns "k1-" and the lowercase hex HMAC-SHA256, under the key, of the
// purpose and then each part. Every one of them is length-prefixed, so no
// split of the same bytes into different parts, and no purpose, can collide
// with another.
func (k *Key) Sum(purpose string, parts ...[]byte) string {
	m := hmac.New(sha256.New, k.k.Reveal())
	writeField(m, []byte(purpose))
	for _, p := range parts {
		writeField(m, p)
	}
	return prefix + hex.EncodeToString(m.Sum(nil))
}

// writeField writes one length-prefixed field. A hash.Hash's Write never
// returns an error.
func writeField(w io.Writer, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = w.Write(n[:])
	_, _ = w.Write(b)
}

// IsKeyed reports whether h is a keyed fingerprint, as Sum returns it.
func IsKeyed(h string) bool { return strings.HasPrefix(h, prefix) }
