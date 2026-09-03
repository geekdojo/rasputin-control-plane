// Package sealtest opens sealed archives. FOR TESTS ONLY.
//
// The decryption lives here, in a package neither binary imports, and nowhere
// else — which is the property under test as much as it is a means of
// testing. backupxfer seals to a public key and holds no private key; an
// opener in that package would be a private-key consumer in exactly the
// processes design/storage.md §4.6 says must not have one. Restore is a
// separate, interactive path (§4.5 unpacks before the api's first start), and
// it is where a production opener belongs.
//
// Both the api's and the agent's tests import this so each end's tests verify
// the other end's bytes against the documented format rather than against a
// reader written beside the writer.
package sealtest

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
)

// sealInfo duplicates the writer's HKDF context string on purpose: a reader
// that imported the writer's constant would follow a drift in it.
const sealInfo = "rasputin.backup.archive.v1"

// Open decrypts a sealed archive with the recipient's private key and returns
// the plaintext and the header. It is written independently against the
// format's description so a bug shared between the writer and its own reader
// cannot hide.
func Open(sealed []byte, priv *ecdh.PrivateKey) ([]byte, backupxfer.Header, error) {
	var h backupxfer.Header
	if !bytes.HasPrefix(sealed, []byte(backupxfer.SealMagic)) {
		return nil, h, errors.New("sealtest: no magic")
	}
	rest := sealed[len(backupxfer.SealMagic):]
	nl := bytes.IndexByte(rest, '\n')
	if nl < 0 {
		return nil, h, errors.New("sealtest: no header line")
	}
	headerBytes := rest[:nl]
	body := rest[nl+1:]
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return nil, h, fmt.Errorf("sealtest: header: %w", err)
	}
	epkRaw, err := base64.RawURLEncoding.DecodeString(h.EphemeralPublicKey)
	if err != nil {
		return nil, h, err
	}
	epk, err := ecdh.X25519().NewPublicKey(epkRaw)
	if err != nil {
		return nil, h, err
	}
	shared, err := priv.ECDH(epk)
	if err != nil {
		return nil, h, err
	}
	salt := append(append([]byte{}, epkRaw...), priv.PublicKey().Bytes()...)
	key, err := hkdf.Key(sha256.New, shared, salt, sealInfo, chacha20poly1305.KeySize)
	if err != nil {
		return nil, h, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, h, err
	}
	var plain []byte
	nonce := make([]byte, chacha20poly1305.NonceSize)
	chunk := h.ChunkSize + aead.Overhead()
	var counter uint64
	sawLast := false
	for len(body) > 0 {
		n := chunk
		last := false
		if len(body) < chunk {
			n = len(body)
			last = true
		}
		for {
			for i := range nonce {
				nonce[i] = 0
			}
			binary.BigEndian.PutUint64(nonce[0:8], counter)
			if last {
				nonce[8] = 1
			}
			out, derr := aead.Open(nil, nonce, body[:n], headerBytes)
			if derr == nil {
				plain = append(plain, out...)
				sawLast = last
				break
			}
			if last {
				return nil, h, fmt.Errorf("sealtest: chunk %d failed to open: %w", counter, derr)
			}
			// A full-sized final chunk: retry with the last flag set.
			last = true
		}
		body = body[n:]
		counter++
	}
	if !sawLast {
		return nil, h, errors.New("sealtest: no chunk carried the last-chunk flag; a truncated archive would be indistinguishable from a complete one")
	}
	return plain, h, nil
}
