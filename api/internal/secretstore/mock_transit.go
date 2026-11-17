package secretstore

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The Mock's Transit keys (geekdojo/geekdojo-brain#1084), with the client's
// outcomes: an encrypt under an absent key is ErrDenied, as the store's policy
// refuses it; a decrypt under an absent key is ErrNotFound; a ciphertext made
// under another key, or malformed, is ErrInvalidCiphertext. The Mock does NOT
// encrypt: its ciphertext is the key's id and the plaintext, base64-encoded,
// in Transit's vault:v1: form. It is for a configuration that names the mock
// explicitly, which holds nothing across a restart anyway.

const mockCiphertextPrefix = "vault:v1:"

// TransitCreateKey creates k; an existing key is left as it is.
func (m *Mock) TransitCreateKey(_ context.Context, _ secret.Value, k TransitKey) error {
	if !k.valid() {
		return fail("transit_create", k.kvPath(), ErrInvalidValue, errors.New("the key is the zero TransitKey"))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[k]; !ok {
		m.nextKey++
		m.keys[k] = m.nextKey
	}
	return nil
}

// TransitEncrypt wraps plaintext with k's id.
func (m *Mock) TransitEncrypt(_ context.Context, _ secret.Value, k TransitKey, plaintext secret.Value) (secret.Value, error) {
	m.mu.Lock()
	id, ok := m.keys[k]
	m.mu.Unlock()
	if !ok {
		return secret.Value{}, fail("transit_encrypt", k.kvPath(), ErrDenied, errors.New("no such key"))
	}
	raw := binary.BigEndian.AppendUint64(nil, id)
	raw = append(raw, plaintext.Reveal()...)
	out := secret.New([]byte(mockCiphertextPrefix + base64.StdEncoding.EncodeToString(raw)))
	clear(raw)
	return out, nil
}

// TransitDecrypt returns the plaintext a ciphertext made under k carries.
func (m *Mock) TransitDecrypt(_ context.Context, _ secret.Value, k TransitKey, ciphertext secret.Value) (secret.Value, error) {
	const op = "transit_decrypt"
	m.mu.Lock()
	id, ok := m.keys[k]
	m.mu.Unlock()
	if !ok {
		return secret.Value{}, fail(op, k.kvPath(), ErrNotFound, nil)
	}
	enc, found := strings.CutPrefix(string(ciphertext.Reveal()), mockCiphertextPrefix)
	raw, err := base64.StdEncoding.DecodeString(enc)
	if !found || err != nil || len(raw) < 8 || binary.BigEndian.Uint64(raw) != id {
		clear(raw)
		return secret.Value{}, fail(op, k.kvPath(), ErrInvalidCiphertext, nil)
	}
	out := secret.New(raw[8:])
	clear(raw)
	return out, nil
}

// TransitDestroyKey removes k; an absent key is ErrNotFound, as the client's.
func (m *Mock) TransitDestroyKey(_ context.Context, _ secret.Value, k TransitKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[k]; !ok {
		return fail("transit_destroy", k.kvPath(), ErrNotFound, nil)
	}
	delete(m.keys, k)
	return nil
}
