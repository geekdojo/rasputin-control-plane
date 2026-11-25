// Package passkeytest is a soft P-256 WebAuthn authenticator for tests: it
// registers as a COSE key and answers an assertion ceremony the way a
// platform authenticator does (WebAuthn Level 3 §6.3.3), so the real
// go-webauthn verifier can be driven end to end. Tests only
// (geekdojo/geekdojo-brain#1005: the bridge's unit and CI tests).
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// Authenticator is one discoverable credential: its key, its id and the
// user handle it was registered for.
type Authenticator struct {
	Key          *ecdsa.PrivateKey
	CredentialID []byte
	UserHandle   []byte
	// SignCount is the counter the next assertion reports.
	SignCount uint32
}

// New is a fresh credential for handle.
func New(credentialID, handle []byte) (*Authenticator, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Authenticator{Key: key, CredentialID: credentialID, UserHandle: handle}, nil
}

// COSE is the public key as a COSE_Key (RFC 9053: kty EC2, alg ES256, crv
// P-256, x, y), as an authenticator registers it.
func COSE(key *ecdsa.PrivateKey) []byte {
	pub, _ := key.PublicKey.ECDH()
	raw := pub.Bytes() // 0x04 || x || y
	out := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20}
	out = append(out, raw[1:33]...)
	out = append(out, 0x22, 0x58, 0x20)
	return append(out, raw[33:65]...)
}

// COSE is a's public key (COSE).
func (a *Authenticator) COSE() []byte { return COSE(a.Key) }

// Request is what one assertion answers.
type Request struct {
	// Challenge is the options' challenge, base64url as the options carry
	// it; RPID and Origin are what the browser would report.
	Challenge, RPID, Origin string
	// NoUV leaves the user-verified flag clear; BadSignature corrupts the
	// signature; CredentialID, when set, replaces the credential's id.
	NoUV         bool
	BadSignature bool
	CredentialID []byte
}

// ChallengeOf reads the challenge from a begin response's options JSON
// ({"publicKey":{"challenge":…}}).
func ChallengeOf(options []byte) (string, error) {
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil {
		return "", err
	}
	if o.PublicKey.Challenge == "" {
		return "", errors.New("passkeytest: the options carry no challenge")
	}
	return o.PublicKey.Challenge, nil
}

// Assert is the PublicKeyCredential JSON a browser posts for req.
func (a *Authenticator) Assert(req Request) ([]byte, error) {
	client, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": req.Challenge, "origin": req.Origin, "crossOrigin": false})
	if err != nil {
		return nil, err
	}
	rpHash := sha256.Sum256([]byte(req.RPID))
	flags := byte(0x01) // UP
	if !req.NoUV {
		flags |= 0x04 // UV
	}
	auth := append(append([]byte{}, rpHash[:]...), flags)
	auth = binary.BigEndian.AppendUint32(auth, a.SignCount)
	clientHash := sha256.Sum256(client)
	digest := sha256.Sum256(append(append([]byte{}, auth...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("passkeytest: sign: %w", err)
	}
	if req.BadSignature {
		sig[len(sig)-1] ^= 0xff
	}
	id := a.CredentialID
	if req.CredentialID != nil {
		id = req.CredentialID
	}
	b64 := base64.RawURLEncoding.EncodeToString
	return json.Marshal(map[string]any{
		"id": b64(id), "rawId": b64(id), "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]string{
			"clientDataJSON": b64(client), "authenticatorData": b64(auth), "signature": b64(sig), "userHandle": b64(a.UserHandle),
		},
	})
}
