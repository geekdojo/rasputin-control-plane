package storage

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// §4.6's write path: seal an archive to the target's PUBLIC key.
//
// This file is the whole reason the 2026-09-02 amendment exists. A weekly
// 3 a.m. backup.run has nobody at a keyboard, so under the previous single
// symmetric key the api would have had to cache that key in the clear — which
// is precisely the exposure §4.6 was written to close. Sealing to a public key
// needs no secret at rest and no human.
//
// So the invariant this file enforces, and which every test in
// backup_seal_test.go exists to hold:
//
//	THIS PACKAGE NEVER HOLDS A PRIVATE KEY THAT CAN OPEN AN ARCHIVE.
//
// A fresh ephemeral X25519 keypair is minted per run inside Seal, used once,
// and dropped when the function returns. Its PUBLIC half goes in the header (a
// reader needs it to derive the same secret); its private half is never
// returned, never logged, never stored, and has no field on any result type to
// be stored in. The recipient's private key is not here either — it is on the
// backup disk, wrapped under the operator's passphrase and recovery code, and
// this process could not unwrap it if it wanted to.
//
// The cost, recorded so nobody rediscovers it as a bug: THIS CONTROLPLANE CAN
// WRITE ARCHIVES AND CANNOT READ THEM BACK. Integrity is therefore verified
// from a digest over the ciphertext (SealResult.Digest), never by decrypting.
// Restore is interactive by construction — §4.5 unpacks before the api's first
// start — so a human with a custody secret is present by definition.

// SealMagic opens every sealed archive. A fixed, greppable prefix so a restore
// path, or an operator with `file` and `head -c`, can tell a Rasputin archive
// from a tarball somebody dropped on the disk.
const SealMagic = "RASPUTIN-ARCHIVE-1\n"

// SealAlg names the construction. Written into the header so a reader years
// from now parses what it is looking at rather than assuming whatever this code
// does at that moment — the same reason StorageBackupSet carries KeyAlg.
//
// X25519 for the exchange because the target's key is X25519 (§4.6's amendment
// and ArchiveKey.PublicKey). HKDF-SHA-256 for the derivation. ChaCha20-Poly1305
// for the AEAD, deliberately over AES-GCM: §4.6's consequences list asks for an
// AEAD with a fast SOFTWARE path, because Pi 4 class hardware (Cortex-A72, no
// ARMv8 crypto extensions) runs AES in software. That consequence was written
// about the agent's per-node encryption, and the same reasoning applies to a
// controlplane on Pi-class hardware — which the BitScope one is.
const SealAlg = "x25519-hkdf-sha256-chacha20poly1305-stream-v1"

// sealChunkSize is the plaintext chunk size of the STREAM construction.
//
// Chunked rather than one-shot because the archive is a database plus a trust
// directory and can be hundreds of megabytes: a one-shot AEAD would hold the
// whole plaintext AND the whole ciphertext in memory on an appliance whose
// budget §5 is a table about. 64 KiB is the usual figure and keeps the per-
// chunk 16-byte tag overhead at 0.02%.
const sealChunkSize = 64 << 10

// sealInfo is the HKDF context string. It binds the derived key to THIS
// construction, so a future scheme reusing X25519 and HKDF cannot derive the
// same key from the same exchange.
const sealInfo = "rasputin.backup.archive.v1"

// SealResult is everything the api learns from sealing, and it is chosen to be
// the largest set of facts that contains no secret.
//
// Note what is absent and cannot be added: the ephemeral PRIVATE key, the
// derived content key, and the recipient's private key. This struct is
// marshalled into a saga step result, which the Tasks view renders and the job
// ledger persists — so a field here is a field published. That is the reason
// the sealing function returns this rather than, say, the cipher state.
type SealResult struct {
	// Digest is the SHA-256 of the ENTIRE sealed file, lower-case hex: magic,
	// header and body. It is what the agent re-computes before writing a
	// generation, and what a restore checks before spending a passphrase on an
	// archive that turns out to be truncated.
	Digest string `json:"digest"`
	// SizeBytes is the sealed file's length.
	SizeBytes uint64 `json:"sizeBytes"`
	// PlaintextBytes is what went in. Reported because the compression-free
	// overhead of the construction should be legible in the job feed rather
	// than a mystery.
	PlaintextBytes uint64 `json:"plaintextBytes"`
	// KeyID is the target keypair the archive is sealed to — an identifier, and
	// the thing a restore reads to know which key it needs.
	KeyID string `json:"keyId,omitempty"`
	// Alg is SealAlg, echoed so a step result says what was done rather than
	// leaving it to be inferred from the code of the day.
	Alg string `json:"alg"`
	// EphemeralPublicKey is the PUBLIC half of the per-run keypair, base64url
	// of 32 raw bytes. Publishable by construction: it is in the archive header
	// in clear, because a reader cannot derive the shared secret without it.
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
}

// sealHeader is the archive's clear-text header line.
type sealHeader struct {
	Version int    `json:"v"`
	Alg     string `json:"alg"`
	// KeyID identifies the RECIPIENT keypair; EphemeralPublicKey is this run's.
	KeyID              string `json:"keyId,omitempty"`
	EphemeralPublicKey string `json:"epk"`
	ChunkSize          int    `json:"chunkSize"`
	// Scope repeats proto.BackupScopeIdentityOnly INSIDE the sealed archive as
	// well as in the clear-text manifest beside it. Duplication on purpose: the
	// manifest can be deleted or replaced by anyone holding the disk, and the
	// header cannot be edited without invalidating every chunk's tag — it is the
	// AEAD's additional data. A restore that trusted only the sidecar could be
	// told an identity-only archive was a full one.
	Scope     string    `json:"scope"`
	CreatedAt time.Time `json:"createdAt"`
}

// ErrNoPublicKey is the refusal for a target with no §4.6 public key: one
// claimed before encryption was configured, or under the pre-amendment
// symmetric design.
//
// A refusal rather than a fallback to writing in clear, and this is the single
// most consequential branch in the file. §4.6 opens by stating that the archive
// §4.5 specifies IS an unencrypted portable copy of every secret in the
// cluster — the SQLite DB with its users, passkey credentials and bus tokens,
// `mesh-ca.key`, and Headscale state. A build that quietly wrote that in clear
// when a key was missing would be shipping the exposure §4.6 exists to close,
// on the path where the operator is least likely to notice.
var ErrNoPublicKey = errors.New("storage: the backup target has no archive public key, so nothing can be sealed to it")

// Seal encrypts everything read from src to the target's public key and writes
// the sealed archive to dst, returning facts about it and no secrets.
//
// publicKey is base64url of 32 raw bytes — ArchiveKey.PublicKey, as validated
// at claim time and re-validated here. Re-validated rather than trusted:
// between the claim and this call the value has been through a database column,
// and a garbage public key is an archive nobody can ever read, discovered on
// restore day.
func Seal(dst io.Writer, src io.Reader, publicKey, keyID, scope string) (*SealResult, error) {
	if strings.TrimSpace(publicKey) == "" {
		return nil, ErrNoPublicKey
	}
	if err := validatePublicKey(publicKey); err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(publicKey))
	if err != nil {
		return nil, fmt.Errorf("archive public key: %w", err)
	}
	recipient, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("archive public key: %w", err)
	}
	if scope == "" {
		scope = proto.BackupScopeIdentityOnly
	}

	// The one keypair this function mints, uses, and drops. It exists only
	// inside this call: nothing returns it, nothing stores it, and the
	// SealResult has no field it could occupy.
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}
	shared, err := eph.ECDH(recipient)
	if err != nil {
		return nil, fmt.Errorf("x25519 exchange: %w", err)
	}
	epk := eph.PublicKey().Bytes()
	// Salt binds the derivation to BOTH public keys, so the same ephemeral key
	// used against a different recipient yields a different content key.
	salt := make([]byte, 0, len(epk)+len(raw))
	salt = append(salt, epk...)
	salt = append(salt, raw...)
	contentKey, err := hkdf.Key(sha256.New, shared, salt, sealInfo, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("derive content key: %w", err)
	}
	aead, err := chacha20poly1305.New(contentKey)
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}

	header, err := json.Marshal(sealHeader{
		Version:            1,
		Alg:                SealAlg,
		KeyID:              keyID,
		EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(epk),
		ChunkSize:          sealChunkSize,
		Scope:              scope,
		CreatedAt:          time.Now().UTC(),
	})
	if err != nil {
		return nil, err
	}

	digest := sha256.New()
	out := io.MultiWriter(dst, digest)
	written := uint64(0)
	emit := func(b []byte) error {
		n, err := out.Write(b)
		written += uint64(n)
		return err
	}
	if err := emit([]byte(SealMagic)); err != nil {
		return nil, err
	}
	if err := emit(append(header, '\n')); err != nil {
		return nil, err
	}

	// The header is the AEAD's additional data for every chunk, so the key-id,
	// the ephemeral public key, the chunk size and the SCOPE are all
	// authenticated. Editing any of them on the platter breaks every tag.
	plain := make([]byte, sealChunkSize)
	sealed := make([]byte, 0, sealChunkSize+aead.Overhead())
	nonce := make([]byte, chacha20poly1305.NonceSize)
	var counter uint64
	var plaintextBytes uint64
	for {
		n, rerr := io.ReadFull(src, plain)
		last := rerr == io.EOF || rerr == io.ErrUnexpectedEOF
		if rerr != nil && !last {
			return nil, fmt.Errorf("read plaintext: %w", rerr)
		}
		if n == 0 && counter > 0 && last {
			// The previous chunk was a full one and the stream ended exactly on
			// the boundary. Emit a final empty chunk so the last-flag is set on
			// something — a reader must be able to tell "the stream ended" from
			// "the file was truncated at a chunk boundary", and an unterminated
			// stream is exactly what truncation looks like.
			if err := sealChunk(aead, nonce, counter, true, header, sealed[:0], nil, emit); err != nil {
				return nil, err
			}
			break
		}
		if err := sealChunk(aead, nonce, counter, last, header, sealed[:0], plain[:n], emit); err != nil {
			return nil, err
		}
		plaintextBytes += uint64(n)
		counter++
		if last {
			break
		}
	}

	return &SealResult{
		Digest:             hex.EncodeToString(digest.Sum(nil)),
		SizeBytes:          written,
		PlaintextBytes:     plaintextBytes,
		KeyID:              keyID,
		Alg:                SealAlg,
		EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(epk),
	}, nil
}

// sealChunk seals one chunk under a nonce derived from the chunk counter and
// the last-chunk flag — the STREAM construction age uses.
//
// The counter is what keeps nonces unique, and the content key is fresh per run
// by construction (a new ephemeral keypair every call to Seal), so a nonce is
// never reused under a key even across runs to the same target. The last flag
// is what makes truncation detectable: a stream whose final chunk is not marked
// last was cut short.
func sealChunk(aead cipher.AEAD, nonce []byte, counter uint64, last bool, aad, dst, plaintext []byte, emit func([]byte) error) error {
	for i := range nonce {
		nonce[i] = 0
	}
	binary.BigEndian.PutUint64(nonce[0:8], counter)
	if last {
		nonce[8] = 1
	}
	return emit(aead.Seal(dst, nonce, plaintext, aad))
}
