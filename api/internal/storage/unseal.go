package storage

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
)

// The production opener for a sealed archive — the inverse of backupxfer.Seal,
// and the ONE place in either binary that consumes a §4.6 private key.
//
// It lives here, in the api's restore path, and not in backupxfer, on purpose.
// backupxfer is imported by the agent as well as the api, and its documented
// invariant is that it never holds a private key that can open an archive: a
// compute node seals its own volumes and could not read them back if it
// wanted to. Restore is interactive by construction (§4.5 unpacks before the
// api's first start), so a human with a custody secret is present, the key is
// supplied for the duration of one restore, and this is the only code that
// ever sees it.
//
// # What this function does with the key, exactly
//
// It receives the 32-byte X25519 scalar as a slice the CALLER owns and zeroes.
// It uses it for one scalar multiplication against the archive's ephemeral
// public key (the shared secret) and one against the base point (to bind the
// derivation to the recipient's public key, as the writer does). Both results
// are zeroed before it returns. The derived content key is handed to the AEAD
// constructor, which copies it; that copy is inside the cipher state and is
// released with it. The key is never formatted, never logged, never in an
// error, and there is no field on UnsealResult that could carry it.
//
// # Integrity
//
// Every chunk is authenticated before a byte of its plaintext is written to
// dst, with the header as additional data, so what a reader downstream sees
// is authentic — but it may be INCOMPLETE until this function returns nil. A
// stream whose final chunk does not carry the last-chunk flag was cut short,
// and that is an error here, not a short read. Callers that unpack as they go
// must therefore treat the whole extraction as failed unless Unseal returned
// nil — which is what the restore does by staging first and moving once.

// unsealInfo duplicates the writer's HKDF context string deliberately, the way
// sealtest does: a reader that imported the writer's constant would follow a
// drift in it and never notice.
const unsealInfo = "rasputin.backup.archive.v1"

// maxUnsealChunk bounds the chunk size a header may name. The header is
// authenticated — but only once a chunk has been opened with it as additional
// data, and the chunk size is what decides how many bytes to read before that
// first open. A hostile header naming a gigabyte chunk would otherwise size a
// buffer before anything had been verified.
const maxUnsealChunk = 16 << 20

// ErrArchiveTruncated is the refusal for a sealed stream that ended without a
// chunk carrying the last-chunk flag. Indistinguishable from a complete
// archive by length alone, which is why the flag exists.
var ErrArchiveTruncated = errors.New("sealed archive is truncated: the stream ended without its last chunk")

// ErrArchiveKeyMismatch is the refusal for a private key that cannot open the
// archive's chunks — the wrong key, or a chunk edited on the platter.
var ErrArchiveKeyMismatch = errors.New("sealed archive did not open: the key does not match, or the archive has been altered")

// UnsealResult is what a restore learns from opening an archive: the header
// facts and the digest over the sealed bytes it actually read. No secret.
type UnsealResult struct {
	Header backupxfer.Header
	// SealedDigest is the SHA-256 over the whole sealed file as read, lower-
	// case hex — comparable with the SealResult.Digest the run recorded.
	SealedDigest   string
	SealedBytes    uint64
	PlaintextBytes uint64
}

// Unseal opens a sealed archive from src with the recipient's 32-byte X25519
// private key and writes the plaintext to dst.
//
// privateKey is borrowed, not consumed: the caller zeroes it. See the file
// comment for what this function does with it and what it zeroes itself.
func Unseal(dst io.Writer, src io.Reader, privateKey []byte) (*UnsealResult, error) {
	if dst == nil || src == nil {
		return nil, errors.New("unseal needs a destination and a source")
	}
	if len(privateKey) != curve25519.ScalarSize {
		return nil, fmt.Errorf("the archive key is %d bytes; an X25519 private key is %d", len(privateKey), curve25519.ScalarSize)
	}

	digest := sha256.New()
	h, consumed, err := backupxfer.ReadHeader(io.TeeReader(src, digest))
	if err != nil {
		return nil, err
	}
	if h.ChunkSize <= 0 || h.ChunkSize > maxUnsealChunk {
		return nil, fmt.Errorf("sealed archive names a %d-byte chunk; this build reads chunks of at most %d", h.ChunkSize, maxUnsealChunk)
	}
	// The header JSON exactly as the writer marshalled it, which is the AEAD's
	// additional data: consumed is magic + header + newline.
	aad := consumed[len(backupxfer.SealMagic) : len(consumed)-1]

	epk, err := base64.RawURLEncoding.DecodeString(h.EphemeralPublicKey)
	if err != nil || len(epk) != curve25519.PointSize {
		return nil, errors.New("sealed archive header carries an unusable ephemeral public key")
	}

	// The two scalar multiplications, on buffers this function owns and zeroes.
	shared, err := curve25519.X25519(privateKey, epk)
	if err != nil {
		return nil, fmt.Errorf("x25519 exchange: %w", err)
	}
	defer zeroBytes(shared)
	recipientPub, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("x25519 public key: %w", err)
	}
	salt := make([]byte, 0, len(epk)+len(recipientPub))
	salt = append(salt, epk...)
	salt = append(salt, recipientPub...)
	contentKey, err := hkdf.Key(sha256.New, shared, salt, unsealInfo, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("derive content key: %w", err)
	}
	aead, err := chacha20poly1305.New(contentKey)
	zeroBytes(contentKey)
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}

	body := io.TeeReader(src, digest)
	sealedLen := uint64(len(consumed))
	full := h.ChunkSize + aead.Overhead()
	buf := make([]byte, full)
	plain := make([]byte, 0, h.ChunkSize)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	var counter, plaintextBytes uint64
	sawLast := false
	open := func(ct []byte, last bool) ([]byte, error) {
		for i := range nonce {
			nonce[i] = 0
		}
		binary.BigEndian.PutUint64(nonce[0:8], counter)
		if last {
			nonce[8] = 1
		}
		return aead.Open(plain[:0], nonce, ct, aad)
	}
	for {
		n, rerr := io.ReadFull(body, buf)
		sealedLen += byteCount(int64(n))
		if n == 0 {
			if rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
				return nil, fmt.Errorf("read sealed archive: %w", rerr)
			}
			if !sawLast {
				return nil, ErrArchiveTruncated
			}
			break
		}
		if sawLast {
			// Bytes after the chunk that declared itself last: an appended
			// tail, or two archives concatenated. Neither is this archive.
			return nil, errors.New("sealed archive carries data after its last chunk")
		}
		if rerr != nil && !errors.Is(rerr, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("read sealed archive: %w", rerr)
		}
		var out []byte
		if n < full {
			// A short chunk can only be the last one.
			out, err = open(buf[:n], true)
			if err != nil {
				return nil, ErrArchiveKeyMismatch
			}
			sawLast = true
		} else {
			// A full-sized chunk is usually not the last, but a stream whose
			// length is an exact multiple of the chunk size ends on one that
			// is (or on an empty last chunk after it). Try the ordinary nonce
			// first; the AEAD's tag decides.
			out, err = open(buf[:n], false)
			if err != nil {
				out, err = open(buf[:n], true)
				if err != nil {
					return nil, ErrArchiveKeyMismatch
				}
				sawLast = true
			}
		}
		if len(out) > 0 {
			if _, werr := dst.Write(out); werr != nil {
				return nil, fmt.Errorf("write plaintext: %w", werr)
			}
		}
		plaintextBytes += uint64(len(out))
		counter++
		if sawLast {
			// Drain to prove nothing follows; one more read decides.
			continue
		}
	}
	return &UnsealResult{
		Header:         h,
		SealedDigest:   hex.EncodeToString(digest.Sum(nil)),
		SealedBytes:    sealedLen,
		PlaintextBytes: plaintextBytes,
	}, nil
}

// PublicKeyForPrivate derives the base64url X25519 public key for a 32-byte
// private scalar. Used by the restore to check a supplied key against the
// disk's marker BEFORE anything is opened.
func PublicKeyForPrivate(privateKey []byte) (string, error) {
	if len(privateKey) != curve25519.ScalarSize {
		return "", fmt.Errorf("the archive key is %d bytes; an X25519 private key is %d", len(privateKey), curve25519.ScalarSize)
	}
	pub, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(pub), nil
}

// publicKeysEqual compares two base64url public keys in constant time after
// decoding both; anything undecodable compares unequal.
func publicKeysEqual(a, b string) bool {
	ra, erra := base64.RawURLEncoding.DecodeString(a)
	rb, errb := base64.RawURLEncoding.DecodeString(b)
	if erra != nil || errb != nil || len(ra) != curve25519.PointSize || len(rb) != curve25519.PointSize {
		return false
	}
	return subtle.ConstantTimeCompare(ra, rb) == 1
}

// zeroBytes overwrites b. Go offers no guarantee the compiler keeps a store
// to memory that is never read again, but the slices zeroed here are read
// again by nothing, so the store is the best that can be done from this side.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
