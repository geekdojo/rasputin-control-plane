package backupxfer_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/backupxfer/sealtest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// §4.6's write path, tested from both sides. The DECRYPTION lives in sealtest,
// a package neither binary imports — which is the property under test as much
// as it is a means of testing.

const sealInfo = "rasputin.backup.archive.v1"

// sealChunkSize duplicates the writer's constant so a drift in it shows up
// here rather than being followed.
const sealChunkSize = 64 << 10

type testKeypair struct {
	priv      *ecdh.PrivateKey
	publicB64 string
}

func newTestKeypair(t *testing.T) testKeypair {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	return testKeypair{priv: priv, publicB64: base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())}
}

func open(t *testing.T, sealed []byte, priv *ecdh.PrivateKey) ([]byte, backupxfer.Header) {
	t.Helper()
	plain, h, err := sealtest.Open(sealed, priv)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return plain, h
}

func TestSealRoundTripsAndDigestMatches(t *testing.T) {
	key := newTestKeypair(t)
	plaintext := bytes.Repeat([]byte("the mesh CA and every bus token, in clear. "), 5000)

	var out bytes.Buffer
	res, err := backupxfer.Seal(&out, bytes.NewReader(plaintext), key.publicB64, "key-1", proto.BackupScopeFull)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sum := sha256.Sum256(out.Bytes())
	if res.Digest != hex.EncodeToString(sum[:]) {
		t.Errorf("digest = %s, but the sealed bytes hash to %s", res.Digest, hex.EncodeToString(sum[:]))
	}
	if res.SizeBytes != uint64(out.Len()) || res.PlaintextBytes != uint64(len(plaintext)) || res.Alg != backupxfer.SealAlg {
		t.Errorf("result = %+v", res)
	}
	if bytes.Contains(out.Bytes(), plaintext[:64]) {
		t.Fatal("the sealed archive contains its own plaintext")
	}
	got, header := open(t, out.Bytes(), key.priv)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round trip produced %d bytes, want %d", len(got), len(plaintext))
	}
	if header.KeyID != "key-1" || header.Scope != proto.BackupScopeFull {
		t.Errorf("header = %+v", header)
	}
	if header.EphemeralPublicKey == key.publicB64 {
		t.Error("the ephemeral public key equals the recipient's: no fresh keypair was minted")
	}
	// ReadHeader, the ingest's parse, agrees with the opener about the header
	// and consumes exactly the prefix.
	h2, prefix, err := backupxfer.ReadHeader(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if h2 != header || !bytes.HasPrefix(out.Bytes(), prefix) || prefix[len(prefix)-1] != '\n' {
		t.Errorf("ReadHeader = %+v over %d bytes", h2, len(prefix))
	}
}

func TestSealMintsAFreshEphemeralKeyPerRun(t *testing.T) {
	key := newTestKeypair(t)
	plaintext := []byte("identical input, twice")
	var a, b bytes.Buffer
	ra, err := backupxfer.Seal(&a, bytes.NewReader(plaintext), key.publicB64, "key-1", "s")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	rb, err := backupxfer.Seal(&b, bytes.NewReader(plaintext), key.publicB64, "key-1", "s")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if ra.EphemeralPublicKey == rb.EphemeralPublicKey || bytes.Equal(a.Bytes(), b.Bytes()) || ra.Digest == rb.Digest {
		t.Fatal("two seals of the same plaintext produced the same key, bytes or digest")
	}
}

func TestSealRefusesWithoutAUsablePublicKeyOrScope(t *testing.T) {
	cases := []struct{ name, key, scope, want string }{
		{"no key at all", "", "s", "no archive public key"},
		{"not base64url", "!!!!not base64!!!!", "s", "base64url"},
		{"wrong length", base64.RawURLEncoding.EncodeToString([]byte("short")), "s", "X25519 public key is"},
		{"all zeroes", base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "s", "all zeroes"},
		{"empty scope", newTestKeypair(t).publicB64, "", "empty scope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			_, err := backupxfer.Seal(&out, strings.NewReader("secrets"), tc.key, "key-1", tc.scope)
			if err == nil {
				t.Fatal("Seal accepted an unusable input")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
			if out.Len() != 0 {
				t.Errorf("a refused seal still wrote %d bytes", out.Len())
			}
		})
	}
}

// contentKey derives the AEAD for hand-decryption, for the cases where a
// FAILURE to open is the pass.
func contentKey(t *testing.T, key testKeypair, h backupxfer.Header) (aead interface {
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	Overhead() int
}) {
	t.Helper()
	epkRaw, _ := base64.RawURLEncoding.DecodeString(h.EphemeralPublicKey)
	epk, _ := ecdh.X25519().NewPublicKey(epkRaw)
	shared, _ := key.priv.ECDH(epk)
	salt := append(append([]byte{}, epkRaw...), key.priv.PublicKey().Bytes()...)
	ck, _ := hkdf.Key(sha256.New, shared, salt, sealInfo, chacha20poly1305.KeySize)
	a, _ := chacha20poly1305.New(ck)
	return a
}

func TestSealDetectsTampering(t *testing.T) {
	key := newTestKeypair(t)
	var out bytes.Buffer
	if _, err := backupxfer.Seal(&out, strings.NewReader("payload that must not open after an edit"), key.publicB64, "key-1", proto.BackupScopeFull); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealed := out.Bytes()
	edited := bytes.Replace(sealed, []byte(`"scope":"full"`), []byte(`"scope":"FULL"`), 1)
	if bytes.Equal(edited, sealed) {
		t.Fatal("the header does not carry the scope in the shape this test edits")
	}
	rest := edited[len(backupxfer.SealMagic):]
	nl := bytes.IndexByte(rest, '\n')
	headerBytes, body := rest[:nl], rest[nl+1:]
	var h backupxfer.Header
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		t.Fatalf("edited header: %v", err)
	}
	aead := contentKey(t, key, h)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	nonce[8] = 1
	if _, err := aead.Open(nil, nonce, body, headerBytes); err == nil {
		t.Fatal("an edited header still opened: the scope inside the archive is forgeable")
	}
}

func TestSealTerminatesOnAnExactChunkBoundary(t *testing.T) {
	key := newTestKeypair(t)
	for _, size := range []int{0, sealChunkSize, 2 * sealChunkSize} {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			plaintext := bytes.Repeat([]byte("x"), size)
			var out bytes.Buffer
			res, err := backupxfer.Seal(&out, bytes.NewReader(plaintext), key.publicB64, "key-1", "s")
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if res.PlaintextBytes != uint64(size) {
				t.Errorf("plaintextBytes = %d, want %d", res.PlaintextBytes, size)
			}
			got, _ := open(t, out.Bytes(), key.priv)
			if !bytes.Equal(got, plaintext) {
				t.Errorf("round trip produced %d bytes, want %d", len(got), size)
			}
		})
	}
}

func TestSealDetectsTruncationAtAChunkBoundary(t *testing.T) {
	key := newTestKeypair(t)
	var out bytes.Buffer
	if _, err := backupxfer.Seal(&out, bytes.NewReader(bytes.Repeat([]byte("y"), 2*sealChunkSize)), key.publicB64, "key-1", "s"); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	full := out.Bytes()
	truncated := full[:len(full)-16]
	if _, _, err := sealtest.Open(truncated, key.priv); err == nil {
		t.Fatal("a truncated archive opened cleanly")
	}
	rest := truncated[len(backupxfer.SealMagic):]
	nl := bytes.IndexByte(rest, '\n')
	headerBytes, body := rest[:nl], rest[nl+1:]
	var h backupxfer.Header
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		t.Fatalf("header: %v", err)
	}
	aead := contentKey(t, key, h)
	chunk := h.ChunkSize + aead.Overhead()
	nonce := make([]byte, chacha20poly1305.NonceSize)
	for i := 0; i*chunk < len(body); i++ {
		end := min((i+1)*chunk, len(body))
		for j := range nonce {
			nonce[j] = 0
		}
		binary.BigEndian.PutUint64(nonce[0:8], uint64(i))
		nonce[8] = 1
		if _, err := aead.Open(nil, nonce, body[i*chunk:end], headerBytes); err == nil {
			t.Fatalf("chunk %d opened as a terminating chunk; truncation would be undetectable", i)
		}
	}
}

func TestReadHeaderRefusesWhatIsNotAnArchive(t *testing.T) {
	for _, body := range []string{
		"", "RASPUTIN-ARCHIVE-1", "RASPUTIN-ARCHIVE-1\n", "RASPUTIN-ARCHIVE-1\nnot json\n",
		"RASPUTIN-ARCHIVE-2\n{}\n", "SQLite format 3\x00", "RASPUTIN-ARCHIVE-1\n{\"v\":1}\n",
		"RASPUTIN-ARCHIVE-1\n" + strings.Repeat("x", backupxfer.MaxHeaderBytes+1),
	} {
		if _, _, err := backupxfer.ReadHeader(strings.NewReader(body)); err == nil {
			t.Errorf("ReadHeader accepted %q", body[:min(len(body), 40)])
		}
	}
}
