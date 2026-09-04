package storage

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/backupxfer"
)

// Unseal is the inverse of backupxfer.Seal, written against the format's
// description rather than beside the writer. These cases hold it to the
// format: round-trips at every chunk-boundary shape, and refusals for the
// ways an archive on a disk somebody else held can be wrong.

func sealBytes(t *testing.T, key testKeypair, plain []byte, scope string) []byte {
	t.Helper()
	var out bytes.Buffer
	if _, err := backupxfer.Seal(&out, bytes.NewReader(plain), key.publicB64, "key-1", scope); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return out.Bytes()
}

func TestUnsealRoundTripsEveryChunkShape(t *testing.T) {
	key := newTestKeypair(t)
	// 64 KiB is the writer's chunk; the shapes that matter are below one
	// chunk, exactly one, exactly two (an empty last chunk follows), and one
	// and a bit.
	for _, n := range []int{0, 1, 1000, 64 << 10, 128 << 10, (64 << 10) + 17, 3*(64<<10) - 1} {
		plain := make([]byte, n)
		_, _ = rand.Read(plain)
		sealed := sealBytes(t, key, plain, "full")
		var got bytes.Buffer
		res, err := Unseal(&got, bytes.NewReader(sealed), key.priv.Bytes())
		if err != nil {
			t.Fatalf("n=%d: Unseal: %v", n, err)
		}
		if !bytes.Equal(got.Bytes(), plain) {
			t.Fatalf("n=%d: plaintext differs", n)
		}
		if res.PlaintextBytes != uint64(n) || res.SealedBytes != uint64(len(sealed)) {
			t.Fatalf("n=%d: sizes %d/%d, want %d/%d", n, res.PlaintextBytes, res.SealedBytes, n, len(sealed))
		}
		if res.Header.Scope != "full" || res.Header.KeyID != "key-1" {
			t.Fatalf("n=%d: header %+v", n, res.Header)
		}
	}
}

func TestUnsealDigestMatchesTheWriter(t *testing.T) {
	key := newTestKeypair(t)
	plain := []byte(strings.Repeat("identity ", 10000))
	var out bytes.Buffer
	sr, err := backupxfer.Seal(&out, bytes.NewReader(plain), key.publicB64, "key-1", "full")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Unseal(io.Discard, bytes.NewReader(out.Bytes()), key.priv.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if res.SealedDigest != sr.Digest {
		t.Fatalf("digest %s, writer recorded %s", res.SealedDigest, sr.Digest)
	}
}

func TestUnsealRefusesTheWrongKey(t *testing.T) {
	key, other := newTestKeypair(t), newTestKeypair(t)
	sealed := sealBytes(t, key, []byte("secret"), "full")
	var got bytes.Buffer
	_, err := Unseal(&got, bytes.NewReader(sealed), other.priv.Bytes())
	if !errors.Is(err, ErrArchiveKeyMismatch) {
		t.Fatalf("err = %v, want ErrArchiveKeyMismatch", err)
	}
	if got.Len() != 0 {
		t.Fatalf("plaintext was written under the wrong key: %q", got.String())
	}
}

func TestUnsealRefusesTruncation(t *testing.T) {
	key := newTestKeypair(t)
	plain := make([]byte, 3*(64<<10)+5)
	_, _ = rand.Read(plain)
	sealed := sealBytes(t, key, plain, "full")
	// Cut inside the last chunk, and at an exact chunk boundary — the
	// second is the one a length check cannot see.
	headerEnd := bytes.IndexByte(sealed[len(backupxfer.SealMagic):], '\n') + len(backupxfer.SealMagic) + 1
	chunk := (64 << 10) + 16
	for _, cut := range []int{len(sealed) - 3, headerEnd + 2*chunk, headerEnd + chunk} {
		_, err := Unseal(io.Discard, bytes.NewReader(sealed[:cut]), key.priv.Bytes())
		if err == nil {
			t.Fatalf("cut at %d: truncated archive opened", cut)
		}
		if !errors.Is(err, ErrArchiveTruncated) && !errors.Is(err, ErrArchiveKeyMismatch) {
			t.Fatalf("cut at %d: err = %v", cut, err)
		}
	}
}

func TestUnsealRefusesAnEditedHeader(t *testing.T) {
	key := newTestKeypair(t)
	sealed := sealBytes(t, key, []byte("payload"), "full")
	// The scope is authenticated data: editing it on the platter breaks every
	// tag. This is the property that stops a sidecar manifest from being
	// believed over the seal.
	edited := bytes.Replace(sealed, []byte(`"scope":"full"`), []byte(`"scope":"fake"`), 1)
	if bytes.Equal(edited, sealed) {
		t.Fatal("test setup: scope not found in header")
	}
	_, err := Unseal(io.Discard, bytes.NewReader(edited), key.priv.Bytes())
	if !errors.Is(err, ErrArchiveKeyMismatch) {
		t.Fatalf("err = %v, want ErrArchiveKeyMismatch", err)
	}
}

func TestUnsealRefusesTrailingData(t *testing.T) {
	key := newTestKeypair(t)
	sealed := sealBytes(t, key, []byte("payload"), "full")
	// One byte after a short last chunk lengthens that chunk, so the tag
	// fails; a whole extra chunk after a full-sized last one is data after
	// the last chunk. Both are refusals.
	_, err := Unseal(io.Discard, bytes.NewReader(append(sealed, 'x')), key.priv.Bytes())
	if !errors.Is(err, ErrArchiveKeyMismatch) {
		t.Fatalf("err = %v", err)
	}
	exact := sealBytes(t, key, make([]byte, 64<<10), "full")
	tail := make([]byte, (64<<10)+16)
	_, err = Unseal(io.Discard, bytes.NewReader(append(exact, tail...)), key.priv.Bytes())
	if err == nil || (!strings.Contains(err.Error(), "after its last chunk") && !errors.Is(err, ErrArchiveKeyMismatch)) {
		t.Fatalf("err = %v", err)
	}
}

func TestUnsealRefusesNotAnArchive(t *testing.T) {
	key := newTestKeypair(t)
	_, err := Unseal(io.Discard, strings.NewReader("this is a tarball somebody dropped here"), key.priv.Bytes())
	if err == nil || !strings.Contains(err.Error(), "not a sealed archive") {
		t.Fatalf("err = %v", err)
	}
	_, err = Unseal(io.Discard, strings.NewReader(""), key.priv.Bytes())
	if err == nil {
		t.Fatal("empty input opened")
	}
}

func TestUnsealRefusesAWrongSizedKey(t *testing.T) {
	key := newTestKeypair(t)
	sealed := sealBytes(t, key, []byte("payload"), "full")
	_, err := Unseal(io.Discard, bytes.NewReader(sealed), key.priv.Bytes()[:31])
	if err == nil || !strings.Contains(err.Error(), "32") {
		t.Fatalf("err = %v", err)
	}
}

func TestPublicKeyForPrivateMatchesTheKeypair(t *testing.T) {
	key := newTestKeypair(t)
	pub, err := PublicKeyForPrivate(key.priv.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if pub != key.publicB64 {
		t.Fatalf("derived %s, keypair says %s", pub, key.publicB64)
	}
	if !publicKeysEqual(pub, key.publicB64) || publicKeysEqual(pub, newTestKeypair(t).publicB64) || publicKeysEqual("nope", pub) {
		t.Fatal("publicKeysEqual is wrong")
	}
}
