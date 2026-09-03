package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/artifactsig"
)

// largeArtifact is bigger than Download's 64 KiB read buffer, so resp.Body.Read
// is forced to return at least once with (n>0, nil) BEFORE the terminating EOF.
// That intermediate read is the only thing that exercises the read loop's error
// branch (`if rerr != nil`) with a non-EOF, non-error result — the small bodies
// the other download tests use return their bytes together with io.EOF in a
// single Read, so the loop breaks before that branch is ever evaluated. Content
// is deterministic so the sha and the on-disk bytes can be asserted exactly.
func largeArtifact() []byte {
	b := make([]byte, 200*1024)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return b
}

// TestOpenWrtDownload_MultiChunkBodyIsWrittenWhole downloads an artifact larger
// than the read buffer and asserts the returned path, the observed sha and the
// bytes actually on disk. Negating the read loop's `if rerr != nil` guard
// (openwrt_ab.go) turns the first intermediate (n, nil) read into an early
// `return "", "", nil`: Download then reports success with an EMPTY path and a
// truncated (empty) sha, and stages nothing. Asserting all three catches that.
func TestOpenWrtDownload_MultiChunkBodyIsWrittenWhole(t *testing.T) {
	body := largeArtifact()
	sum := sha256.Sum256(body)
	wantSHA := hex.EncodeToString(sum[:])
	as := newArtifactServer(t, body, []byte("detached-cms-bytes"))

	b, err := NewOpenWrtABBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path, observed, err := b.Download(context.Background(), "b1", as.bundleURL(), as.sigURL(),
		wantSHA, int64(len(body)), nil)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if path == "" {
		t.Fatal("Download returned an empty path on success — the artifact was not staged")
	}
	if observed != wantSHA {
		t.Errorf("observed sha = %q, want %q", observed, wantSHA)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read staged artifact: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("staged artifact is %d bytes, want the full %d-byte body", len(got), len(body))
	}
	if _, err := os.ReadFile(artifactsig.SigPathFor(path)); err != nil {
		t.Errorf("signature not staged beside the artifact: %v", err)
	}
}

// TestRAUCDownload_MultiChunkBodyIsWrittenWhole is the same assertion for the
// RAUC backend's read loop (rauc.go): a >64 KiB body must arrive whole, with the
// returned path and sha reflecting it. Negating that loop's `if rerr != nil`
// guard makes the first intermediate read return early with an empty path/sha
// and no file written.
func TestRAUCDownload_MultiChunkBodyIsWrittenWhole(t *testing.T) {
	body := largeArtifact()
	sum := sha256.Sum256(body)
	wantSHA := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	b, err := newRAUCBackend(t.TempDir(), "/bin/true")
	if err != nil {
		t.Fatalf("newRAUCBackend: %v", err)
	}
	path, observed, err := b.Download(context.Background(), "b1", srv.URL+"/bundle", "", wantSHA, int64(len(body)), nil)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if path == "" {
		t.Fatal("Download returned an empty path on success — the bundle was not staged")
	}
	if observed != wantSHA {
		t.Errorf("observed sha = %q, want %q", observed, wantSHA)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read staged bundle: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("staged bundle is %d bytes, want the full %d-byte body", len(got), len(body))
	}
}

// TestOpenWrtDownload_RejectsShaMismatch is the download-integrity gate: when the
// bytes on the wire don't hash to the expected sha, Download must refuse rather
// than stage a corrupt artifact. It guards the `expectedSHA != "" && observed !=
// expectedSHA` check (openwrt_ab.go) — every other openwrt-ab download test
// passes either the correct sha or an empty one, so no existing test drives a
// genuine mismatch, and negating either half of that condition (accepting a
// corrupt bundle) survives them all.
func TestOpenWrtDownload_RejectsShaMismatch(t *testing.T) {
	body := []byte("SQUASHFS-BYTES")
	as := newArtifactServer(t, body, []byte("detached-cms-bytes"))

	b, err := NewOpenWrtABBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	wrongSHA := hex.EncodeToString(sha256.New().Sum(nil)) // sha256 of empty, never the body's
	path, observed, err := b.Download(context.Background(), "b1", as.bundleURL(), as.sigURL(),
		wrongSHA, int64(len(body)), nil)
	if err == nil {
		t.Fatalf("Download accepted an artifact whose bytes don't match the expected sha (path=%q)", path)
	}
	if !strings.Contains(err.Error(), "sha mismatch") {
		t.Errorf("error should name the sha mismatch, got: %v", err)
	}
	sum := sha256.Sum256(body)
	if observed != hex.EncodeToString(sum[:]) {
		t.Errorf("observed sha = %q, want the body's actual sha so the caller can see what arrived", observed)
	}
}

// TestRAUCDownload_RejectsShaMismatch is the same integrity gate for the RAUC
// backend's read path (rauc.go): a bundle whose bytes don't match the expected
// sha must be refused, not staged.
func TestRAUCDownload_RejectsShaMismatch(t *testing.T) {
	body := []byte("rauc bundle bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	b, err := newRAUCBackend(t.TempDir(), "/bin/true")
	if err != nil {
		t.Fatalf("newRAUCBackend: %v", err)
	}
	wrongSHA := hex.EncodeToString(sha256.New().Sum(nil))
	path, observed, err := b.Download(context.Background(), "b1", srv.URL+"/bundle", "", wrongSHA, int64(len(body)), nil)
	if err == nil {
		t.Fatalf("Download accepted a bundle whose bytes don't match the expected sha (path=%q)", path)
	}
	if !strings.Contains(err.Error(), "sha mismatch") {
		t.Errorf("error should name the sha mismatch, got: %v", err)
	}
	sum := sha256.Sum256(body)
	if observed != hex.EncodeToString(sum[:]) {
		t.Errorf("observed sha = %q, want the body's actual sha", observed)
	}
}
