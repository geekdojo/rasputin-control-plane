package backupxfer

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A stalled upload holds the only slot; IdleTimeout is what takes it back.
// Internal test so the timeout can be shortened without exporting a knob.

type stallingReader struct {
	r       io.Reader
	after   int
	sent    int
	release chan struct{}
}

func (s *stallingReader) Read(p []byte) (int, error) {
	if s.sent >= s.after {
		<-s.release // never released: the client has gone quiet for good
		return 0, io.EOF
	}
	if len(p) > s.after-s.sent {
		p = p[:s.after-s.sent]
	}
	n, err := s.r.Read(p)
	s.sent += n
	return n, err
}

func TestIngestDropsAStalledUploadAndFreesTheSlot(t *testing.T) {
	auth, _ := NewAuthority()
	ing := New(auth, 1)
	ing.idle = 300 * time.Millisecond
	mux := http.NewServeMux()
	mux.Handle("PUT "+IngestPathPrefix, ing)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	gens := filepath.Join(t.TempDir(), "generations")
	genDir, err := ing.Open(gens, "20260903T120000Z-JOB12345-full", "01JOB")
	if err != nil {
		t.Fatal(err)
	}
	member := "volumes/vaultwarden/vaultwarden-data.rasputin-archive"
	cred, err := ing.Mint(Grant{Generation: "20260903T120000Z-JOB12345-full", Member: member, NodeID: "n", JobID: "01JOB", MaxBytes: 1 << 20}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	dest, _ := IngestDestination(srv.URL)
	tr := NewHTTPTransport(HTTPOptions{AcceptWait: 5 * time.Second})

	// A body that starts like an archive and then goes silent forever.
	body := &stallingReader{r: strings.NewReader(SealMagic + strings.Repeat("x", 100)), after: len(SealMagic) + 10, release: make(chan struct{})}
	start := time.Now()
	_, err = tr.Put(context.Background(), PutRequest{
		Destination: dest, Generation: "20260903T120000Z-JOB12345-full", Member: member, Credential: cred,
		Body: body, Sealed: func() (string, uint64) { return "", 0 },
	})
	if err == nil {
		t.Fatal("a stalled upload was reported landed")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the stalled upload held the slot for %s; the idle timeout did not fire", took)
	}
	if _, ok := ing.Landed("20260903T120000Z-JOB12345-full", member); ok {
		t.Fatal("a stalled upload was recorded")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		left := 0
		_ = filepath.Walk(genDir, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				left++
			}
			return nil
		})
		if left == 0 || time.Now().After(deadline) {
			if left != 0 {
				t.Fatal("a partial member survived the stalled upload")
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The slot is free: a real upload lands promptly.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var sealed bytes.Buffer
	key, _ := newX25519Public()
	res, err := Seal(&sealed, strings.NewReader("real"), key, "k", "full")
	if err != nil {
		t.Fatal(err)
	}
	cred2, _ := ing.Mint(Grant{Generation: "20260903T120000Z-JOB12345-full", Member: member, NodeID: "n", JobID: "01JOB", MaxBytes: 1 << 20}, time.Minute)
	if _, err := tr.Put(ctx, PutRequest{
		Destination: dest, Generation: "20260903T120000Z-JOB12345-full", Member: member, Credential: cred2,
		Body: bytes.NewReader(sealed.Bytes()), Sealed: func() (string, uint64) { return res.Digest, res.SizeBytes },
	}); err != nil {
		t.Fatalf("the upload after the stalled one failed: %v — the slot leaked", err)
	}
}
