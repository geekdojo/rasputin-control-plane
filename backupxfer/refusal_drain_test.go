package backupxfer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A refused client that never stops sending is answered, then cut off once
// the endpoint has read the drain's worth of its body: it cannot hold the
// upload slot by ignoring the refusal. Internal test so the drain can be
// shortened without exporting a knob.
func TestIngestCutsOffAClientThatKeepsSendingAfterTheRefusal(t *testing.T) {
	const (
		gen    = "20260903T120000Z-JOB12345-full"
		member = "volumes/vaultwarden/vaultwarden-data.rasputin-archive"
	)
	auth, _ := NewAuthority()
	ing := New(auth, 1, slog.New(slog.DiscardHandler))
	ing.drain = 1 << 20
	mux := http.NewServeMux()
	mux.Handle("PUT "+IngestPathPrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ing.ServeNode(w, r, "n") }))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	genDir, err := ing.Open(filepath.Join(t.TempDir(), "generations"), gen, "01JOB")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := ing.Mint(Grant{Generation: gen, Member: member, NodeID: "n", JobID: "01JOB", MaxBytes: 64 << 10}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := newX25519Public()
	var sealed bytes.Buffer
	if _, err := Seal(&sealed, strings.NewReader("x"), key, "k", "full"); err != nil {
		t.Fatal(err)
	}

	// A raw client: no declared length, a real archive header, then chunks
	// forever, and it never reads while it writes. The deadline bounds the
	// test's I/O only: the cut-off is the server closing the connection.
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "PUT %s%s/%s HTTP/1.1\r\nHost: ingest\r\nAuthorization: Bearer %s\r\nTransfer-Encoding: chunked\r\n\r\n",
		IngestPathPrefix, gen, member, cred); err != nil {
		t.Fatal(err)
	}
	writeErr := make(chan error, 1)
	var sent int64
	go func() {
		chunk := func(p []byte) error {
			_, err := fmt.Fprintf(conn, "%x\r\n%s\r\n", len(p), p)
			return err
		}
		if err := chunk(sealed.Bytes()); err != nil {
			writeErr <- err
			return
		}
		filler := bytes.Repeat([]byte("x"), 32<<10)
		for {
			if err := chunk(filler); err != nil {
				writeErr <- err
				return
			}
			sent += int64(len(filler))
		}
	}()

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no refusal reached the client: %v", err)
	}
	var p Problem
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil || resp.StatusCode != http.StatusRequestEntityTooLarge || p.Code != CodeOverBound {
		t.Fatalf("answered %d %+v (%v), want 413 %s", resp.StatusCode, p, err, CodeOverBound)
	}
	err = <-writeErr
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("the endpoint was still reading after %d bytes; the drain never cut the client off", sent)
	}
	// What the endpoint read (the bound, then the drain) plus what the two
	// socket buffers held when it closed.
	if limit := int64(64<<10) + int64(ing.drain) + 16<<20; sent > limit {
		t.Errorf("the client sent %d bytes before it was cut off; want at most %d", sent, limit)
	}

	// Nothing landed, and the slot is free. The server hangs up only after
	// the handler has returned, and the handler gives the slot back on its
	// way out, so by the time the client's write failed the slot is back:
	// a fact to check, not a wait.
	if _, ok := ing.Landed(gen, member); ok {
		t.Fatal("the refused upload was recorded")
	}
	if held := len(ing.sem); held != 0 {
		t.Fatalf("%d upload slot(s) still held after the refused client was cut off", held)
	}
	// And a real upload lands in it. The 30 seconds bound this one call's
	// wait for 100 Continue, as the raw client's deadline bounds its I/O.
	sealed.Reset()
	res, err := Seal(&sealed, strings.NewReader("real"), key, "k", "full")
	if err != nil {
		t.Fatal(err)
	}
	cred2, _ := ing.Mint(Grant{Generation: gen, Member: member, NodeID: "n", JobID: "01JOB", MaxBytes: 64 << 10}, time.Minute)
	dest, _ := IngestDestination(srv.URL)
	if _, err := NewHTTPTransport(HTTPOptions{AcceptWait: 30 * time.Second}).Put(context.Background(), PutRequest{
		Destination: dest, Generation: gen, Member: member, Credential: cred2,
		Body: bytes.NewReader(sealed.Bytes()), Sealed: func() (string, uint64) { return res.Digest, res.SizeBytes },
	}); err != nil {
		t.Fatalf("the upload after the refused one failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(genDir, filepath.FromSlash(member))); err != nil {
		t.Fatalf("the upload after the refused one did not land: %v", err)
	}
}
