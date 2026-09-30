package backupxfer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto/tlstest"
)

// The transport verifies the api with exactly the TLS config the caller
// hands it (geekdojo/geekdojo-brain#590) — on a node, the mesh CA bundle.
// No config means no trust, never the system roots.

const (
	trustGen    = "20260903T120000Z-JOB12345-full"
	trustMember = "volumes/vaultwarden/vaultwarden-data.rasputin-archive"
	trustCred   = "rbx1.TEST-CREDENTIAL.sig"
)

// endpointStub is the ingest (PUT) and egress (GET) surface of the api, as
// far as the client's success path needs it, counting every request that
// reaches a handler.
func endpointStub(hits *atomic.Int32) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT "+IngestPathPrefix, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(Receipt{Generation: trustGen, Member: trustMember})
	})
	mux.HandleFunc("GET "+EgressPathPrefix, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", EgressContentType)
		w.Header().Set(HeaderPlaintextBytes, "3")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "TAR")
	})
	return mux
}

// putAndGet runs one Put and one Get against srv through a transport built
// from opts, and returns both errors.
func putAndGet(t *testing.T, srv *httptest.Server, opts HTTPOptions) (putErr, getErr error) {
	t.Helper()
	dest, err := IngestDestination(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := TransportFor(dest, opts)
	if err != nil {
		t.Fatal(err)
	}
	_, putErr = tr.Put(context.Background(), PutRequest{
		Destination: dest, Generation: trustGen, Member: trustMember, Credential: trustCred,
		Body: strings.NewReader("sealed"), Sealed: func() (string, uint64) { return "d", 6 },
	})

	source, err := EgressDestination(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	f, err := FetcherFor(source, opts)
	if err != nil {
		t.Fatal(err)
	}
	st, getErr := f.Get(context.Background(), GetRequest{Source: source, Generation: trustGen, Member: trustMember, Credential: trustCred})
	if getErr == nil {
		_ = st.Body.Close()
	}
	return putErr, getErr
}

func transportTLS(t *testing.T, opts HTTPOptions) *tls.Config {
	t.Helper()
	return NewHTTPTransport(opts).client.Transport.(*http.Transport).TLSClientConfig
}

// TC-590-12: with no TLSConfig the transport's root pool is empty and
// non-nil — never the system roots — so a Put and a Get to an HTTPS server
// both fail the handshake, and the server's handler never runs.
func TestNewHTTPTransport_NilTLSConfigTrustsNothing(t *testing.T) {
	cfg := transportTLS(t, HTTPOptions{})
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs is nil, which means the system roots")
	}
	if !cfg.RootCAs.Equal(x509.NewCertPool()) {
		t.Error("RootCAs is not empty")
	}

	var hits atomic.Int32
	srv := tlstest.NewCA(t, "mesh").NewServer(t, endpointStub(&hits))
	putErr, getErr := putAndGet(t, srv, HTTPOptions{})
	if !tlstest.IsUnknownAuthority(putErr) {
		t.Errorf("Put: err = %v, want an unknown-authority failure", putErr)
	}
	if !tlstest.IsUnknownAuthority(getErr) {
		t.Errorf("Get: err = %v, want an unknown-authority failure", getErr)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("handler invoked %d time(s), want 0", n)
	}
}

// TC-590-13: the caller's config is what the transport trusts, cloned with
// MinVersion raised to TLS 1.2 — the caller's own config is not touched —
// and a stricter MinVersion is kept.
func TestNewHTTPTransport_UsesTheGivenConfigWithoutMutatingIt(t *testing.T) {
	ca := tlstest.NewCA(t, "mesh")
	var hits atomic.Int32
	srv := ca.NewServer(t, endpointStub(&hits))

	given := &tls.Config{RootCAs: ca.Pool()} // MinVersion 0
	putErr, getErr := putAndGet(t, srv, HTTPOptions{TLSConfig: given})
	if putErr != nil {
		t.Errorf("Put over the trusted CA: %v", putErr)
	}
	if getErr != nil {
		t.Errorf("Get over the trusted CA: %v", getErr)
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("handler invoked %d time(s), want 2", n)
	}
	if got := transportTLS(t, HTTPOptions{TLSConfig: given}).MinVersion; got != tls.VersionTLS12 {
		t.Errorf("transport MinVersion = %#x, want TLS 1.2", got)
	}
	if given.MinVersion != 0 {
		t.Errorf("caller's MinVersion was changed to %#x", given.MinVersion)
	}

	strict := &tls.Config{RootCAs: ca.Pool(), MinVersion: tls.VersionTLS13}
	if got := transportTLS(t, HTTPOptions{TLSConfig: strict}).MinVersion; got != tls.VersionTLS13 {
		t.Errorf("transport MinVersion = %#x, want the caller's TLS 1.3 kept", got)
	}
}

// TC-590-14 (the blast radius): a caller that passes no TLSConfig and talks
// plain http — a dev api, the api/internal/storage functional tests — is
// unaffected. The storage suite and scripts/test-restore-roundtrip.sh run
// that path end to end; this pins it at the package.
func TestNewHTTPTransport_PlainHTTPUnaffectedByNoTLSConfig(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(endpointStub(&hits))
	t.Cleanup(srv.Close)
	putErr, getErr := putAndGet(t, srv, HTTPOptions{})
	if putErr != nil || getErr != nil {
		t.Fatalf("plain http with no TLSConfig: Put %v, Get %v", putErr, getErr)
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("handler invoked %d time(s), want 2", n)
	}
}

// F-590-05: a non-nil config whose RootCAs is nil would mean the system
// roots. The transport gives it an empty pool instead, so a Put and a Get to
// an HTTPS server both fail the handshake with unknown-authority and the
// handler never runs, and the caller's config is left as it was.
func TestNewHTTPTransport_NilRootCAsTrustsNothing(t *testing.T) {
	given := &tls.Config{MinVersion: tls.VersionTLS12} // RootCAs nil
	cfg := transportTLS(t, HTTPOptions{TLSConfig: given})
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs is nil, which means the system roots")
	}
	if !cfg.RootCAs.Equal(x509.NewCertPool()) {
		t.Error("RootCAs is not empty")
	}

	var hits atomic.Int32
	srv := tlstest.NewCA(t, "mesh").NewServer(t, endpointStub(&hits))
	putErr, getErr := putAndGet(t, srv, HTTPOptions{TLSConfig: given})
	if !tlstest.IsUnknownAuthority(putErr) {
		t.Errorf("Put: err = %v, want an unknown-authority failure", putErr)
	}
	if !tlstest.IsUnknownAuthority(getErr) {
		t.Errorf("Get: err = %v, want an unknown-authority failure", getErr)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("handler invoked %d time(s), want 0", n)
	}
	if given.RootCAs != nil {
		t.Error("caller's RootCAs was changed")
	}
}
