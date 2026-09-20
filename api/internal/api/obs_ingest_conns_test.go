package api

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// countingLiveness is a fake IngestRegistry that counts every Admitted call,
// so a test can assert how often the listener consults it — and, because it
// holds nothing but maps, that the answer never comes from a database.
type countingLiveness struct {
	calls atomic.Int64
	mu    sync.Mutex
	live  map[string]bool
	keys  map[string]inventory.KeyOwner
	hooks []func(string)
}

func (f *countingLiveness) Admitted(nodeID string) bool {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.live[nodeID]
}

func (f *countingLiveness) AdmitKey(spki string) (inventory.KeyOwner, bool) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.keys[spki]
	return o, ok && f.live[o.NodeID]
}

func (f *countingLiveness) OnNodeExcluded(fn func(string)) {
	f.mu.Lock()
	f.hooks = append(f.hooks, fn)
	f.mu.Unlock()
}

func (f *countingLiveness) OnKeysRetired(func(string, []string)) {}

// ingressTLS is a real mTLS ingress: a Mesh CA, the api's server leaf and a
// collector client leaf per node, served by the real ObsIngestHandler behind
// the same RequireAndVerifyClientCert config main.go builds.
type ingressTLS struct {
	srv     *httptest.Server
	ca      *mesh.MeshCA
	roots   *x509.CertPool
	clients map[string]tls.Certificate
}

func startIngress(t *testing.T, s *Server, gate IngestRegistry, nodes ...string) *ingressTLS {
	t.Helper()
	ca, err := mesh.EnsureMeshCA(filepath.Join(t.TempDir(), "trust"), "test")
	if err != nil {
		t.Fatalf("EnsureMeshCA: %v", err)
	}
	serverCertPEM, serverKeyPEM, err := mesh.MintLeaf(ca, mesh.LeafSpec{CommonName: "api", IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}})
	if err != nil {
		t.Fatalf("server leaf: %v", err)
	}
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	it := &ingressTLS{ca: ca, roots: pool, clients: map[string]tls.Certificate{}}
	for _, n := range nodes {
		c, k, err := mesh.MintLeaf(ca, mesh.LeafSpec{CommonName: n, DNSNames: []string{n}, ClientAuth: true})
		if err != nil {
			t.Fatalf("client leaf %s: %v", n, err)
		}
		if it.clients[n], err = tls.X509KeyPair(c, k); err != nil {
			t.Fatal(err)
		}
	}
	it.srv = httptest.NewUnstartedServer(s.ObsIngestHandler())
	// The production shape: the stack verifies nothing (a node's own key is
	// wrapped in a certificate no CA issued), and admission is decided in
	// VerifyConnection against the registry. A legacy collector's mesh chain
	// is verified explicitly, against this pool.
	it.srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAnyClientCert,
		Certificates: []tls.Certificate{serverCert},
	}
	it.srv.Config.TLSConfig = it.srv.TLS
	if err := s.WireObsIngest(it.srv.Config, gate, pool); err != nil {
		t.Fatalf("WireObsIngest: %v", err)
	}
	it.srv.TLS = it.srv.Config.TLSConfig
	it.srv.StartTLS()
	t.Cleanup(it.srv.Close)
	return it
}

func (it *ingressTLS) clientTLS(node string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: it.roots, Certificates: []tls.Certificate{it.clients[node]}, ServerName: "127.0.0.1"}
}

// keepAliveClient is an http.Client that holds one connection open.
func (it *ingressTLS) keepAliveClient(node string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: it.clientTLS(node), MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, ForceAttemptHTTP2: false,
	}}
}

func postIngest(c *http.Client, base string) (int, error) {
	resp, err := c.Post(base+"/api/obs/ingest", "application/x-protobuf", strings.NewReader("x"))
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// The listener consults the node registry once in the handshake and once per
// request, and NOTHING else: a connection outlives the facts it was admitted
// on, so the request in flight when a node is revoked must not be served on a
// decision the registry has since reversed (geekdojo/geekdojo-brain#513).
//
// The registry is memory, so the re-check costs a map lookup — see
// TestObsIngress_RequestPathReadsNoDatabase, which proves nothing here reads a
// database. The pushes pass every gate (503 "backend not ready":
// observability is off in the fixture).
func TestObsIngress_AdmissionIsRecheckedPerRequest(t *testing.T) {
	s := newIngestServer(t, obs.NewStatus(obs.NewNoopSupervisor(), nil, nil), "c02")
	gate := &countingLiveness{live: map[string]bool{"c02": true}}
	it := startIngress(t, s, gate, "c02")

	c := it.keepAliveClient("c02")
	const requests = 5
	for i := range requests {
		code, err := postIngest(c, it.srv.URL)
		if err != nil || code != http.StatusServiceUnavailable {
			t.Fatalf("request %d = (%d, %v), want 503 backend-not-ready", i, code, err)
		}
	}
	// One handshake and one re-check per request. A mesh-chain client has no
	// registered key, so identify misses AdmitKey and then calls Admitted;
	// the request path calls Admitted once more after that.
	if want, n := int64(3*requests+2), gate.calls.Load(); n != want {
		t.Errorf("the registry was consulted %d times for one connection and %d requests; want %d", n, requests, want)
	}

	// And a revoke between requests is caught by the re-check, not only by
	// the connection close.
	gate.mu.Lock()
	gate.live["c02"] = false
	gate.mu.Unlock()
	if code, _ := postIngest(c, it.srv.URL); code != http.StatusUnauthorized && code != http.StatusForbidden {
		t.Errorf("a request after the node stopped being admitted = %d, want 401 or 403", code)
	}
}

// A node the registry does not admit cannot complete a handshake.
func TestObsIngress_RevokedNodeHandshakeIsRefused(t *testing.T) {
	s := newIngestServer(t, obs.NewStatus(obs.NewNoopSupervisor(), nil, nil), "c02", "c03")
	gate := &countingLiveness{live: map[string]bool{"c02": true}}
	it := startIngress(t, s, gate, "c02", "c03")

	if _, err := postIngest(it.keepAliveClient("c03"), it.srv.URL); err == nil {
		t.Fatal("a node with no live token completed a request; want the handshake refused")
	}
	conn, err := tls.Dial("tcp", strings.TrimPrefix(it.srv.URL, "https://"), it.clientTLS("c03"))
	if err == nil {
		// TLS 1.3 reports the server's refusal of a client certificate on
		// the first read, not in Dial.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Read(make([]byte, 1))
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("the refused node's handshake succeeded and its connection was readable")
	}
	t.Logf("refused: %v", err)
	if code, err := postIngest(it.keepAliveClient("c02"), it.srv.URL); err != nil || code != http.StatusServiceUnavailable {
		t.Errorf("a live node alongside it = (%d, %v), want 503", code, err)
	}
}

// realRegistry is the production wiring: a real inventory store (membership
// and the registry) and a real token store pushing liveness into it, with a
// live token for each of nodes.
func realRegistry(t *testing.T, s *Server, nodes ...string) (*inventory.Store, *busauth.Store) {
	t.Helper()
	ctx := context.Background()
	tokens, err := busauth.OpenStore(ctx, filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tokens.Close() })
	inv := s.inv
	for _, n := range nodes {
		if _, _, err := tokens.MintBound(ctx, "compute", n, proto.RoleCompute); err != nil {
			t.Fatal(err)
		}
	}
	if err := tokens.SetNodeRegistry(ctx, inv.Registry()); err != nil {
		t.Fatal(err)
	}
	return inv, tokens
}

// openConn dials one raw, kept-alive connection and proves it usable.
func openConn(t *testing.T, it *ingressTLS, node string) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := tls.Dial("tcp", strings.TrimPrefix(it.srv.URL, "https://"), it.clientTLS(node))
	if err != nil {
		t.Fatalf("%s dial: %v", node, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	br := bufio.NewReader(conn)
	send(t, conn, br, node)
	return conn, br
}

// assertClosedByServer checks the server closed conn: the next read ends
// rather than timing out.
func assertClosedByServer(t *testing.T, conn *tls.Conn, br *bufio.Reader, why string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatalf("%s: the connection is still delivering data", why)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("%s: the connection was not closed (read timed out)", why)
	}
}

// With the real registry: an ESTABLISHED kept-alive connection is closed the
// moment its node's token is revoked, and the node's next handshake is
// refused; another node's connection is untouched; a fresh token admits it
// again.
func TestObsIngress_RevokeClosesTheNodesOpenConnections(t *testing.T) {
	ctx := context.Background()
	s := newIngestServer(t, obs.NewStatus(obs.NewNoopSupervisor(), nil, nil), "c02", "c03")
	inv, tokens := realRegistry(t, s, "c02", "c03")
	it := startIngress(t, s, inv.Registry(), "c02", "c03")

	c02, br02 := openConn(t, it, "c02")
	c03, br03 := openConn(t, it, "c03")
	if _, _, err := tokens.RevokeByNodeID(ctx, "c02"); err != nil {
		t.Fatalf("RevokeByNodeID: %v", err)
	}
	assertClosedByServer(t, c02, br02, "revoked node")
	send(t, c03, br03, "c03")
	if _, err := postIngest(it.keepAliveClient("c02"), it.srv.URL); err == nil {
		t.Error("the revoked node completed a new request")
	}
	if _, _, err := tokens.MintBound(ctx, "compute", "c02", proto.RoleCompute); err != nil {
		t.Fatal(err)
	}
	if code, err := postIngest(it.keepAliveClient("c02"), it.srv.URL); err != nil || code != http.StatusServiceUnavailable {
		t.Errorf("after a re-mint = (%d, %v), want 503", code, err)
	}
}

// Removing a node from inventory closes its open connections too, even with
// its token still live, and refuses its next handshake. A node with a live
// token that never registered is refused.
func TestObsIngress_RemovalClosesTheNodesOpenConnections(t *testing.T) {
	ctx := context.Background()
	s := newIngestServer(t, obs.NewStatus(obs.NewNoopSupervisor(), nil, nil), "c02")
	inv, tokens := realRegistry(t, s, "c02", "stranger")
	it := startIngress(t, s, inv.Registry(), "c02", "stranger")

	if _, err := postIngest(it.keepAliveClient("stranger"), it.srv.URL); err == nil {
		t.Error("a node with a live token but no inventory row completed a request")
	}
	c02, br02 := openConn(t, it, "c02")
	if err := inv.Delete(ctx, "c02"); err != nil {
		t.Fatal(err)
	}
	if !tokensLive(t, tokens, "c02") {
		t.Fatal("test setup: c02's token should still be live")
	}
	assertClosedByServer(t, c02, br02, "removed node")
	if _, err := postIngest(it.keepAliveClient("c02"), it.srv.URL); err == nil {
		t.Error("the removed node completed a new request")
	}
}

func tokensLive(t *testing.T, tokens *busauth.Store, node string) bool {
	t.Helper()
	ok, err := tokens.NodeHasLiveToken(context.Background(), node)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// No database on the request path: with an admitted connection open, both the
// inventory and token databases are closed, and requests on that connection
// still pass every gate.
func TestObsIngress_RequestPathReadsNoDatabase(t *testing.T) {
	s := newIngestServer(t, obs.NewStatus(obs.NewNoopSupervisor(), nil, nil), "c02")
	inv, tokens := realRegistry(t, s, "c02")
	it := startIngress(t, s, inv.Registry(), "c02")
	conn, br := openConn(t, it, "c02")
	_ = tokens.Close()
	_ = inv.Close()
	for range 3 {
		send(t, conn, br, "c02")
	}
}

// send writes one ingest request on conn and reads its response, which must
// have passed every gate.
func send(t *testing.T, conn *tls.Conn, br *bufio.Reader, node string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "POST /api/obs/ingest HTTP/1.1\r\nHost: ingest\r\nContent-Length: 1\r\n\r\nx"); err != nil {
		t.Fatalf("%s write: %v", node, err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("%s read: %v", node, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("%s: status %d, want 503 backend-not-ready", node, resp.StatusCode)
	}
	_ = conn.SetDeadline(time.Time{})
}

func TestWireObsIngest_RefusesWithoutAGate(t *testing.T) {
	s := &Server{}
	if err := s.WireObsIngest(&http.Server{TLSConfig: &tls.Config{}}, nil, nil); err == nil {
		t.Error("no gate: want an error")
	}
	if err := s.WireObsIngest(&http.Server{}, &countingLiveness{}, nil); err == nil {
		t.Error("no TLS config: want an error")
	}
}
