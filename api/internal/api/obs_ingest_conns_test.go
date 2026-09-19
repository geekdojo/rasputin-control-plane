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
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// countingLiveness is a fake IngestLiveness that counts every NodeLive call,
// so a test can assert how often the ingress consults it.
type countingLiveness struct {
	calls atomic.Int64
	mu    sync.Mutex
	live  map[string]bool
	hooks []func(string)
}

func (f *countingLiveness) NodeLive(nodeID string) bool {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.live[nodeID]
}

func (f *countingLiveness) OnNodeRevoked(fn func(string)) {
	f.mu.Lock()
	f.hooks = append(f.hooks, fn)
	f.mu.Unlock()
}

// ingressTLS is a real mTLS ingress: a Mesh CA, the api's server leaf and a
// collector client leaf per node, served by the real ObsIngestHandler behind
// the same RequireAndVerifyClientCert config main.go builds.
type ingressTLS struct {
	srv     *httptest.Server
	ca      *mesh.MeshCA
	roots   *x509.CertPool
	clients map[string]tls.Certificate
}

func startIngress(t *testing.T, s *Server, gate IngestLiveness, nodes ...string) *ingressTLS {
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
	it.srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		Certificates: []tls.Certificate{serverCert},
	}
	it.srv.Config.TLSConfig = it.srv.TLS
	if err := s.WireObsIngest(it.srv.Config, gate); err != nil {
		t.Fatalf("WireObsIngest: %v", err)
	}
	it.srv.TLS = it.srv.Config.TLSConfig
	it.srv.StartTLS()
	t.Cleanup(it.srv.Close)
	return it
}

func (it *ingressTLS) clientTLS(node string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: it.roots, Certificates: []tls.Certificate{it.clients[node]}, ServerName: "127.0.0.1"}
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

// The ingress consults the live-node set once per CONNECTION, in the
// handshake, and never on a request: five requests over one kept-alive
// connection cost one check. The pushes pass every gate (503 "backend not
// ready": observability is off in the fixture).
func TestObsIngress_LivenessIsCheckedOncePerConnection(t *testing.T) {
	s := newIngestServer(t, obs.NewStatus(obs.NewNoopSupervisor(), nil, nil), "c02")
	gate := &countingLiveness{live: map[string]bool{"c02": true}}
	it := startIngress(t, s, gate, "c02")

	c := it.keepAliveClient("c02")
	for i := range 5 {
		code, err := postIngest(c, it.srv.URL)
		if err != nil || code != http.StatusServiceUnavailable {
			t.Fatalf("request %d = (%d, %v), want 503 backend-not-ready", i, code, err)
		}
	}
	if n := gate.calls.Load(); n != 1 {
		t.Errorf("NodeLive was called %d times for one connection and five requests; want 1 (handshake only)", n)
	}
}

// A node not in the live-node set cannot complete a handshake.
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

// With the real token store: an ESTABLISHED kept-alive connection is closed
// the moment its node's token is revoked, and the node's next handshake is
// refused. Another node's connection is untouched.
func TestObsIngress_RevokeClosesTheNodesOpenConnections(t *testing.T) {
	ctx := context.Background()
	s := newIngestServer(t, obs.NewStatus(obs.NewNoopSupervisor(), nil, nil), "c02", "c03")
	tokens, err := busauth.OpenStore(ctx, filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tokens.Close() })
	for _, n := range []string{"c02", "c03"} {
		if _, _, err := tokens.MintBound(ctx, "compute", n, proto.RoleCompute); err != nil {
			t.Fatal(err)
		}
	}
	it := startIngress(t, s, tokens, "c02", "c03")
	addr := strings.TrimPrefix(it.srv.URL, "https://")

	// One raw, kept-alive connection per node, each proven usable.
	open := func(node string) (*tls.Conn, *bufio.Reader) {
		t.Helper()
		conn, err := tls.Dial("tcp", addr, it.clientTLS(node))
		if err != nil {
			t.Fatalf("%s dial: %v", node, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		br := bufio.NewReader(conn)
		send(t, conn, br, node)
		return conn, br
	}
	c02, br02 := open("c02")
	c03, br03 := open("c03")

	if _, _, err := tokens.RevokeByNodeID(ctx, "c02"); err != nil {
		t.Fatalf("RevokeByNodeID: %v", err)
	}

	// c02's open connection is closed by the server: the next read ends.
	_ = c02.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br02.ReadByte(); err == nil {
		t.Fatal("the revoked node's open connection is still delivering data")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the revoked node's open connection was not closed (read timed out)")
	}
	// c03 still works on its same connection.
	send(t, c03, br03, "c03")
	// And c02 cannot connect again.
	if _, err := postIngest(it.keepAliveClient("c02"), it.srv.URL); err == nil {
		t.Error("the revoked node completed a new request")
	}
	// A fresh token for c02 admits it again.
	if _, _, err := tokens.MintBound(ctx, "compute", "c02", proto.RoleCompute); err != nil {
		t.Fatal(err)
	}
	if code, err := postIngest(it.keepAliveClient("c02"), it.srv.URL); err != nil || code != http.StatusServiceUnavailable {
		t.Errorf("after a re-mint = (%d, %v), want 503", code, err)
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
	if err := s.WireObsIngest(&http.Server{TLSConfig: &tls.Config{}}, nil); err == nil {
		t.Error("no gate: want an error")
	}
	if err := s.WireObsIngest(&http.Server{}, &countingLiveness{}); err == nil {
		t.Error("no TLS config: want an error")
	}
}
