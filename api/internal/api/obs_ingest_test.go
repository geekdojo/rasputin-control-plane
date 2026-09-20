package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// certState fabricates a *tls.ConnectionState carrying a single client leaf
// with the given CommonName. nodeIDFromClientCert only reads
// Subject.CommonName, so a bare x509.Certificate (no signing) is enough —
// these tests exercise identity extraction, not the TLS stack.
func certState(cn string) *tls.ConnectionState {
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}},
	}
}

// nodeKeyCerts hands out one stable key per node id, and the connection state
// a client presenting it produces. The node listener identifies a caller by
// its key's SPKI, so a handler test needs a real key rather than a bare
// Subject — the key IS the identity now.
var nodeKeyCerts = struct {
	mu    sync.Mutex
	certs map[string]*x509.Certificate
}{certs: map[string]*x509.Certificate{}}

func nodeKeyCert(t *testing.T, node string) *x509.Certificate {
	t.Helper()
	nodeKeyCerts.mu.Lock()
	defer nodeKeyCerts.mu.Unlock()
	if c, ok := nodeKeyCerts.certs[node]; ok {
		return c
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: node},
		NotBefore:    time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	nodeKeyCerts.certs[node] = cert
	return cert
}

// nodeKeyState is the connection state a node presenting its registered key
// produces.
func nodeKeyState(t *testing.T, node string) *tls.ConnectionState {
	t.Helper()
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{nodeKeyCert(t, node)}}
}

// registerCollectorKey records node's key as its COLLECTOR key and makes the
// node admitted, which is what the listener's routes require.
func registerCollectorKey(t *testing.T, inv *inventory.Store, node string) {
	t.Helper()
	hash, err := proto.NodeKeySPKIHash(nodeKeyCert(t, node).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	inv.Registry().SetTokenLive(node, true)
	if _, err := inv.SetNodeKeys(context.Background(), node, proto.NodeKeys{proto.NodeKeyCollector: hash}); err != nil {
		t.Fatal(err)
	}
}

func TestNodeIDFromClientCert(t *testing.T) {
	tests := []struct {
		name    string
		cs      *tls.ConnectionState
		want    string
		wantErr bool
	}{
		{"nil state (non-TLS request)", nil, "", true},
		{"no peer certificates", &tls.ConnectionState{}, "", true},
		{"empty CommonName", certState("   "), "", true},
		{"valid CN", certState("c02"), "c02", false},
		{"trims surrounding whitespace", certState("  c02\n"), "c02", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nodeIDFromClientCert(tt.cs)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil (value=%q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("node id: got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestProxyRemoteWrite verifies the proxy mechanics in isolation: the inbound
// path is rewritten to VM's remote-write endpoint, the authoritative
// node_id is stamped via extra_label, and method + body pass through verbatim.
func TestProxyRemoteWrite(t *testing.T) {
	var gotPath, gotExtraLabel, gotMethod, gotBody string
	stubVM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotExtraLabel = r.URL.Query().Get("extra_label") // percent-decoded by net/http
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer stubVM.Close()

	const body = "snappy-remote-write-bytes"
	req := httptest.NewRequest(http.MethodPost, "/api/obs/ingest", strings.NewReader(body))
	req.Header.Set("Content-Encoding", "snappy")
	rec := httptest.NewRecorder()

	(&Server{}).proxyRemoteWrite(rec, req, stubVM.URL, "c02")

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204; body=%q", rec.Code, rec.Body.String())
	}
	if gotPath != vmRemoteWritePath {
		t.Errorf("VM path: got %q, want %q", gotPath, vmRemoteWritePath)
	}
	if gotExtraLabel != "node_id=c02" {
		t.Errorf("extra_label: got %q, want node_id=c02", gotExtraLabel)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method: got %q, want POST", gotMethod)
	}
	if gotBody != body {
		t.Errorf("body: got %q, want %q", gotBody, body)
	}
}

// fakeVMSup is a Supervisor whose VMBaseURL points at a stub VM. It embeds the
// real NoopSupervisor for every other method — and, being a distinct type, is
// NOT caught by VMWriteBaseURL's `NoopSupervisor` short-circuit, so the base
// URL flows through.
type fakeVMSup struct {
	obs.NoopSupervisor
	vmBase   string
	lokiBase string
}

func (f fakeVMSup) VMBaseURL() string   { return f.vmBase }
func (f fakeVMSup) LokiBaseURL() string { return f.lokiBase }

// newIngestServer builds a minimal Server holding just the two fields the
// ingress touches — a real (SQLite) inventory store seeded with seedNodes, and
// the given obs.Status.
func newIngestServer(t *testing.T, obsStatus *obs.Status, seedNodes ...string) *Server {
	t.Helper()
	ctx := context.Background()
	invStore, err := inventory.OpenStore(ctx, filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatalf("inventory OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = invStore.Close() })
	for _, id := range seedNodes {
		if err := invStore.Insert(ctx, &proto.Node{ID: id, Role: proto.RoleCompute, Hostname: id}); err != nil {
			t.Fatalf("insert node %q: %v", id, err)
		}
	}
	for _, id := range seedNodes {
		registerCollectorKey(t, invStore, id)
	}
	return &Server{inv: invStore, obs: obsStatus, nodeGate: newIngestConns(invStore.Registry(), nil)}
}

func ingestReq(t *testing.T, node string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/obs/ingest",
		bytes.NewReader(remoteWriteBody(series("container_cpu_usage_seconds_total", "name", "web"))))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	if node != "" {
		req.TLS = nodeKeyState(t, node)
	}
	return req
}

// TestProxyLokiPush verifies the log-push proxy: the inbound path is rewritten
// to Loki's push endpoint, no extra_label is added (Loki has none — node_id
// rides in the stream labels), and method + body pass through verbatim.
func TestProxyLokiPush(t *testing.T) {
	var gotPath, gotQuery, gotMethod, gotBody string
	stubLoki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer stubLoki.Close()

	const body = "snappy-loki-push-bytes"
	req := httptest.NewRequest(http.MethodPost, "/api/obs/logs/ingest", strings.NewReader(body))
	rec := httptest.NewRecorder()

	(&Server{}).proxyLokiPush(rec, req, stubLoki.URL)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204; body=%q", rec.Code, rec.Body.String())
	}
	if gotPath != lokiPushPath {
		t.Errorf("Loki path: got %q, want %q", gotPath, lokiPushPath)
	}
	if gotQuery != "" {
		t.Errorf("Loki push must carry no query (no extra_label), got %q", gotQuery)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method: got %q, want POST", gotMethod)
	}
	if gotBody != body {
		t.Errorf("body: got %q, want %q", gotBody, body)
	}
}

func TestHandleObsLogsIngest(t *testing.T) {
	offStatus := func() *obs.Status { return obs.NewStatus(obs.NewNoopSupervisor(), nil, nil) }

	t.Run("no client cert → 401", func(t *testing.T) {
		s := newIngestServer(t, offStatus(), "c02")
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/obs/logs/ingest", strings.NewReader("x"))
		s.handleObsLogsIngest(rec, req) // req.TLS nil
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("got %d, want 401; body=%q", rec.Code, rec.Body.String())
		}
	})

	t.Run("member node but Loki off → 503", func(t *testing.T) {
		s := newIngestServer(t, offStatus(), "c02")
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/obs/logs/ingest", strings.NewReader("x"))
		req.TLS = certState("c02")
		s.handleObsLogsIngest(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("got %d, want 503; body=%q", rec.Code, rec.Body.String())
		}
	})

	t.Run("member node + Loki up → proxied to Loki push", func(t *testing.T) {
		var gotPath string
		stubLoki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		}))
		defer stubLoki.Close()

		s := newIngestServer(t, obs.NewStatus(fakeVMSup{lokiBase: stubLoki.URL}, nil, nil), "c02")
		rec := httptest.NewRecorder()
		body := lokiPushBody(lokiStream(`{container="db"}`, "line"))
		req := httptest.NewRequest(http.MethodPost, "/api/obs/logs/ingest", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.Header.Set("Content-Encoding", "snappy")
		req.TLS = certState("c02")
		s.handleObsLogsIngest(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("got %d, want 204; body=%q", rec.Code, rec.Body.String())
		}
		if gotPath != lokiPushPath {
			t.Errorf("Loki path: got %q, want %q", gotPath, lokiPushPath)
		}
	})
}

// A handler whose listener was never given the admission gate refuses
// everything: fail closed.
func TestObsIngestHandlers_RefuseWithoutTheHandshakeGate(t *testing.T) {
	s := newIngestServer(t, obs.NewStatus(obs.NewNoopSupervisor(), nil, nil), "c02")
	s.nodeGate = nil
	rec := httptest.NewRecorder()
	s.handleObsIngest(rec, ingestReq(t, "c02"))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "admission") {
		t.Errorf("metrics: got %d %q, want 503 naming admission", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/obs/logs/ingest", strings.NewReader("x"))
	req.TLS = nodeKeyState(t, "c02")
	s.handleObsLogsIngest(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("logs: got %d, want 503", rec.Code)
	}
}

// The route's purpose is checked per request: a node's AGENT key is not its
// collector, so it cannot push the collector's metrics or logs even though
// both keys belong to the same admitted node.
func TestObsIngestHandlers_RefuseTheWrongKeyPurpose(t *testing.T) {
	ctx := context.Background()
	s := newIngestServer(t, obs.NewStatus(obs.NewNoopSupervisor(), nil, nil), "c02")
	hash, err := proto.NodeKeySPKIHash(nodeKeyCert(t, "c02-agent").PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.inv.SetNodeKeys(ctx, "c02", proto.NodeKeys{proto.NodeKeyAgent: hash}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.handleObsIngest(rec, ingestReq(t, "c02-agent"))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "collector key") {
		t.Errorf("metrics with the agent key: got %d %q, want 403 naming the collector key", rec.Code, rec.Body.String())
	}
}

// A node that stops being admitted between the handshake and the request is
// refused by the per-request re-check, without a database read.
func TestObsIngestHandlers_RecheckAdmissionPerRequest(t *testing.T) {
	s := newIngestServer(t, obs.NewStatus(obs.NewNoopSupervisor(), nil, nil), "c02")
	rec := httptest.NewRecorder()
	s.handleObsIngest(rec, ingestReq(t, "c02"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("baseline: got %d, want 503 backend-not-ready", rec.Code)
	}
	s.inv.Registry().SetTokenLive("c02", false)
	rec = httptest.NewRecorder()
	s.handleObsIngest(rec, ingestReq(t, "c02"))
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Errorf("after the token was revoked: got %d %q, want 401 or 403", rec.Code, rec.Body.String())
	}
}

func TestHandleObsIngest(t *testing.T) {
	offStatus := func() *obs.Status { return obs.NewStatus(obs.NewNoopSupervisor(), nil, nil) }

	t.Run("no client cert → 401", func(t *testing.T) {
		s := newIngestServer(t, offStatus(), "c02")
		rec := httptest.NewRecorder()
		s.handleObsIngest(rec, ingestReq(t, "")) // req.TLS nil
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("got %d, want 401; body=%q", rec.Code, rec.Body.String())
		}
	})

	t.Run("member node but obs off → 503 (backend not ready)", func(t *testing.T) {
		s := newIngestServer(t, offStatus(), "c02")
		rec := httptest.NewRecorder()
		s.handleObsIngest(rec, ingestReq(t, "c02"))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("got %d, want 503; body=%q", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "not ready") {
			t.Errorf("expected a 'backend not ready' message, got %q", rec.Body.String())
		}
	})

	t.Run("member node + obs on → proxied to VM with authoritative node_id", func(t *testing.T) {
		var gotPath, gotExtraLabel string
		var gotBody []byte
		stubVM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotExtraLabel = r.URL.Query().Get("extra_label")
			gotBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer stubVM.Close()

		s := newIngestServer(t, obs.NewStatus(fakeVMSup{vmBase: stubVM.URL}, nil, nil), "c02")
		rec := httptest.NewRecorder()
		s.handleObsIngest(rec, ingestReq(t, "c02"))

		if rec.Code != http.StatusNoContent {
			t.Fatalf("got %d, want 204; body=%q", rec.Code, rec.Body.String())
		}
		if gotPath != vmRemoteWritePath {
			t.Errorf("VM path: got %q, want %q", gotPath, vmRemoteWritePath)
		}
		if gotExtraLabel != "node_id=c02" {
			t.Errorf("extra_label: got %q, want node_id=c02", gotExtraLabel)
		}
		if want := remoteWriteBody(series("container_cpu_usage_seconds_total", "name", "web")); !bytes.Equal(gotBody, want) {
			t.Errorf("forwarded body differs from the one received (%d vs %d bytes)", len(gotBody), len(want))
		}
	})
}
