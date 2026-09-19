package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// certState fabricates a *tls.ConnectionState carrying a single client leaf
// with the given CommonName. nodeIDFromClientCert only reads
// Subject.CommonName, so a bare x509.Certificate (no signing) is enough — the
// real listener's RequireAndVerifyClientCert does the cryptographic
// verification before any handler runs; these tests exercise identity
// extraction and the authorization gates, not the TLS stack.
func certState(cn string) *tls.ConnectionState {
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}},
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

// newIngestServer builds a minimal Server holding just the fields the ingress
// touches — a real (SQLite) inventory store seeded with seedNodes, a real bus
// token store holding a live token for each of them, and the given obs.Status.
func newIngestServer(t *testing.T, obsStatus *obs.Status, seedNodes ...string) *Server {
	t.Helper()
	ctx := context.Background()
	invStore, err := inventory.OpenStore(ctx, filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatalf("inventory OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = invStore.Close() })
	tokens, err := busauth.OpenStore(ctx, filepath.Join(t.TempDir(), "bus.db"))
	if err != nil {
		t.Fatalf("busauth OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = tokens.Close() })
	for _, id := range seedNodes {
		if err := invStore.Insert(ctx, &proto.Node{ID: id, Role: proto.RoleCompute, Hostname: id}); err != nil {
			t.Fatalf("insert node %q: %v", id, err)
		}
		if _, _, err := tokens.MintBound(ctx, "compute", id, proto.RoleCompute); err != nil {
			t.Fatalf("mint token for %q: %v", id, err)
		}
	}
	return &Server{inv: invStore, obs: obsStatus, busTokens: tokens}
}

func ingestReq(cn string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/obs/ingest", strings.NewReader("payload"))
	if cn != "" {
		req.TLS = certState(cn)
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

	t.Run("verified cert but node not in inventory → 403", func(t *testing.T) {
		s := newIngestServer(t, offStatus()) // no nodes
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/obs/logs/ingest", strings.NewReader("x"))
		req.TLS = certState("ghost")
		s.handleObsLogsIngest(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("got %d, want 403; body=%q", rec.Code, rec.Body.String())
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
		req := httptest.NewRequest(http.MethodPost, "/api/obs/logs/ingest", strings.NewReader("payload"))
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

func TestHandleObsIngest(t *testing.T) {
	offStatus := func() *obs.Status { return obs.NewStatus(obs.NewNoopSupervisor(), nil, nil) }

	t.Run("no client cert → 401", func(t *testing.T) {
		s := newIngestServer(t, offStatus(), "c02")
		rec := httptest.NewRecorder()
		s.handleObsIngest(rec, ingestReq("")) // req.TLS nil
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("got %d, want 401; body=%q", rec.Code, rec.Body.String())
		}
	})

	t.Run("verified cert but node not in inventory → 403", func(t *testing.T) {
		s := newIngestServer(t, offStatus()) // no nodes seeded
		rec := httptest.NewRecorder()
		s.handleObsIngest(rec, ingestReq("ghost"))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("got %d, want 403; body=%q", rec.Code, rec.Body.String())
		}
	})

	t.Run("member node but obs off → 503 (backend not ready)", func(t *testing.T) {
		s := newIngestServer(t, offStatus(), "c02")
		rec := httptest.NewRecorder()
		s.handleObsIngest(rec, ingestReq("c02"))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("got %d, want 503; body=%q", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "not ready") {
			t.Errorf("expected a 'backend not ready' message, got %q", rec.Body.String())
		}
	})

	t.Run("inventory store error → 503 (fail closed, don't drop as 403)", func(t *testing.T) {
		ctx := context.Background()
		invStore, err := inventory.OpenStore(ctx, filepath.Join(t.TempDir(), "inv.db"))
		if err != nil {
			t.Fatalf("inventory OpenStore: %v", err)
		}
		_ = invStore.Close() // closed store → Get errors
		s := &Server{inv: invStore, obs: offStatus()}
		rec := httptest.NewRecorder()
		s.handleObsIngest(rec, ingestReq("c02"))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("got %d, want 503; body=%q", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "inventory") {
			t.Errorf("expected an 'inventory unavailable' message, got %q", rec.Body.String())
		}
	})

	t.Run("member node + obs on → proxied to VM with authoritative node_id", func(t *testing.T) {
		var gotPath, gotExtraLabel string
		stubVM := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotExtraLabel = r.URL.Query().Get("extra_label")
			w.WriteHeader(http.StatusNoContent)
		}))
		defer stubVM.Close()

		s := newIngestServer(t, obs.NewStatus(fakeVMSup{vmBase: stubVM.URL}, nil, nil), "c02")
		rec := httptest.NewRecorder()
		s.handleObsIngest(rec, ingestReq("c02"))

		if rec.Code != http.StatusNoContent {
			t.Fatalf("got %d, want 204; body=%q", rec.Code, rec.Body.String())
		}
		if gotPath != vmRemoteWritePath {
			t.Errorf("VM path: got %q, want %q", gotPath, vmRemoteWritePath)
		}
		if gotExtraLabel != "node_id=c02" {
			t.Errorf("extra_label: got %q, want node_id=c02", gotExtraLabel)
		}
	})
}

// A node whose join token is revoked stays in inventory (its history stays
// readable) but its collector is refused on both ingress routes, with a 403
// that names why — whatever the backend's state. A node that holds a second,
// live token is still admitted; one whose only live token names no role is
// not, because the bus would not admit it either.
func TestObsIngest_RefusesANodeWhoseTokenIsRevoked(t *testing.T) {
	ctx := context.Background()
	var hits int
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer stub.Close()
	s := newIngestServer(t, obs.NewStatus(fakeVMSup{vmBase: stub.URL, lokiBase: stub.URL}, nil, nil), "c02")

	push := func() (metrics, logs *httptest.ResponseRecorder) {
		metrics = httptest.NewRecorder()
		s.handleObsIngest(metrics, ingestReq("c02"))
		logs = httptest.NewRecorder()
		lreq := httptest.NewRequest(http.MethodPost, "/api/obs/logs/ingest", strings.NewReader("x"))
		lreq.TLS = certState("c02")
		s.handleObsLogsIngest(logs, lreq)
		return metrics, logs
	}

	if m, l := push(); m.Code != http.StatusNoContent || l.Code != http.StatusNoContent {
		t.Fatalf("live token: metrics %d, logs %d; want 204, 204", m.Code, l.Code)
	}

	if _, _, err := s.busTokens.RevokeByNodeID(ctx, "c02"); err != nil {
		t.Fatalf("RevokeByNodeID: %v", err)
	}
	before := hits
	m, l := push()
	for name, rec := range map[string]*httptest.ResponseRecorder{"metrics": m, "logs": l} {
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "revoked") {
			t.Errorf("revoked token, %s: got %d %q; want 403 naming the revoke", name, rec.Code, rec.Body.String())
		}
	}
	if hits != before {
		t.Errorf("a refused push reached the backend (%d proxied)", hits-before)
	}
	if n, err := s.inv.Get(ctx, "c02"); err != nil || n == nil {
		t.Errorf("revoke removed the node from inventory: (%v, %v)", n, err)
	}

	// A fresh token for the node re-admits it.
	if _, _, err := s.busTokens.MintBound(ctx, "compute", "c02", proto.RoleCompute); err != nil {
		t.Fatalf("MintBound: %v", err)
	}
	if m, l := push(); m.Code != http.StatusNoContent || l.Code != http.StatusNoContent {
		t.Errorf("re-minted token: metrics %d, logs %d; want 204, 204", m.Code, l.Code)
	}
}

// No token store wired is a refusal, not an open door.
func TestObsIngest_NoTokenStoreFailsClosed(t *testing.T) {
	s := newIngestServer(t, obs.NewStatus(obs.NewNoopSupervisor(), nil, nil), "c02")
	s.busTokens = nil
	rec := httptest.NewRecorder()
	s.handleObsIngest(rec, ingestReq("c02"))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "token store") {
		t.Fatalf("got %d %q, want 503 naming the token store", rec.Code, rec.Body.String())
	}
}
