package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
)

// fakeSupGrafana mirrors obs.fakeSupervisor — needed here because
// fakeSupervisor isn't exported and the proxy test lives in the api
// package.
type fakeSupGrafana struct {
	healthy          bool
	vmURL            string
	lokiURL          string
	grafanaURL       string
	grafanaTransport http.RoundTripper
}

func (f *fakeSupGrafana) Start(context.Context) error              { return nil }
func (f *fakeSupGrafana) Stop(context.Context) error               { return nil }
func (f *fakeSupGrafana) Healthy(context.Context) (bool, error)    { return f.healthy, nil }
func (f *fakeSupGrafana) StackReady(context.Context) (bool, error) { return f.healthy, nil }
func (f *fakeSupGrafana) VMBaseURL() string                        { return f.vmURL }
func (f *fakeSupGrafana) LokiBaseURL() string                      { return f.lokiURL }
func (f *fakeSupGrafana) GrafanaBaseURL() string                   { return f.grafanaURL }
func (f *fakeSupGrafana) GrafanaTransport() http.RoundTripper      { return f.grafanaTransport }

// TestObsProxy_ForwardsUserHeader confirms the proxy strips any
// client-supplied X-Webauth-* and replaces it with the authenticated
// user's name. The stub upstream records the headers it received.
func TestObsProxy_ForwardsUserHeader(t *testing.T) {
	var lastUser atomic.Value // string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastUser.Store(r.Header.Get("X-Webauth-User"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("grafana-pong"))
	}))
	defer stub.Close()

	sup := &fakeSupGrafana{healthy: true, vmURL: "http://x", grafanaURL: stub.URL}
	sink, _ := obs.NewVMSink(obs.VMSinkConfig{Supervisor: sup})
	srv := &Server{obs: obs.NewStatus(sup, sink, nil)}

	req := httptest.NewRequest(http.MethodGet, "/observability/api/health", nil)
	// Spoof a different X-Webauth-User on the way in to prove the
	// proxy clears it.
	req.Header.Set("X-Webauth-User", "attacker")
	ctx := auth.WithUser(req.Context(), &auth.User{Name: "alice"})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	srv.handleObservabilityProxy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); !strings.Contains(got, "grafana-pong") {
		t.Errorf("body lost upstream content: %s", got)
	}
	got, _ := lastUser.Load().(string)
	if got != "alice" {
		t.Errorf("X-Webauth-User = %q, want alice (proxy must overwrite client header)", got)
	}
}

// TestObsProxy_ServiceUnavailableWhenGrafanaOff confirms the proxy
// returns 503 — not 502 — when Grafana isn't configured. That keeps
// the operator-facing error specific ("Grafana is disabled") vs.
// "upstream connection refused".
func TestObsProxy_ServiceUnavailableWhenGrafanaOff(t *testing.T) {
	sup := &fakeSupGrafana{healthy: true, vmURL: "http://x"} // no grafanaURL
	sink, _ := obs.NewVMSink(obs.VMSinkConfig{Supervisor: sup})
	srv := &Server{obs: obs.NewStatus(sup, sink, nil)}

	req := httptest.NewRequest(http.MethodGet, "/observability/", nil)
	ctx := auth.WithUser(req.Context(), &auth.User{Name: "alice"})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	srv.handleObservabilityProxy(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("want 503, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestObsProxy_ReachesGrafanaOverUnixSocket is the api half of
// geekdojo-brain#453: on a controlplane Grafana has no TCP listener, so the
// proxy's target URL carries a placeholder host and the SUPERVISOR'S
// transport is what actually reaches it. A proxy that ignored the transport
// would fail to resolve that host — this test would then fail rather than
// silently falling back to a port that no longer exists.
func TestObsProxy_ReachesGrafanaOverUnixSocket(t *testing.T) {
	// Short path: a unix socket path over ~104 bytes cannot bind, and
	// t.TempDir() is long on macOS.
	dir, err := os.MkdirTemp("/tmp", "obsprx")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "grafana.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	var lastUser atomic.Value // string
	stub := &httptest.Server{
		Listener: ln,
		Config: &http.Server{Handler: http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				lastUser.Store(r.Header.Get("X-Webauth-User"))
				_, _ = w.Write([]byte("grafana-over-socket"))
			})},
	}
	stub.Start()
	defer stub.Close()

	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
		},
	}
	sup := &fakeSupGrafana{
		healthy:          true,
		vmURL:            "http://x",
		grafanaURL:       "http://grafana.invalid", // placeholder host, never resolved
		grafanaTransport: tr,
	}
	sink, _ := obs.NewVMSink(obs.VMSinkConfig{Supervisor: sup})
	srv := &Server{obs: obs.NewStatus(sup, sink, nil)}

	req := httptest.NewRequest(http.MethodGet, "/observability/api/search", nil)
	req.Header.Set("X-Webauth-User", "attacker")
	req = req.WithContext(auth.WithUser(req.Context(), &auth.User{Name: "alice"}))
	w := httptest.NewRecorder()
	srv.handleObservabilityProxy(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200 over the socket, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "grafana-over-socket") {
		t.Errorf("body = %q", w.Body.String())
	}
	// The strip still applies — the socket is who may call, the strip is
	// who they may claim to be.
	if got, _ := lastUser.Load().(string); got != "alice" {
		t.Errorf("X-Webauth-User = %q, want alice", got)
	}
}
