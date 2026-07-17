package api

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	healthy    bool
	vmURL      string
	lokiURL    string
	grafanaURL string
}

func (f *fakeSupGrafana) Start(context.Context) error              { return nil }
func (f *fakeSupGrafana) Stop(context.Context) error               { return nil }
func (f *fakeSupGrafana) Healthy(context.Context) (bool, error)    { return f.healthy, nil }
func (f *fakeSupGrafana) StackReady(context.Context) (bool, error) { return f.healthy, nil }
func (f *fakeSupGrafana) VMBaseURL() string                        { return f.vmURL }
func (f *fakeSupGrafana) LokiBaseURL() string                      { return f.lokiURL }
func (f *fakeSupGrafana) GrafanaBaseURL() string                   { return f.grafanaURL }

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
