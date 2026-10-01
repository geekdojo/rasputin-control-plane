package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// logCapture is a slog.Handler that keeps every record the Server writes.
type logCapture struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }
func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, r.Clone())
	return nil
}
func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }

// withAttr returns the captured records carrying key=value.
func (c *logCapture) withAttr(key, value string) []slog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []slog.Record
	for _, r := range c.recs {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == key && a.Value.String() == value {
				out = append(out, r)
				return false
			}
			return true
		})
	}
	return out
}

func recAttr(r slog.Record, key string) (string, bool) {
	var v string
	found := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			v, found = a.Value.String(), true
			return false
		}
		return true
	})
	return v, found
}

// sequentialIDs is a deterministic correlation id generator: cid-1, cid-2, …
func sequentialIDs() func() string {
	var n atomic.Int64
	return func() string { return fmt.Sprintf("cid-%d", n.Add(1)) }
}

// useBusState rebuilds the fixture's server around st, the way main builds it
// from what the bus key and certificate turned out to be.
func (f *apiFixture) useBusState(t *testing.T, st BusState) {
	t.Helper()
	srv, err := NewServer(f.jobsStore, f.runner, f.inv, inventory.NewService(f.inv, f.nc, slog.New(slog.DiscardHandler)),
		f.fw, f.appsStore, f.metricsStore, f.updStore, f.verifier, f.bundleDir, f.srv.trustDir,
		f.mesh, f.bmcSvc, f.setupSvc, f.authSvc, nil /* obsStatus */, f.srv.busTokens, f.nc,
		st, f.srv.log, f.srv.newCorrelationID)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.SetConsole(f.console)
	f.srv, f.handler = srv, srv.Handler()
}

// tokenCount is how many join tokens the store holds.
func (f *apiFixture) tokenCount(t *testing.T) int {
	t.Helper()
	toks, err := f.srv.busTokens.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	return len(toks)
}

// decodeCoded decodes a coded-error body and checks its exact key set.
func decodeCoded(t *testing.T, body []byte) codedError {
	t.Helper()
	var keys map[string]any
	if err := json.Unmarshal(body, &keys); err != nil {
		t.Fatalf("body %s is not JSON: %v", body, err)
	}
	if len(keys) != 3 {
		t.Fatalf("body %s has keys %v, want exactly error, code and correlationId", body, keys)
	}
	var c codedError
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// TC-517-19: GET /api/bus/tls answers exactly {"pin": P} with a key, and a
// 503 bus_unavailable body — which says nothing of plaintext — without one.
// It is session-gated, and there is no PUT.
func TestBusTLSEndpoint(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	w := f.do(t, http.MethodGet, "/api/bus/tls", "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d %s", w.Code, w.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 1 || body["pin"] != f.busKey.Pin() {
		t.Fatalf("GET body = %v, want exactly {\"pin\": %q}", body, f.busKey.Pin())
	}
	if w := f.do(t, http.MethodGet, "/api/bus/tls", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("GET without a session = %d, want 401", w.Code)
	}
	if w := f.do(t, http.MethodPut, "/api/bus/tls", `{"mode":"require"}`, cookie); w.Code == http.StatusOK {
		t.Fatalf("PUT /api/bus/tls = %d; nothing about the bus is settable over the api", w.Code)
	}

	f.useBusState(t, bustls.Unavailable(filepath.Join(t.TempDir(), "bus", "bus.key"), errors.New("unreadable")))
	w = f.do(t, http.MethodGet, "/api/bus/tls", "", cookie)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET without a bus key = %d, want 503", w.Code)
	}
	c := decodeCoded(t, w.Body.Bytes())
	if c.Code != "bus_unavailable" {
		t.Fatalf("code = %q, want bus_unavailable", c.Code)
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "plaintext") {
		t.Fatalf("the 503 still speaks of plaintext: %s", w.Body)
	}
}

// TC-517-20: mint refuses with no key, before MintBound, so no token row is
// created; with a key, the seed carries the pin.
func TestMintBusToken_CarriesTheLivePin(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	w := f.do(t, http.MethodPost, "/api/bus/tokens", `{"role":"compute","label":"t","nodeId":"n2"}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("mint = %d %s", w.Code, w.Body)
	}
	body := map[string]string{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["busPin"] != f.busKey.Pin() || body["token"] == "" {
		t.Fatalf("mint response = %v, want the token and busPin %s", body, f.busKey.Pin())
	}
	if !strings.Contains(body["seed"], proto.SeedKeyBusPin+"='"+f.busKey.Pin()+"'") {
		t.Fatalf("the seed does not carry %s=%s:\n%s", proto.SeedKeyBusPin, f.busKey.Pin(), body["seed"])
	}

	f.useBusState(t, bustls.Unavailable(filepath.Join(t.TempDir(), "bus", "bus.key"), errors.New("unreadable")))
	before := f.tokenCount(t)
	w = f.do(t, http.MethodPost, "/api/bus/tokens", `{"role":"compute","label":"t","nodeId":"n1"}`, cookie)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("mint with no bus key = %d %s, want 503", w.Code, w.Body)
	}
	if c := decodeCoded(t, w.Body.Bytes()); c.Code != "bus_unavailable" {
		t.Fatalf("code = %q, want bus_unavailable", c.Code)
	}
	if after := f.tokenCount(t); after != before {
		t.Fatalf("a refused mint changed the token count from %d to %d", before, after)
	}
}

// TC-517-49: a coded 503 carries a code, a safe message and a correlation id,
// and nothing internal; the cause — the file and the error — is logged at WARN
// under the same id, with the route.
func TestBusUnavailable_EnvelopeAndLog(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)
	file := filepath.Join(t.TempDir(), "bus", "bus.crt")
	cause := errors.New("open " + file + ": permission denied")
	f.useBusState(t, bustls.Unavailable(file, cause))

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/bus/tls", ""},
		{http.MethodPost, "/api/bus/tokens", `{"role":"compute","label":"t","nodeId":"n9"}`},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := f.do(t, tc.method, tc.path, tc.body, cookie)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("= %d %s, want 503", w.Code, w.Body)
			}
			c := decodeCoded(t, w.Body.Bytes())
			if c.Code != "bus_unavailable" || c.CorrelationID == "" || c.Error == "" {
				t.Fatalf("body = %+v, want code bus_unavailable, a message and a correlation id", c)
			}
			if strings.Contains(w.Body.String(), file) || strings.Contains(w.Body.String(), "permission denied") {
				t.Fatalf("the body leaks the cause: %s", w.Body)
			}
			recs := f.logs.withAttr("correlation_id", c.CorrelationID)
			if len(recs) != 1 {
				t.Fatalf("%d log records carry correlation id %s, want 1", len(recs), c.CorrelationID)
			}
			r := recs[0]
			if r.Level != slog.LevelWarn {
				t.Errorf("level = %s, want WARN", r.Level)
			}
			for key, want := range map[string]string{
				"route": tc.method + " " + tc.path,
				"code":  "bus_unavailable",
				"file":  file,
				"err":   cause.Error(),
			} {
				if got, ok := recAttr(r, key); !ok || got != want {
					t.Errorf("%s = %q, want %q", key, got, want)
				}
			}
		})
	}
}

// TC-517-50: NewServer refuses a nil logger, a nil id generator or a nil
// BusState, each alone, with an error and no Server — never a panic later.
func TestNewServer_RefusesNilCollaborators(t *testing.T) {
	f := newAPIFixture(t)
	key := bustls.Available(f.busKey)
	logger := slog.New(&logCapture{})
	ids := sequentialIDs()
	for name, tc := range map[string]struct {
		bus BusState
		log *slog.Logger
		ids func() string
	}{
		"nil BusState":     {nil, logger, ids},
		"nil logger":       {key, nil, ids},
		"nil id generator": {key, logger, nil},
	} {
		t.Run(name, func(t *testing.T) {
			srv, err := NewServer(f.jobsStore, f.runner, f.inv, inventory.NewService(f.inv, f.nc, slog.New(slog.DiscardHandler)),
				f.fw, f.appsStore, f.metricsStore, f.updStore, f.verifier, f.bundleDir, f.srv.trustDir,
				f.mesh, f.bmcSvc, f.setupSvc, f.authSvc, nil, f.srv.busTokens, f.nc,
				tc.bus, tc.log, tc.ids)
			if err == nil || srv != nil {
				t.Fatalf("NewServer = (%v, %v), want (nil, an error)", srv, err)
			}
		})
	}
}

// TC-517-54: the zero State and Available(nil) are unavailable: both endpoints
// answer 503 bus_unavailable, nothing panics, and no token row is created.
func TestBusState_ZeroValueFailsClosed(t *testing.T) {
	for name, st := range map[string]bustls.State{"zero": {}, "Available(nil)": bustls.Available(nil)} {
		t.Run(name, func(t *testing.T) {
			f := newAPIFixture(t)
			cookie := f.authenticate(t)
			f.useBusState(t, st)
			before := f.tokenCount(t)
			for _, tc := range []struct{ method, path, body string }{
				{http.MethodGet, "/api/bus/tls", ""},
				{http.MethodPost, "/api/bus/tokens", `{"role":"compute","label":"t","nodeId":"n7"}`},
			} {
				w := f.do(t, tc.method, tc.path, tc.body, cookie)
				if w.Code != http.StatusServiceUnavailable {
					t.Fatalf("%s %s = %d %s, want 503", tc.method, tc.path, w.Code, w.Body)
				}
				if c := decodeCoded(t, w.Body.Bytes()); c.Code != "bus_unavailable" {
					t.Fatalf("code = %q", c.Code)
				}
			}
			if after := f.tokenCount(t); after != before {
				t.Fatalf("token count %d → %d", before, after)
			}
		})
	}
}
