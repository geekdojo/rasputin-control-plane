package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

type memBusTLSSettings struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memBusTLSSettings) Get(_ context.Context, k string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[k], nil
}

func (s *memBusTLSSettings) Set(_ context.Context, k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
	return nil
}

func wireBusTLS(t *testing.T, f *apiFixture) *bustls.Service {
	t.Helper()
	key, _, err := bustls.EnsureKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Not started: no evaluation runs, so the rung stays where this puts it.
	svc := bustls.NewService(bustls.Config{
		Key:       key,
		Settings:  &memBusTLSSettings{m: map[string]string{}},
		StartMode: bustls.ModeMigrate,
		Nodes:     f.inv.List,
		Plaintext: func() ([]bus.PlaintextClient, error) { return nil, nil },
	})
	f.srv.SetBusTLS(svc)
	return svc
}

// The seed the UI renders comes from the mint response, so the pin must be in
// it: a token and a pin from the same moment.
func TestMintBusToken_CarriesTheLivePin(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	w := f.do(t, http.MethodPost, "/api/bus/tokens", `{"role":"compute","label":"t","nodeId":"n1"}`, cookie)
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if v, ok := body["busPin"]; !ok || v != "" {
		t.Fatalf("with bus TLS unavailable, busPin = (%q, present=%t), want present and empty", v, ok)
	}

	svc := wireBusTLS(t, f)
	w = f.do(t, http.MethodPost, "/api/bus/tokens", `{"role":"compute","label":"t","nodeId":"n2"}`, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("mint = %d %s", w.Code, w.Body)
	}
	body = map[string]string{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["busPin"] != svc.Pin() || body["token"] == "" {
		t.Fatalf("mint response = %v, want the token and busPin %s", body, svc.Pin())
	}
}

// GET /api/bus/tls is session-gated, 503 without a bus key, and otherwise the
// read-only status: the rung, the pin, and the facts holding the next rung
// back. There is no PUT — the api moves the ladder itself.
func TestBusTLSEndpoint(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	if w := f.do(t, http.MethodGet, "/api/bus/tls", "", cookie); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET without a bus key = %d, want 503", w.Code)
	}
	if w := f.do(t, http.MethodGet, "/api/bus/tls", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("GET without a session = %d, want 401", w.Code)
	}

	svc := wireBusTLS(t, f)
	now := time.Now().UTC()
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "n1", Role: proto.RoleCompute, FirstSeen: now, LastSeen: now,
		Metadata: map[string]any{proto.MetadataBusTLS: false},
	}); err != nil {
		t.Fatal(err)
	}

	w := f.do(t, http.MethodGet, "/api/bus/tls", "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d %s", w.Code, w.Body)
	}
	var st bustls.Status
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Pin != svc.Pin() || st.Mode != bustls.ModeMigrate || st.Next != bustls.ModeRequire || len(st.Blockers) != 1 {
		t.Fatalf("status = %+v, want migrate → require held back by n1 alone", st)
	}

	if w := f.do(t, http.MethodPut, "/api/bus/tls", `{"mode":"require"}`, cookie); w.Code == http.StatusOK {
		t.Fatalf("PUT /api/bus/tls = %d; the mode must not be settable over the api", w.Code)
	}
}
