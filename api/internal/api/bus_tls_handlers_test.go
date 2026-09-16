package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
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

func wireBusTLS(t *testing.T, f *apiFixture) (*bustls.Service, *atomic.Int32) {
	t.Helper()
	key, _, err := bustls.EnsureKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var restarts atomic.Int32
	svc := bustls.NewService(bustls.Config{
		Key:       key,
		Settings:  &memBusTLSSettings{m: map[string]string{}},
		StartMode: bustls.ModeOffer,
		Nodes:     f.inv.List,
		Plaintext: func() ([]bus.PlaintextClient, error) { return nil, nil },
		Restart:   func() { restarts.Add(1) },
	})
	f.srv.SetBusTLS(svc)
	return svc, &restarts
}

// The seed the UI renders comes from the mint response, so the pin must be in
// it: a token and a pin from the same moment.
func TestMintBusToken_CarriesTheLivePin(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	w := f.do(t, http.MethodPost, "/api/bus/tokens", `{"label":"t","nodeId":"n1"}`, cookie)
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if v, ok := body["busPin"]; !ok || v != "" {
		t.Fatalf("with bus TLS unavailable, busPin = (%q, present=%t), want present and empty", v, ok)
	}

	svc, _ := wireBusTLS(t, f)
	w = f.do(t, http.MethodPost, "/api/bus/tokens", `{"label":"t","nodeId":"n2"}`, cookie)
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

func TestBusTLSEndpoints(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	if w := f.do(t, http.MethodGet, "/api/bus/tls", "", cookie); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET without a bus key = %d, want 503", w.Code)
	}
	if w := f.do(t, http.MethodGet, "/api/bus/tls", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("GET without a session = %d, want 401", w.Code)
	}

	svc, restarts := wireBusTLS(t, f)
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
	if st.Pin != svc.Pin() || st.Mode != bustls.ModeOffer || st.Ready || len(st.Blockers) != 1 {
		t.Fatalf("status = %+v", st)
	}

	if w := f.do(t, http.MethodPut, "/api/bus/tls", `{"mode":"sideways"}`, cookie); w.Code != http.StatusBadRequest {
		t.Fatalf("PUT bad mode = %d, want 400", w.Code)
	}
	w = f.do(t, http.MethodPut, "/api/bus/tls", `{"mode":"require"}`, cookie)
	if w.Code != http.StatusConflict {
		t.Fatalf("PUT require while n1 is plaintext = %d %s, want 409", w.Code, w.Body)
	}
	var refused struct {
		Error  string        `json:"error"`
		Status bustls.Status `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &refused); err != nil {
		t.Fatal(err)
	}
	if refused.Error == "" || len(refused.Status.Blockers) != 1 {
		t.Fatalf("409 body = %s, want the error and the blocker", w.Body)
	}

	n, err := f.inv.Get(f.ctx, "n1")
	if err != nil {
		t.Fatal(err)
	}
	n.Metadata = map[string]any{proto.MetadataBusTLS: true}
	if err := f.inv.Update(f.ctx, n); err != nil {
		t.Fatal(err)
	}
	if w := f.do(t, http.MethodPut, "/api/bus/tls", `{"mode":"require"}`, cookie); w.Code != http.StatusOK {
		t.Fatalf("PUT require when ready = %d %s, want 200", w.Code, w.Body)
	}
	if got := restarts.Load(); got != 1 {
		t.Fatalf("restart requested %d times, want 1", got)
	}
}
