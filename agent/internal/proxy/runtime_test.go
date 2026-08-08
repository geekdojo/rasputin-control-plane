package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLeafStore_Routes(t *testing.T) {
	s := NewLeafStore(t.TempDir())
	if err := s.Write("a1", []byte("C1"), []byte("K1"), RouteMeta{
		TailnetFQDN: "jellyfin.home1.internal", LANFQDN: "jellyfin.lan.home1.internal", UpstreamPort: 8096,
	}); err != nil {
		t.Fatalf("write a1: %v", err)
	}
	if err := s.Write("a2", []byte("C2"), []byte("K2"), RouteMeta{
		TailnetFQDN: "vault.home1.internal", UpstreamPort: 8080, // tailnet-only
	}); err != nil {
		t.Fatalf("write a2: %v", err)
	}

	routes, err := s.Routes()
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes))
	}
	byID := map[string]AppRoute{}
	for _, r := range routes {
		byID[r.AppID] = r
	}
	if r := byID["a1"]; r.TailnetFQDN != "jellyfin.home1.internal" || r.LANFQDN != "jellyfin.lan.home1.internal" ||
		r.UpstreamPort != 8096 || r.CertPath != s.CertPath("a1") || r.KeyPath != s.KeyPath("a1") {
		t.Errorf("a1 route wrong: %+v", r)
	}
	if r := byID["a2"]; r.LANFQDN != "" || r.UpstreamPort != 8080 {
		t.Errorf("a2 route wrong: %+v", r)
	}
}

func TestReconcile_PushesRenderedConfig(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/load" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	adminAddr := strings.TrimPrefix(srv.URL, "http://")

	store := NewLeafStore(t.TempDir())
	if err := store.Write("a1", []byte("C"), []byte("K"), RouteMeta{
		TailnetFQDN: "jellyfin.home1.internal", UpstreamPort: 8096,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := NewReconciler(store, adminAddr,
		func() string { return "100.64.0.2" },
		func() string { return "192.168.1.2" })
	if err := r.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	body := string(got)
	if !strings.Contains(body, "jellyfin.home1.internal") || !strings.Contains(body, "127.0.0.1:8096") {
		t.Errorf("pushed config missing route: %s", body)
	}
}

func TestPushConfig_ErrorsOnReject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad config"))
	}))
	defer srv.Close()
	err := pushConfig(srv.Client(), strings.TrimPrefix(srv.URL, "http://"), []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Errorf("want a 'rejected' error, got %v", err)
	}
}
