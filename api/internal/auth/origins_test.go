package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNormalizeOrigin(t *testing.T) {
	ok := []struct{ in, want string }{
		{"https://rasputin.local", "https://rasputin.local"},
		{"HTTPS://Rasputin.LOCAL", "https://rasputin.local"},
		{"https://rasputin.local:443", "https://rasputin.local"},
		{"http://localhost:80", "http://localhost"},
		{"http://localhost:3000", "http://localhost:3000"},
		{"https://rasputin.local:8443", "https://rasputin.local:8443"},
		{"https://rasputin.local/", "https://rasputin.local"},
		{"  http://localhost:8080  ", "http://localhost:8080"},
		{"http://[::1]:8080", "http://[::1]:8080"},
		{"http://[::1]", "http://[::1]"},
		{"http://[::1]:80", "http://[::1]"},
		{"http://10.0.0.5:3000", "http://10.0.0.5:3000"},
	}
	for _, c := range ok {
		got, err := NormalizeOrigin(c.in)
		if err != nil {
			t.Errorf("NormalizeOrigin(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeOrigin(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	bad := []string{
		"",
		"null",
		"rasputin.local",
		"localhost:3000",
		"ftp://rasputin.local",
		"file:///etc/passwd",
		"https://",
		"https://user@rasputin.local",
		"https://rasputin.local/path",
		"https://rasputin.local?x=1",
		"https://rasputin.local?",
		"https://rasputin.local#frag",
		"https://rasputin.local:notaport",
		"javascript:alert(1)",
	}
	for _, in := range bad {
		if got, err := NormalizeOrigin(in); err == nil {
			t.Errorf("NormalizeOrigin(%q) = %q, want an error", in, got)
		}
	}
}

func TestNewOriginAllowlistNormalizesAndDeduplicates(t *testing.T) {
	a, err := NewOriginAllowlist([]string{
		"https://Rasputin.local:443", "http://localhost:3000", "https://rasputin.local/",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://rasputin.local", "http://localhost:3000"}
	if got := a.Origins(); !reflect.DeepEqual(got, want) {
		t.Errorf("Origins() = %q, want %q", got, want)
	}
	if _, err := NewOriginAllowlist([]string{"https://rasputin.local", "rasputin.local"}); err == nil {
		t.Error("a malformed entry must fail the whole list")
	}
}

func TestOriginAllowlistAllowsIsSchemeAware(t *testing.T) {
	a, err := NewOriginAllowlist([]string{"https://rasputin.local"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"https://rasputin.local":        true,
		"https://RASPUTIN.local:443":    true,
		"http://rasputin.local":         false, // same host, wrong scheme
		"https://rasputin.local:8443":   false, // same host, other port
		"https://app.rasputin.local":    false,
		"https://rasputin.local.evil":   false,
		"https://evil.example":          false,
		"null":                          false,
		"":                              false,
		"https://rasputin.local/x":      false,
		"https://user@rasputin.local":   false,
		"wss://rasputin.local":          false,
		"https://rasputin.local:443/":   true,
		"https://rasputin.local:0443":   false,
		"https://rasputin.local:443:44": false,
	}
	for in, want := range cases {
		if got := a.Allows(in); got != want {
			t.Errorf("Allows(%q) = %v, want %v", in, got, want)
		}
	}
	var nilList *OriginAllowlist
	if nilList.Allows("https://rasputin.local") || nilList.Origins() != nil {
		t.Error("a nil allowlist must allow nothing")
	}
}

// The patterns go to coder/websocket, which matches them with path.Match
// against "scheme://host" when a pattern carries a scheme. Each must match
// exactly its own origin — an IPv6 literal's brackets included — and nothing
// with another scheme.
func TestWebSocketOriginPatterns(t *testing.T) {
	a, err := NewOriginAllowlist([]string{"https://rasputin.local", "http://[::1]:8080"})
	if err != nil {
		t.Fatal(err)
	}
	pats := a.WebSocketOriginPatterns()
	if len(pats) != 2 {
		t.Fatalf("patterns = %q", pats)
	}
	match := func(target string) bool {
		for _, p := range pats {
			ok, err := path.Match(p, target)
			if err != nil {
				t.Fatalf("pattern %q: %v", p, err)
			}
			if ok {
				return true
			}
		}
		return false
	}
	for target, want := range map[string]bool{
		"https://rasputin.local": true,
		"http://rasputin.local":  false,
		"http://[::1]:8080":      true,
		"http://:8080":           false,
		"http://1:8080":          false,
	} {
		if got := match(target); got != want {
			t.Errorf("patterns match %q = %v, want %v", target, got, want)
		}
	}
}

func TestNewServiceRefusesMalformedOriginsAndNormalizes(t *testing.T) {
	store, err := OpenStore(context.Background(), filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := NewService(store, Config{RPID: "rasputin.local", RPOrigins: []string{"rasputin.local"}}); err == nil {
		t.Error("NewService accepted an origin with no scheme")
	}
	svc, err := NewService(store, Config{RPID: "rasputin.local", RPOrigins: []string{"https://Rasputin.local:443"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := svc.Origins().Origins(); !reflect.DeepEqual(got, []string{"https://rasputin.local"}) {
		t.Errorf("Origins() = %q", got)
	}
	if got := svc.web.Config.RPOrigins; !reflect.DeepEqual(got, []string{"https://rasputin.local"}) {
		t.Errorf("WebAuthn RPOrigins = %q, want the normalized list", got)
	}
}

func TestRequireSessionChecksOrigin(t *testing.T) {
	f := newAuthFixture(t) // RPOrigins: http://localhost:3000
	u := f.mintUser(t, "alice")
	sess := freshSession(t, f, u)
	reached := false
	h := f.svc.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	cases := []struct {
		name    string
		origins []string
		cookie  bool
		want    int
	}{
		{"no Origin, session", nil, true, http.StatusOK},
		{"allowed Origin, session", []string{"http://localhost:3000"}, true, http.StatusOK},
		{"foreign Origin, session", []string{"https://evil.example"}, true, http.StatusForbidden},
		{"same host, other scheme", []string{"https://localhost:3000"}, true, http.StatusForbidden},
		{"opaque Origin", []string{"null"}, true, http.StatusForbidden},
		{"one bad copy among two", []string{"http://localhost:3000", "https://evil.example"}, true, http.StatusForbidden},
		{"foreign Origin, no session", []string{"https://evil.example"}, false, http.StatusForbidden},
		{"allowed Origin, no session", []string{"http://localhost:3000"}, false, http.StatusUnauthorized},
	}
	for _, c := range cases {
		reached = false
		r := httptest.NewRequest(http.MethodGet, "/ws/jobs", nil)
		for _, o := range c.origins {
			r.Header.Add("Origin", o)
		}
		if c.cookie {
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess.Token})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, w.Code, c.want)
		}
		if reached != (c.want == http.StatusOK) {
			t.Errorf("%s: handler reached = %v", c.name, reached)
		}
	}
}

func TestStripCookies(t *testing.T) {
	h := http.Header{}
	h.Add("Cookie", "rasputin-session=s3cret; grafana_session=g1")
	h.Add("Cookie", "rasputin-pending=p3nding; theme=dark")
	StripCookies(h)
	if got := h.Values("Cookie"); !reflect.DeepEqual(got, []string{"grafana_session=g1; theme=dark"}) {
		t.Errorf("Cookie = %q", got)
	}

	only := http.Header{"Cookie": {"rasputin-session=s3cret; rasputin-pending=p"}}
	StripCookies(only)
	if _, present := only["Cookie"]; present {
		t.Errorf("Cookie header kept with nothing left in it: %q", only.Values("Cookie"))
	}

	none := http.Header{}
	StripCookies(none)
	if len(none) != 0 {
		t.Errorf("StripCookies added headers: %v", none)
	}
}
