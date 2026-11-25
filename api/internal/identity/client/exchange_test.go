package idclient

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

func doorHeaders(h http.Header) {
	h.Set("X-Forwarded-Host", "sso-ci.local")
	h.Set("X-Forwarded-Proto", "https")
	h.Set("X-Forwarded-Port", "443")
}

func exchange(code string) CodeExchange {
	return CodeExchange{Realm: "rasputin", ClientID: "rasputin-console", Code: secret.New([]byte(code)),
		Verifier: secret.New([]byte("verifier-0123456789")), RedirectURI: "https://ci.local/api/auth/callback", Forward: doorHeaders}
}

// The code exchange posts the authorization-code form with the PKCE
// verifier to the realm's token endpoint over the client leaf, with the
// door's forwarded headers, and returns only the ID token; a spent code is
// ErrProtocol with OAuth error invalid_grant, and a service error is
// ErrUnreachable. Nothing it logs holds the code or the verifier.
func TestExchangeCode(t *testing.T) {
	p := newPKI(t)
	var form url.Values
	var hdr http.Header
	srv := newServer(t, p, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(b))
		hdr = r.Header.Clone()
		switch form.Get("code") {
		case "spent":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		case "down":
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			_, _ = w.Write([]byte(`{"access_token":"at","refresh_token":"rt","id_token":"the-id-token"}`))
		}
	}, nil)
	c, rec := newClient(t, p, srv.URL)
	tok, err := c.ExchangeCode(t.Context(), exchange("good-code"))
	if err != nil {
		t.Fatal(err)
	}
	if string(tok.Reveal()) != "the-id-token" {
		t.Errorf("token = %q", tok.Reveal())
	}
	want := url.Values{"grant_type": {"authorization_code"}, "client_id": {"rasputin-console"}, "code": {"good-code"},
		"code_verifier": {"verifier-0123456789"}, "redirect_uri": {"https://ci.local/api/auth/callback"}}
	for k, v := range want {
		if form.Get(k) != v[0] {
			t.Errorf("form %s = %q, want %q", k, form.Get(k), v[0])
		}
	}
	if hdr.Get("X-Forwarded-Host") != "sso-ci.local" || hdr.Get("X-Forwarded-Port") != "443" {
		t.Errorf("forwarded headers %v", hdr)
	}
	if _, err := c.ExchangeCode(t.Context(), exchange("spent")); !errors.Is(err, ErrProtocol) {
		t.Errorf("a spent code: %v", err)
	} else if e := (*Error)(nil); errors.As(err, &e) && e.OAuthError != "invalid_grant" {
		t.Errorf("oauth error %q", e.OAuthError)
	}
	if _, err := c.ExchangeCode(t.Context(), exchange("down")); !errors.Is(err, ErrUnreachable) {
		t.Errorf("a 503: %v", err)
	}
	bad := exchange("x")
	bad.Forward = nil
	if _, err := c.ExchangeCode(t.Context(), bad); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("no door: %v", err)
	}
	for _, n := range []string{"good-code", "spent", "verifier-0123456789", "the-id-token"} {
		if strings.Contains(rec.Text(), n) {
			t.Errorf("the log holds %q", n)
		}
	}
}

// Forwarding sends a door URL's request to the loopback listener with the
// door's Host and headers, and refuses a path outside /realms/.
func TestForwarding(t *testing.T) {
	p := newPKI(t)
	var host, path string
	srv := newServer(t, p, func(w http.ResponseWriter, r *http.Request) { host, path = r.Host, r.URL.Path }, nil)
	c, _ := newClient(t, p, srv.URL)
	hc := c.Forwarding(doorHeaders)
	resp, err := hc.Get("https://sso-ci.local/realms/rasputin/protocol/openid-connect/certs")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if host != "sso-ci.local" || path != "/realms/rasputin/protocol/openid-connect/certs" {
		t.Errorf("host %q path %q", host, path)
	}
	before := srv.requests()
	if _, err := hc.Get("https://sso-ci.local/admin/realms/rasputin/users"); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("an admin path: %v", err)
	}
	if srv.requests() != before {
		t.Error("an admin path was sent")
	}
}

// TC-992-06: with NoVerifier the form carries no code_verifier and
// ExchangeAccessToken returns the answer's access token, ExchangeCode its ID
// token; an empty verifier without the flag, and the flag with a verifier,
// are refused with ErrInvalidValue before any request is sent.
func TestExchange_TC992_06_NoVerifier(t *testing.T) {
	p := newPKI(t)
	var form url.Values
	srv := newServer(t, p, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(b))
		_, _ = w.Write([]byte(`{"access_token":"the-access-token","refresh_token":"rt","id_token":"the-id-token"}`))
	}, nil)
	c, rec := newClient(t, p, srv.URL)
	reset := func() CodeExchange {
		x := exchange("reset-code")
		x.ClientID, x.Verifier, x.NoVerifier = "rasputin-reset-home", secret.Value{}, true
		return x
	}
	tok, err := c.ExchangeAccessToken(t.Context(), reset())
	if err != nil || string(tok.Reveal()) != "the-access-token" {
		t.Fatalf("ExchangeAccessToken = %v", err)
	}
	if form.Has("code_verifier") || form.Get("code") != "reset-code" || form.Get("client_id") != "rasputin-reset-home" {
		t.Errorf("form %v, want the code and no code_verifier", form)
	}
	if tok, err := c.ExchangeCode(t.Context(), reset()); err != nil || string(tok.Reveal()) != "the-id-token" {
		t.Errorf("ExchangeCode with NoVerifier = %v", err)
	}
	before := srv.requests()
	noFlag := reset()
	noFlag.NoVerifier = false
	both := exchange("x")
	both.NoVerifier = true
	for name, x := range map[string]CodeExchange{"empty verifier, no flag": noFlag, "flag and a verifier": both} {
		if _, err := c.ExchangeAccessToken(t.Context(), x); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%s: %v, want ErrInvalidValue", name, err)
		}
		if _, err := c.ExchangeCode(t.Context(), x); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%s: ExchangeCode %v, want ErrInvalidValue", name, err)
		}
	}
	if srv.requests() != before {
		t.Errorf("%d requests sent for refused exchanges", srv.requests()-before)
	}
	for _, n := range []string{"reset-code", "the-access-token"} {
		if strings.Contains(rec.Text(), n) {
			t.Errorf("the log holds %q", n)
		}
	}
}
