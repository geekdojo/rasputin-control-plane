package idtoken_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth/idtoken"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// keyServer is the identity service's key set on a TLS test server, which
// records every request's forwarded headers.
type keyServer struct {
	mu      sync.Mutex
	keys    []*rsa.PrivateKey
	headers []http.Header
	hosts   []string
	srv     *httptest.Server
}

func newKeyServer(t *testing.T) *keyServer {
	t.Helper()
	ks := &keyServer{}
	ks.add(t)
	ks.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ks.mu.Lock()
		ks.headers = append(ks.headers, r.Header.Clone())
		ks.hosts = append(ks.hosts, r.Host)
		var keys []map[string]string
		for i, k := range ks.keys {
			keys = append(keys, map[string]string{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid(i),
				"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())})
		}
		ks.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(ks.srv.Close)
	return ks
}

func kid(i int) string { return "kid-" + string(rune('a'+i)) }

func (ks *keyServer) add(t *testing.T) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ks.mu.Lock()
	ks.keys = append(ks.keys, k)
	ks.mu.Unlock()
}

func (ks *keyServer) sign(t *testing.T, claims map[string]any) secret.Value {
	t.Helper()
	ks.mu.Lock()
	i := len(ks.keys) - 1
	k := ks.keys[i]
	ks.mu.Unlock()
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid(i)})
	c, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return secret.New([]byte(in + "." + base64.RawURLEncoding.EncodeToString(sig)))
}

// client is the production identity client against the key server.
func (ks *keyServer) client(t *testing.T) *idclient.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ks.srv.Certificate())
	u, _ := url.Parse(ks.srv.URL)
	c, err := idclient.New(idclient.Config{Addr: u, MgmtAddr: u, TLS: &tls.Config{RootCAs: pool}, CallTimeout: 10 * time.Second,
		Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TC-989-21 (T160): a token signed under a key id the verifier does not
// hold makes it fetch the key set once more and accept the token after the
// rotation; every key set request carries the home door's forwarded
// headers through the api leaf's client.
func TestVerifier_RefetchOnUnknownKidThroughTheDoor(t *testing.T) {
	ks := newKeyServer(t)
	table, err := doors.New("ci")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	v, err := idtoken.New(t.Context(), table.Home.Issuer, "rasputin-console", ks.client(t).Forwarding(table.Home.SetForwarded), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": table.Home.Issuer, "aud": "rasputin-console", "sub": "s", "azp": "rasputin-console",
		"sid": "sid-1", "nonce": "n", "auth_time": now.Unix(), "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(),
		"preferred_username": "alice", "rasputin_roles": []string{"admin"}}
	c, err := v.IDToken(t.Context(), ks.sign(t, claims))
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "s" || c.SessionID != "sid-1" || c.AuthorizedParty != "rasputin-console" || c.PreferredUsername != "alice" ||
		len(c.Roles) != 1 || c.AuthTime.Unix() != now.Unix() {
		t.Errorf("claims %+v", c)
	}
	ks.add(t) // rotation: the next token is signed under a key id the verifier has not seen
	if _, err := v.IDToken(t.Context(), ks.sign(t, claims)); err != nil {
		t.Fatalf("a token under the rotated key: %v", err)
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if len(ks.headers) != 2 {
		t.Errorf("%d key set fetches, want 2 (the first and one for the new key id)", len(ks.headers))
	}
	want := http.Header{}
	table.Home.SetForwarded(want)
	for i, h := range ks.headers {
		for _, k := range []string{"X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port"} {
			if h.Get(k) != want.Get(k) {
				t.Errorf("fetch %d: %s = %q, want %q", i, k, h.Get(k), want.Get(k))
			}
		}
		if ks.hosts[i] != table.Home.Host {
			t.Errorf("fetch %d: Host = %q, want the door's", i, ks.hosts[i])
		}
	}
}

// The verifier tells a key set it could not fetch (ErrUnavailable) from a
// token it refuses (ErrInvalid), and reads a logout token's sid.
func TestVerifier_UnavailableAndLogout(t *testing.T) {
	ks := newKeyServer(t)
	table, _ := doors.New("ci")
	now := time.Now()
	down := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("connection refused") })}
	v, err := idtoken.New(t.Context(), table.Home.Issuer, "rasputin-console", down, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	tok := ks.sign(t, map[string]any{"iss": table.Home.Issuer, "aud": "rasputin-console", "exp": now.Add(time.Minute).Unix()})
	if _, err := v.IDToken(t.Context(), tok); !errors.Is(err, idtoken.ErrUnavailable) {
		t.Errorf("a key set that cannot be fetched: %v, want ErrUnavailable", err)
	}
	v, _ = idtoken.New(t.Context(), table.Home.Issuer, "rasputin-console", ks.client(t).Forwarding(table.Home.SetForwarded), func() time.Time { return now })
	expired := ks.sign(t, map[string]any{"iss": table.Home.Issuer, "aud": "rasputin-console", "sub": "s", "exp": now.Add(-time.Minute).Unix()})
	if _, err := v.IDToken(t.Context(), expired); !errors.Is(err, idtoken.ErrInvalid) {
		t.Errorf("an expired token: %v, want ErrInvalid", err)
	}
	logout := ks.sign(t, map[string]any{"iss": table.Home.Issuer, "aud": "rasputin-console", "sub": "s", "sid": "sid-9", "jti": "j",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}})
	if sid, err := v.LogoutToken(t.Context(), logout); err != nil || sid != "sid-9" {
		t.Errorf("LogoutToken = %q, %v", sid, err)
	}
	if _, err := idtoken.New(t.Context(), "", "c", down, time.Now); err == nil {
		t.Error("New accepted an empty issuer")
	}
	if _, err := idtoken.New(t.Context(), "i", "c", nil, time.Now); err == nil {
		t.Error("New accepted a nil client")
	}
	if _, err := idtoken.New(t.Context(), "i", "c", down, nil); err == nil {
		t.Error("New accepted a nil clock")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TC-992-07's verifier half (T201): an access token issued to the reset
// client verifies with any audience and yields iss, azp and sub; one with
// another azp, a typ other than Bearer (an ID token), no sub, a foreign
// issuer, a bad signature or an expired exp is ErrInvalid.
func TestVerifier_AccessToken(t *testing.T) {
	ks := newKeyServer(t)
	table, _ := doors.New("ci")
	now := time.Now()
	v, err := idtoken.New(t.Context(), table.App.Issuer, "rasputin-reset-app", ks.client(t).Forwarding(table.App.SetForwarded), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	claims := func(edit func(map[string]any)) map[string]any {
		c := map[string]any{"iss": table.App.Issuer, "aud": "account", "sub": "s-1", "azp": "rasputin-reset-app", "typ": "Bearer",
			"iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
		if edit != nil {
			edit(c)
		}
		return c
	}
	c, err := v.AccessToken(t.Context(), ks.sign(t, claims(nil)))
	if err != nil || c != (idtoken.AccessClaims{Issuer: table.App.Issuer, AuthorizedParty: "rasputin-reset-app", Subject: "s-1"}) {
		t.Fatalf("AccessToken = %+v, %v", c, err)
	}
	for name, edit := range map[string]func(map[string]any){
		"another client": func(c map[string]any) { c["azp"] = "rasputin-console" },
		"an ID token":    func(c map[string]any) { c["typ"] = "ID" },
		"no typ":         func(c map[string]any) { delete(c, "typ") },
		"no subject":     func(c map[string]any) { delete(c, "sub") },
		"foreign issuer": func(c map[string]any) { c["iss"] = table.Home.Issuer },
		"expired":        func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() },
	} {
		if _, err := v.AccessToken(t.Context(), ks.sign(t, claims(edit))); !errors.Is(err, idtoken.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	forged := ks.sign(t, claims(nil))
	b := []byte(string(forged.Reveal()))
	b[len(b)-3] ^= 1
	if _, err := v.AccessToken(t.Context(), secret.New(b)); !errors.Is(err, idtoken.ErrInvalid) {
		t.Errorf("a bad signature: %v, want ErrInvalid", err)
	}
	down := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("connection refused") })}
	dv, _ := idtoken.New(t.Context(), table.App.Issuer, "rasputin-reset-app", down, func() time.Time { return now })
	if _, err := dv.AccessToken(t.Context(), ks.sign(t, claims(nil))); !errors.Is(err, idtoken.ErrUnavailable) {
		t.Errorf("a key set that cannot be fetched: %v, want ErrUnavailable", err)
	}
}
