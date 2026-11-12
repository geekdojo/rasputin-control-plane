package signin

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The fake server serves #959's fixtures, captured from Keycloak 26.8.2, with
// their form actions pointed at itself. It proves the client's handling of
// each page and answer; that real Keycloak gives those pages is the
// functional self-test's (TestIdentity_PasswordCodeFlowPKCE).

const (
	fakePW        = "pw-SENTINEL-4f1c"
	sentinelCode  = "code-SENTINEL-77ab"
	fakeTok       = "tok-SENTINEL-c0de"
	redirectURI   = "https://127.0.0.1/callback"
	fixtureOrigin = "https://sso-kc959.local:19591"
)

func fixture(t *testing.T, id string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", "pages", id+".html"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// scenario says how the fake answers the posted sign-in form and the token
// request.
type scenario struct {
	afterPost   func(w http.ResponseWriter, r *http.Request, state string)
	tokenAnswer func(w http.ResponseWriter, nonce string)
}

type fakeKeycloak struct {
	t   *testing.T
	srv *httptest.Server
	sc  scenario

	mu             sync.Mutex
	state, nonce   string
	challenge      string
	authCookies    []int // cookies each authorization request carried
	postedPassword string
}

func newFake(t *testing.T, sc scenario) *fakeKeycloak {
	t.Helper()
	f := &fakeKeycloak{t: t, sc: sc}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /realms/harness/protocol/openid-connect/auth", f.auth)
	mux.HandleFunc("POST /realms/rasputin/login-actions/authenticate", f.post)
	mux.HandleFunc("GET /loop", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", http.StatusFound) })
	mux.HandleFunc("POST /realms/harness/protocol/openid-connect/token", f.token)
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeKeycloak) page(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html")
	_, _ = io.WriteString(w, strings.ReplaceAll(body, fixtureOrigin, f.srv.URL))
}

func (f *fakeKeycloak) auth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.mu.Lock()
	f.state, f.nonce, f.challenge = q.Get("state"), q.Get("nonce"), q.Get("code_challenge")
	f.authCookies = append(f.authCookies, len(r.Cookies()))
	f.mu.Unlock()
	for k, want := range map[string]string{"response_type": "code", "code_challenge_method": "S256", "prompt": "login",
		"client_id": "harness-public", "redirect_uri": redirectURI, "scope": "openid"} {
		if q.Get(k) != want {
			f.t.Errorf("authorization request %s = %q, want %q", k, q.Get(k), want)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: "AUTH_SESSION_ID", Value: "s1", Path: "/"})
	f.page(w, fixture(f.t, "login-login"))
}

func (f *fakeKeycloak) post(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		f.t.Errorf("parse the posted form: %v", err)
	}
	if len(r.Cookies()) == 0 {
		f.t.Error("the form post carried no session cookie")
	}
	if r.PostForm.Get("username") != "harness-user" {
		f.t.Errorf("posted username = %q", r.PostForm.Get("username"))
	}
	f.mu.Lock()
	f.postedPassword = r.PostForm.Get("password")
	state := f.state
	f.mu.Unlock()
	f.sc.afterPost(w, r, state)
}

func (f *fakeKeycloak) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		f.t.Errorf("parse the token request: %v", err)
	}
	f.mu.Lock()
	challenge, nonce := f.challenge, f.nonce
	f.mu.Unlock()
	if got := Challenge(r.PostForm.Get("code_verifier")); got != challenge {
		f.t.Errorf("the verifier's challenge %q is not the one sent, %q", got, challenge)
	}
	if r.PostForm.Get("code") != sentinelCode || r.PostForm.Get("grant_type") != "authorization_code" {
		f.t.Errorf("token request = %v", r.PostForm)
	}
	f.sc.tokenAnswer(w, nonce)
}

func redirectWithCode(w http.ResponseWriter, r *http.Request, state string) {
	http.Redirect(w, r, redirectURI+"?state="+url.QueryEscape(state)+"&code="+sentinelCode, http.StatusFound)
}

func idToken(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc(b) + "." + enc([]byte(fakeTok))
}

func goodToken(issuer string) func(http.ResponseWriter, string) {
	return func(w http.ResponseWriter, nonce string) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": fakeTok,
			"id_token":     idToken(map[string]any{"iss": issuer, "sub": "user-1", "aud": "harness-public", "nonce": nonce}),
		})
	}
}

func newClient(t *testing.T, f *fakeKeycloak, log *slog.Logger) *Client {
	t.Helper()
	c, err := New(Config{
		Transport: f.srv.Client().Transport, Issuer: f.srv.URL + "/realms/harness",
		ClientID: "harness-public", RedirectURI: redirectURI, Rand: rand.Reader, Logger: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TC-966-08: the password code flow against a fake serving #959's fixtures,
// over six paths, with a sentinel scan of every record and error, and two
// calls that share no cookies.
func TestPasswordCodeFlow(t *testing.T) {
	refusal := func(id, alert string) func(http.ResponseWriter, *http.Request, string) {
		return func(w http.ResponseWriter, r *http.Request, _ string) {
			body := fixture(t, id)
			if id == "login-login" {
				body = strings.Replace(body, `<div id="input-error-container-username">`,
					`<div id="input-error-container-username"><span id="input-error">`+alert+`</span>`, 1)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, body)
		}
	}
	var issuer string
	cases := []struct {
		name  string
		sc    scenario
		check func(t *testing.T, res Result, err error)
	}{
		{"happy path", scenario{afterPost: redirectWithCode}, func(t *testing.T, res Result, err error) {
			if err != nil {
				t.Fatalf("PasswordCodeFlow = %v", err)
			}
			if strings.Join(res.PageIDs, ",") != "login-login" {
				t.Errorf("PageIDs = %v, want [login-login]", res.PageIDs)
			}
			if res.Claims.Iss != issuer || res.Claims.Sub != "user-1" || len(res.Claims.Aud) != 1 ||
				res.Claims.Aud[0] != "harness-public" || res.Claims.Nonce == "" {
				t.Errorf("Claims = %+v", res.Claims)
			}
		}},
		{"state mismatch", scenario{afterPost: func(w http.ResponseWriter, r *http.Request, _ string) {
			redirectWithCode(w, r, "another-state")
		}}, func(t *testing.T, _ Result, err error) {
			if !errors.Is(err, ErrStateMismatch) {
				t.Errorf("err = %v, want ErrStateMismatch", err)
			}
		}},
		{"unknown page", scenario{afterPost: func(w http.ResponseWriter, _ *http.Request, _ string) {
			_, _ = io.WriteString(w, `<html><body data-page-id="login-something-new"></body></html>`)
		}}, func(t *testing.T, _ Result, err error) {
			var u *UnknownPageError
			if !errors.As(err, &u) || u.ID != "login-something-new" {
				t.Errorf("err = %v, want *UnknownPageError naming login-something-new", err)
			}
		}},
		{"refused on login-login", scenario{afterPost: refusal("login-login", "Invalid username or password.")}, func(t *testing.T, res Result, err error) {
			var r *RefusedError
			if !errors.As(err, &r) || r.PageID != "login-login" || r.Message != "Invalid username or password." {
				t.Errorf("err = %v, want a refusal on login-login carrying the alert", err)
			}
			if strings.Join(res.PageIDs, ",") != "login-login,login-login" {
				t.Errorf("PageIDs = %v", res.PageIDs)
			}
		}},
		{"refused on login-error", scenario{afterPost: refusal("login-error", "")}, func(t *testing.T, _ Result, err error) {
			var r *RefusedError
			if !errors.As(err, &r) || r.PageID != "login-error" || !strings.Contains(r.Message, "Ask another administrator") {
				t.Errorf("err = %v, want a refusal on login-error carrying its sentence", err)
			}
		}},
		{"never redirects", scenario{afterPost: func(w http.ResponseWriter, r *http.Request, _ string) {
			http.Redirect(w, r, "/loop", http.StatusFound)
		}}, func(t *testing.T, _ Result, err error) {
			if !errors.Is(err, ErrNoRedirect) {
				t.Errorf("err = %v, want ErrNoRedirect", err)
			}
		}},
		{"token error", scenario{afterPost: redirectWithCode, tokenAnswer: func(w http.ResponseWriter, _ string) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"Code not valid `+sentinelCode+`"}`)
		}}, func(t *testing.T, _ Result, err error) {
			var te *TokenError
			if !errors.As(err, &te) || te.Status != 400 || te.OAuthError != "invalid_grant" {
				t.Errorf("err = %v, want a TokenError 400 invalid_grant", err)
			}
			if strings.Contains(err.Error(), "Code not valid") {
				t.Errorf("err = %v repeats the body beyond the error code", err)
			}
		}},
		{"nonce mismatch", scenario{afterPost: redirectWithCode, tokenAnswer: func(w http.ResponseWriter, _ string) {
			goodToken(issuer)(w, "another-nonce")
		}}, func(t *testing.T, _ Result, err error) {
			if !errors.Is(err, ErrNonceMismatch) {
				t.Errorf("err = %v, want ErrNonceMismatch", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log, rec := logkittest.New()
			if tc.sc.tokenAnswer == nil {
				tc.sc.tokenAnswer = func(w http.ResponseWriter, nonce string) { goodToken(issuer)(w, nonce) }
			}
			f := newFake(t, tc.sc)
			issuer = f.srv.URL + "/realms/harness"
			pw := secret.New([]byte(fakePW))
			res, err := newClient(t, f, log).PasswordCodeFlow(t.Context(), "harness-user", pw)
			tc.check(t, res, err)
			if f.postedPassword != fakePW {
				t.Errorf("posted password = %q, want the sentinel", f.postedPassword)
			}
			if len(rec.AtLevel(slog.LevelDebug)) == 0 {
				t.Error("no DEBUG page record: the scan below would prove nothing")
			}
			for _, s := range []string{fakePW, sentinelCode, fakeTok} {
				if strings.Contains(rec.Text(), s) {
					t.Errorf("a record holds %q:\n%s", s, rec.Text())
				}
				if err != nil && strings.Contains(err.Error(), s) {
					t.Errorf("the error holds %q: %v", s, err)
				}
				if strings.Contains(fmt.Sprintf("%+v", res), s) {
					t.Errorf("the Result holds %q", s)
				}
			}
		})
	}
}

// TC-966-08: two calls on one Client share no cookies: the second
// authorization request carries none.
func TestPasswordCodeFlow_FreshJarPerCall(t *testing.T) {
	var f *fakeKeycloak
	f = newFake(t, scenario{afterPost: redirectWithCode, tokenAnswer: func(w http.ResponseWriter, nonce string) {
		goodToken(f.srv.URL+"/realms/harness")(w, nonce)
	}})
	c := newClient(t, f, slog.New(slog.DiscardHandler))
	for range 2 {
		if _, err := c.PasswordCodeFlow(t.Context(), "harness-user", secret.New([]byte(fakePW))); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.authCookies) != 2 || f.authCookies[0] != 0 || f.authCookies[1] != 0 {
		t.Errorf("cookies on the authorization requests = %v, want none on either", f.authCookies)
	}
}

// TC-966-06: signin.New refuses each missing field, naming it.
func TestNew_RefusesIncompleteConfig(t *testing.T) {
	full := func() Config {
		return Config{Transport: http.DefaultTransport, Issuer: "https://x/realms/r", ClientID: "c",
			RedirectURI: "https://x/cb", Rand: rand.Reader, Logger: slog.New(slog.DiscardHandler)}
	}
	for field, clear := range map[string]func(*Config){
		"Transport":   func(c *Config) { c.Transport = nil },
		"Issuer":      func(c *Config) { c.Issuer = "" },
		"ClientID":    func(c *Config) { c.ClientID = "" },
		"RedirectURI": func(c *Config) { c.RedirectURI = "" },
		"Rand":        func(c *Config) { c.Rand = nil },
		"Logger":      func(c *Config) { c.Logger = nil },
	} {
		cfg := full()
		clear(&cfg)
		if c, err := New(cfg); c != nil || err == nil || !strings.Contains(err.Error(), "Config."+field) {
			t.Errorf("New without %s = %v, %v; want an error naming it", field, c, err)
		}
	}
	if _, err := New(full()); err != nil {
		t.Errorf("New with every field = %v", err)
	}
}

// The flow reports a reader that fails before any request.
func TestPasswordCodeFlow_RandFails(t *testing.T) {
	errX := errors.New("no entropy")
	c, err := New(Config{Transport: http.DefaultTransport, Issuer: "https://127.0.0.1:1/realms/r", ClientID: "c",
		RedirectURI: redirectURI, Rand: iotest.ErrReader(errX), Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PasswordCodeFlow(t.Context(), "u", secret.New([]byte("p"))); !errors.Is(err, errX) {
		t.Errorf("PasswordCodeFlow = %v, want the reader's error", err)
	}
}

// idTokenClaims takes aud as a string or an array and refuses a token that is
// not three parts.
func TestIDTokenClaims(t *testing.T) {
	c, err := idTokenClaims(idToken(map[string]any{"iss": "i", "sub": "s", "aud": []string{"a", "b"}, "nonce": "n"}))
	if err != nil || strings.Join(c.Aud, ",") != "a,b" {
		t.Errorf("array aud = %+v, %v", c, err)
	}
	if _, err := idTokenClaims("one.two"); err == nil {
		t.Error("a two-part token was accepted")
	}
	if _, err := idTokenClaims("a.!!!.c"); err == nil {
		t.Error("an undecodable payload was accepted")
	}
}
