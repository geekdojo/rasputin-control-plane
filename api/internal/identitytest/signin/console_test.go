package signin

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

// fakeConsole is a console and its door on one test server: /api/auth/signin
// redirects to the door's login page (#959's fixture), the posted form
// returns to /api/auth/callback, which sets the session cookie and answers
// /login, or /login?signin=<refuse> when refuse is set.
func fakeConsole(t *testing.T, refuse string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/auth/signin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/realms/rasputin/protocol/openid-connect/auth?client_id=rasputin-console", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /realms/rasputin/protocol/openid-connect/auth", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(strings.ReplaceAll(fixture(t, "login-login"), fixtureOrigin, srv.URL)))
	})
	mux.HandleFunc("POST /realms/rasputin/login-actions/authenticate", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("username") != "fixture" || r.PostForm.Get("password") != fakePW {
			t.Errorf("posted %q", r.PostForm.Get("username"))
		}
		http.Redirect(w, r, "/api/auth/callback?code=c&state=s&iss=x", http.StatusFound)
	})
	mux.HandleFunc("GET /api/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		if refuse != "" {
			http.Redirect(w, r, "/login?signin="+refuse, http.StatusSeeOther)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "__Host-rasputin-session", Value: "console-cookie", Path: "/", Secure: true, HttpOnly: true})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// ConsoleSignIn follows the launcher's route through the door's page to the
// console's callback, and returns the jar holding the console session; a
// return to the launcher with a reason is a ConsoleRefusedError.
func TestConsoleSignIn(t *testing.T) {
	srv := fakeConsole(t, "")
	pw := secret.New([]byte(fakePW))
	defer pw.Destroy()
	c := Console{Origin: srv.URL, Transport: srv.Client().Transport, Logger: slog.New(slog.DiscardHandler)}
	jar, pages, err := ConsoleSignIn(t.Context(), c, "fixture", pw)
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 1 || pages[0] != "login-login" {
		t.Errorf("pages %v", pages)
	}
	u := mustParse(t, srv.URL)
	var got string
	for _, ck := range jar.Cookies(u) {
		if ck.Name == "__Host-rasputin-session" {
			got = ck.Value
		}
	}
	if got != "console-cookie" {
		t.Errorf("the jar holds %q, want the console session", got)
	}

	refused := fakeConsole(t, "failed")
	c.Origin, c.Transport = refused.URL, refused.Client().Transport
	var ce *ConsoleRefusedError
	if _, _, err := ConsoleSignIn(t.Context(), c, "fixture", pw); !errors.As(err, &ce) || ce.Reason != "failed" {
		t.Errorf("a refused sign-in: %v", err)
	}
	if _, _, err := ConsoleSignIn(t.Context(), Console{}, "fixture", pw); err == nil {
		t.Error("an empty Console was accepted")
	}
}

func mustParse(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// Steps answers the pages after the sign-in form: here the authenticator
// code page, whose form is posted with the page's own fields and the code;
// without Steps that page is an UnexpectedPageError, and a form Steps names
// that the page lacks is an error (geekdojo/geekdojo-brain#321).
func TestConsoleSignIn_Steps(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/auth/signin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/realms/rasputin/protocol/openid-connect/auth?client_id=rasputin-console", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /realms/rasputin/protocol/openid-connect/auth", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.ReplaceAll(fixture(t, "login-login"), fixtureOrigin, srv.URL)))
	})
	mux.HandleFunc("POST /realms/rasputin/login-actions/authenticate", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("password") != "" {
			_, _ = w.Write([]byte(strings.ReplaceAll(fixture(t, "login-login-otp"), fixtureOrigin, srv.URL)))
			return
		}
		if r.PostForm.Get("otp") != "123456" {
			t.Errorf("posted otp %q", r.PostForm.Get("otp"))
		}
		http.Redirect(w, r, "/api/auth/callback", http.StatusFound)
	})
	mux.HandleFunc("GET /api/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "__Host-rasputin-session", Value: "admin-cookie", Path: "/", Secure: true, HttpOnly: true})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	pw := secret.New([]byte(fakePW))
	defer pw.Destroy()
	c := Console{Origin: srv.URL, Transport: srv.Client().Transport, Logger: slog.New(slog.DiscardHandler),
		Steps: func(p Page, body []byte) (string, map[string]string, error) {
			if p.ID != "login-login-otp" || len(body) == 0 {
				return "", nil, errors.New("unexpected page " + p.ID)
			}
			return "kc-otp-login-form", map[string]string{"otp": "123456"}, nil
		}}
	_, pages, err := ConsoleSignIn(t.Context(), c, "fixture", pw)
	if err != nil || strings.Join(pages, ",") != "login-login,login-login-otp" {
		t.Fatalf("pages %v: %v", pages, err)
	}
	c.Steps = func(Page, []byte) (string, map[string]string, error) { return "no-such-form", nil, nil }
	if _, _, err := ConsoleSignIn(t.Context(), c, "fixture", pw); err == nil {
		t.Error("a form the page lacks was posted")
	}
	c.Steps = nil
	var ue *UnexpectedPageError
	if _, _, err := ConsoleSignIn(t.Context(), c, "fixture", pw); !errors.As(err, &ue) {
		t.Errorf("without Steps: %v", err)
	}
}
