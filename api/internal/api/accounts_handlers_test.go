package api

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth/idtoken"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/pwpolicy"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The reset route's collaborators that are not under test: the account
// read and the sign-in's identity calls, which a POST never reaches.
type resetAccounts map[string]accounts.Person

func (a resetAccounts) Read(_ context.Context, sub string) (accounts.Person, error) {
	p, ok := a[sub]
	if !ok {
		return accounts.Person{}, &idclient.Error{Op: "admin", Status: 404, Kind: idclient.ErrNotFound}
	}
	return p, nil
}

type unusedExchange struct{}

func (unusedExchange) ExchangeCode(context.Context, idclient.CodeExchange) (secret.Value, error) {
	return secret.Value{}, errors.New("unused")
}

type unusedTokens struct{}

func (unusedTokens) IDToken(context.Context, secret.Value) (idtoken.Claims, error) {
	return idtoken.Claims{}, errors.New("unused")
}
func (unusedTokens) LogoutToken(context.Context, secret.Value) (string, error) {
	return "", errors.New("unused")
}

type unusedEnder struct{}

func (unusedEnder) EndSession(context.Context, string) error { return nil }

type readyNow struct{}

func (readyNow) Ready(context.Context) error { return nil }

type noopAction struct{}

func (noopAction) Run(context.Context, auth.Principal, auth.ActionPayload) (string, error) {
	return "/", nil
}

// resetRoute is the api fixture with a sign-in installed (so PrepareAction
// can hold) and the reset's real Resetter over a staged deny list.
func resetRoute(t *testing.T, listed bool) (*apiFixture, string) {
	t.Helper()
	f := newAPIFixture(t)
	table, err := doors.New("ci")
	if err != nil {
		t.Fatal(err)
	}
	si, err := auth.NewSignIn(auth.SignInDeps{Door: table.Home, ConsoleHost: "ci.local", ClientID: flows.ConsoleClient, Realm: "rasputin",
		Exchanger: unusedExchange{}, Verifier: unusedTokens{}, Ender: unusedEnder{}, Ready: readyNow{}, Sessions: f.sessions,
		FirstRun: f.authSvc, Claimer: unusedClaimer{}, Observer: unusedObserver{},
		Actions: map[string]auth.Action{accounts.ResetKind: noopAction{}}, Clock: syncedClock{}, Now: time.Now, Rand: rand.Reader, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	f.authSvc.SetSignIn(si)
	dir := t.TempDir()
	if listed {
		if err := os.WriteFile(filepath.Join(dir, flows.DenylistFile), []byte("correcthorsebatterystaple\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	checker, err := pwpolicy.New(dir, flows.PasswordPolicy)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := authz.NewKindPolicy(noAppFacts{})
	if err != nil {
		t.Fatal(err)
	}
	rs, err := accounts.NewResetter(accounts.ResetterDeps{Authorizer: kp, Checker: checker, Log: f.srv.log,
		Users: resetAccounts{"sub-bob": {Username: "bob-longname", Email: "bob@example.org", Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetResetter(rs)
	return f, dir
}

func postReset(f *apiFixture, target, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/accounts/"+target+"/reset-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	return w
}

// TC-992-18: the admin route's answers, each with nothing submitted and
// nothing held (no pending cookie set); a valid request answers the fresh
// sign-in's start.
func TestResetPassword_TC992_18(t *testing.T) {
	const good = `{"password":"a long unlisted passphrase"}`
	f, _ := resetRoute(t, true)
	admin := f.authenticateAs(t, "sub-alice", "alice", "admin")
	held := func(w *httptest.ResponseRecorder) bool {
		return strings.Contains(w.Header().Get("Set-Cookie"), "pending")
	}
	jobsNow := func() int {
		js, err := f.jobsStore.ListJobs(f.ctx, 100)
		if err != nil {
			t.Fatal(err)
		}
		return len(js)
	}
	before := jobsNow()
	cases := []struct {
		name, target, body string
		cookie             *http.Cookie
		status             int
		code, msg          string
	}{
		{"no session", "sub-bob", good, nil, 401, "", ""},
		{"own account", "sub-alice", good, admin, 403, "job_own_account", ""},
		{"operator", "sub-bob", good, f.authenticateAs(t, "sub-op", "op", "operator"), 403, "route_not_permitted", ""},
		{"viewer", "sub-bob", good, f.authenticateAs(t, "sub-v", "v", "viewer"), 403, "route_not_permitted", ""},
		{"no account", "sub-nobody", good, admin, 404, "account_not_found", "That account doesn't exist."},
		{"short", "sub-bob", `{"password":"short"}`, admin, 400, "password_refused", "Use at least 15 characters."},
		{"listed", "sub-bob", `{"password":"CorrectHorseBatteryStaple"}`, admin, 400, "password_refused", "That password is too common. Choose another."},
		{"no body", "sub-bob", `{}`, admin, 400, "invalid_request", ""},
	}
	for _, c := range cases {
		w := postReset(f, c.target, c.body, c.cookie)
		if w.Code != c.status || held(w) {
			t.Errorf("%s: %d %s (held %v), want %d", c.name, w.Code, w.Body.String(), held(w), c.status)
			continue
		}
		if c.code != "" {
			e := coded(t, w)
			if e.Code != c.code || e.CorrelationID == "" || (c.msg != "" && e.Error != c.msg) {
				t.Errorf("%s: %+v, want %s %q", c.name, e, c.code, c.msg)
			}
		}
	}
	w := postReset(f, "sub-bob", good, admin)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"next":"/api/auth/signin?action=accounts.reset_password"}` || !held(w) {
		t.Errorf("valid: %d %s", w.Code, w.Body.String())
	}
	if n := jobsNow(); n != before {
		t.Errorf("%d jobs submitted, want none before the fresh sign-in", n-before)
	}
	for _, r := range f.logs.recs {
		text := r.Message
		r.Attrs(func(a slog.Attr) bool { text += " " + a.Value.String(); return true })
		if strings.Contains(text, "a long unlisted passphrase") || strings.Contains(text, "CorrectHorse") {
			t.Errorf("a log record holds the password: %s", text)
		}
	}

	t.Run("list unreadable", func(t *testing.T) {
		f, _ := resetRoute(t, false) // the list was never staged
		w := postReset(f, "sub-bob", good, f.authenticateAs(t, "sub-alice", "alice", "admin"))
		if e := coded(t, w); w.Code != 503 || e.Code != "password_check_unavailable" ||
			e.Error != "Rasputin can't check passwords right now, so the reset wasn't started." || held(w) {
			t.Errorf("%d %+v", w.Code, e)
		}
		if recs := f.logs.withAttr("event", "pwpolicy.list_unreadable"); len(recs) != 1 || recs[0].Level != slog.LevelError {
			t.Errorf("%d pwpolicy.list_unreadable records", len(recs))
		}
	})
	t.Run("unset", func(t *testing.T) {
		f := newAPIFixture(t)
		w := postReset(f, "sub-bob", good, f.authenticateAs(t, "sub-alice", "alice", "admin"))
		if e := coded(t, w); w.Code != 503 || e.Code != "identity_not_ready" {
			t.Errorf("%d %+v", w.Code, e)
		}
	})
}

// unusedClaimer and unusedObserver are the first-run claim's collaborators
// (geekdojo/geekdojo-brain#990), which no reset case reaches.
type unusedClaimer struct{}

func (unusedClaimer) Earliest(context.Context) (string, error) { return "", errors.New("unused") }

// syncedClock is a clock-sync fact that holds.
type syncedClock struct{}

func (syncedClock) Synced(context.Context) bool { return true }

type unusedObserver struct{}

func (unusedObserver) SignedIn(context.Context, string) {}
