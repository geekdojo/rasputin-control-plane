package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
)

// switchClock is a clock-sync fact a test turns on and off.
type switchClock struct{ synced atomic.Bool }

func (c *switchClock) Synced(context.Context) bool { return c.synced.Load() }

// methodRoute is the api fixture with a sign-in installed, as main wires it,
// over a clock-sync fact that holds until the test turns it off.
func methodRoute(t *testing.T, f *apiFixture) *switchClock {
	t.Helper()
	table, err := doors.New("ci")
	if err != nil {
		t.Fatal(err)
	}
	clock := &switchClock{}
	clock.synced.Store(true)
	si, err := auth.NewSignIn(auth.SignInDeps{Door: table.Home, ConsoleHost: "ci.local", ClientID: flows.ConsoleClient, Realm: "rasputin",
		Exchanger: unusedExchange{}, Verifier: unusedTokens{}, Ender: unusedEnder{}, Ready: readyNow{}, Sessions: f.sessions,
		FirstRun: f.authSvc, Claimer: unusedClaimer{}, Observer: unusedObserver{},
		Actions: map[string]auth.Action{}, Clock: clock, Now: time.Now, Rand: rand.Reader, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	f.authSvc.SetSignIn(si)
	return clock
}

func postMethod(f *apiFixture, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "https://ci.local/api/me/sign-in-methods", strings.NewReader(body))
	req.Host = "ci.local"
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	return w
}

// pendingOf is the pending cookie a response set, or nil.
func pendingOf(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if strings.Contains(c.Name, "pending") && c.Value != "" {
			return c
		}
	}
	return nil
}

// TC-1150-12: the self route's boundary. A role-less person's valid body
// answers 200 with next and sets the pending cookie; every refusal is its
// code and sentence with a correlation id and one WARN record carrying it,
// the route, the code and the cause, holds nothing, and no record or
// response carries the body.
func TestAddSignInMethod_TC1150_12(t *testing.T) {
	const (
		msgBody  = "The request body must be a JSON object with one string field, method."
		msgClock = "Authenticator apps can be added once Rasputin's clock is set. Add a passkey or security key now, or try again later."
		sentinel = "BODY-SENTINEL-1150"
	)
	f := newAPIFixture(t)
	clock := methodRoute(t, f)
	none := f.authenticateAs(t, "sub-alice-1150", "alice")

	w := postMethod(f, `{"method":"passkey"}`, none)
	var ok struct {
		Next string `json:"next"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &ok) != nil || ok.Next != "/api/auth/signin?action=add_passkey" {
		t.Fatalf("passkey: %d %s", w.Code, w.Body.String())
	}
	if pendingOf(w) == nil {
		t.Error("passkey: no pending cookie")
	}

	cases := []struct {
		name, body   string
		status       int
		code, msg    string
		cause        string
		clockSynced  bool
		noSignInRoot bool
	}{
		{"invalid JSON", `{"method":`, 400, codeInvalidRequest, msgBody, "body", true, false},
		{"empty object", `{}`, 400, codeInvalidRequest, msgBody, "body", true, false},
		{"null method", `{"method":null}`, 400, codeInvalidRequest, msgBody, "body", true, false},
		{"number method", `{"method":1}`, 400, codeInvalidRequest, msgBody, "body", true, false},
		{"another account", `{"method":"passkey","accountId":"` + sentinel + `"}`, 400, codeInvalidRequest, msgBody, "body", true, false},
		{"over 1 KiB", `{"method":"` + sentinel + strings.Repeat("a", 1100) + `"}`, 400, codeInvalidRequest, msgBody, "body", true, false},
		{"unknown method", `{"method":"` + sentinel + `"}`, 400, codeUnknownMethod, "Choose a passkey, a security key, an authenticator app or recovery codes.", "unknown_method", true, false},
		{"clock not set", `{"method":"authenticator_app"}`, 409, codeClockNotSet, msgClock, "authenticator_app", false, false},
		{"no sign-in", `{"method":"passkey"}`, 503, codeIdentityNotReady, "The sign-in service isn't ready, so nothing was started. Try again.", "no_signin", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, cookie := f, none
			if c.noSignInRoot {
				g = newAPIFixture(t)
				cookie = g.authenticateAs(t, "sub-alice-1150", "alice")
			}
			clock.synced.Store(c.clockSynced)
			defer clock.synced.Store(true)
			before := len(g.records(slog.LevelWarn, "api: request refused"))
			w := postMethod(g, c.body, cookie)
			e := coded(t, w)
			if w.Code != c.status || e.Code != c.code || e.Error != c.msg || e.CorrelationID == "" {
				t.Fatalf("%d %+v, want %d %s %q", w.Code, e, c.status, c.code, c.msg)
			}
			if pendingOf(w) != nil {
				t.Error("a refusal set the pending cookie")
			}
			recs := g.records(slog.LevelWarn, "api: request refused")[before:]
			if len(recs) != 1 {
				t.Fatalf("%d refusal records, want 1", len(recs))
			}
			if a := attrs(recs[0]); a["correlation_id"] != e.CorrelationID || a["route"] != "POST /api/me/sign-in-methods" ||
				a["code"] != c.code || a["cause"] != c.cause {
				t.Errorf("refusal attrs %v", a)
			}
			if strings.Contains(w.Body.String(), sentinel) {
				t.Errorf("the response echoes the body: %s", w.Body.String())
			}
			g.logs.mu.Lock()
			all := append([]slog.Record(nil), g.logs.recs...)
			g.logs.mu.Unlock()
			for _, r := range all {
				if text := r.Message + fmt.Sprint(attrs(r)); strings.Contains(text, sentinel) {
					t.Errorf("a log record holds the body: %s", text)
				}
			}
		})
	}
}

// TC-1150-13 (the idorProbes entry): the record PrepareMethod holds is bound
// to the caller. Alice POSTs; Bob, with his own session and Alice's pending
// cookie, follows next and is sent to the action-failed sentence, not the
// door. Alice's body naming Bob's account is refused 400, holding nothing.
func probeSignInMethodsIDOR(t *testing.T) {
	f := newAPIFixture(t)
	methodRoute(t, f)
	alice := f.authenticateAs(t, "sub-alice-6d2e", "alice-name")
	bob := f.authenticateAs(t, "sub-bob-0c4a", "bob-name-8e1f")
	w := postMethod(f, `{"method":"passkey"}`, alice)
	var ans struct {
		Next string `json:"next"`
	}
	pending := pendingOf(w)
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &ans) != nil || pending == nil {
		t.Fatalf("Alice's POST: %d %s", w.Code, w.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "https://ci.local"+ans.Next, nil)
	req.Host = "ci.local"
	req.AddCookie(bob)
	req.AddCookie(pending)
	g := httptest.NewRecorder()
	f.handler.ServeHTTP(g, req)
	if loc := g.Header().Get("Location"); g.Code != http.StatusSeeOther || loc != "/login?signin=action-failed" {
		t.Errorf("Bob following Alice's next: %d %q, want 303 to the action-failed sentence", g.Code, loc)
	}
	if w := postMethod(f, `{"method":"passkey","accountId":"sub-bob-0c4a"}`, alice); w.Code != http.StatusBadRequest || pendingOf(w) != nil {
		t.Errorf("Alice naming Bob's account: %d, want 400 holding nothing", w.Code)
	}
	if w := postMethod(f, `{"method":"passkey"}`); w.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", w.Code)
	}
}
