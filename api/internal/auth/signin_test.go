package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-989-01: Begin stores one record and sends the browser to the home
// door's authorization endpoint with every parameter the flow needs, and
// sets the pending cookie.
func TestSignIn_Begin(t *testing.T) {
	r := newSigninRig(t)
	b := r.begin(t)
	if got := b.loc.Scheme + "://" + b.loc.Host + b.loc.Path; got != r.door.Issuer+"/protocol/openid-connect/auth" {
		t.Errorf("Location = %s, want the home door's auth endpoint", got)
	}
	want := map[string]string{
		"response_type": "code", "client_id": "rasputin-console", "redirect_uri": "https://ci.local/api/auth/callback",
		"scope": "openid", "code_challenge_method": "S256", "prompt": "login",
	}
	for k, v := range want {
		if got := b.q[k]; len(got) != 1 || got[0] != v {
			t.Errorf("%s = %v, want exactly %q", k, got, v)
		}
	}
	for _, k := range []string{"state", "nonce", "code_challenge"} {
		if len(b.q.Get(k)) < 43 {
			t.Errorf("%s = %q, want 32 random bytes", k, b.q.Get(k))
		}
	}
	if r.si.pending.size() != 1 {
		t.Fatalf("records = %d, want 1", r.si.pending.size())
	}
	rec := r.si.pending.m[b.pending.Value]
	sum := sha256.Sum256(rec.verifier.Reveal())
	if base64.RawURLEncoding.EncodeToString(sum[:]) != b.q.Get("code_challenge") || rec.state != b.q.Get("state") ||
		rec.nonce != b.q.Get("nonce") || !rec.begin.Equal(r.f.clock.Now()) {
		t.Errorf("the record does not match the request: %+v", rec)
	}
	c := b.pending
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
		t.Errorf("pending cookie %+v is not a __Host- Lax cookie", c)
	}
}

// TC-989-02: a sign-in begun at any name but the console's is sent to the
// launcher's wrong-host sentence with no record, no cookie and no log.
func TestSignIn_BeginWrongHost(t *testing.T) {
	r := newSigninRig(t)
	for _, host := range []string{"127.0.0.1", "[::1]", "localhost", "ci", "other.local", "sso-ci.local", "ci.local:8443"} {
		w := r.get("/api/auth/signin", host)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?signin=wrong-host" {
			t.Errorf("%s: %d %s, want 303 to wrong-host", host, w.Code, w.Header().Get("Location"))
		}
		if len(w.Result().Cookies()) != 0 {
			t.Errorf("%s: set %v", host, w.Result().Cookies())
		}
	}
	if r.si.pending.size() != 0 || len(r.log.Records()) != 0 {
		t.Errorf("records %d, log %q; want none", r.si.pending.size(), r.log.Text())
	}
}

// TC-989-03 (auth part): with no sign-in installed, /api/auth/signin is
// unavailable, status says ready:false and a gated route answers 401.
func TestSignIn_NotInstalled(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	w := get(h, "/api/auth/signin")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?signin=unavailable" {
		t.Errorf("signin: %d %s", w.Code, w.Header().Get("Location"))
	}
	w = get(h, "/api/auth/callback?code=x&state=y")
	if w.Header().Get("Location") != "/login?signin=unavailable" {
		t.Errorf("callback: %d %s", w.Code, w.Header().Get("Location"))
	}
	if st := status(t, h); st["ready"] != false {
		t.Errorf("status = %v, want ready:false", st)
	}
	gated := f.svc.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	if w := get(gated, "/api/nodes"); w.Code != http.StatusUnauthorized {
		t.Errorf("gated route: %d, want 401", w.Code)
	}
}

// TC-989-04: a wrong, repeated or missing state or code is refused, the
// record consumed, nothing minted, one WARN reason=state.
func TestSignIn_CallbackState(t *testing.T) {
	for name, edit := range map[string]func(url.Values){
		"wrong state":    func(q url.Values) { q.Set("state", "not-the-state") },
		"repeated state": func(q url.Values) { q.Add("state", q.Get("state")) },
		"repeated code":  func(q url.Values) { q.Add("code", "code-2") },
		"no code":        func(q url.Values) { q.Del("code") },
	} {
		t.Run(name, func(t *testing.T) {
			r := newSigninRig(t)
			b := r.begin(t)
			q := r.callbackQuery(b, "code-1")
			edit(q)
			w := r.callback(q, b.pending)
			assertRefused(t, r, w, "/login?signin=failed")
			if got := r.refusals(); !slices.Equal(got, []string{"state"}) {
				t.Errorf("refusals = %v, want [state]", got)
			}
			if r.si.pending.size() != 0 {
				t.Error("the record was not consumed")
			}
		})
	}
}

// assertRefused checks a callback answered 303 to loc and minted nothing.
func assertRefused(t *testing.T, r *signinRig, w interface {
	Result() *http.Response
}, loc string) {
	t.Helper()
	res := w.Result()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != loc {
		t.Errorf("answer %d %s, want 303 %s", res.StatusCode, res.Header.Get("Location"), loc)
	}
	for _, c := range res.Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			t.Error("a refused callback set a session cookie")
		}
	}
	if n := r.f.countRows(t, "console_sessions"); n != 0 {
		t.Errorf("%d session rows, want 0", n)
	}
}

// TC-989-05: the RFC 9207 iss parameter must be the home door's issuer;
// absent, the app door's or anything else is refused before any exchange.
func TestSignIn_CallbackIssParameter(t *testing.T) {
	r0 := newSigninRig(t)
	for name, iss := range map[string]*string{"absent": nil, "app door": ptrTo(r0.app.Issuer), "other": ptrTo("https://evil.example/realms/rasputin"),
		"trailing slash": ptrTo(r0.door.Issuer + "/")} {
		t.Run(name, func(t *testing.T) {
			r := newSigninRig(t)
			b := r.begin(t)
			q := r.callbackQuery(b, "code-1")
			q.Del("iss")
			if iss != nil {
				q.Set("iss", *iss)
			}
			assertRefused(t, r, r.callback(q, b.pending), "/login?signin=failed")
			if r.ex.calls != 0 {
				t.Errorf("exchanged %d times, want 0", r.ex.calls)
			}
			if got := r.refusals(); !slices.Equal(got, []string{"iss"}) {
				t.Errorf("refusals = %v", got)
			}
		})
	}
}

func ptrTo(s string) *string { return &s }

// TC-989-06: an ID token signed by a key the issuer does not publish is
// refused by the real go-oidc verifier, and no row is written.
func TestSignIn_CallbackSignature(t *testing.T) {
	r := newSigninRig(t)
	b := r.begin(t)
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	r.ex.set(signWith(t, stranger, "kid-a", r.idClaims(b)), nil)
	assertRefused(t, r, r.callback(r.callbackQuery(b, "code-1"), b.pending), "/login?signin=failed")
	if got := r.refusals(); !slices.Equal(got, []string{"token"}) {
		t.Errorf("refusals = %v", got)
	}
}

// TC-989-07 (issue TC-01): an ID token from the app door's issuer never
// becomes a console session.
func TestSignIn_CallbackIssuerIsolation(t *testing.T) {
	r := newSigninRig(t)
	w := r.signIn(t, func(c map[string]any) { c["iss"] = r.app.Issuer })
	assertRefused(t, r, w, "/login?signin=failed")
}

// TC-989-08 and TC-989-09: each of aud, azp, sid, sub, nonce and exp is
// checked.
func TestSignIn_CallbackClaims(t *testing.T) {
	for _, c := range []struct {
		tc, name, reason string
		edit             func(*signinRig, map[string]any)
	}{
		{"TC-989-08", "wrong aud", "token", func(_ *signinRig, c map[string]any) { c["aud"] = "rasputin-account" }},
		{"TC-989-08", "azp another client", "azp", func(_ *signinRig, c map[string]any) { c["azp"] = "rasputin-mesh" }},
		{"TC-989-08", "no azp", "azp", func(_ *signinRig, c map[string]any) { delete(c, "azp") }},
		{"TC-989-08", "missing sid", "sid", func(_ *signinRig, c map[string]any) { delete(c, "sid") }},
		{"TC-989-08", "missing sub", "token", func(_ *signinRig, c map[string]any) { delete(c, "sub") }},
		{"TC-989-09", "nonce differs", "nonce", func(_ *signinRig, c map[string]any) { c["nonce"] = "another-nonce" }},
		{"TC-989-09", "exp passed", "token", func(r *signinRig, c map[string]any) { c["exp"] = r.f.clock.Now().Add(-time.Second).Unix() }},
	} {
		t.Run(c.tc+" "+c.name, func(t *testing.T) {
			r := newSigninRig(t)
			w := r.signIn(t, func(m map[string]any) { c.edit(r, m) })
			assertRefused(t, r, w, "/login?signin=failed")
			if got := r.refusals(); len(got) != 1 || (got[0] != c.reason && !(c.name == "missing sub" && got[0] == "sub")) {
				t.Errorf("refusals = %v, want [%s]", got, c.reason)
			}
		})
	}
}

// TC-989-10 (issue TC-02): auth_time one second before the begin
// (truncated to the second) is refused; equal to it is accepted.
func TestSignIn_CallbackStaleAuthTime(t *testing.T) {
	r := newSigninRig(t)
	begin := r.f.clock.Now().Truncate(time.Second)
	w := r.signIn(t, func(c map[string]any) { c["auth_time"] = begin.Add(-time.Second).Unix() })
	assertRefused(t, r, w, "/login?signin=failed")
	if got := r.refusals(); !slices.Equal(got, []string{"auth_time"}) {
		t.Errorf("refusals = %v", got)
	}
	w = r.signIn(t, func(c map[string]any) { c["auth_time"] = begin.Unix() })
	if sessionFrom(w) == nil || w.Header().Get("Location") != "/login" {
		t.Errorf("auth_time equal to begin: %d %s, want a session", w.Code, w.Header().Get("Location"))
	}
	r2 := newSigninRig(t)
	assertRefused(t, r2, r2.signIn(t, func(c map[string]any) { delete(c, "auth_time") }), "/login?signin=failed")
}

// TC-989-11: a refused code or the door's error= is failed; an exchange or
// key fetch the service did not answer is unavailable, with one ERROR
// naming its kind. None mints a session.
func TestSignIn_CallbackExchangeFailures(t *testing.T) {
	t.Run("invalid_grant", func(t *testing.T) {
		r := newSigninRig(t)
		b := r.begin(t)
		r.ex.set("", invalidGrant())
		assertRefused(t, r, r.callback(r.callbackQuery(b, "spent"), b.pending), "/login?signin=failed")
		if got := r.refusals(); !slices.Equal(got, []string{"exchange"}) {
			t.Errorf("refusals = %v", got)
		}
	})
	t.Run("door error", func(t *testing.T) {
		r := newSigninRig(t)
		b := r.begin(t)
		q := url.Values{"error": {"access_denied"}, "state": {b.q.Get("state")}, "iss": {r.door.Issuer}}
		assertRefused(t, r, r.callback(q, b.pending), "/login?signin=failed")
		if r.ex.calls != 0 {
			t.Error("an error= return was exchanged")
		}
	})
	t.Run("exchange unreachable", func(t *testing.T) {
		r := newSigninRig(t)
		b := r.begin(t)
		r.ex.set("", unreachable())
		assertRefused(t, r, r.callback(r.callbackQuery(b, "c"), b.pending), "/login?signin=unavailable")
		recs := r.events("signin.exchange_failed")
		if len(recs) != 1 || recs[0].Level != slog.LevelError {
			t.Fatalf("records %v, want one ERROR", r.log.Text())
		}
		if k, _ := logkittest.Attr(recs[0], "kind"); k != "unreachable" {
			t.Errorf("kind = %q", k)
		}
	})
	t.Run("keys unreachable", func(t *testing.T) {
		r := newSigninRig(t)
		b := r.begin(t)
		r.is.down.Store(true)
		r.ex.set(r.is.sign(t, r.idClaims(b)), nil)
		assertRefused(t, r, r.callback(r.callbackQuery(b, "c"), b.pending), "/login?signin=unavailable")
		recs := r.events("signin.exchange_failed")
		if len(recs) != 1 || recs[0].Level != slog.LevelError {
			t.Fatalf("records %v, want one ERROR", r.log.Text())
		}
		if k, _ := logkittest.Attr(recs[0], "kind"); k != "keys" {
			t.Errorf("kind = %q", k)
		}
	})
}

// TC-989-12: no pending cookie, a cookie with no record, or a malformed one
// is sent to the expired sentence with no session.
func TestSignIn_CallbackNoRecord(t *testing.T) {
	for name, cookie := range map[string]*http.Cookie{
		"no cookie":    nil,
		"no record":    {Name: pendingCookieName, Value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"malformed":    {Name: pendingCookieName, Value: "%%%;not-a-key"},
		"empty value":  {Name: pendingCookieName, Value: ""},
		"legacy named": {Name: "rasputin-pending", Value: "x"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newSigninRig(t)
			b := r.begin(t)
			var cookies []*http.Cookie
			if cookie != nil {
				cookies = append(cookies, cookie)
			}
			assertRefused(t, r, r.callback(r.callbackQuery(b, "c"), cookies...), "/login?signin=expired")
			if r.ex.calls != 0 {
				t.Error("exchanged without a record")
			}
		})
	}
}

// TC-989-13: a valid return mints one session row holding sub, sid, roles,
// name and the cookie's hash, sets the cookie, answers 303 /login and runs
// the login hook once with preferred_username; a store error answers 500
// with ERROR and no cookie.
func TestSignIn_CallbackSuccess(t *testing.T) {
	r := newSigninRig(t)
	var hooked []string
	r.f.svc.SetLoginHook(func(_ context.Context, name string) error { hooked = append(hooked, name); return nil })
	w := r.signIn(t, nil)
	c := sessionFrom(w)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" || c == nil {
		t.Fatalf("answer %d %s cookie %v", w.Code, w.Header().Get("Location"), c)
	}
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" || c.MaxAge != int(sessionLifetime/time.Second) {
		t.Errorf("session cookie %+v", c)
	}
	var sub, sid, roles, name, hash string
	if err := r.f.store.db.QueryRow(`SELECT sub, sid, roles, name, token_hash FROM console_sessions`).Scan(&sub, &sid, &roles, &name, &hash); err != nil {
		t.Fatal(err)
	}
	if sub != rigSub || sid != rigSID || roles != `["admin"]` || name != "alice" || hash != hashOf(c.Value) {
		t.Errorf("row %q %q %q %q %q", sub, sid, roles, name, hash)
	}
	if !slices.Equal(hooked, []string{"alice"}) {
		t.Errorf("hook ran with %v, want [alice] once", hooked)
	}

	t.Run("store fault", func(t *testing.T) {
		r := newSigninRig(t)
		b := r.begin(t)
		r.ex.set(r.is.sign(t, r.idClaims(b)), nil)
		if _, err := r.f.store.db.Exec(`DROP TABLE console_sessions`); err != nil {
			t.Fatal(err)
		}
		w := r.callback(r.callbackQuery(b, "c"), b.pending)
		if w.Code != http.StatusInternalServerError || sessionFrom(w) != nil {
			t.Errorf("answer %d cookie %v, want 500 and none", w.Code, sessionFrom(w))
		}
		if recs := r.events("signin.store_failed"); len(recs) != 1 || recs[0].Level != slog.LevelError {
			t.Errorf("log %s", r.log.Text())
		}
	})
}

// TC-989-14: a fresh-sign-in action runs only for the person it began for,
// re-authenticated after it began, and mints no session; StartAction sends
// the browser into the same prompt=login round trip.
func TestSignIn_Action(t *testing.T) {
	start := func(t *testing.T, r *signinRig) begun {
		t.Helper()
		pending := r.prepare(t, rigSub, "test-action", nil)
		req := httptestRequest(rigConsole, "/settings/act")
		req.AddCookie(pending)
		req = req.WithContext(WithPrincipal(req.Context(), Principal{Sub: rigSub, Name: "alice"}))
		w := recorder()
		r.si.StartAction(w, req, "test-action")
		if w.Code != http.StatusSeeOther {
			t.Fatalf("StartAction: %d", w.Code)
		}
		loc, _ := url.Parse(w.Header().Get("Location"))
		if loc.Query().Get("prompt") != "login" || !strings.HasPrefix(loc.String(), r.door.Issuer+"/protocol/openid-connect/auth") {
			t.Errorf("StartAction Location %s", loc)
		}
		b := begun{q: loc.Query(), loc: loc}
		for _, c := range w.Result().Cookies() {
			if c.Name == pendingCookieName {
				b.pending = c
			}
		}
		return b
	}
	run := func(t *testing.T, r *signinRig, b begun, edit func(map[string]any)) *httptestRecorder {
		c := r.idClaims(b)
		edit(c)
		r.ex.set(r.is.sign(t, c), nil)
		return r.callback(r.callbackQuery(b, "c"), b.pending)
	}
	t.Run("another person", func(t *testing.T) {
		r := newSigninRig(t)
		w := run(t, r, start(t, r), func(c map[string]any) { c["sub"] = "someone-else" })
		// TC-1150-09: another person's return is the action-failed sentence.
		assertRefused(t, r, w, "/login?signin=action-failed")
		if r.action.count() != 0 {
			t.Error("the action ran for another person")
		}
	})
	t.Run("stale auth_time", func(t *testing.T) {
		r := newSigninRig(t)
		b := start(t, r)
		w := run(t, r, b, func(c map[string]any) { c["auth_time"] = r.f.clock.Now().Add(-time.Hour).Unix() })
		assertRefused(t, r, w, "/login?signin=failed")
		if r.action.count() != 0 {
			t.Error("the action ran on a stale sign-in")
		}
	})
	t.Run("same person, fresh", func(t *testing.T) {
		r := newSigninRig(t)
		w := run(t, r, start(t, r), func(map[string]any) {})
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/settings?done=1" || sessionFrom(w) != nil {
			t.Errorf("answer %d %s", w.Code, w.Header().Get("Location"))
		}
		if r.action.count() != 1 || r.f.countRows(t, "console_sessions") != 0 {
			t.Errorf("runs %d rows %d, want 1 and 0", r.action.count(), r.f.countRows(t, "console_sessions"))
		}
	})
	t.Run("unknown kind and no principal", func(t *testing.T) {
		r := newSigninRig(t)
		w := recorder()
		r.si.StartAction(w, httptestRequest(rigConsole, "/x"), "no-such")
		if w.Code != http.StatusNotFound {
			t.Errorf("unknown kind: %d", w.Code)
		}
		w = recorder()
		r.si.StartAction(w, httptestRequest(rigConsole, "/x"), "test-action")
		if w.Code != http.StatusUnauthorized {
			t.Errorf("no principal: %d", w.Code)
		}
	})
}

// TC-989-15: a record is consumed by its callback; a newer sign-in from the
// same cookie replaces it; it lives for signinPendingLifetime on the
// injected clock, which is at least the realm's page timeouts; at the cap
// the record closest to expiry goes.
func TestSignIn_PendingOrder(t *testing.T) {
	t.Run("consumed", func(t *testing.T) {
		r := newSigninRig(t)
		b := r.begin(t)
		r.ex.set(r.is.sign(t, r.idClaims(b)), nil)
		if w := r.callback(r.callbackQuery(b, "c"), b.pending); sessionFrom(w) == nil {
			t.Fatal("first callback minted nothing")
		}
		if w := r.callback(r.callbackQuery(b, "c"), b.pending); w.Header().Get("Location") != "/login?signin=expired" {
			t.Errorf("second callback: %s, want expired", w.Header().Get("Location"))
		}
	})
	t.Run("replaced", func(t *testing.T) {
		r := newSigninRig(t)
		old := r.begin(t)
		newer := r.begin(t, old.pending)
		if newer.pending.Value != old.pending.Value || r.si.pending.size() != 1 {
			t.Fatalf("a newer sign-in from the same cookie made a second record")
		}
		r.ex.set(r.is.sign(t, r.idClaims(old)), nil)
		assertRefused(t, r, r.callback(r.callbackQuery(old, "c"), old.pending), "/login?signin=failed")
		newer = r.begin(t, old.pending)
		r.ex.set(r.is.sign(t, r.idClaims(newer)), nil)
		if w := r.callback(r.callbackQuery(newer, "c"), newer.pending); sessionFrom(w) == nil {
			t.Errorf("the newer state was refused: %s", w.Header().Get("Location"))
		}
	})
	t.Run("lifetime", func(t *testing.T) {
		r := newSigninRig(t)
		b := r.begin(t)
		r.f.clock.Add(signinPendingLifetime - time.Nanosecond)
		if !r.si.pending.live(b.pending.Value) {
			t.Fatal("the record died before its lifetime")
		}
		r.f.clock.Add(time.Nanosecond)
		r.si.prune()
		if r.si.pending.size() != 0 {
			t.Fatal("the record outlived its lifetime")
		}
		realm := flows.Render(flows.Inputs{}).Realm
		for _, k := range []string{"accessCodeLifespanLogin", "accessCodeLifespanUserAction"} {
			secs, ok := realm[k].(int)
			if !ok {
				t.Fatalf("%s = %#v", k, realm[k])
			}
			if signinPendingLifetime < time.Duration(secs)*time.Second {
				t.Errorf("signinPendingLifetime %v < %s %ds", signinPendingLifetime, k, secs)
			}
		}
	})
	t.Run("cap", func(t *testing.T) {
		clock := newTestClock()
		p := newPendingSignins(clock.Now)
		p.put("first", &pendingSignin{begin: clock.Now()})
		clock.Add(time.Second)
		for i := 1; i < maxSigninPending; i++ {
			p.put("k"+string(rune(i)), &pendingSignin{begin: clock.Now()})
		}
		p.put("overflow", &pendingSignin{begin: clock.Now()})
		if p.size() != maxSigninPending || p.live("first") || !p.live("overflow") {
			t.Errorf("size %d, first live %v: want the cap and the oldest gone", p.size(), p.live("first"))
		}
	})
}

// TC-989-16 (issue TC-05): every console cookie is __Host- shaped; a
// duplicated cookie is a 400 with its code at the gate, the callback and
// the sign-in; IsOwnCookie and StripCookies drop all three names.
func TestCookies_ShapesAndDuplicates(t *testing.T) {
	w := recorder()
	setCookie(w, SessionCookieName, "v", time.Hour)
	setCookie(w, pendingCookieName, "v", time.Hour)
	clearCookie(w, SessionCookieName)
	for _, c := range w.Result().Cookies() {
		if !strings.HasPrefix(c.Name, "__Host-rasputin-") || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
			t.Errorf("cookie %+v is not a __Host- Lax cookie", c)
		}
	}
	r := newSigninRig(t)
	gated := r.f.svc.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	sess := consoleCookie(t, r.f, Principal{Sub: "a"})
	pend := &http.Cookie{Name: pendingCookieName, Value: "p"}
	for name, w := range map[string]*httptestRecorder{
		"gate":     serve(gated, rigConsole, "/api/nodes", sess, sess),
		"me":       serve(r.h, rigConsole, "/api/auth/me", sess, sess),
		"callback": serve(r.h, rigConsole, "/api/auth/callback?code=c&state=s", pend, pend),
		"signin":   serve(r.h, rigConsole, "/api/auth/signin", pend, pend),
	} {
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"error":"duplicate_cookie"`) || !strings.Contains(w.Body.String(), "more than once") {
			t.Errorf("%s: %d %s, want 400 duplicate_cookie with a sentence", name, w.Code, w.Body.String())
		}
	}
	h := http.Header{"Cookie": {SessionCookieName + "=a; " + pendingCookieName + "=b; " + "__Host-rasputin-ceremony" + "=c; grafana_session=g"}}
	StripCookies(h)
	if got := h.Get("Cookie"); got != "grafana_session=g" {
		t.Errorf("StripCookies left %q", got)
	}
	for _, n := range []string{SessionCookieName, pendingCookieName, "__Host-rasputin-ceremony"} {
		if !IsOwnCookie(n) {
			t.Errorf("IsOwnCookie(%s) = false", n)
		}
	}
}

// TC-989-25: no log record of any refusal class or a success holds the
// code, the state, the nonce, the verifier, a token, the cookie or the
// query string.
func TestSignIn_LogsCarryNoSecret(t *testing.T) {
	r := newSigninRig(t)
	var needles []string
	add := func(s ...string) { needles = append(needles, s...) }
	runOne := func(code string, edit func(map[string]any), q func(url.Values)) {
		b := r.begin(t)
		c := r.idClaims(b)
		if edit != nil {
			edit(c)
		}
		tok := r.is.sign(t, c)
		r.ex.set(tok, nil)
		qv := r.callbackQuery(b, code)
		if q != nil {
			q(qv)
		}
		w := r.callback(qv, b.pending)
		add(code, b.q.Get("state"), b.q.Get("nonce"), b.q.Get("code_challenge"), tok, b.pending.Value, qv.Encode(), r.ex.verif)
		if s := sessionFrom(w); s != nil {
			add(s.Value)
		}
	}
	runOne("code-success-1234567890", nil, nil)
	runOne("code-state-1234567890", nil, func(q url.Values) { q.Set("state", "wrong-state-0987654321") })
	runOne("code-iss-1234567890", nil, func(q url.Values) { q.Set("iss", "https://elsewhere") })
	runOne("code-nonce-1234567890", func(c map[string]any) { c["nonce"] = "nonce-0987654321-other" }, nil)
	runOne("code-azp-1234567890", func(c map[string]any) { c["azp"] = "other" }, nil)
	runOne("code-time-1234567890", func(c map[string]any) { c["auth_time"] = 1 }, nil)
	r.ex.err = invalidGrant()
	runOne("code-grant-1234567890", nil, nil)
	r.ex.err = unreachable()
	runOne("code-down-1234567890", nil, nil)
	text := r.log.Text()
	if len(r.log.Records()) < 8 {
		t.Fatalf("only %d records: the scan would prove nothing", len(r.log.Records()))
	}
	for _, n := range needles {
		if n != "" && strings.Contains(text, n) {
			t.Errorf("a log record holds %q", n)
		}
	}
}
