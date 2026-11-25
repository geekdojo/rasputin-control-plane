package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// The sign-in methods a person adds (geekdojo/geekdojo-brain#1150).

const bobSub = "0b6e2f4a-sub-bob"

// methodRequest is a request on the console's name signed in as sub, with
// cookies; sub "" carries no principal.
func methodRequest(sub, path string, cookies ...*http.Cookie) *http.Request {
	req := httptestRequest(rigConsole, path)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if sub != "" {
		req = req.WithContext(WithPrincipal(req.Context(), Principal{Sub: sub, Name: "n-" + sub}))
	}
	return req
}

// prepareMethod runs PrepareMethod for sub and returns next, the error and
// the pending cookie it set (nil when none).
func (r *signinRig) prepareMethod(sub string, m Method, cookies ...*http.Cookie) (string, error, *http.Cookie) {
	w := recorder()
	next, err := r.si.PrepareMethod(w, methodRequest(sub, "/api/me/sign-in-methods", cookies...), m)
	for _, c := range w.Result().Cookies() {
		if c.Name == pendingCookieName && c.Value != "" {
			return next, err, c
		}
	}
	return next, err, nil
}

// startMethod prepares m for sub and starts its fresh sign-in, and returns
// the begun sign-in.
func (r *signinRig) startMethod(t *testing.T, sub string, m Method) begun {
	t.Helper()
	next, err, pending := r.prepareMethod(sub, m)
	if err != nil || pending == nil {
		t.Fatalf("PrepareMethod(%s) = %q, %v", m, next, err)
	}
	w := recorder()
	r.si.StartAction(w, methodRequest(sub, next, pending), methods[m].kind)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("StartAction(%s): %d %s", m, w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	b := begun{q: loc.Query(), loc: loc}
	for _, c := range w.Result().Cookies() {
		if c.Name == pendingCookieName {
			b.pending = c
		}
	}
	if b.pending == nil {
		t.Fatal("StartAction set no pending cookie")
	}
	return b
}

// record is the record under the pending cookie c, or nil.
func (r *signinRig) record(c *http.Cookie) *pendingSignin {
	r.si.pending.mu.Lock()
	defer r.si.pending.mu.Unlock()
	return r.si.pending.m[c.Value]
}

// anyForwarded reports whether any record held carries the forwarded mark.
func (r *signinRig) anyForwarded() bool {
	r.si.pending.mu.Lock()
	defer r.si.pending.mu.Unlock()
	for _, rec := range r.si.pending.m {
		if rec.action != nil && rec.action.forwarded {
			return true
		}
	}
	return false
}

func consoleAction(action, state string) policy.ActionRequest {
	return policy.ActionRequest{Client: "rasputin-console", Action: action, State: state}
}

// TC-1150-01: the closed method set. The four methods map to their one kind
// and one Keycloak action; anything else is ErrUnknownMethod, and no entry
// removes a credential or changes a password.
func TestParseMethod_TC1150_01(t *testing.T) {
	want := map[string]methodSpec{
		"passkey":           {kind: "add_passkey", kcAction: flows.ActionPasskeyRegister},
		"security_key":      {kind: "add_security_key", kcAction: flows.ActionSecurityKey},
		"authenticator_app": {kind: "add_authenticator_app", kcAction: flows.ActionConfigureTOTP},
		"recovery_codes":    {kind: "add_recovery_codes", kcAction: flows.ActionRecoveryCodes},
	}
	if len(methods) != len(want) {
		t.Fatalf("%d methods, want %d", len(methods), len(want))
	}
	for name, spec := range want {
		m, err := ParseMethod(name)
		if err != nil || string(m) != name || methods[m] != spec {
			t.Errorf("ParseMethod(%q) = %q, %v, spec %+v; want %+v", name, m, err, methods[m], spec)
		}
	}
	for _, bad := range []string{"", "PASSKEY", "passkey ", "delete_credential", "update_password", "UPDATE_PASSWORD"} {
		if m, err := ParseMethod(bad); !errors.Is(err, ErrUnknownMethod) || m != "" {
			t.Errorf("ParseMethod(%q) = %q, %v; want ErrUnknownMethod", bad, m, err)
		}
	}
	for m, spec := range methods {
		for _, never := range []string{flows.ActionDeleteCredential, flows.ActionUpdatePassword} {
			if strings.EqualFold(spec.kcAction, never) {
				t.Errorf("%s runs %s", m, spec.kcAction)
			}
		}
	}
}

// TC-1150-02: PrepareMethod authorizes in the service: no principal, or the
// pending cookie twice, is ErrNoAction holding nothing; the Service with no
// sign-in installed refuses too; the record names the principal's sub.
func TestPrepareMethod_TC1150_02(t *testing.T) {
	r := newSigninRig(t)
	t.Run("no principal", func(t *testing.T) {
		before := r.si.pending.size()
		if _, err, c := r.prepareMethod("", MethodPasskey); !errors.Is(err, ErrNoAction) || c != nil || r.si.pending.size() != before {
			t.Errorf("err %v cookie %v size %d->%d", err, c, before, r.si.pending.size())
		}
	})
	t.Run("the pending cookie twice", func(t *testing.T) {
		before := r.si.pending.size()
		a := &http.Cookie{Name: pendingCookieName, Value: "one"}
		b := &http.Cookie{Name: pendingCookieName, Value: "two"}
		if _, err, c := r.prepareMethod(rigSub, MethodPasskey, a, b); !errors.Is(err, ErrNoAction) || c != nil || r.si.pending.size() != before {
			t.Errorf("err %v cookie %v size %d->%d", err, c, before, r.si.pending.size())
		}
	})
	t.Run("no sign-in installed", func(t *testing.T) {
		f := newAuthFixture(t)
		w := recorder()
		if _, err := f.svc.PrepareMethod(w, methodRequest(rigSub, "/api/me/sign-in-methods"), MethodPasskey); !errors.Is(err, ErrNoAction) ||
			len(w.Result().Cookies()) != 0 {
			t.Errorf("err %v cookies %v", err, w.Result().Cookies())
		}
	})
	t.Run("the principal's account", func(t *testing.T) {
		w := recorder()
		next, err := r.f.svc.PrepareMethod(w, methodRequest(rigSub, "/api/me/sign-in-methods"), MethodPasskey)
		if err != nil || next != "/api/auth/signin?action=add_passkey" {
			t.Fatalf("PrepareMethod = %q, %v", next, err)
		}
		var c *http.Cookie
		for _, ck := range w.Result().Cookies() {
			if ck.Name == pendingCookieName {
				c = ck
			}
		}
		rec := r.record(c)
		if rec == nil || !rec.prepared || rec.action.sub != rigSub || rec.action.method != MethodPasskey {
			t.Errorf("record %+v", rec)
		}
	})
}

// TC-1150-03: the clock rule at the route. With the fact off an
// authenticator app is ErrClockNotSet holding nothing, and the other three
// still prepare; with it on the authenticator app prepares with the
// caller's sub, its kind and CONFIGURE_TOTP.
func TestPrepareMethod_TC1150_03_Clock(t *testing.T) {
	r := newSigninRig(t)
	r.clock.synced.Store(false)
	before := r.si.pending.size()
	if _, err, c := r.prepareMethod(rigSub, MethodAuthenticatorApp); !errors.Is(err, ErrClockNotSet) || c != nil || r.si.pending.size() != before {
		t.Errorf("clock off: err %v cookie %v size %d->%d", err, c, before, r.si.pending.size())
	}
	for _, m := range []Method{MethodPasskey, MethodSecurityKey, MethodRecoveryCodes} {
		if _, err, c := r.prepareMethod(rigSub, m); err != nil || c == nil {
			t.Errorf("clock off: %s: %v %v", m, err, c)
		}
	}
	r.clock.synced.Store(true)
	next, err, c := r.prepareMethod(rigSub, MethodAuthenticatorApp)
	if err != nil || next != "/api/auth/signin?action=add_authenticator_app" || c == nil {
		t.Fatalf("clock on: %q %v %v", next, err, c)
	}
	rec := r.record(c)
	if rec == nil || rec.action.sub != rigSub || rec.action.kind != "add_authenticator_app" || rec.action.kcAction != flows.ActionConfigureTOTP {
		t.Errorf("record %+v", rec.action)
	}
}

// TC-1150-04: the fresh sign-in carries one action. Each method's start is
// prompt=login with exactly one kc_action, its own, and a begun record; a
// reset-kind action carries none; an unknown kind is 404; another person's
// start of a record is action-failed and destroys it.
func TestStartMethod_TC1150_04(t *testing.T) {
	r := newSigninRig(t)
	for m, spec := range methods {
		b := r.startMethod(t, rigSub, m)
		if !strings.HasPrefix(b.loc.String(), r.door.Issuer+"/protocol/openid-connect/auth?") {
			t.Errorf("%s: Location %s", m, b.loc)
		}
		q, err := url.ParseQuery(b.loc.RawQuery)
		if err != nil || q.Get("prompt") != "login" || len(q["kc_action"]) != 1 || q.Get("kc_action") != spec.kcAction {
			t.Errorf("%s: query %v", m, q)
		}
		if rec := r.record(b.pending); rec == nil || rec.prepared || rec.state == "" || rec.state != q.Get("state") {
			t.Errorf("%s: the record is not begun under the request's state", m)
		}
	}
	t.Run("a reset kind carries no kc_action", func(t *testing.T) {
		pending := r.prepare(t, rigSub, "test-action", nil)
		w := recorder()
		r.si.StartAction(w, methodRequest(rigSub, "/api/auth/signin?action=test-action", pending), "test-action")
		loc, _ := url.Parse(w.Header().Get("Location"))
		if w.Code != http.StatusSeeOther || loc.Query().Has("kc_action") || loc.Query().Get("prompt") != "login" {
			t.Errorf("%d %s", w.Code, loc)
		}
	})
	t.Run("an unknown kind", func(t *testing.T) {
		w := recorder()
		r.si.StartAction(w, methodRequest(rigSub, "/api/auth/signin?action=add_password"), "add_password")
		if w.Code != http.StatusNotFound {
			t.Errorf("%d, want 404", w.Code)
		}
	})
	t.Run("started by another person", func(t *testing.T) {
		_, _, pending := r.prepareMethod(rigSub, MethodPasskey)
		w := recorder()
		r.si.StartAction(w, methodRequest(bobSub, "/api/auth/signin?action=add_passkey", pending), "add_passkey")
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != signinActionFailed {
			t.Errorf("%d %s", w.Code, w.Header().Get("Location"))
		}
		if r.record(pending) != nil {
			t.Error("the record survived another person's start")
		}
	})
}

// TC-1150-05: Issued forwards a begun method record's action once.
func TestIssued_TC1150_05_Once(t *testing.T) {
	r := newSigninRig(t)
	b := r.startMethod(t, rigSub, MethodPasskey)
	a := consoleAction(flows.ActionPasskeyRegister, b.q.Get("state"))
	if ok, err := r.si.Issued(context.Background(), a); !ok || err != nil {
		t.Fatalf("first: %v %v, want true", ok, err)
	}
	if rec := r.record(b.pending); rec == nil || !rec.action.forwarded {
		t.Error("the record is not marked forwarded")
	}
	if ok, err := r.si.Issued(context.Background(), a); ok || err != nil {
		t.Errorf("second: %v %v, want false", ok, err)
	}
}

// TC-1150-06 (F-1150-02): Issued is false, marking nothing, for every
// request but the exact one a begun method record was issued for.
func TestIssued_TC1150_06_Binding(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(t *testing.T, r *signinRig) policy.ActionRequest{
		"another client": func(t *testing.T, r *signinRig) policy.ActionRequest {
			b := r.startMethod(t, rigSub, MethodPasskey)
			return policy.ActionRequest{Client: "rasputin-mesh", Action: flows.ActionPasskeyRegister, State: b.q.Get("state")}
		},
		"a case variant": func(t *testing.T, r *signinRig) policy.ActionRequest {
			b := r.startMethod(t, rigSub, MethodAuthenticatorApp)
			return consoleAction("configure_totp", b.q.Get("state"))
		},
		"another person's state with this action": func(t *testing.T, r *signinRig) policy.ActionRequest {
			r.startMethod(t, rigSub, MethodPasskey)
			bob := r.startMethod(t, bobSub, MethodSecurityKey)
			return consoleAction(flows.ActionPasskeyRegister, bob.q.Get("state"))
		},
		"an unknown state": func(t *testing.T, r *signinRig) policy.ActionRequest {
			r.startMethod(t, rigSub, MethodPasskey)
			return consoleAction(flows.ActionPasskeyRegister, "not-a-state")
		},
		"an empty state": func(t *testing.T, r *signinRig) policy.ActionRequest {
			r.startMethod(t, rigSub, MethodPasskey)
			return consoleAction(flows.ActionPasskeyRegister, "")
		},
		"a prepared, not begun record": func(t *testing.T, r *signinRig) policy.ActionRequest {
			if _, err, c := r.prepareMethod(rigSub, MethodPasskey); err != nil || c == nil {
				t.Fatal(err)
			}
			return consoleAction(flows.ActionPasskeyRegister, "")
		},
		"a record the callback consumed": func(t *testing.T, r *signinRig) policy.ActionRequest {
			b := r.startMethod(t, rigSub, MethodPasskey)
			r.ex.set(r.is.sign(t, r.idClaims(b)), nil)
			r.callback(r.callbackQuery(b, "c"), b.pending)
			return consoleAction(flows.ActionPasskeyRegister, b.q.Get("state"))
		},
		"a record replaced by a newer sign-in": func(t *testing.T, r *signinRig) policy.ActionRequest {
			b := r.startMethod(t, rigSub, MethodPasskey)
			r.begin(t, b.pending)
			return consoleAction(flows.ActionPasskeyRegister, b.q.Get("state"))
		},
		"a record past its lifetime": func(t *testing.T, r *signinRig) policy.ActionRequest {
			b := r.startMethod(t, rigSub, MethodPasskey)
			r.f.clock.Add(signinPendingLifetime + time.Second)
			return consoleAction(flows.ActionPasskeyRegister, b.q.Get("state"))
		},
		"an empty action under a plain sign-in": func(t *testing.T, r *signinRig) policy.ActionRequest {
			return consoleAction("", r.begin(t).q.Get("state"))
		},
		"an empty action under a reset record": func(t *testing.T, r *signinRig) policy.ActionRequest {
			return consoleAction("", r.startReset(t).q.Get("state"))
		},
		"an action under a reset record": func(t *testing.T, r *signinRig) policy.ActionRequest {
			return consoleAction(flows.ActionUpdatePassword, r.startReset(t).q.Get("state"))
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			r := newSigninRig(t)
			a := build(t, r)
			if ok, err := r.si.Issued(ctx, a); ok || err != nil {
				t.Errorf("Issued = %v, %v; want false", ok, err)
			}
			if r.anyForwarded() {
				t.Error("a record was marked forwarded")
			}
		})
	}
}

// startReset begins the rig's reset-kind action for rigSub.
func (r *signinRig) startReset(t *testing.T) begun {
	t.Helper()
	pending := r.prepare(t, rigSub, "test-action", nil)
	w := recorder()
	r.si.StartAction(w, methodRequest(rigSub, "/api/auth/signin?action=test-action", pending), "test-action")
	loc, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusSeeOther || loc.Query().Get("state") == "" {
		t.Fatalf("reset start: %d %s", w.Code, loc)
	}
	return begun{q: loc.Query(), loc: loc}
}

// TC-1150-07: Issued re-reads the clock fact, for CONFIGURE_TOTP alone.
func TestIssued_TC1150_07_Clock(t *testing.T) {
	r := newSigninRig(t)
	totp := r.startMethod(t, rigSub, MethodAuthenticatorApp)
	key := r.startMethod(t, bobSub, MethodSecurityKey)
	r.clock.synced.Store(false)
	reads := r.clock.reads.Load()
	if ok, _ := r.si.Issued(context.Background(), consoleAction(flows.ActionConfigureTOTP, totp.q.Get("state"))); ok {
		t.Error("CONFIGURE_TOTP was forwarded with the clock fact off")
	}
	if n := r.clock.reads.Load() - reads; n != 1 {
		t.Errorf("the fact was read %d times for CONFIGURE_TOTP, want 1", n)
	}
	reads = r.clock.reads.Load()
	if ok, _ := r.si.Issued(context.Background(), consoleAction(flows.ActionSecurityKey, key.q.Get("state"))); !ok {
		t.Error("a security key was not forwarded with the clock fact off")
	}
	if n := r.clock.reads.Load() - reads; n != 0 {
		t.Errorf("the fact was read %d times for a security key, want 0", n)
	}
}

// methodCallback runs b's return as sub with extra query values, and
// returns the answer.
func (r *signinRig) methodCallback(t *testing.T, b begun, sub string, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	c := r.idClaims(b)
	c["sub"] = sub
	r.ex.set(r.is.sign(t, c), nil)
	q := r.callbackQuery(b, "code-1150")
	for k, vs := range extra {
		q[k] = vs
	}
	return r.callback(q, b.pending)
}

// TC-1150-08: the return's landing follows kc_action_status, mints no
// session, and tells the observer once in every case.
func TestMethodReturn_TC1150_08(t *testing.T) {
	cases := []struct {
		name   string
		status []string
		loc    string
	}{
		{"success", []string{"success"}, "/login"},
		{"cancelled", []string{"cancelled"}, "/login?signin=method-cancelled"},
		{"error", []string{"error"}, "/login?signin=action-failed"},
		{"missing", nil, "/login?signin=action-failed"},
		{"given twice", []string{"success", "success"}, "/login?signin=action-failed"},
		{"bogus", []string{"bogus"}, "/login?signin=action-failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newSigninRig(t)
			b := r.startMethod(t, rigSub, MethodPasskey)
			extra := url.Values{}
			if c.status != nil {
				extra["kc_action_status"] = c.status
			}
			w := r.methodCallback(t, b, rigSub, extra)
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != c.loc {
				t.Errorf("%d %s, want 303 %s", w.Code, w.Header().Get("Location"), c.loc)
			}
			if sessionFrom(w) != nil || r.f.countRows(t, "console_sessions") != 0 {
				t.Error("a method's return minted a session")
			}
			if seen := r.observer.seen(); len(seen) != 1 || seen[0] != rigSub {
				t.Errorf("observer told %v, want [%s]", seen, rigSub)
			}
		})
	}
}

// TC-1150-09: another person's return from a method is the action-failed
// sentence, mints nothing and is refused with reason action.
func TestMethodReturn_TC1150_09_AnotherPerson(t *testing.T) {
	r := newSigninRig(t)
	b := r.startMethod(t, rigSub, MethodPasskey)
	w := r.methodCallback(t, b, bobSub, url.Values{"kc_action_status": {"success"}})
	assertRefused(t, r, w, "/login?signin=action-failed")
	if got := r.refusals(); len(got) != 1 || got[0] != "action" {
		t.Errorf("refusals %v, want [action]", got)
	}
}

// TC-1150-10: the start and return records carry the method, its kind or
// outcome and the sub at their levels; no record carries the state, nonce,
// code, PKCE verifier, kc_action value or token.
func TestMethodLogs_TC1150_10(t *testing.T) {
	r := newSigninRig(t)
	var secrets []string
	for _, c := range []struct {
		status, outcome string
		level           slog.Level
	}{
		{"success", "success", slog.LevelInfo},
		{"cancelled", "cancelled", slog.LevelInfo},
		{"error", "error", slog.LevelWarn},
	} {
		b := r.startMethod(t, rigSub, MethodPasskey)
		claims := r.idClaims(b)
		token := r.is.sign(t, claims)
		r.ex.set(token, nil)
		q := r.callbackQuery(b, "code-sentinel-"+c.status)
		q.Set("kc_action_status", c.status)
		r.callback(q, b.pending)
		secrets = append(secrets, b.q.Get("state"), b.q.Get("nonce"), b.q.Get("code_challenge"), "code-sentinel-"+c.status, token, r.ex.verif, b.pending.Value)
		recs := r.events("signin.method_returned")
		last := recs[len(recs)-1]
		for k, want := range map[string]string{"method": "passkey", "outcome": c.outcome, "sub": rigSub} {
			if v, _ := logkittest.Attr(last, k); v != want {
				t.Errorf("%s: %s = %q, want %q", c.status, k, v, want)
			}
		}
		if last.Level != c.level {
			t.Errorf("%s: level %v, want %v", c.status, last.Level, c.level)
		}
	}
	started := r.events("signin.method_started")
	if len(started) != 3 {
		t.Fatalf("%d method_started records, want 3", len(started))
	}
	for k, want := range map[string]string{"method": "passkey", "kind": "add_passkey", "sub": rigSub} {
		if v, _ := logkittest.Attr(started[0], k); v != want || started[0].Level != slog.LevelInfo {
			t.Errorf("method_started %s = %q at %v, want %q at INFO", k, v, started[0].Level, want)
		}
	}
	text := r.log.Text()
	for _, s := range append(secrets, flows.ActionPasskeyRegister) {
		if s != "" && strings.Contains(text, s) {
			t.Errorf("a log record holds %q", s)
		}
	}
}

// TC-1150-11: NewSignIn refuses a nil Clock.
func TestNewSignIn_TC1150_11_RefusesNilClock(t *testing.T) {
	r := newSigninRig(t)
	d := r.si.d
	d.Clock = nil
	if _, err := NewSignIn(d); err == nil || !strings.Contains(err.Error(), "Clock") {
		t.Errorf("NewSignIn with no Clock: %v", err)
	}
}
