package auth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// startPrepared sends GET /api/auth/signin?action=kind through the
// service's handler with a console session for sub and the pending cookie.
func startPrepared(t *testing.T, r *signinRig, sub, kind string, pending *http.Cookie) *httptestRecorder {
	t.Helper()
	cookies := []*http.Cookie{consoleCookie(t, r.f, Principal{Sub: sub, Name: "alice", Roles: []string{"admin"}})}
	if pending != nil {
		cookies = append(cookies, pending)
	}
	return r.get("/api/auth/signin?action="+url.QueryEscape(kind), rigConsole, cookies...)
}

// TC-992-13: PrepareAction needs a principal; StartAction begins only from
// the browser's live prepared record of the same kind and sub, and then sets
// state, nonce, verifier and begin and sends the browser to the home door
// with prompt=login. With ?action= and no session the route answers 401.
func TestSignIn_TC992_13_PreparedAction(t *testing.T) {
	t.Run("no principal", func(t *testing.T) {
		r := newSigninRig(t)
		p := &countingPayload{}
		if _, err := r.si.PrepareAction(recorder(), httptestRequest(rigConsole, "/x"), "test-action", p); !errors.Is(err, ErrNoAction) {
			t.Errorf("PrepareAction = %v, want ErrNoAction", err)
		}
		if p.count() != 1 || r.si.pending.size() != 0 {
			t.Errorf("destroyed %d, held %d; want 1 and 0", p.count(), r.si.pending.size())
		}
	})
	t.Run("unknown kind", func(t *testing.T) {
		r := newSigninRig(t)
		req := httptestRequest(rigConsole, "/x")
		req = req.WithContext(WithPrincipal(req.Context(), Principal{Sub: rigSub}))
		if _, err := r.si.PrepareAction(recorder(), req, "no-such", nil); !errors.Is(err, ErrNoAction) {
			t.Errorf("PrepareAction = %v", err)
		}
	})
	t.Run("no session", func(t *testing.T) {
		r := newSigninRig(t)
		pending := r.prepare(t, rigSub, "test-action", nil)
		w := r.get("/api/auth/signin?action=test-action", rigConsole, pending)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("no session: %d, want 401", w.Code)
		}
	})
	for name, c := range map[string]struct {
		sub, kind string
		prepare   bool
	}{
		"absent record":  {sub: rigSub, kind: "test-action"},
		"another kind":   {sub: rigSub, kind: "other-action", prepare: true},
		"another person": {sub: "someone-else", kind: "test-action", prepare: true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newSigninRig(t)
			r.si.d.Actions["other-action"] = &fakeAction{}
			p := &countingPayload{}
			var pending *http.Cookie
			if c.prepare {
				pending = r.prepare(t, rigSub, "test-action", p)
			}
			w := startPrepared(t, r, c.sub, c.kind, pending)
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?signin=action-failed" {
				t.Errorf("answer %d %s", w.Code, w.Header().Get("Location"))
			}
			if c.prepare && (p.count() != 1 || r.si.pending.size() != 0) {
				t.Errorf("payload destroyed %d, held %d; want the record gone", p.count(), r.si.pending.size())
			}
			if got := r.refusals(); len(got) != 1 || got[0] != "action_record" {
				t.Errorf("refusals %v", got)
			}
		})
	}
	t.Run("matching record", func(t *testing.T) {
		r := newSigninRig(t)
		pending := r.prepare(t, rigSub, "test-action", &countingPayload{})
		before := r.f.clock.Now()
		r.f.clock.Add(time.Minute)
		w := startPrepared(t, r, rigSub, "test-action", pending)
		loc, _ := url.Parse(w.Header().Get("Location"))
		if w.Code != http.StatusSeeOther || !strings.HasPrefix(loc.String(), r.door.Issuer+"/protocol/openid-connect/auth") ||
			loc.Query().Get("prompt") != "login" || loc.Query().Get("state") == "" || loc.Query().Get("nonce") == "" ||
			loc.Query().Get("code_challenge") == "" {
			t.Fatalf("answer %d %s", w.Code, loc)
		}
		rec := r.si.pending.m[pending.Value]
		if rec == nil || rec.prepared || rec.state != loc.Query().Get("state") || rec.verifier.Len() == 0 || !rec.begin.After(before) ||
			rec.action.kind != "test-action" || rec.action.sub != rigSub {
			t.Errorf("record %+v", rec)
		}
	})
	t.Run("a prepared record never completes a callback", func(t *testing.T) {
		r := newSigninRig(t)
		pending := r.prepare(t, rigSub, "test-action", nil)
		w := r.callback(url.Values{"state": {""}, "code": {"c"}, "iss": {r.door.Issuer}}, pending)
		if w.Header().Get("Location") != "/login?signin=failed" || r.ex.calls != 0 || r.action.count() != 0 {
			t.Errorf("answer %s, exchanges %d, runs %d", w.Header().Get("Location"), r.ex.calls, r.action.count())
		}
	})
}

// TC-992-14: the payload is destroyed exactly once on each way its record
// leaves: taken at the callback (after Run received it, once), replaced by a
// newer Begin from the same cookie, evicted at the cap, pruned after expiry.
func TestSignIn_TC992_14_PayloadLifetime(t *testing.T) {
	t.Run("callback", func(t *testing.T) {
		r := newSigninRig(t)
		p := &countingPayload{}
		pending := r.prepare(t, rigSub, "test-action", p)
		w := startPrepared(t, r, rigSub, "test-action", pending)
		loc, _ := url.Parse(w.Header().Get("Location"))
		b := begun{q: loc.Query(), loc: loc, pending: pending}
		r.ex.set(r.is.sign(t, r.idClaims(b)), nil)
		r.callback(r.callbackQuery(b, "c"), pending)
		if r.action.count() != 1 || r.action.payloads[0] != ActionPayload(p) || p.count() != 1 {
			t.Errorf("runs %d payload %v destroyed %d; want 1, it, 1", r.action.count(), r.action.payloads, p.count())
		}
	})
	t.Run("replaced", func(t *testing.T) {
		r := newSigninRig(t)
		p := &countingPayload{}
		pending := r.prepare(t, rigSub, "test-action", p)
		r.begin(t, pending)
		if p.count() != 1 {
			t.Errorf("destroyed %d, want 1", p.count())
		}
	})
	t.Run("evicted", func(t *testing.T) {
		r := newSigninRig(t)
		p := &countingPayload{}
		r.prepare(t, rigSub, "test-action", p)
		r.f.clock.Add(time.Second)
		for range maxSigninPending {
			r.begin(t)
		}
		if p.count() != 1 {
			t.Errorf("destroyed %d, want 1", p.count())
		}
	})
	t.Run("pruned", func(t *testing.T) {
		r := newSigninRig(t)
		p := &countingPayload{}
		r.prepare(t, rigSub, "test-action", p)
		r.f.clock.Add(signinPendingLifetime)
		r.si.prune()
		r.si.prune()
		if p.count() != 1 || r.si.pending.size() != 0 {
			t.Errorf("destroyed %d, held %d", p.count(), r.si.pending.size())
		}
	})
	t.Run("not ready at start", func(t *testing.T) {
		r := newSigninRig(t)
		p := &countingPayload{}
		pending := r.prepare(t, rigSub, "test-action", p)
		r.si.d.Ready = fakeReady{err: errTest}
		w := startPrepared(t, r, rigSub, "test-action", pending)
		if w.Header().Get("Location") != "/login?signin=unavailable" || p.count() != 1 {
			t.Errorf("answer %s destroyed %d", w.Header().Get("Location"), p.count())
		}
	})
}

// TC-992-15: an action whose Run fails sends the browser to
// ?signin=action-failed, not ?signin=failed.
func TestSignIn_TC992_15_ActionFailed(t *testing.T) {
	r := newSigninRig(t)
	r.action.err = errTest
	pending := r.prepare(t, rigSub, "test-action", nil)
	w := startPrepared(t, r, rigSub, "test-action", pending)
	loc, _ := url.Parse(w.Header().Get("Location"))
	b := begun{q: loc.Query(), loc: loc, pending: pending}
	r.ex.set(r.is.sign(t, r.idClaims(b)), nil)
	w = r.callback(r.callbackQuery(b, "c"), pending)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?signin=action-failed" {
		t.Errorf("answer %d %s", w.Code, w.Header().Get("Location"))
	}
	if len(r.events("signin.action_failed")) != 1 {
		t.Errorf("log %s", r.log.Text())
	}
}

// Service.PrepareAction with no sign-in installed destroys the payload.
func TestService_PrepareActionUninstalled(t *testing.T) {
	f := newAuthFixture(t)
	p := &countingPayload{}
	if _, err := f.svc.PrepareAction(recorder(), httptestRequest(rigConsole, "/x"), "k", p); !errors.Is(err, ErrNoAction) || p.count() != 1 {
		t.Errorf("PrepareAction = %v, destroyed %d", err, p.count())
	}
	r := newSigninRig(t)
	req := httptestRequest(rigConsole, "/x")
	req = req.WithContext(WithPrincipal(req.Context(), Principal{Sub: rigSub}))
	if next, err := r.f.svc.PrepareAction(recorder(), req, "test-action", nil); err != nil || next != "/api/auth/signin?action=test-action" {
		t.Errorf("installed: %q %v", next, err)
	}
}
