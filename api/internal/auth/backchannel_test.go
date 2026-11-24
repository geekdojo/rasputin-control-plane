package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// logoutClaims are a valid logout token's claims for sid.
func (r *signinRig) logoutClaims(sid string) map[string]any {
	now := r.f.clock.Now()
	return map[string]any{
		"iss": r.door.Issuer, "aud": "rasputin-console", "sub": rigSub, "sid": sid, "jti": "jti-1",
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "typ": "Logout",
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
}

func (r *signinRig) postLogout(client, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "https://127.0.0.1/api/identity/backchannel/"+client,
		strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}

// TC-989-19 (issue TC-04, unit part): a valid logout token ends its sid's
// sessions; a forged, foreign, nonce-carrying, event-less or sid-less token
// is a 400 with WARN and leaves the rows; an unknown client is a 404; a
// store error is a 500 with ERROR.
func TestBackchannel(t *testing.T) {
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		edit func(*signinRig, map[string]any)
		sign func(*signinRig, map[string]any) string
	}{
		{"forged signature", nil, func(_ *signinRig, c map[string]any) string { return signWith(t, stranger, "kid-a", c) }},
		{"wrong issuer", func(r *signinRig, c map[string]any) { c["iss"] = r.app.Issuer }, nil},
		{"a nonce", func(_ *signinRig, c map[string]any) { c["nonce"] = "n" }, nil},
		{"no events member", func(_ *signinRig, c map[string]any) { delete(c, "events") }, nil},
		{"another event", func(_ *signinRig, c map[string]any) { c["events"] = map[string]any{"urn:other": map[string]any{}} }, nil},
		{"no sid", func(_ *signinRig, c map[string]any) { delete(c, "sid") }, nil},
		{"an ID token", func(r *signinRig, c map[string]any) {
			for k := range c {
				delete(c, k)
			}
			for k, v := range r.idClaims(begun{q: url.Values{"nonce": {"n"}}}) {
				c[k] = v
			}
		}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newSigninRig(t)
			consoleCookie(t, r.f, Principal{Sub: rigSub, Session: SessionRef{SID: rigSID}})
			claims := r.logoutClaims(rigSID)
			if c.edit != nil {
				c.edit(r, claims)
			}
			tok := ""
			if c.sign != nil {
				tok = c.sign(r, claims)
			} else {
				tok = r.is.sign(t, claims)
			}
			w := r.postLogout("rasputin-console", tok)
			if w.Code != http.StatusBadRequest || r.f.countRows(t, "console_sessions") != 1 {
				t.Errorf("answer %d rows %d, want 400 and the row kept", w.Code, r.f.countRows(t, "console_sessions"))
			}
			recs := r.events("backchannel.refused")
			if len(recs) != 1 || recs[0].Level != slog.LevelWarn {
				t.Errorf("log %s", r.log.Text())
			}
			if strings.Contains(r.log.Text(), tok) {
				t.Error("the log holds the token")
			}
		})
	}
	t.Run("valid", func(t *testing.T) {
		r := newSigninRig(t)
		gone := consoleCookie(t, r.f, Principal{Sub: rigSub, Session: SessionRef{SID: rigSID}})
		kept := consoleCookie(t, r.f, Principal{Sub: rigSub, Session: SessionRef{SID: "sid-other"}})
		if w := r.postLogout("rasputin-console", r.is.sign(t, r.logoutClaims(rigSID))); w.Code != http.StatusOK {
			t.Fatalf("answer %d %s", w.Code, w.Body.String())
		}
		if get(r.h, "/api/auth/me", gone).Code != http.StatusUnauthorized || get(r.h, "/api/auth/me", kept).Code != http.StatusOK {
			t.Error("the logout ended the wrong sessions")
		}
	})
	t.Run("unknown client", func(t *testing.T) {
		r := newSigninRig(t)
		if w := r.postLogout("rasputin-account", r.is.sign(t, r.logoutClaims(rigSID))); w.Code != http.StatusNotFound {
			t.Errorf("answer %d, want 404", w.Code)
		}
		f := newAuthFixture(t)
		req := httptest.NewRequest(http.MethodPost, "/api/identity/backchannel/rasputin-console", strings.NewReader("logout_token=x"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		f.handler().ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("no sign-in installed: %d, want 404", w.Code)
		}
	})
	t.Run("store error", func(t *testing.T) {
		r := newSigninRig(t)
		if _, err := r.f.store.db.Exec(`DROP TABLE console_sessions`); err != nil {
			t.Fatal(err)
		}
		if w := r.postLogout("rasputin-console", r.is.sign(t, r.logoutClaims(rigSID))); w.Code != http.StatusInternalServerError {
			t.Errorf("answer %d, want 500", w.Code)
		}
		if recs := r.events("backchannel.store_failed"); len(recs) != 1 || recs[0].Level != slog.LevelError {
			t.Errorf("log %s", r.log.Text())
		}
	})
}

// recordingSink records the admin events it is given, in order.
type recordingSink struct{ seen *[]string }

func (s recordingSink) AdminEvent(_ context.Context, e events.AdminEvent) {
	*s.seen = append(*s.seen, e.ID)
}

// TC-989-20: a client or realm role-mapping event ends only that user's
// sessions; other resource types end nothing; a store error is an ERROR and
// the drain's later sinks still run.
func TestRoleChangeSink(t *testing.T) {
	f := newAuthFixture(t)
	log, rec := logkittest.New()
	sink, err := NewRoleChangeSink(f.sessions, log)
	if err != nil {
		t.Fatal(err)
	}
	x := consoleCookie(t, f, Principal{Sub: "X", Session: SessionRef{SID: "x1"}})
	y := consoleCookie(t, f, Principal{Sub: "Y", Session: SessionRef{SID: "y1"}})
	live := func(c *http.Cookie) bool { return get(f.handler(), "/api/auth/me", c).Code == http.StatusOK }
	for _, e := range []events.AdminEvent{
		{ID: "1", ResourceType: "USER", ResourcePath: "users/X"},
		{ID: "2", ResourceType: "CLIENT", ResourcePath: "clients/c-1"},
		{ID: "3", ResourceType: "CLIENT_ROLE_MAPPING", ResourcePath: "groups/g/role-mappings/clients/c-1"},
		{ID: "4", ResourceType: "CLIENT_ROLE_MAPPING", ResourcePath: "users/"},
	} {
		sink.AdminEvent(f.ctx, e)
	}
	if !live(x) || !live(y) {
		t.Fatal("an unrelated event ended a session")
	}
	sink.AdminEvent(f.ctx, events.AdminEvent{ID: "5", ResourceType: "CLIENT_ROLE_MAPPING", ResourcePath: "users/X/role-mappings/clients/c-1"})
	if live(x) || !live(y) {
		t.Fatal("a client role change ended the wrong sessions")
	}
	sink.AdminEvent(f.ctx, events.AdminEvent{ID: "6", ResourceType: "REALM_ROLE_MAPPING", ResourcePath: "users/Y/role-mappings/realm"})
	if live(y) {
		t.Fatal("a realm role change did not end the user's session")
	}

	if _, err := f.store.db.Exec(`DROP TABLE console_sessions`); err != nil {
		t.Fatal(err)
	}
	var seen []string
	sinks := []events.AdminSink{sink, recordingSink{seen: &seen}}
	for _, s := range sinks {
		s.AdminEvent(f.ctx, events.AdminEvent{ID: "7", ResourceType: "CLIENT_ROLE_MAPPING", ResourcePath: "users/Z/role-mappings/clients/c"})
	}
	if !slices.Equal(seen, []string{"7"}) {
		t.Errorf("the later sink saw %v", seen)
	}
	if recs := rec.AtLevel(slog.LevelError); len(recs) != 1 {
		t.Errorf("log %s, want one ERROR", rec.Text())
	}
	if _, err := NewRoleChangeSink(nil, log); err == nil {
		t.Error("NewRoleChangeSink accepted a nil store")
	}
}

// TC-989-22: sign-out deletes the row, clears the cookie and ends the
// identity session; when that fails it still answers 200 and WARNs.
func TestSignOut(t *testing.T) {
	for _, fail := range []bool{false, true} {
		r := newSigninRig(t)
		if fail {
			r.ender.err = errTest
		}
		c := consoleCookie(t, r.f, Principal{Sub: rigSub, Session: SessionRef{SID: "sid-out"}})
		req := httptestRequest(rigConsole, "/api/auth/logout")
		req.Method = http.MethodPost
		req.AddCookie(c)
		w := recorder()
		r.h.ServeHTTP(w, req)
		if w.Code != http.StatusOK || r.f.countRows(t, "console_sessions") != 0 {
			t.Errorf("fail=%v: answer %d rows %d", fail, w.Code, r.f.countRows(t, "console_sessions"))
		}
		cleared := false
		for _, ck := range w.Result().Cookies() {
			cleared = cleared || (ck.Name == SessionCookieName && ck.MaxAge < 0)
		}
		if !cleared || !slices.Equal(r.ender.sids, []string{"sid-out"}) {
			t.Errorf("fail=%v: cleared %v ender %v", fail, cleared, r.ender.sids)
		}
		recs := r.events("signout.sid_not_ended")
		if fail != (len(recs) == 1 && recs[0].Level == slog.LevelWarn) {
			t.Errorf("fail=%v: log %s", fail, r.log.Text())
		}
	}
}
