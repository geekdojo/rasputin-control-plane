package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// TC-989-23 (acceptance; issue TC-06): a valid pre-update passkey gets 410
// with a sentence from login/begin and login/finish, no cookie, and no row
// in either session table. (register/* is gone: TC-990-06.)
func TestOldPasskeyRoutesGone(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	u := f.mintUser(t, "alice")
	a := f.enrol(t, u)
	opts, _ := json.Marshal(map[string]any{"publicKey": map[string]string{
		"challenge": base64.RawURLEncoding.EncodeToString([]byte("a-challenge-the-api-never-issued")),
	}})
	for _, c := range []struct{ path, body string }{
		{"/api/auth/login/begin", ""},
		{"/api/auth/login/finish", a.assert(t, opts, u.ID)},
	} {
		w := post(h, c.path, c.body)
		if w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "Sign in from the sign-in page") {
			t.Errorf("%s: %d %s, want 410 with the sentence", c.path, w.Code, w.Body.String())
		}
		if len(w.Result().Cookies()) != 0 {
			t.Errorf("%s set %v", c.path, w.Result().Cookies())
		}
	}
	if f.countRows(t, "sessions") != 0 || f.countRows(t, "console_sessions") != 0 {
		t.Error("a pre-update passkey opened a session")
	}
}

// TC-989-24: status carries firstRun and ready and never a count, and user
// only with a console session; me is {sub, name, roles, capabilities}, or 401.
func TestStatusAndMe(t *testing.T) {
	r := newSigninRig(t)
	st := status(t, r.h)
	if st["firstRun"] != true || st["ready"] != true || len(st) != 2 {
		t.Errorf("status without a session = %v, want exactly firstRun and ready", st)
	}
	c := consoleCookie(t, r.f, Principal{Sub: "sub-a", Name: "alice", Roles: []string{"operator"}})
	st = status(t, r.h, c)
	user, _ := st["user"].(map[string]any)
	if user["sub"] != "sub-a" || user["name"] != "alice" {
		t.Errorf("status user = %v", st["user"])
	}
	for _, k := range []string{"hasUsers", "userCount"} {
		if _, ok := st[k]; ok {
			t.Errorf("status carries %s", k)
		}
	}
	w := get(r.h, "/api/auth/me", c)
	var me map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil || w.Code != http.StatusOK {
		t.Fatalf("me: %d %s", w.Code, w.Body.String())
	}
	keys := make([]string, 0, len(me))
	for k := range me {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	// capabilities joined in geekdojo/geekdojo-brain#1000 (TC-1000-18).
	if !slices.Equal(keys, []string{"capabilities", "name", "roles", "sub"}) || me["sub"] != "sub-a" {
		t.Errorf("me = %v, want exactly sub, name, roles, capabilities", me)
	}
	if w := get(r.h, "/api/auth/me"); w.Code != http.StatusUnauthorized {
		t.Errorf("me without a session: %d", w.Code)
	}
	if w := get(r.h, "/api/auth/me", &http.Cookie{Name: "rasputin-session", Value: "legacy"}); w.Code != http.StatusUnauthorized {
		t.Errorf("me with the legacy cookie: %d", w.Code)
	}
	r.si.d.Ready = fakeReady{err: errTest}
	if st := status(t, r.h); st["ready"] != false {
		t.Errorf("status with the service not ready = %v", st)
	}
	if w := get(r.h, "/api/auth/signin"); w.Header().Get("Location") != "/login?signin=unavailable" {
		t.Errorf("signin with the service not ready: %s", w.Header().Get("Location"))
	}
}
