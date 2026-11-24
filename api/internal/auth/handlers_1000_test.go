package auth

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

var (
	adminCaps    = []any{"view", "apps", "apps.host", "updates", "secrets", "nodes", "firewall", "mesh", "bmc", "iam", "system", "self"}
	operatorCaps = []any{"view", "apps", "updates", "secrets", "self"}
	viewerCaps   = []any{"view", "self"}
	selfCaps     = []any{"self"}
)

// meBody is GET /api/auth/me's decoded body.
func meBody(t *testing.T, h http.Handler, c *http.Cookie) map[string]any {
	t.Helper()
	w := get(h, "/api/auth/me", c)
	if w.Code != http.StatusOK {
		t.Fatalf("me: %d %s", w.Code, w.Body.String())
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TC-1000-18: /api/auth/me and /api/auth/status's user block report the
// session's capabilities, in List's order, always as a JSON array; roles
// are unchanged.
func TestTC1000_18_MeReportsCapabilities(t *testing.T) {
	r := newSigninRig(t)
	for _, c := range []struct {
		name  string
		roles []string
		want  []any
	}{
		{"viewer", []string{"viewer"}, viewerCaps},
		{"operator", []string{"operator"}, operatorCaps},
		{"admin", []string{"admin"}, adminCaps},
		{"none", []string{}, selfCaps},
		{"owner", []string{"owner"}, selfCaps},
	} {
		cookie := consoleCookie(t, r.f, Principal{Sub: "sub-" + c.name, Name: c.name, Roles: c.roles})
		me := meBody(t, r.h, cookie)
		got, ok := me["capabilities"].([]any)
		if !ok || !slices.Equal(got, c.want) {
			t.Errorf("TC-1000-18 %s: me capabilities = %#v, want the array %v", c.name, me["capabilities"], c.want)
		}
		roles, ok := me["roles"].([]any)
		if !ok || len(roles) != len(c.roles) || (len(c.roles) > 0 && roles[0] != c.roles[0]) {
			t.Errorf("TC-1000-18 %s: me roles = %#v, want %v", c.name, me["roles"], c.roles)
		}
		user, _ := status(t, r.h, cookie)["user"].(map[string]any)
		if got, ok := user["capabilities"].([]any); !ok || !slices.Equal(got, c.want) {
			t.Errorf("TC-1000-18 %s: status user capabilities = %#v, want %v", c.name, user["capabilities"], c.want)
		}
	}
}

// TC-1000-19: a console_sessions row in the previous release's shape,
// written straight into the table, is accepted, and its capabilities are
// computed from its stored roles: no migration.
func TestTC1000_19_PreviousReleaseSessionRow(t *testing.T) {
	r := newSigninRig(t)
	for _, c := range []struct {
		name, roles, cookie string
		want                []any
	}{
		{"admin", `["admin"]`, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", adminCaps},
		{"none", `[]`, "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", selfCaps},
	} {
		v := secret.New([]byte(c.cookie))
		now := ms(r.f.clock.Now())
		if _, err := r.f.store.db.ExecContext(r.f.ctx, `
            INSERT INTO console_sessions (token_hash, sub, sid, roles, name, created_at, last_active_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)`, hashCookie(v), "sub-old-"+c.name, "sid-old-"+c.name, c.roles, c.name, now, now); err != nil {
			t.Fatal(err)
		}
		v.Destroy()
		me := meBody(t, r.h, &http.Cookie{Name: SessionCookieName, Value: c.cookie})
		if got, ok := me["capabilities"].([]any); !ok || !slices.Equal(got, c.want) || me["sub"] != "sub-old-"+c.name {
			t.Errorf("TC-1000-19 %s: me = %v, want capabilities %v", c.name, me, c.want)
		}
	}
}
