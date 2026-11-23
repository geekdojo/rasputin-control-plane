package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// lockMux registers the real route shapes behind RequireSession, as the api
// server does.
func lockMux(svc *Service) *http.ServeMux {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux := http.NewServeMux()
	for _, p := range []string{
		"GET /api/nodes", "POST /api/nodes/{id}/reboot", "PUT /api/settings", "PATCH /api/settings", "DELETE /api/apps/{id}",
		"POST /api/auth/logout", "GET /ws/bmc/{nodeId}/sol", "GET /ws/jobs", "GET /ws/alerts",
	} {
		mux.Handle(p, svc.RequireSession(ok))
	}
	return mux
}

// TC-987-34: while the gate refuses, every unsafe method outside
// /api/auth/ answers 423 with its code and sentence, a plain GET passes, the
// serial console's upgrade is refused, a view socket passes, and each
// refusal logs auth.control_locked with the method and route; with the gate
// allowing, or none set, everything passes.
func TestControlLock(t *testing.T) {
	f := newAuthFixture(t)
	sess := freshSession(t, f, f.mintUser(t, "alice"))
	mux := lockMux(f.svc)
	send := func(method, path string, upgrade bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess.Token})
		if upgrade {
			r.Header.Set("Connection", "Upgrade")
			r.Header.Set("Upgrade", "websocket")
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	type req struct {
		method, path string
		upgrade      bool
		locked       bool
	}
	cases := []req{
		{http.MethodPost, "/api/nodes/n1/reboot", false, true},
		{http.MethodPut, "/api/settings", false, true},
		{http.MethodPatch, "/api/settings", false, true},
		{http.MethodDelete, "/api/apps/a", false, true},
		{http.MethodGet, "/ws/bmc/n1/sol", true, true},
		{http.MethodGet, "/api/nodes", false, false},
		{http.MethodGet, "/ws/jobs", true, false},
		{http.MethodGet, "/ws/alerts", true, false},
		{http.MethodPost, "/api/auth/logout", false, false},
	}
	// No gate: all pass.
	for _, c := range cases {
		if w := send(c.method, c.path, c.upgrade); w.Code != http.StatusOK {
			t.Errorf("no gate: %s %s = %d", c.method, c.path, w.Code)
		}
	}
	if f.svc.HasControlGate() {
		t.Error("a gate is reported before one is set")
	}
	log, rec := logkittest.New()
	f.svc.SetControlGate(func(context.Context) error { return errors.New("differs") }, log)
	for _, c := range cases {
		w := send(c.method, c.path, c.upgrade)
		if !c.locked {
			if w.Code != http.StatusOK {
				t.Errorf("locked: %s %s = %d, want 200", c.method, c.path, w.Code)
			}
			continue
		}
		body := w.Body.String()
		if w.Code != http.StatusLocked || !strings.Contains(body, `"code":"signin_rules_differ"`) ||
			!strings.Contains(body, "Administrator tools are locked because Rasputin's sign-in rules differ from its settings. They unlock when Rasputin restores them; see Alerts.") {
			t.Errorf("locked: %s %s = %d %s", c.method, c.path, w.Code, body)
		}
	}
	recs := rec.Matching(slog.LevelInfo, "A control request was refused: the sign-in rules differ from Rasputin's.")
	if len(recs) != 5 {
		t.Errorf("%d auth.control_locked records, want 5:\n%s", len(recs), rec.Text())
	}
	if !strings.Contains(rec.Text(), "route=GET /ws/bmc/{nodeId}/sol") || !strings.Contains(rec.Text(), "method=POST") {
		t.Errorf("the records lack the method or the route:\n%s", rec.Text())
	}
	f.svc.SetControlGate(func(context.Context) error { return nil }, log)
	for _, c := range cases {
		if w := send(c.method, c.path, c.upgrade); w.Code != http.StatusOK {
			t.Errorf("gate allows: %s %s = %d", c.method, c.path, w.Code)
		}
	}
	// A request with no session is still 401, never 423.
	f.svc.SetControlGate(func(context.Context) error { return errors.New("differs") }, nil)
	r := httptest.NewRequest(http.MethodPost, "/api/nodes/n1/reboot", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", w.Code)
	}
	if !f.svc.HasControlGate() {
		t.Error("the gate set is not reported")
	}
}
