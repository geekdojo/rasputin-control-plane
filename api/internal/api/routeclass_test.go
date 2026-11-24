package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
)

// TC-1002-17: authorize fails closed. Each case drives authorize over a stub
// handler that counts its calls.
func TestAuthorize_TC1002_17_FailsClosed(t *testing.T) {
	f := newAPIFixture(t)
	admin := auth.Principal{Sub: "sub-alice", Name: "alice", Roles: []string{"admin"}}
	noRole := auth.Principal{Sub: "sub-nora", Name: "nora"}
	for _, c := range []struct {
		name   string
		rule   routeRule
		who    *auth.Principal
		passes bool
	}{
		{"(a) no principal, view", needs(authz.NeedView()), nil, false},
		{"(b) the zero rule, admin", routeRule{}, &admin, false},
		{"(c) a job rule with no kinds, admin", job(), &admin, false},
		{"(d) admin, control under bmc", needs(authz.NeedControl(authz.BMC)), &admin, true},
		{"(e) anyJob, no role", anyJob(), &noRole, true},
		{"anyJob, no principal", anyJob(), nil, false},
		{"a job rule, no principal", job("node.update"), nil, false},
	} {
		calls := 0
		h := f.srv.authorize(c.rule, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusTeapot)
		}))
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.Pattern = "POST /x"
		if c.who != nil {
			req = req.WithContext(auth.WithPrincipal(req.Context(), *c.who))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if c.passes {
			if calls != 1 || w.Code != http.StatusTeapot {
				t.Errorf("%s: handler called %d times (%d), want once", c.name, calls, w.Code)
			}
			continue
		}
		if calls != 0 {
			t.Errorf("%s: handler called %d times, want never", c.name, calls)
		}
		want := codeRouteNotPermitted
		if c.rule.kind == ruleJob && len(c.rule.kinds) > 0 {
			want = "job_" + authz.CodeNotPermitted
		}
		wantRefused(t, c.name, w, want)
	}
}

// The labels the route table test and the refusal record read.
func TestRouteRule_Labels(t *testing.T) {
	for want, r := range map[string]routeRule{
		"view":                    needs(authz.NeedView()),
		"control:bmc":             needs(authz.NeedControl(authz.BMC)),
		"self":                    needs(authz.NeedSelf()),
		"job:app.edit,app.revert": job("app.edit", "app.revert"),
		"anyjob":                  anyJob(),
		"none":                    {},
	} {
		if got := r.label(); got != want {
			t.Errorf("label = %q, want %q", got, want)
		}
	}
	if got := needs(authz.Requirement{}).label(); got != "none" {
		t.Errorf("a need with no class: %q, want none", got)
	}
	if needs(authz.Requirement{}).check(authz.For(authz.Subject{Sub: "s", Roles: []string{"admin"}})) == nil {
		t.Error("a need with no class passed")
	}
}

// A route refusal's record carries the rule's need and never the person.
func TestAuthorize_RefusalRecordCarriesTheNeed(t *testing.T) {
	f := newAPIFixture(t)
	h := f.srv.authorize(needs(authz.NeedControl(authz.Mesh)), http.NotFoundHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/mesh/keys", nil)
	req.Pattern = "GET /api/mesh/keys"
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Sub: "sub-vic-91", Name: "vic", Roles: []string{"viewer"}}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	wantRefused(t, "viewer mesh keys", w, codeRouteNotPermitted)
	recs := f.records(slog.LevelWarn, "api: request refused")
	if len(recs) != 1 {
		t.Fatalf("%d refusal records, want 1", len(recs))
	}
	if a := attrs(recs[0]); a["need"] != "control:mesh" || a["route"] != "GET /api/mesh/keys" || a["code"] != codeRouteNotPermitted {
		t.Errorf("refusal attrs = %v", a)
	}
}
