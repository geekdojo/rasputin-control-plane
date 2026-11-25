package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass"
	"github.com/geekdojo/rasputin-control-plane/api/internal/console"
	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The route-class matrix (geekdojo/geekdojo-brain#1002; identity-authz.md
// §3.2). Every route on the console mux has exactly one class:
//
//   - open: registered raw and listed in openRoutes (routes_auth_test.go);
//   - signin: registered by auth.RegisterRoutes through signinRegistrar, and
//     either open or pinned in signinSessionRoutes with its reason;
//   - door: the door muxes' door.Routes;
//   - gated: registered through Server.gate with a routeRule.
//
// classProblems reads the classes off the recording mux the server routes
// with, and wantClass is the independent, literal expectation every recorded
// rule is checked against, both ways. An unclassified route, a misclassed
// route or an unpinned sign-in route fails go test ./api/....

// signinSessionRoutes pins the sign-in patterns that are not open routes:
// each is reached with a session, and the handler itself resolves only the
// caller's own cookie. The list is closed (F-1002-01): any other pattern
// auth.RegisterRoutes records fails classProblems until it is an open route,
// pinned here with its reason, or registered through gate.
var signinSessionRoutes = map[string]string{
	"GET /api/auth/me": "the caller's own session view; the handler resolves only the caller's cookie and answers 401 without one",
}

// idorProbes holds, for every route classed self, the test that proves a
// person reaches only their own records through it. A self route with no
// entry fails TestRouteClasses_TC1002_03_SelfRoutesHaveIDORProbes.
// /api/me/* (geekdojo/geekdojo-brain#319, #1036, #1150) adds its probes here.
var idorProbes = map[string]func(t *testing.T){
	// TC-1150-13: the sign-in method a person adds is their own.
	"POST /api/me/sign-in-methods": probeSignInMethodsIDOR,
}

// wantClass is every gated pattern at this change and its class, written out
// literally (TC-1002-04, F-1002-04): view, control:<capability>, self,
// job:<kinds>, or anyjob.
var wantClass = map[string]string{
	// geekdojo/geekdojo-brain#321: the break-glass repair session's routes.
	"GET /api/repair/state":    "repair:control:repair",
	"POST /api/repair/end":     "repair:control:repair",
	"POST /api/repair/restart": "repair:job:identity.restart",
	"POST /api/jobs":           "anyjob",
	// TC-992-22: the administrator's password reset (geekdojo/geekdojo-brain#992).
	"POST /api/accounts/{id}/reset-password": "control:iam",
	"POST /api/accounts/jobs":                "anyjob",
	// TC-1150-13: a person adds a sign-in method to their own account.
	"POST /api/me/sign-in-methods": "self",
	// TC-990-25: how many people wait for access (geekdojo/geekdojo-brain#990).
	"GET /api/accounts/waiting":              "control:iam",
	"GET /api/jobs":                          "view",
	"GET /api/jobs/{id}":                     "view",
	"GET /api/jobs/{id}/steps":               "view",
	"GET /api/jobs/{id}/events":              "view",
	"GET /api/nodes":                         "view",
	"GET /api/nodes/{id}":                    "view",
	"GET /api/nodes/{id}/removal-impact":     "view",
	"DELETE /api/nodes/{id}":                 "control:nodes",
	"GET /api/metrics/{id}":                  "view",
	"GET /api/firewall/intents":              "view",
	"POST /api/firewall/intents":             "control:firewall",
	"PATCH /api/firewall/intents/{id}":       "control:firewall",
	"DELETE /api/firewall/intents/{id}":      "control:firewall",
	"GET /api/firewall/state":                "view",
	"POST /api/firewall/apply":               "job:firewall.apply",
	"POST /api/firewall/reconcile":           "job:firewall.reconcile",
	"GET /api/apps":                          "view",
	"POST /api/apps":                         "control:apps.host",
	"GET /api/apps/{id}":                     "view",
	"PATCH /api/apps/{id}":                   "control:apps",
	"DELETE /api/apps/{id}":                  "job:app.delete",
	"POST /api/apps/{id}/deploy":             "job:app.deploy",
	"POST /api/apps/{id}/stop":               "job:app.stop",
	"PUT /api/apps/{id}/compose":             "job:app.upgrade,app.edit,app.revert",
	"GET /api/apps/{id}/volumes":             "view",
	"GET /api/apps/{id}/restore-sources":     "view",
	"POST /api/apps/{id}/restore":            "job:backup.restore_app",
	"GET /api/apps/{id}/secrets":             "view",
	"PUT /api/apps/{id}/secrets/{name}":      "control:secrets",
	"GET /api/volumes/orphans":               "view",
	"POST /api/volumes/orphans/reclaim":      "control:apps",
	"GET /api/catalog":                       "view",
	"GET /api/catalog/_status":               "view",
	"POST /api/catalog/_refresh":             "control:apps",
	"GET /api/catalog/{id}":                  "view",
	"POST /api/catalog/{id}/install":         "control:apps",
	"GET /api/bundles":                       "view",
	"POST /api/bundles":                      "control:updates",
	"DELETE /api/bundles/{sha}":              "control:updates",
	"POST /api/updates":                      "job:node.update",
	"POST /api/updates/system":               "job:system.update",
	"POST /api/updates/system/plan":          "control:updates",
	"GET /api/updates":                       "view",
	"POST /api/updates/check":                "control:updates",
	"POST /api/updates/pull":                 "control:updates",
	"GET /api/backup/candidates":             "view",
	"GET /api/backup/targets":                "view",
	"POST /api/backup/targets":               "job:backup.target.claim",
	"GET /api/backup/runs":                   "view",
	"POST /api/backup/runs":                  "job:backup.run",
	"GET /api/backup/restores":               "view",
	"GET /api/backup/schedule":               "view",
	"PUT /api/backup/schedule":               "control:system",
	"GET /api/mesh/state":                    "view",
	"GET /api/mesh/devices":                  "view",
	"DELETE /api/mesh/devices/{hsId}":        "control:mesh",
	"GET /api/mesh/keys":                     "control:mesh",
	"POST /api/mesh/keys":                    "control:mesh",
	"PATCH /api/mesh/keys/{id}":              "control:mesh",
	"DELETE /api/mesh/keys/{id}":             "control:mesh",
	"GET /api/mesh/routes":                   "view",
	"POST /api/mesh/routes":                  "control:mesh",
	"PATCH /api/mesh/routes/{id}":            "control:mesh",
	"DELETE /api/mesh/routes/{id}":           "control:mesh",
	"POST /api/mesh/apply":                   "job:mesh.apply",
	"POST /api/mesh/reconcile":               "job:mesh.reconcile",
	"POST /api/mesh/enroll/{nodeId}":         "job:mesh.enroll_node",
	"GET /api/mesh/enroll-defaults/{nodeId}": "view",
	"GET /api/bus/tokens":                    "view",
	"POST /api/bus/tokens":                   "control:nodes",
	"DELETE /api/bus/tokens/{id}":            "control:nodes",
	"GET /api/bus/tls":                       "view",
	"POST /api/setup/install-name":           "control:system",
	"POST /api/setup/mode":                   "control:firewall",
	"POST /api/setup/mesh":                   "job:mesh.enroll_node",
	"POST /api/setup/complete":               "control:system",
	"GET /api/settings/dns-forwarding":       "view",
	"POST /api/settings/dns-forwarding":      "control:system",
	"GET /api/enroll/operator-key":           "view",
	"PUT /api/enroll/operator-key":           "control:nodes",
	"GET /api/console/root-password":         "view",
	"PUT /api/console/root-password":         "control:nodes",
	"POST /api/console/root-password/push":   "job:console.root_push",
	"GET /api/bmc":                           "view",
	"GET /api/bmc/backends":                  "view",
	"GET /api/bmc/config":                    "view",
	"POST /api/bmc/config":                   "control:bmc",
	"POST /api/bmc/probe":                    "control:bmc",
	"POST /api/bmc/csr":                      "control:bmc",
	"GET /api/bmc/{nodeId}/status":           "view",
	"POST /api/bmc/{nodeId}/power/{verb}":    "job:bmc.power",
	"GET /ws/bmc/{nodeId}/sol":               "control:bmc",
	"GET /api/alerts":                        "view",
	"POST /api/alerts/{id}/ack":              "control:system",
	"POST /api/alerts/{id}/dismiss":          "control:system",
	"GET /api/obs/status":                    "view",
	"GET /api/obs/logs":                      "view",
	"GET /api/obs/series":                    "view",
	"GET /api/obs/containers":                "view",
	"POST /api/obs/enable":                   "job:obs.enable",
	"POST /api/obs/disable":                  "job:obs.disable",
	"/observability/":                        "view",
	"GET /ws/jobs":                           "view",
	"GET /ws/inventory":                      "view",
	"GET /ws/firewall":                       "view",
	"GET /ws/apps":                           "view",
	"GET /ws/updates":                        "view",
	"GET /ws/updates/system":                 "view",
	"GET /ws/mesh":                           "view",
	"GET /ws/bmc":                            "view",
	"GET /ws/alerts":                         "view",
}

// unsafeMethods are the methods a view route must not carry.
var unsafeMethods = []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// classProblems reports every route on m without exactly one class, and
// every rule that breaks a class invariant. open is the open-route registry
// and pinned the sign-in session routes.
func classProblems(m *routeMux, open, pinned map[string]string) []string {
	var out []string
	signin := m.SigninPatterns()
	admin := authz.For(authz.Subject{Sub: "probe-admin", Roles: []string{"admin"}})
	for _, p := range m.Patterns() {
		rule, ruled := m.Rule(p)
		_, isOpen := open[p]
		_, isPinned := pinned[p]
		switch {
		case signin[p] && ruled:
			out = append(out, p+": a rule on a sign-in pattern")
			continue
		case signin[p] && !isOpen && !isPinned:
			out = append(out, p+": an unclassified sign-in pattern; make it open, pin it in signinSessionRoutes, or gate it")
			continue
		case signin[p]:
			continue
		case isOpen && ruled:
			out = append(out, p+": a rule on an open route")
			continue
		case isOpen:
			continue
		case !ruled:
			out = append(out, p+": unclassified; register it through gate with its class")
			continue
		}
		out = append(out, ruleProblems(p, rule, admin)...)
	}
	for p := range pinned {
		if !signin[p] {
			out = append(out, p+": a stale signinSessionRoutes entry; no sign-in route has it")
		}
	}
	sort.Strings(out)
	return out
}

// ruleProblems reports what is wrong with rule on pattern p.
func ruleProblems(p string, rule routeRule, admin authz.Set) []string {
	var out []string
	method, path, ok := strings.Cut(p, " ")
	if !ok {
		method, path = "", p
	}
	read := method == http.MethodGet || method == http.MethodHead || method == ""
	switch rule.kind {
	case ruleNone:
		out = append(out, p+": the zero rule")
	case ruleNeed:
		if rule.need.Class == authz.ClassView && slices.Contains(unsafeMethods, method) {
			out = append(out, p+": view on an unsafe method")
		}
	case ruleJob, ruleAnyJob:
		if read {
			out = append(out, p+": a job rule on a read")
		}
	}
	if rule.kind == ruleJob {
		if len(rule.kinds) == 0 {
			out = append(out, p+": a job rule with no kinds")
		}
		for _, k := range rule.kinds {
			if err := admin.PermitsKindRoute(k); err != nil {
				out = append(out, fmt.Sprintf("%s: job kind %s refuses even an administrator (%v)", p, k, err))
			}
		}
	}
	if under(path, "/api/me") || under(path, "/ws/me") {
		if rule.kind != ruleNeed || rule.need != authz.NeedSelf() {
			out = append(out, p+": an /api/me or /ws/me route not classed self")
		}
	}
	if read && (under(path, "/api/accounts") || under(path, "/ws/accounts")) {
		if rule.kind != ruleNeed || rule.need != authz.AccountsRead() {
			out = append(out, p+": an Accounts read not classed AccountsRead")
		}
	}
	return out
}

// under reports whether path is root or below it.
func under(path, root string) bool { return path == root || strings.HasPrefix(path, root+"/") }

// idorProblems reports every self-classed route on m with no idorProbes
// entry, and every entry no self route has.
func idorProblems(m *routeMux, probes map[string]func(t *testing.T)) []string {
	var out []string
	self := map[string]bool{}
	for _, p := range m.Patterns() {
		if r, ok := m.Rule(p); ok && r.kind == ruleNeed && r.need == authz.NeedSelf() {
			self[p] = true
			if probes[p] == nil {
				out = append(out, p+": a self route with no IDOR probe in idorProbes")
			}
		}
	}
	for p := range probes {
		if !self[p] {
			out = append(out, p+": a stale idorProbes entry")
		}
	}
	sort.Strings(out)
	return out
}

// synthMux is a routeMux with one route per entry: a nil rule registers the
// route raw behind the session, as before #1002.
func synthMux(t *testing.T, f *apiFixture, routes map[string]*routeRule) *routeMux {
	t.Helper()
	m := newRouteMux()
	h := http.NotFoundHandler()
	for p, r := range routes {
		if r == nil {
			m.Handle(p, f.srv.auth.RequireSession(h))
			continue
		}
		f.srv.gate(m, p, *r, h)
	}
	return m
}

func rulePtr(r routeRule) *routeRule { return &r }

// mentions reports whether any problem names pattern.
func mentions(problems []string, pattern string) bool {
	for _, p := range problems {
		if strings.HasPrefix(p, pattern+":") {
			return true
		}
	}
	return false
}

// TC-1002-02: an unclassified route is reported; the real routes() has none,
// and a rule is recorded for all 115 gated patterns (112, and #321's three
// repair routes).
func TestRouteClasses_TC1002_02_EveryRouteIsClassified(t *testing.T) {
	f := routeFixture(t)
	m := synthMux(t, f, map[string]*routeRule{"POST /api/new-thing": nil, "GET /api/nodes": rulePtr(needs(authz.NeedView()))})
	if got := classProblems(m, openRoutes, signinSessionRoutes); !mentions(got, "POST /api/new-thing") || mentions(got, "GET /api/nodes") {
		t.Errorf("synthetic mux: %v, want only the unclassified route reported (beside the stale pins)", got)
	}
	real := f.srv.routes()
	if got := classProblems(real, openRoutes, signinSessionRoutes); len(got) != 0 {
		t.Errorf("routes() class problems:\n%s", strings.Join(got, "\n"))
	}
	if n := len(real.rules); n != 119 {
		t.Errorf("%d rules recorded, want 119", n)
	}
}

// TC-1002-13: classProblems reports each kind of misclass, naming its
// pattern, and passes the right ones.
func TestRouteClasses_TC1002_13_Misclasses(t *testing.T) {
	f := newAPIFixture(t)
	view, sys := rulePtr(needs(authz.NeedView())), rulePtr(needs(authz.NeedControl(authz.System)))
	bad := map[string]map[string]*routeRule{
		"(a) a rule on an open route":  {"GET /healthz": view},
		"(b) view on an unsafe method": {"POST /api/b": view, "PUT /api/b": view, "PATCH /api/b": view, "DELETE /api/b": view},
		"(c) a job rule on a GET":      {"GET /api/c": rulePtr(job("app.deploy"))},
		"(d) /api/me not self": {"GET /api/me": view, "PATCH /api/me": view, "GET /api/me/credentials": view,
			"GET /ws/me": view},
		"(e) Accounts reads not AccountsRead": {"GET /api/accounts": view, "GET /api/accounts/{id}": sys, "GET /ws/accounts": view},
		"(f) a job route an admin's floor refuses": {"POST /api/f1": rulePtr(job("identity.migrate")),
			"POST /api/f2": rulePtr(job("no.such.kind")), "POST /api/f3": rulePtr(job("os.identity_rollback"))},
	}
	for name, routes := range bad {
		got := classProblems(synthMux(t, f, routes), openRoutes, nil)
		for p := range routes {
			if !mentions(got, p) {
				t.Errorf("%s: %s not reported: %v", name, p, got)
			}
		}
	}
	// (g) a rule on a sign-in pattern.
	m := newRouteMux()
	m.signin = map[string]bool{"GET /api/auth/me": true}
	f.srv.gate(m, "GET /api/auth/me", needs(authz.NeedSelf()), http.NotFoundHandler())
	if got := classProblems(m, openRoutes, signinSessionRoutes); !mentions(got, "GET /api/auth/me") {
		t.Errorf("(g) a rule on a sign-in pattern not reported: %v", got)
	}
	// Not reported.
	good := synthMux(t, f, map[string]*routeRule{
		"GET /api/mesh/state": view, "GET /ws/mesh": view,
		"GET /api/me/credentials": rulePtr(needs(authz.NeedSelf())),
		"GET /api/accounts":       rulePtr(needs(authz.AccountsRead())),
	})
	if got := classProblems(good, openRoutes, nil); len(got) != 0 {
		t.Errorf("well-classed routes reported: %v", got)
	}
}

// TC-1002-14: the sign-in class is closed (F-1002-01). Every pattern
// auth.RegisterRoutes registers is open or pinned with a reason; a new one
// is reported, and so is a stale pin.
func TestRouteClasses_TC1002_14_SigninIsClosed(t *testing.T) {
	f := newAPIFixture(t)
	m := newRouteMux()
	f.srv.auth.RegisterRoutes(signinRegistrar{m})
	signin := m.SigninPatterns()
	// 14 since the move's bridge's four (geekdojo/geekdojo-brain#1005).
	if len(signin) != 14 {
		t.Errorf("auth.RegisterRoutes registered %d patterns, want 14", len(signin))
	}
	for p := range signin {
		why, ok := openRoutes[p]
		if !ok {
			why, ok = signinSessionRoutes[p]
		}
		if !ok || strings.TrimSpace(why) == "" {
			t.Errorf("sign-in pattern %s is neither open nor pinned with a reason", p)
		}
	}
	if got := classProblems(m, openRoutes, signinSessionRoutes); len(got) != 0 {
		t.Errorf("the sign-in routes: %v, want none", got)
	}

	signinRegistrar{m}.HandleFunc("POST /api/repair/actions/{id}", http.NotFound)
	pinned := map[string]string{"GET /api/auth/gone": "a route auth no longer registers"}
	for p, why := range signinSessionRoutes {
		pinned[p] = why
	}
	got := classProblems(m, openRoutes, pinned)
	if !mentions(got, "POST /api/repair/actions/{id}") || !mentions(got, "GET /api/auth/gone") || len(got) != 2 {
		t.Errorf("problems = %v, want the unpinned sign-in route and the stale pin", got)
	}
}

// TC-1002-03: AC 2's stand-in (F-1002-07). Alice's /api/auth/me with Bob's
// sub in the query answers only her own; and a self route with no IDOR probe
// fails the registry check, naming it.
func TestRouteClasses_TC1002_03_SelfRoutesHaveIDORProbes(t *testing.T) {
	f := routeFixture(t)
	alice := f.authenticateAs(t, "sub-alice-6d2e", "alice-name", "viewer")
	f.authenticateAs(t, "sub-bob-0c4a", "bob-name-8e1f", "admin")
	w := f.do(t, http.MethodGet, "/api/auth/me?sub=sub-bob-0c4a", "", alice)
	var me struct {
		Sub string `json:"sub"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &me) != nil || me.Sub != "sub-alice-6d2e" {
		t.Errorf("Alice's /api/auth/me = %d %s, want 200 with her own sub", w.Code, w.Body.String())
	}
	for _, bob := range []string{"sub-bob-0c4a", "bob-name-8e1f"} {
		if strings.Contains(w.Body.String(), bob) {
			t.Errorf("Alice's /api/auth/me holds %q: %s", bob, w.Body.String())
		}
	}

	self := synthMux(t, f, map[string]*routeRule{"GET /api/me/credentials": rulePtr(needs(authz.NeedSelf()))})
	if got := idorProblems(self, nil); !mentions(got, "GET /api/me/credentials") {
		t.Errorf("a self route without a probe: %v, want it reported", got)
	}
	if got := idorProblems(self, map[string]func(t *testing.T){"GET /api/me/credentials": func(*testing.T) {}}); len(got) != 0 {
		t.Errorf("a self route with a probe: %v, want none", got)
	}
	if got := idorProblems(f.srv.routes(), idorProbes); len(got) != 0 {
		t.Errorf("routes(): %v", got)
	}
	for p, probe := range idorProbes {
		t.Run(p, probe)
	}
}

// matrixRoles are the sessions every probe is sent with.
var matrixRoles = []struct {
	name  string
	roles []string
}{
	{"admin", []string{"admin"}},
	{"operator", []string{"operator"}},
	{"viewer", []string{"viewer"}},
	{"none", nil},
	{"superuser", []string{"superuser"}},
}

// wantOutcome is what the table says caps meets label with: whether it
// passes, and the code a refusal answers. It reads the label, never the
// recorded rule.
func wantOutcome(t *testing.T, label string, caps authz.Set) (bool, string) {
	t.Helper()
	switch {
	case label == "view":
		return caps.Has(authz.View), codeRouteNotPermitted
	case label == "self", label == "anyjob":
		return caps.Has(authz.Self), codeRouteNotPermitted
	case strings.HasPrefix(label, "control:"):
		c, ok := authz.ParseCapability(strings.TrimPrefix(label, "control:"))
		if !ok {
			t.Fatalf("label %q names no capability", label)
		}
		return caps.Has(c), codeRouteNotPermitted
	case strings.HasPrefix(label, "job:"):
		for _, k := range strings.Split(strings.TrimPrefix(label, "job:"), ",") {
			var kr *authz.KindRefusal
			if err := caps.PermitsKindRoute(k); errors.As(err, &kr) {
				return false, "job_" + kr.Code
			}
		}
		return true, ""
	}
	t.Fatalf("label %q is not a class", label)
	return false, ""
}

// TC-1002-04: the per-role matrix. Every recorded rule equals its literal
// table entry, both ways. Then every probe goes out for every role: where
// the table refuses, Handler() answers 403 with the right code and a
// correlation id; where it permits, the recorded rule registered through
// gate over a stub reaches the stub. A repair route answers every console
// role 401; a repair session reaches the repair routes alone, and every
// other route answers it 403 repair_only (geekdojo/geekdojo-brain#321).
func TestRouteClasses_TC1002_04_PerRoleMatrix(t *testing.T) {
	f := routeFixture(t)
	real := f.srv.routes()
	for p, want := range wantClass {
		r, ok := real.Rule(p)
		if !ok {
			t.Errorf("wantClass %s: no such gated route (stale entry)", p)
			continue
		}
		if got := r.label(); got != want {
			t.Errorf("%s: class %q, want %q", p, got, want)
		}
	}
	var gated []string
	for _, p := range real.Patterns() {
		if _, ok := real.Rule(p); !ok {
			continue
		}
		gated = append(gated, p)
		if _, ok := wantClass[p]; !ok {
			t.Errorf("%s: gated, but missing from wantClass", p)
		}
	}

	stubs := newRouteMux()
	reached := map[string]int{}
	for _, p := range gated {
		r, _ := real.Rule(p)
		f.srv.gate(stubs, p, r, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached[p]++
			w.WriteHeader(http.StatusTeapot)
		}))
	}

	refused, passed := 0, 0
	for _, role := range matrixRoles {
		sub := "sub-matrix-" + role.name
		cookie := f.authenticateAs(t, sub, "name-"+role.name, role.roles...)
		caps := authz.For(authz.Subject{Sub: sub, Roles: role.roles})
		for _, pr := range enumerateRoutes(t, gated) {
			what := fmt.Sprintf("%s %s %s", role.name, pr.method, pr.path)
			req := newProbeRequest(pr)
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			if strings.HasPrefix(wantClass[pr.pattern], "repair:") {
				// A console session is never a repair session (#321).
				f.handler.ServeHTTP(w, req)
				if w.Code != http.StatusUnauthorized {
					t.Errorf("%s: %d, want 401 on a repair route", what, w.Code)
				}
				refused++
				continue
			}
			permit, code := wantOutcome(t, wantClass[pr.pattern], caps)
			if !permit {
				f.handler.ServeHTTP(w, req)
				wantRefused(t, what, w, code)
				refused++
				continue
			}
			before := reached[pr.pattern]
			stubs.ServeHTTP(w, req)
			if w.Code != http.StatusTeapot || reached[pr.pattern] != before+1 {
				t.Errorf("%s: %d through the gate, want the stub reached", what, w.Code)
			}
			passed++
		}
	}
	// The repair-session row (geekdojo/geekdojo-brain#321): a live repair
	// session reaches exactly the repair routes, through the gate, and every
	// console route answers 403 repair_only.
	rr := &repairRig{f: f}
	rr.svc = newRepairService(t, rr, nil)
	f.srv.SetRepair(rr.svc)
	repair := rr.open(t, repairHost)
	repairCaps := breakglass.Session{}.Capabilities()
	repairRoutes := 0
	for _, pr := range enumerateRoutes(t, gated) {
		what := fmt.Sprintf("repair session %s %s", pr.method, pr.path)
		req := newProbeRequest(pr)
		req.Host = repairHost
		req.AddCookie(repair)
		w := httptest.NewRecorder()
		label, isRepair := strings.CutPrefix(wantClass[pr.pattern], "repair:")
		if !isRepair {
			f.handler.ServeHTTP(w, req)
			wantRefused(t, what, w, codeRepairOnly)
			refused++
			continue
		}
		if permit, _ := wantOutcome(t, label, repairCaps); !permit {
			t.Errorf("%s: the table refuses a repair session its own route", what)
		}
		before := reached[pr.pattern]
		stubs.ServeHTTP(w, req)
		if w.Code != http.StatusTeapot || reached[pr.pattern] != before+1 {
			t.Errorf("%s: %d through the gate, want the stub reached", what, w.Code)
		}
		passed++
		repairRoutes++
	}
	if repairRoutes != 3 {
		t.Errorf("the repair session reached %d repair routes, want 3", repairRoutes)
	}
	if refused == 0 || passed == 0 {
		t.Fatalf("%d refused and %d passed cells; the matrix is vacuous", refused, passed)
	}
	t.Logf("%d gated patterns: %d refused cells, %d permitted cells", len(gated), refused, passed)
}

// TC-1002-01: the serial console is control under bmc. A viewer's and an
// operator's upgrade are refused by the router, never 101 and never the
// handler; an administrator passes the router.
func TestRouteClasses_TC1002_01_SerialConsole(t *testing.T) {
	f := routeFixture(t)
	pr := routeProbe{pattern: "GET /ws/bmc/{nodeId}/sol", method: http.MethodGet, path: "/ws/bmc/n1/sol"}
	for _, role := range []string{"viewer", "operator"} {
		req := newProbeRequest(pr)
		req.AddCookie(f.authenticateAs(t, "sub-"+role, role, role))
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, req)
		wantRefused(t, role+" serial console", w, codeRouteNotPermitted)
	}
	needs := 0
	for _, r := range f.records(slog.LevelWarn, "api: request refused") {
		if attrs(r)["need"] == "control:bmc" {
			needs++
		}
	}
	if needs != 2 {
		t.Errorf("%d router refusals for the serial console, want 2", needs)
	}
	req := newProbeRequest(pr)
	req.AddCookie(f.authenticate(t))
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Code == http.StatusSwitchingProtocols || strings.Contains(w.Body.String(), codeRouteNotPermitted) {
		t.Errorf("admin serial console: %d %s, want the handler's own answer", w.Code, w.Body.String())
	}
	if n := len(f.records(slog.LevelWarn, "api: request refused")); n != 2 {
		t.Errorf("%d refusal records after the admin's request, want still 2", n)
	}
}

// TC-1002-05: the issue's named viewer refusals: power cycle, power reset,
// node update and system update are 403 job_not_permitted, with no rows and
// nothing on the bus.
func TestRouteClasses_TC1002_05_ViewerRefusals(t *testing.T) {
	f := newAPIFixture(t)
	for _, k := range []string{"bmc.power", "node.update", "system.update"} {
		f.runner.Register(noop(k))
	}
	viewer := f.authenticateAs(t, "sub-vic", "vic", "viewer")
	bus := recordBus(t, f.nc)
	for _, c := range []struct{ path, body string }{
		{"/api/bmc/n1/power/cycle", ""},
		{"/api/bmc/n1/power/reset", ""},
		{"/api/updates", `{"nodeId":"n1","bundleSha256":"ab"}`},
		{"/api/updates/system", `{"version":"2026.08.4"}`},
	} {
		w := f.do(t, http.MethodPost, c.path, c.body, viewer)
		wantRefused(t, "viewer POST "+c.path, w, "job_not_permitted")
		if e := coded(t, w); e.Error != "You don't have permission to run this job." {
			t.Errorf("viewer POST %s: sentence %q", c.path, e.Error)
		}
	}
	for _, k := range []string{"bmc.power", "node.update", "system.update"} {
		if got := f.rows(t, k); len(got) != 0 {
			t.Errorf("%s: %d rows, want none", k, len(got))
		}
	}
	if got := bus.seen(t, f.nc); len(got) != 0 {
		t.Errorf("the viewer's calls published %v, want nothing", got)
	}
}

// TC-1002-06: the Job floor lets a permitted role through: an operator's
// node update, system update and routine deploy are 202 with one row each
// created by the operator.
func TestRouteClasses_TC1002_06_OperatorJobsPass(t *testing.T) {
	f, _, _, _ := upgradeFixture(t)
	for _, k := range []string{"node.update", "system.update", "app.deploy"} {
		f.runner.Register(noop(k))
	}
	seedTieredApp(t, f, tcRoutineID, "vw", "vaultwarden", tileschema.TierRoutine)
	operator := f.authenticateAs(t, "sub-otto", "otto", "operator")
	for _, c := range []struct{ path, body string }{
		{"/api/updates", `{"nodeId":"n1","bundleSha256":"ab"}`},
		{"/api/updates/system", `{"version":"2026.08.4"}`},
		{"/api/apps/" + tcRoutineID + "/deploy", ""},
	} {
		if w := f.do(t, http.MethodPost, c.path, c.body, operator); w.Code != http.StatusAccepted {
			t.Errorf("operator POST %s: %d %s, want 202", c.path, w.Code, w.Body.String())
		}
	}
	f.runner.Wait()
	for _, k := range []string{"node.update", "system.update", "app.deploy"} {
		if got := f.rows(t, k); len(got) != 1 || got[0].CreatedBy != "sub-otto" {
			t.Errorf("%s rows = %v, want one created by sub-otto", k, got)
		}
	}
}

// TC-1002-07: the mesh pre-auth key list is control under mesh.
func TestRouteClasses_TC1002_07_MeshKeys(t *testing.T) {
	f := newAPIFixture(t)
	for _, role := range []string{"viewer", "operator"} {
		wantRefused(t, role+" GET /api/mesh/keys", f.do(t, http.MethodGet, "/api/mesh/keys", "", f.authenticateAs(t, "sub-"+role, role, role)),
			codeRouteNotPermitted)
	}
	if w := f.do(t, http.MethodGet, "/api/mesh/keys", "", f.authenticate(t)); w.Code != http.StatusOK {
		t.Errorf("admin GET /api/mesh/keys: %d %s, want 200", w.Code, w.Body.String())
	}
}

// TC-1002-08: F-1001-17. An operator's BMC configuration with an unlock is
// refused before anything is stored; an administrator's is accepted and
// stores it.
func TestRouteClasses_TC1002_08_BMCConfig(t *testing.T) {
	f := newAPIFixture(t)
	f.runner.Register(noop("bmc.configure"))
	for _, id := range []string{"self-node", "node-1"} {
		if err := f.inv.Insert(f.ctx, &proto.Node{ID: id, Role: proto.RoleCompute, Hostname: id,
			FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	st := f.setupSvc.Store()
	const unlock = "SENTINEL-UNLOCK-5a7b"
	body := `{"kind":"bitscope","hostNodeId":"self-node","config":{"targets":[{"pos":"A-0","node_id":"node-1"}],"unlock":"` + unlock + `"}}`
	before, _ := st.Get(f.ctx, setup.KeyBMCConfig)
	wantRefused(t, "operator POST /api/bmc/config", f.do(t, http.MethodPost, "/api/bmc/config", body,
		f.authenticateAs(t, "sub-otto", "otto", "operator")), codeRouteNotPermitted)
	if v, _ := st.Get(f.ctx, setup.KeyBMCBitscopeUnlock); v != "" {
		t.Error("the operator's unlock was stored")
	}
	if after, _ := st.Get(f.ctx, setup.KeyBMCConfig); after != before {
		t.Errorf("bmc.config changed: %q → %q", before, after)
	}
	if got := f.rows(t, "bmc.configure"); len(got) != 0 {
		t.Errorf("%d bmc.configure rows, want none", len(got))
	}
	if w := f.do(t, http.MethodPost, "/api/bmc/config", body, f.authenticate(t)); w.Code != http.StatusAccepted {
		t.Fatalf("admin POST /api/bmc/config: %d %s, want 202", w.Code, w.Body.String())
	}
	f.runner.Wait()
	if v, _ := st.Get(f.ctx, setup.KeyBMCBitscopeUnlock); v == "" {
		t.Error("the administrator's unlock was not stored")
	}
}

// TC-1002-09: F-1001-11. An operator's and a viewer's console root password
// is refused before anything is stored, logged or started.
func TestRouteClasses_TC1002_09_ConsoleRootPassword(t *testing.T) {
	f := newAPIFixture(t)
	f.runner.Register(noop(console.PushKind))
	for _, role := range []string{"operator", "viewer"} {
		wantRefused(t, role+" PUT /api/console/root-password", f.do(t, http.MethodPut, "/api/console/root-password",
			`{"password":"`+testConsolePassword+`"}`, f.authenticateAs(t, "sub-"+role, role, role)), codeRouteNotPermitted)
	}
	if id, err := f.console.CurrentHashID(f.ctx); err != nil || id != "" {
		t.Errorf("a password was stored: %q, %v", id, err)
	}
	if n := len(f.records(slog.LevelInfo, "console: console root password set")); n != 0 {
		t.Errorf("%d INFO change records, want none", n)
	}
	if got := f.rows(t, console.PushKind); len(got) != 0 {
		t.Errorf("%d %s rows, want none", len(got), console.PushKind)
	}
}

// TC-1002-10: F-1001-11. An operator's setup mode change and dns-forward
// intent writes are refused with nothing changed and no job; an
// administrator's mode change is applied.
func TestRouteClasses_TC1002_10_SetupModeAndIntents(t *testing.T) {
	f := newAPIFixture(t)
	f.hasFirewallNode = true
	registerDNSForwardStub(f)
	f.runner.Register(noop("firewall.set_active"))
	now := time.Now().UTC()
	fwd := &firewall.Intent{ID: "fwd", Kind: string(proto.IntentDNSForward), Name: "DNS-Forward-Internal", Enabled: true,
		Spec: json.RawMessage(`{"zone":"test1.internal","target":"192.168.1.2"}`), CreatedAt: now, UpdatedAt: now}
	if err := f.fw.CreateIntent(f.ctx, fwd); err != nil {
		t.Fatal(err)
	}
	st := f.setupSvc.Store()
	modeBefore, _ := st.Get(f.ctx, setup.KeyMode)
	operator := f.authenticateAs(t, "sub-otto", "otto", "operator")
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/setup/mode", `{"mode":"lan_peer"}`},
		{http.MethodPost, "/api/firewall/intents", `{"kind":"dns_forward","name":"x","enabled":true,"spec":{}}`},
		{http.MethodPatch, "/api/firewall/intents/fwd", `{"enabled":false}`},
		{http.MethodDelete, "/api/firewall/intents/fwd", ""},
	} {
		wantRefused(t, "operator "+c.method+" "+c.path, f.do(t, c.method, c.path, c.body, operator), codeRouteNotPermitted)
	}
	if m, _ := st.Get(f.ctx, setup.KeyMode); m != modeBefore {
		t.Errorf("mode changed: %q → %q", modeBefore, m)
	}
	list, err := f.fw.ListIntents(f.ctx)
	if err != nil || len(list) != 1 || !list[0].Enabled || list[0].ID != "fwd" {
		t.Errorf("intents after the refusals = %+v, %v; want the forward alone and unchanged", list, err)
	}
	for _, k := range []string{"firewall.set_active", "firewall.dns_forward"} {
		if got := f.rows(t, k); len(got) != 0 {
			t.Errorf("%s: %d rows, want none", k, len(got))
		}
	}
	if w := f.do(t, http.MethodPost, "/api/setup/mode", `{"mode":"lan_peer"}`, f.authenticate(t)); w.Code != http.StatusOK {
		t.Fatalf("admin POST /api/setup/mode: %d %s, want 200", w.Code, w.Body.String())
	}
	f.runner.Wait()
	if m, _ := st.Get(f.ctx, setup.KeyMode); m != "lan_peer" {
		t.Errorf("admin's mode = %q, want lan_peer", m)
	}
}

// TC-1002-11: a person with no role holds only self. Reads, streams and the
// observability proxy are refused; /api/auth/me reports ["self"]; and
// POST /api/jobs for a self kind on their own account passes the router.
func TestRouteClasses_TC1002_11_NoRole(t *testing.T) {
	f := routeFixture(t)
	nora := f.authenticateAs(t, "sub-nora", "nora")
	for _, pr := range []routeProbe{
		{method: http.MethodGet, path: "/api/nodes"},
		{method: http.MethodGet, path: "/api/jobs"},
		{method: http.MethodGet, path: "/ws/jobs"},
		{method: http.MethodGet, path: "/observability/x"},
		{method: http.MethodPost, path: "/observability/x"},
	} {
		req := newProbeRequest(pr)
		req.AddCookie(nora)
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, req)
		wantRefused(t, "no role "+pr.method+" "+pr.path, w, codeRouteNotPermitted)
	}
	w := f.do(t, http.MethodGet, "/api/auth/me", "", nora)
	var me struct {
		Capabilities []string `json:"capabilities"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &me) != nil || !slices.Equal(me.Capabilities, []string{"self"}) {
		t.Errorf("no role /api/auth/me = %d %s, want 200 with capabilities [self]", w.Code, w.Body.String())
	}
	w = f.do(t, http.MethodPost, "/api/jobs", `{"kind":"accounts.rename_credential","spec":{"accountId":"sub-nora"}}`, nora)
	if w.Code != http.StatusBadRequest {
		t.Errorf("no role POST /api/jobs own rename: %d %s, want 400 (authorized, no workflow)", w.Code, w.Body.String())
	}
}

// TC-1002-12: an unknown role fails closed (ERR-CLOSED), case included.
func TestRouteClasses_TC1002_12_UnknownRole(t *testing.T) {
	f := newAPIFixture(t)
	for _, role := range []string{"superuser", "Admin"} {
		c := f.authenticateAs(t, "sub-"+role, role, role)
		wantRefused(t, role+" GET /api/nodes", f.do(t, http.MethodGet, "/api/nodes", "", c), codeRouteNotPermitted)
		wantRefused(t, role+" DELETE /api/nodes/n1", f.do(t, http.MethodDelete, "/api/nodes/n1", "", c), codeRouteNotPermitted)
	}
}

// TC-1002-18: a router refusal writes one WARN with the correlation id, the
// pattern, the code and the need or the kinds, and nothing personal.
func TestRouteClasses_TC1002_18_RefusalLogging(t *testing.T) {
	f := routeFixture(t)
	viewer := f.authenticateAs(t, "sub-vic-3b8f", "vic-name-77aa", "viewer")
	const appID = "app-5e1d-sentinel"
	const sentinel = "BODY-SENTINEL-41c9"

	req := newProbeRequest(routeProbe{method: http.MethodGet, path: "/ws/bmc/node-7c1e/sol"})
	req.AddCookie(viewer)
	sol := httptest.NewRecorder()
	f.handler.ServeHTTP(sol, req)
	wantRefused(t, "viewer serial console", sol, codeRouteNotPermitted)
	compose := f.do(t, http.MethodPut, "/api/apps/"+appID+"/compose", `{"composeYaml":"`+sentinel+`"}`, viewer)
	wantRefused(t, "viewer compose", compose, "job_not_permitted")

	recs := f.records(slog.LevelWarn, "api: request refused")
	if len(recs) != 2 {
		t.Fatalf("%d refusal records, want 2", len(recs))
	}
	if a := attrs(recs[0]); a["correlation_id"] != coded(t, sol).CorrelationID || a["route"] != "GET /ws/bmc/{nodeId}/sol" ||
		a["code"] != codeRouteNotPermitted || a["need"] != "control:bmc" {
		t.Errorf("serial console refusal attrs = %v", a)
	}
	if a := attrs(recs[1]); a["correlation_id"] != coded(t, compose).CorrelationID || a["route"] != "PUT /api/apps/{id}/compose" ||
		a["code"] != "job_not_permitted" || a["kind"] != "app.upgrade,app.edit,app.revert" {
		t.Errorf("compose refusal attrs = %v", a)
	}
	f.logs.mu.Lock()
	all := append([]slog.Record(nil), f.logs.recs...)
	f.logs.mu.Unlock()
	for _, secret := range []string{"sub-vic-3b8f", "vic-name-77aa", "node-7c1e", appID, sentinel} {
		for _, w := range []*httptest.ResponseRecorder{sol, compose} {
			if strings.Contains(w.Body.String(), secret) {
				t.Errorf("a response holds %q: %s", secret, w.Body.String())
			}
		}
		for _, r := range all {
			if text := r.Message + fmt.Sprint(attrs(r)); strings.Contains(text, secret) {
				t.Errorf("a log record holds %q: %s", secret, text)
			}
		}
	}
}

// TC-1002-19: the router refuses before the body is read (SEC-INPUT): a
// malformed or oversized body is 403, never 400 or 413.
func TestRouteClasses_TC1002_19_RefusedBeforeTheBody(t *testing.T) {
	f := newAPIFixture(t)
	viewer := f.authenticateAs(t, "sub-vic", "vic", "viewer")
	operator := f.authenticateAs(t, "sub-otto", "otto", "operator")
	big := `{"pad":"` + strings.Repeat("x", 2<<20) + `"}`
	for _, c := range []struct{ who, method, path, body string }{
		{"viewer", http.MethodPost, "/api/bmc/config", "{"},
		{"viewer", http.MethodPost, "/api/bmc/config", big},
		{"operator", http.MethodPut, "/api/console/root-password", "{"},
		{"operator", http.MethodPut, "/api/console/root-password", big},
	} {
		cookie := viewer
		if c.who == "operator" {
			cookie = operator
		}
		wantRefused(t, fmt.Sprintf("%s %s %s (%d bytes)", c.who, c.method, c.path, len(c.body)),
			f.do(t, c.method, c.path, c.body, cookie), codeRouteNotPermitted)
	}
}

// TC-1002-20: F-1002-02. An operator's tier-raising catalog upgrade, with
// consent, is refused by the runner before the consent is written; an
// administrator's identical request records the consent in their name.
func TestRouteClasses_TC1002_20_ConsentAfterAuthorization(t *testing.T) {
	f, admin, _, _ := upgradeFixtureWith(t, hostTrustingBundleTile())
	seedTieredApp(t, f, haID, "ha", "homeassistant", tileschema.TierRoutine)
	operator := f.authenticateAs(t, "sub-otto", "otto", "operator")
	const body = `{"source":"catalog","acceptPrivilegeTier":"host-trusting"}`

	wantRefused(t, "operator consented upgrade", f.do(t, http.MethodPut, "/api/apps/"+haID+"/compose", body, operator), "job_not_permitted")
	row, err := f.appsStore.Get(f.ctx, haID)
	if err != nil || row.PrivilegeAck != nil {
		t.Errorf("consent after the operator's refusal = %+v, %v; want none", row.PrivilegeAck, err)
	}
	if got := f.rows(t, "app.upgrade"); len(got) != 0 {
		t.Errorf("%d app.upgrade rows, want none", len(got))
	}

	if w := f.do(t, http.MethodPut, "/api/apps/"+haID+"/compose", body, admin); w.Code != http.StatusAccepted {
		t.Fatalf("admin consented upgrade: %d %s, want 202", w.Code, w.Body.String())
	}
	waitForJobs(t, f.runner)
	row, err = f.appsStore.Get(f.ctx, haID)
	if err != nil || row.PrivilegeAck == nil || row.PrivilegeAck.By != "alice" {
		t.Errorf("consent after the admin's upgrade = %+v, %v; want one by alice", row.PrivilegeAck, err)
	}
}

// F-1002-02: a consent write that finds another compose in place answers
// the same 409 it did before the write moved into prepare, and nothing runs.
func TestRouteClasses_ConsentComposeChangedIs409(t *testing.T) {
	f, _, _, _ := upgradeFixtureWith(t, hostTrustingBundleTile())
	seedTieredApp(t, f, haID, "ha", "homeassistant", tileschema.TierRoutine)
	// The handler read the app; its compose changes before the consent lands.
	r := httptest.NewRequest(http.MethodPut, "/api/apps/"+haID+"/compose", nil)
	r.Pattern = "PUT /api/apps/{id}/compose"
	r = r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Sub: "sub-alice", Name: "alice", Roles: []string{"admin"}}))
	w := httptest.NewRecorder()
	f.srv.submitComposeJob(w, r, "app.upgrade", apps.ComposeChangeSpec{AppID: haID}, func(string) error {
		return apps.ErrComposeChanged
	})
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "compose changed") {
		t.Errorf("compose changed: %d %s, want the 409", w.Code, w.Body.String())
	}
	if got := f.rows(t, "app.upgrade"); len(got) != 0 {
		t.Errorf("%d app.upgrade rows, want none", len(got))
	}
}
