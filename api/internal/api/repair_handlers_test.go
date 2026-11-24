package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/restart"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// The break-glass endpoints (geekdojo/geekdojo-brain#321) over the real
// breakglass.Service, the real router and the real runner.

const (
	repairHost = "ci.local"
	repairIP   = "192.0.2.1"
)

type repairAlerts struct {
	mu               sync.Mutex
	issued, redeemed int
}

func (a *repairAlerts) RaiseBreakGlassIssued(context.Context, string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.issued++
	return nil
}

func (a *repairAlerts) RaiseBreakGlassRedeemed(context.Context, string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.redeemed++
	return nil
}

type repairIdentity struct{ st identitystate.State }

func (r *repairIdentity) State(context.Context) (identitystate.State, error) { return r.st, nil }

type repairRig struct {
	f       *apiFixture
	svc     *breakglass.Service
	rec     *logkittest.Recorder
	bmcHost bool
	// out collects every body and header the rig's requests were answered
	// with, for TC-321-25's search.
	out strings.Builder
}

// newRepairRig is an api fixture with the break-glass service wired, its
// console at ci.local and its LAN address 192.0.2.1. identity nil is a
// control plane with no sign-in service; register registers
// identity.restart on the runner.
func newRepairRig(t *testing.T, identity breakglass.Identity, register bool) *repairRig {
	t.Helper()
	f := routeFixture(t)
	r := &repairRig{f: f}
	r.svc = newRepairService(t, r, identity)
	f.srv.SetRepair(r.svc)
	f.handler = f.srv.Handler()
	if register {
		rs, err := restart.New(restart.Deps{
			Run:  func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
			Held: func(context.Context) bool { return false }, Restoring: func() (string, bool) { return "", false },
			DBUnit: "keycloak-db.service", Unit: "keycloak.service", Log: slog.New(slog.DiscardHandler), StepTimeout: time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		f.runner.Register(rs.Workflow())
	}
	return r
}

func newRepairService(t *testing.T, r *repairRig, identity breakglass.Identity) *breakglass.Service {
	t.Helper()
	log, rec := logkittest.New()
	r.rec = rec
	n := 0
	svc, err := breakglass.New(breakglass.Deps{
		Now: time.Now, Rand: rand.Reader, IDs: func() string { n++; return fmt.Sprintf("ev-%d", n) }, Log: log,
		Alerts: &repairAlerts{}, Jobs: r.f.jobsStore, Identity: identity,
		Busy: func(context.Context) (string, bool) { return "", false },
		Facts: breakglass.Facts{ConsoleHost: repairHost, PrimaryIP: func() net.IP { return net.ParseIP(repairIP) },
			BMCHost: func() bool { return r.bmcHost }},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// issue makes a code as the command does and hands its hash to the service.
func (r *repairRig) issue(t *testing.T) string {
	t.Helper()
	b := make([]byte, 13)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)[:20]
	if err := r.svc.Issue(context.Background(), breakglass.Hash([]byte(code))); err != nil {
		t.Fatal(err)
	}
	return code
}

// req is one request to host from remote (ip:port) through Handler().
type req struct {
	method, path, host, remote, body string
	cookies                          []*http.Cookie
	header                           http.Header
	bare                             bool // the router alone, without the outer origin layers
}

func (r *repairRig) do(q req) *httptest.ResponseRecorder {
	if q.host == "" {
		q.host = repairHost
	}
	hr := httptest.NewRequest(q.method, "https://"+q.host+q.path, strings.NewReader(q.body))
	hr.Host = q.host
	if q.remote != "" {
		hr.RemoteAddr = q.remote
	}
	if q.body != "" {
		hr.Header.Set("Content-Type", "application/json")
	}
	for k, vs := range q.header {
		for _, v := range vs {
			hr.Header.Add(k, v)
		}
	}
	for _, c := range q.cookies {
		hr.AddCookie(c)
	}
	w := httptest.NewRecorder()
	if q.bare {
		r.f.srv.routes().ServeHTTP(w, hr)
	} else {
		r.f.handler.ServeHTTP(w, hr)
	}
	r.out.WriteString(w.Body.String())
	for k, vs := range w.Header() {
		r.out.WriteString(k + ": " + strings.Join(vs, ",") + "\n")
	}
	return w
}

func codeBody(code string) string {
	b, _ := json.Marshal(map[string]string{"code": code})
	return string(b)
}

// redeem posts code at host from remote.
func (r *repairRig) redeem(code, host, remote string) *httptest.ResponseRecorder {
	return r.do(req{method: http.MethodPost, path: "/api/auth/break-glass", host: host, remote: remote, body: codeBody(code)})
}

// repairCookieOf is the repair cookie w set, or nil.
func repairCookieOf(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == repairCookieName && c.Value != "" {
			return c
		}
	}
	return nil
}

// open redeems a fresh code at host and returns the session's cookie.
func (r *repairRig) open(t *testing.T, host string) *http.Cookie {
	t.Helper()
	w := r.redeem(r.issue(t), host, "")
	c := repairCookieOf(w)
	if w.Code != http.StatusOK || c == nil {
		t.Fatalf("redeem at %s: %d %s", host, w.Code, w.Body.String())
	}
	return c
}

func (r *repairRig) state(cookie *http.Cookie, host string) *httptest.ResponseRecorder {
	cs := []*http.Cookie{}
	if cookie != nil {
		cs = append(cs, cookie)
	}
	return r.do(req{method: http.MethodGet, path: "/api/repair/state", host: host, cookies: cs})
}

// wantCoded asserts w is status with code, a sentence and a correlation id.
func wantCoded(t *testing.T, what string, w *httptest.ResponseRecorder, status int, code string) codedError {
	t.Helper()
	if w.Code != status {
		t.Fatalf("%s: %d %s, want %d %s", what, w.Code, w.Body.String(), status, code)
	}
	e := coded(t, w)
	if e.Code != code || e.CorrelationID == "" || !strings.HasSuffix(e.Error, ".") {
		t.Fatalf("%s: body %+v, want %s with a sentence and a correlation id", what, e, code)
	}
	return e
}

// TC-321-08: one code at a time. With A and then B issued, A answers 401
// repair_code_wrong and B redeems.
func TestRepair_OneCodeAtATime_TC321_08(t *testing.T) {
	r := newRepairRig(t, &repairIdentity{st: identitystate.Failed}, false)
	a := r.issue(t)
	b := r.issue(t)
	wantCoded(t, "A after B", r.redeem(a, repairHost, ""), http.StatusUnauthorized, codeRepairCodeWrong)
	if w := r.redeem(b, repairHost, ""); w.Code != http.StatusOK || repairCookieOf(w) == nil {
		t.Fatalf("B: %d %s", w.Code, w.Body.String())
	}
	// TC-321-09 (a): a redeemed code is gone.
	wantCoded(t, "B again", r.redeem(b, repairHost, ""), http.StatusUnauthorized, codeRepairCodeNone)
}

// TC-321-10: five wrong codes refuse a source, keyed by its address without
// the port; forwarding headers change nothing. The sixth, even with A, is
// 429; another source redeems A; a new code lets the first source in again.
func TestRepair_FiveWrongRefuseASource_TC321_10(t *testing.T) {
	r := newRepairRig(t, &repairIdentity{st: identitystate.Failed}, false)
	a := r.issue(t)
	forged := http.Header{"X-Forwarded-For": {"192.0.2.99"}, "Forwarded": {"for=192.0.2.98"}, "X-Real-Ip": {"192.0.2.97"}}
	for i := range 5 {
		w := r.do(req{method: http.MethodPost, path: "/api/auth/break-glass", remote: fmt.Sprintf("192.0.2.10:%d", 40000+i),
			body: codeBody("WRONGWRONGWRONGWRONG"), header: forged})
		wantCoded(t, fmt.Sprintf("wrong %d", i+1), w, http.StatusUnauthorized, codeRepairCodeWrong)
	}
	w := r.do(req{method: http.MethodPost, path: "/api/auth/break-glass", remote: "192.0.2.10:50000", body: codeBody(a), header: forged})
	e := wantCoded(t, "the sixth, with A", w, http.StatusTooManyRequests, codeRepairSourceRefused)
	if e.Error != "This device sent five wrong repair codes, so it can't try again until a new code is made." {
		t.Errorf("sentence %q", e.Error)
	}
	if w := r.redeem(a, repairHost, "192.0.2.11:1"); w.Code != http.StatusOK {
		t.Fatalf("A from 192.0.2.11: %d %s", w.Code, w.Body.String())
	}
	b := r.issue(t)
	if w := r.redeem(b, repairHost, "192.0.2.10:2"); w.Code != http.StatusOK {
		t.Fatalf("B from 192.0.2.10 after the new code: %d %s", w.Code, w.Body.String())
	}
	recs := r.f.logs.withAttr("event", "breakglass.redeem_refused")
	if len(recs) != 6 {
		t.Fatalf("%d redeem_refused records, want 6", len(recs))
	}
	for _, rec := range recs {
		src, _ := recAttr(rec, "source")
		reason, _ := recAttr(rec, "reason")
		if rec.Level != slog.LevelWarn || src != "192.0.2.10" || (reason != "wrong_code" && reason != "source_refused") {
			t.Errorf("record %v source %q reason %q", rec.Level, src, reason)
		}
	}
}

// TC-321-11: with no code outstanding, ten attempts each answer 401
// repair_code_none, and the source is not refused: a code issued afterwards
// redeems from it.
func TestRepair_NoCodeOutstanding_TC321_11(t *testing.T) {
	r := newRepairRig(t, &repairIdentity{st: identitystate.Failed}, false)
	for i := range 10 {
		e := wantCoded(t, fmt.Sprintf("attempt %d", i+1), r.redeem("ABCDEABCDEABCDEABCDE", repairHost, "192.0.2.20:1"),
			http.StatusUnauthorized, codeRepairCodeNone)
		if e.Error != "No repair code is waiting. Run rasputin-api repair-code on the control plane first." {
			t.Fatalf("sentence %q", e.Error)
		}
	}
	if w := r.redeem(r.issue(t), repairHost, "192.0.2.20:1"); w.Code != http.StatusOK {
		t.Fatalf("after the issue: %d %s", w.Code, w.Body.String())
	}
}

// TC-321-12: a code typed in lower case with spaces and dashes redeems.
func TestRepair_TypedCodeTolerance_TC321_12(t *testing.T) {
	r := newRepairRig(t, &repairIdentity{st: identitystate.Failed}, false)
	a := r.issue(t)
	typed := strings.ToLower(a[:5]) + " - " + a[5:10] + "-" + strings.ToLower(a[10:15]) + " " + a[15:]
	if w := r.redeem(typed, repairHost, ""); w.Code != http.StatusOK || repairCookieOf(w) == nil {
		t.Fatalf("%q: %d %s", typed, w.Code, w.Body.String())
	}
}

// TC-321-13: a code redeems at the console's name and at the LAN address
// only. Any other host, the mesh address, the home sign-in door's name, or
// an Origin header that differs from the Host is 403 repair_origin, and the
// console's origin allowlist never gains the IP.
func TestRepair_TwoOriginsOnly_TC321_13(t *testing.T) {
	r := newRepairRig(t, &repairIdentity{st: identitystate.Failed}, false)
	before := r.f.srv.auth.Origins().Origins()
	for _, host := range []string{repairHost, repairIP} {
		if w := r.redeem(r.issue(t), host, ""); w.Code != http.StatusOK {
			t.Fatalf("at %s: %d %s", host, w.Code, w.Body.String())
		}
	}
	for _, host := range []string{"other.local", "100.64.0.1", "sso-ci.local", "ci.local:8443"} {
		a := r.issue(t)
		wantCoded(t, host, r.redeem(a, host, ""), http.StatusForbidden, codeRepairOrigin)
	}
	a := r.issue(t)
	w := r.do(req{method: http.MethodPost, path: "/api/auth/break-glass", body: codeBody(a), bare: true,
		header: http.Header{"Origin": {"https://other.local"}}})
	wantCoded(t, "a differing Origin at the router", w, http.StatusForbidden, codeRepairOrigin)
	if w := r.do(req{method: http.MethodPost, path: "/api/auth/break-glass", body: codeBody(a),
		header: http.Header{"Origin": {"https://other.local"}}}); w.Code != http.StatusForbidden || repairCookieOf(w) != nil {
		t.Errorf("a differing Origin through Handler: %d, want 403 with no cookie", w.Code)
	}
	w = r.do(req{method: http.MethodPost, path: "/api/auth/break-glass", body: codeBody(a),
		header: http.Header{"Origin": {"https://" + repairHost}}})
	if w.Code != http.StatusOK {
		t.Errorf("a matching Origin: %d %s", w.Code, w.Body.String())
	}
	after := r.f.srv.auth.Origins().Origins()
	if !slices.Equal(before, after) {
		t.Errorf("allowlist %v became %v", before, after)
	}
	for _, o := range after {
		if strings.Contains(o, repairIP) {
			t.Errorf("the allowlist holds the IP: %v", after)
		}
	}
}

// TC-321-14: the code travels only in the body. A code in the query string
// with an empty body is refused and the code stays outstanding; a body over
// 1 KiB is refused.
func TestRepair_CodeOnlyInTheBody_TC321_14(t *testing.T) {
	r := newRepairRig(t, &repairIdentity{st: identitystate.Failed}, false)
	a := r.issue(t)
	e := wantCoded(t, "in the query", r.do(req{method: http.MethodPost, path: "/api/auth/break-glass?code=" + a}),
		http.StatusBadRequest, codeRepairCodeBody)
	if e.Error != "Send the repair code in the form, not the address." {
		t.Errorf("sentence %q", e.Error)
	}
	wantCoded(t, "an empty body", r.do(req{method: http.MethodPost, path: "/api/auth/break-glass"}), http.StatusBadRequest, codeRepairCodeBody)
	wantCoded(t, "over 1 KiB", r.do(req{method: http.MethodPost, path: "/api/auth/break-glass",
		body: codeBody(a + strings.Repeat(" ", 1100))}), http.StatusBadRequest, codeRepairCodeBody)
	if w := r.redeem(a, repairHost, ""); w.Code != http.StatusOK {
		t.Fatalf("A from the body afterwards: %d %s", w.Code, w.Body.String())
	}
}

// TC-321-15: the repair cookie is HttpOnly, Secure, SameSite=Strict, Path=/,
// with no Domain and seven days' Max-Age, and is bound to its origin.
func TestRepair_CookieAndOriginBinding_TC321_15(t *testing.T) {
	r := newRepairRig(t, &repairIdentity{st: identitystate.Failed}, false)
	c := r.open(t, repairIP)
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || c.MaxAge != 7*24*3600 {
		t.Errorf("cookie %+v", c)
	}
	if w := r.state(c, repairIP); w.Code != http.StatusOK {
		t.Fatalf("at its own origin: %d %s", w.Code, w.Body.String())
	}
	wantCoded(t, "the IP's session at the name", r.state(c, repairHost), http.StatusUnauthorized, codeRepairSessionRequired)
	c = r.open(t, repairHost)
	wantCoded(t, "the name's session at the IP", r.state(c, repairIP), http.StatusUnauthorized, codeRepairSessionRequired)
	if w := r.do(req{method: http.MethodGet, path: "/api/repair/state", cookies: []*http.Cookie{c, c}}); w.Code != http.StatusBadRequest {
		t.Errorf("two repair cookies: %d", w.Code)
	}
}

// TC-321-16: each end fact ends the session: a newer redemption, END, an
// administrator's sign-in and a fresh Service, each with its INFO record.
func TestRepair_SessionEndFacts_TC321_16(t *testing.T) {
	r := newRepairRig(t, &repairIdentity{st: identitystate.Failed}, false)
	old := r.open(t, repairHost)
	cur := r.open(t, repairHost)
	wantCoded(t, "the older session", r.state(old, repairHost), http.StatusUnauthorized, codeRepairSessionRequired)
	if w := r.state(cur, repairHost); w.Code != http.StatusOK {
		t.Fatalf("the newer session: %d", w.Code)
	}
	if w := r.do(req{method: http.MethodPost, path: "/api/repair/end", cookies: []*http.Cookie{cur}}); w.Code != http.StatusOK {
		t.Fatalf("END: %d %s", w.Code, w.Body.String())
	} else if c := w.Result().Cookies(); len(c) != 1 || c[0].MaxAge >= 0 {
		t.Errorf("END did not clear the cookie: %v", c)
	}
	wantCoded(t, "after END", r.state(cur, repairHost), http.StatusUnauthorized, codeRepairSessionRequired)

	cur = r.open(t, repairHost)
	r.svc.AdminSignedIn(context.Background())
	wantCoded(t, "after an admin's sign-in", r.state(cur, repairHost), http.StatusUnauthorized, codeRepairSessionRequired)

	cur = r.open(t, repairHost)
	fresh := newRepairService(t, r, &repairIdentity{st: identitystate.Failed})
	r.f.srv.SetRepair(fresh)
	wantCoded(t, "after an api restart", r.state(cur, repairHost), http.StatusUnauthorized, codeRepairSessionRequired)
}

// TC-321-16's records: each end writes INFO breakglass.session_ended with its
// reason.
func TestRepair_SessionEndRecords_TC321_16(t *testing.T) {
	r := newRepairRig(t, &repairIdentity{st: identitystate.Failed}, false)
	r.open(t, repairHost)
	cur := r.open(t, repairHost)
	r.do(req{method: http.MethodPost, path: "/api/repair/end", cookies: []*http.Cookie{cur}})
	r.open(t, repairHost)
	r.svc.AdminSignedIn(context.Background())
	var reasons []string
	for _, rec := range r.rec.AtLevel(slog.LevelInfo) {
		if ev, _ := logkittest.Attr(rec, "event"); ev == "breakglass.session_ended" {
			reason, _ := logkittest.Attr(rec, "reason")
			reasons = append(reasons, reason)
		}
	}
	if got := strings.Join(reasons, ","); got != "newer,operator,admin_signin" {
		t.Errorf("session_ended reasons %s", got)
	}
}

// TC-321-18: with a repair session and no console session, console routes
// answer 403 repair_only with the sentence and a correlation id; with the
// session ended, 401; with a console session alone, as before.
func TestRepair_EverythingElseIs403_TC321_18(t *testing.T) {
	r := newRepairRig(t, &repairIdentity{st: identitystate.Failed}, false)
	c := r.open(t, repairHost)
	routes := []req{
		{method: http.MethodPost, path: "/api/jobs", body: `{"kind":"node.reboot","spec":{"nodeId":"n1"}}`},
		{method: http.MethodPost, path: "/api/bmc/n1/power/cycle", body: "{}"},
		{method: http.MethodGet, path: "/api/nodes"},
	}
	before := len(r.f.rows(t, "node.reboot"))
	for _, q := range routes {
		q.cookies = []*http.Cookie{c}
		e := wantCoded(t, q.method+" "+q.path, r.do(q), http.StatusForbidden, codeRepairOnly)
		if e.Error != "A repair session can only repair sign-in." {
			t.Errorf("sentence %q", e.Error)
		}
	}
	if len(r.f.rows(t, "node.reboot")) != before {
		t.Error("a job row was created for the repair session")
	}
	r.svc.AdminSignedIn(context.Background())
	for _, q := range routes {
		q.cookies = []*http.Cookie{c}
		if w := r.do(q); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with the session ended: %d, want 401", q.method, q.path, w.Code)
		}
	}
	console := r.f.authenticateAs(t, "sub-admin", "admin", "admin")
	if w := r.do(req{method: http.MethodGet, path: "/api/nodes", cookies: []*http.Cookie{console}}); w.Code != http.StatusOK {
		t.Errorf("GET /api/nodes with a console session: %d %s", w.Code, w.Body.String())
	}
}

// TC-321-19: RESTART through the repair route submits identity.restart by
// "break-glass" and the page lists it; a console session alone and no
// session are 401; with the kind unregistered the answer is job_unavailable
// and, with no sign-in service, RESTART is not offered as enabled.
func TestRepair_Restart_TC321_19(t *testing.T) {
	r := newRepairRig(t, &repairIdentity{st: identitystate.Failed}, true)
	c := r.open(t, repairHost)
	w := r.do(req{method: http.MethodPost, path: "/api/repair/restart", cookies: []*http.Cookie{c}})
	if w.Code != http.StatusAccepted {
		t.Fatalf("restart: %d %s", w.Code, w.Body.String())
	}
	rows := r.f.rows(t, restart.Kind)
	if len(rows) != 1 || rows[0].CreatedBy != "break-glass" {
		t.Fatalf("rows %+v, want one identity.restart by break-glass", rows)
	}
	var st breakglass.StateView
	if err := json.Unmarshal(r.state(c, repairHost).Body.Bytes(), &st); err != nil || len(st.Jobs) != 1 || st.Jobs[0].ID != rows[0].ID {
		t.Errorf("state jobs %+v %v", st.Jobs, err)
	}
	console := r.f.authenticateAs(t, "sub-admin", "admin", "admin")
	for name, cs := range map[string][]*http.Cookie{"a console session": {console}, "no session": nil} {
		if w := r.do(req{method: http.MethodPost, path: "/api/repair/restart", cookies: cs}); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, w.Code)
		}
	}

	off := newRepairRig(t, nil, false)
	c = off.open(t, repairHost)
	wantCoded(t, "unregistered", off.do(req{method: http.MethodPost, path: "/api/repair/restart", cookies: []*http.Cookie{c}}),
		http.StatusServiceUnavailable, codeJobUnavailable)
	if err := json.Unmarshal(off.state(c, repairHost).Body.Bytes(), &st); err != nil || st.Actions[0].Enabled {
		t.Errorf("identity off: RESTART %+v %v", st.Actions, err)
	}
}

// TC-321-21 (the endpoints): GET /api/repair/ways lists only the ways, the
// serial console only without the BMC-host marker; GET /api/repair/state
// answers 401 without a session and the state, actions and jobs with one.
func TestRepair_WaysAndState_TC321_21(t *testing.T) {
	r := newRepairRig(t, &repairIdentity{st: identitystate.Failed}, false)
	for _, marker := range []bool{false, true} {
		r.bmcHost = marker
		w := r.do(req{method: http.MethodGet, path: "/api/repair/ways"})
		var body map[string]json.RawMessage
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil {
			t.Fatalf("ways: %d %s", w.Code, w.Body.String())
		}
		keys := []string{}
		for k := range body {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, []string{"signInAt", "urls", "ways"}) {
			t.Errorf("ways keys %v", keys)
		}
		if serial := strings.Contains(string(body["ways"]), `"serial"`); serial == marker {
			t.Errorf("marker %v: serial listed %v", marker, serial)
		}
		if !strings.Contains(string(body["ways"]), "ssh -t root@ci.local rasputin-api repair-code") {
			t.Errorf("ways %s", body["ways"])
		}
	}
	wantCoded(t, "state without a session", r.state(nil, repairHost), http.StatusUnauthorized, codeRepairSessionRequired)
	c := r.open(t, repairHost)
	var st breakglass.StateView
	if err := json.Unmarshal(r.state(c, repairHost).Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Sentence == "" || len(st.Actions) != 1 || st.Actions[0].Label != "RESTART" || st.Jobs == nil {
		t.Errorf("state %+v", st)
	}
}

// TC-321-25: across issue, redemption, every refusal and the session's end,
// the code, its hash and the cookie appear in no log record, no response
// body or header, and no Location.
func TestRepair_NoSecretLeaves_TC321_25(t *testing.T) {
	r := newRepairRig(t, &repairIdentity{st: identitystate.Failed}, true)
	var secrets []string
	add := func(code string) {
		h := sha256.Sum256([]byte(code))
		secrets = append(secrets, code, hex.EncodeToString(h[:]))
	}
	a := r.issue(t)
	add(a)
	r.redeem("WRONGWRONGWRONGWRONG", repairHost, "")
	r.redeem(a, "other.local", "")
	r.do(req{method: http.MethodPost, path: "/api/auth/break-glass?code=" + a})
	w := r.redeem(a, repairHost, "")
	c := repairCookieOf(w)
	if c == nil {
		t.Fatalf("redeem: %d", w.Code)
	}
	r.redeem(a, repairHost, "")
	r.do(req{method: http.MethodGet, path: "/api/nodes", cookies: []*http.Cookie{c}})
	r.do(req{method: http.MethodPost, path: "/api/repair/restart", cookies: []*http.Cookie{c}})
	r.state(c, repairHost)
	r.do(req{method: http.MethodPost, path: "/api/repair/end", cookies: []*http.Cookie{c}})
	for range 5 {
		r.redeem("WRONGWRONGWRONGWRONG", repairHost, "192.0.2.30:1")
	}
	r.redeem(r.issue(t), repairHost, "192.0.2.30:1")

	var logs strings.Builder
	logs.WriteString(r.rec.Text())
	r.f.logs.mu.Lock()
	for _, rec := range r.f.logs.recs {
		logs.WriteString(rec.Message)
		rec.Attrs(func(a slog.Attr) bool { logs.WriteString(" " + a.Key + "=" + a.Value.String()); return true })
		logs.WriteString("\n")
	}
	r.f.logs.mu.Unlock()
	out := strings.ReplaceAll(r.out.String(), repairCookieName+"="+c.Value, "") // the one Set-Cookie that carries it
	for _, s := range append(secrets, c.Value) {
		if strings.Contains(logs.String(), s) {
			t.Errorf("a log record carries %q", s)
		}
	}
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("a response carries %q", s)
		}
	}
	if strings.Count(r.out.String(), c.Value) != 1 {
		t.Errorf("the cookie value appears %d times in the responses, want only its Set-Cookie", strings.Count(r.out.String(), c.Value))
	}
	if strings.Contains(r.out.String(), "Location:") {
		t.Error("a response carried a Location")
	}
}

// requestOrigin and requestSource are the endpoint's parsing.
func TestRepair_RequestParsing(t *testing.T) {
	hr := httptest.NewRequest(http.MethodGet, "https://CI.local/", nil)
	if o, same := requestOrigin(hr); o != "https://ci.local" || !same {
		t.Errorf("origin %q %v", o, same)
	}
	hr.Header.Add("Origin", "https://ci.local")
	hr.Header.Add("Origin", "https://evil.example")
	if _, same := requestOrigin(hr); same {
		t.Error("a second differing Origin passed")
	}
	hr.Host = "bad host"
	if _, same := requestOrigin(hr); same {
		t.Error("an unparseable host passed")
	}
	hr.RemoteAddr = "[::ffff:192.0.2.5]:443"
	if a, ok := requestSource(hr); !ok || a.String() != "192.0.2.5" {
		t.Errorf("source %v %v", a, ok)
	}
	hr.RemoteAddr = "garbage"
	if _, ok := requestSource(hr); ok {
		t.Error("a garbage remote parsed")
	}
}

// Without SetRepair the open routes answer 503 and the repair routes 401.
func TestRepair_Unwired(t *testing.T) {
	f := routeFixture(t)
	r := &repairRig{f: f}
	wantCoded(t, "redeem", r.do(req{method: http.MethodPost, path: "/api/auth/break-glass", body: codeBody("x")}),
		http.StatusServiceUnavailable, codeRepairUnavailable)
	wantCoded(t, "ways", r.do(req{method: http.MethodGet, path: "/api/repair/ways"}), http.StatusServiceUnavailable, codeRepairUnavailable)
	wantCoded(t, "state", r.do(req{method: http.MethodGet, path: "/api/repair/state"}), http.StatusUnauthorized, codeRepairSessionRequired)
}
