package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/move"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/restart"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
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
	resets           []string
}

func (a *repairAlerts) RaiseBreakGlassReset(_ context.Context, _, account string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.resets = append(a.resets, account)
	return nil
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
	// resets and move are the reset and C9's state the service is given;
	// alerts are its alerts.
	resets breakglass.Resets
	move   breakglass.MoveState
	alerts *repairAlerts
}

// newRepairRig is an api fixture with the break-glass service wired, its
// console at ci.local and its LAN address 192.0.2.1. identity nil is a
// control plane with no sign-in service; register registers
// identity.restart on the runner.
func newRepairRig(t *testing.T, identity breakglass.Identity, register bool) *repairRig {
	t.Helper()
	return newRepairRigWith(t, identity, register, func(*repairRig) {})
}

// newRepairRigWith is newRepairRig with wire run on the rig before the
// service is built, to give it a reset or C9's state.
func newRepairRigWith(t *testing.T, identity breakglass.Identity, register bool, wire func(*repairRig)) *repairRig {
	t.Helper()
	f := routeFixture(t)
	r := &repairRig{f: f}
	wire(r)
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
		Alerts: r.alertsOrNew(), Jobs: r.f.jobsStore, Identity: identity, Resets: r.resets, Move: r.move,
		Busy: func(context.Context) (string, bool) { return "", false },
		Facts: breakglass.Facts{ConsoleHost: repairHost, PrimaryIP: func() net.IP { return net.ParseIP(repairIP) },
			BMCHost: func() bool { return r.bmcHost }},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func (r *repairRig) alertsOrNew() *repairAlerts {
	if r.alerts == nil {
		r.alerts = &repairAlerts{}
	}
	return r.alerts
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
// and, for a job that is registered but can't be recorded, job_start_failed
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

	// Registered, but the job ledger can't be written: not "can't run here".
	broken := newRepairRig(t, &repairIdentity{st: identitystate.Failed}, true)
	c = broken.open(t, repairHost)
	if err := broken.f.jobsStore.Close(); err != nil {
		t.Fatal(err)
	}
	e := wantCoded(t, "a failed ledger write", broken.do(req{method: http.MethodPost, path: "/api/repair/restart", cookies: []*http.Cookie{c}}),
		http.StatusInternalServerError, codeJobStartFailed)
	if e.Error != sentenceJobStartFailed {
		t.Errorf("a failed ledger write: %q, want %q", e.Error, sentenceJobStartFailed)
	}
	recs := broken.f.logs.withAttr("event", "breakglass.job_failed")
	if len(recs) != 1 || recs[0].Level != slog.LevelError {
		t.Fatalf("a failed ledger write: %d breakglass.job_failed records, want one at ERROR", len(recs))
	}
	if id, _ := recAttr(recs[0], "correlation_id"); id != e.CorrelationID {
		t.Errorf("a failed ledger write: the record's correlation id %q, the body's %q", id, e.CorrelationID)
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

// ---- the reset and the move (geekdojo/geekdojo-brain#321 PR 2) ----

// apiResets is the repair reset over the fixture's real runner: Submit
// submits accounts.repair_reset for the session's submitter unless
// submitErr is set.
type apiResets struct {
	runner    *jobs.Runner
	targets   []accounts.RepairTarget
	submitErr error
}

func (a *apiResets) Targets(context.Context) ([]accounts.RepairTarget, error) { return a.targets, nil }

func (a *apiResets) Confirm(_ context.Context, id string) (accounts.RepairTarget, string, error) {
	for _, t := range a.targets {
		if t.ID == id {
			return t, "tok-" + id, nil
		}
	}
	return accounts.RepairTarget{}, "", accounts.ErrNotRepairTarget
}

func (a *apiResets) Submit(ctx context.Context, by authz.Submitter, id string, _ secret.Value) (*jobs.Job, error) {
	if a.submitErr != nil {
		return nil, a.submitErr
	}
	return a.runner.SubmitFor(ctx, by, accounts.RepairResetKind, accounts.ResetSpec{AccountID: id}, nil)
}

// resetRepairRig is a repair rig with the reset wired over the fixture's
// runner, registered when register is true, and a live session.
func resetRepairRig(t *testing.T, register bool) (*repairRig, *apiResets, *http.Cookie) {
	t.Helper()
	var res *apiResets
	r := newRepairRigWith(t, &repairIdentity{st: identitystate.Failed}, false, func(r *repairRig) {
		res = &apiResets{runner: r.f.runner, targets: []accounts.RepairTarget{{ID: "sub-alice", Username: "alice"}}}
		r.resets = res
	})
	if register {
		r.f.runner.Register(noop(accounts.RepairResetKind))
	}
	return r, res, r.open(t, repairHost)
}

func (r *repairRig) post(path, body string, c *http.Cookie) *httptest.ResponseRecorder {
	cs := []*http.Cookie{}
	if c != nil {
		cs = append(cs, c)
	}
	return r.do(req{method: http.MethodPost, path: path, body: body, cookies: cs})
}

// confirmBody is a 409 repair_confirm's body.
type confirmBody struct {
	Error         string             `json:"error"`
	Code          string             `json:"code"`
	CorrelationID string             `json:"correlationId"`
	StateToken    string             `json:"stateToken"`
	Account       *breakglass.Target `json:"account"`
	Accounts      *int               `json:"accounts"`
}

func wantConfirm(t *testing.T, what string, w *httptest.ResponseRecorder) confirmBody {
	t.Helper()
	var b confirmBody
	if w.Code != http.StatusConflict || json.Unmarshal(w.Body.Bytes(), &b) != nil || b.Code != codeRepairConfirm || b.CorrelationID == "" {
		t.Fatalf("%s: %d %s, want 409 repair_confirm", what, w.Code, w.Body.String())
	}
	return b
}

// logText is every captured server record, rendered.
func (r *repairRig) logText() string {
	var b strings.Builder
	r.f.logs.mu.Lock()
	defer r.f.logs.mu.Unlock()
	for _, rec := range r.f.logs.recs {
		b.WriteString(rec.Message)
		rec.Attrs(func(a slog.Attr) bool { b.WriteString(" " + a.Key + "=" + a.Value.String()); return true })
		b.WriteString("\n")
	}
	return b.String() + r.rec.Text()
}

// TC-321-46: POST /api/repair/reset's answers, and the password nowhere.
func TestRepair_Reset_TC321_46(t *testing.T) {
	password := strings.Join([]string{"zebra", "quantum", "otter", "9471"}, "-") // synthetic test password, built so it reads as no key
	r, res, c := resetRepairRig(t, true)
	before := len(r.f.logs.withAttr("code", codeRepairConfirm))

	for name, body := range map[string]string{"not JSON": "{", "no accountId": `{"stateToken":"x"}`,
		"over the cap": `{"accountId":"` + strings.Repeat("a", maxRepairActionBody) + `"}`} {
		wantCoded(t, name, r.post("/api/repair/reset", body, c), http.StatusBadRequest, codeInvalidRequest)
	}
	b := wantConfirm(t, "no token", r.post("/api/repair/reset", `{"accountId":"sub-alice"}`, c))
	if b.StateToken != "tok-sub-alice" || b.Account == nil || *b.Account != (breakglass.Target{ID: "sub-alice", Name: "alice"}) ||
		!strings.Contains(b.Error, "alice") || !strings.HasSuffix(b.Error, sentenceRepairResetNext) {
		t.Errorf("no token: %+v", b)
	}
	if b = wantConfirm(t, "stale token", r.post("/api/repair/reset", `{"accountId":"sub-alice","stateToken":"old"}`, c)); b.StateToken != "tok-sub-alice" {
		t.Errorf("stale token: %+v", b)
	}
	if n := len(r.f.logs.withAttr("code", codeRepairConfirm)); n != before {
		t.Errorf("a 409 wrote %d refusal records", n-before)
	}
	wantCoded(t, "no password", r.post("/api/repair/reset", `{"accountId":"sub-alice","stateToken":"tok-sub-alice"}`, c),
		http.StatusBadRequest, codeInvalidRequest)
	wantCoded(t, "a non-target", r.post("/api/repair/reset", `{"accountId":"sub-bob"}`, c), http.StatusForbidden, codeRepairResetTarget)

	confirmed := `{"accountId":"sub-alice","stateToken":"tok-sub-alice","password":"` + password + `"}`
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{&accounts.PasswordRefused{Rule: "denylist", Sentence: "That password is too common. Choose another."}, http.StatusBadRequest, codePasswordRefused},
		{accounts.ErrPasswordCheckUnavailable, http.StatusServiceUnavailable, codePasswordCheckUnavailable},
		{fmt.Errorf("%w: down", accounts.ErrIdentityUnavailable), http.StatusServiceUnavailable, codeIdentityNotReady},
		{&authz.KindRefusal{Code: authz.CodeNotPermitted, Sentence: "You don't have permission to run this job."}, http.StatusForbidden, "job_not_permitted"},
		{fmt.Errorf("submit: %w", jobs.ErrUnknownKind), http.StatusServiceUnavailable, codeJobUnavailable},
		{errors.New("the ledger is gone"), http.StatusInternalServerError, codeJobStartFailed},
	} {
		res.submitErr = tc.err
		e := wantCoded(t, tc.code, r.post("/api/repair/reset", confirmed, c), tc.status, tc.code)
		if tc.code == codePasswordRefused && e.Error != "That password is too common. Choose another." {
			t.Errorf("refused: %q", e.Error)
		}
	}
	if n := len(r.f.logs.withAttr("event", "breakglass.job_failed")); n != 1 {
		t.Errorf("%d breakglass.job_failed records, want one", n)
	}
	res.submitErr = nil

	w := r.post("/api/repair/reset", confirmed, c)
	if w.Code != http.StatusAccepted {
		t.Fatalf("confirmed: %d %s", w.Code, w.Body.String())
	}
	rows := r.f.rows(t, accounts.RepairResetKind)
	if len(rows) != 1 || rows[0].CreatedBy != "break-glass" || strings.Contains(string(rows[0].Spec), password) {
		t.Fatalf("rows %+v", rows)
	}
	if len(r.alerts.resets) != 1 || r.alerts.resets[0] != "sub-alice" {
		t.Errorf("reset alerts %v", r.alerts.resets)
	}
	wantCoded(t, "after a reset", r.post("/api/repair/reset", confirmed, c), http.StatusForbidden, codeRepairResetUsed)

	console := r.f.authenticateAs(t, "sub-admin", "admin", "admin")
	for name, ck := range map[string]*http.Cookie{"a console session": console, "no session": nil} {
		if w := r.post("/api/repair/reset", confirmed, ck); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, w.Code)
		}
	}
	if strings.Contains(r.out.String(), password) || strings.Contains(r.logText(), password) {
		t.Error("the password appears in a response or a log record")
	}

	// Unregistered kind, and off keycloak (no reset wired: TC-321-52).
	un, _, uc := resetRepairRig(t, false)
	wantCoded(t, "unregistered", un.post("/api/repair/reset", confirmed, uc), http.StatusServiceUnavailable, codeJobUnavailable)
	off := newRepairRig(t, nil, false)
	oc := off.open(t, repairHost)
	wantCoded(t, "off keycloak", off.post("/api/repair/reset", confirmed, oc), http.StatusServiceUnavailable, codeJobUnavailable)
	var st breakglass.StateView
	if err := json.Unmarshal(off.state(oc, repairHost).Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	for _, a := range st.Actions {
		if a.ID == "reset" || a.ID == "move" {
			t.Errorf("off keycloak lists %+v", a)
		}
	}
}

// apiMove is C9's state, as the kind table and the service both read it.
type apiMove struct {
	mu        sync.Mutex
	r         breakglass.MoveRepair
	tokenErr  error
	repairErr error
}

func (m *apiMove) RepairToken(context.Context) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.r.Token, m.r.Holds, m.tokenErr
}

func (m *apiMove) Repair(context.Context) (breakglass.MoveRepair, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.r, m.repairErr
}

type noAppTiers struct{}

func (noAppTiers) AppFacts(context.Context, string, string) (authz.AppFacts, error) {
	return authz.AppFacts{}, errors.New("no apps")
}

// TC-321-47: POST /api/repair/move's answers, decided by the real kind
// table over C9's state.
func TestRepair_Move_TC321_47(t *testing.T) {
	m := &apiMove{r: breakglass.MoveRepair{Holds: true, Accounts: 3, Token: "tok-3"}}
	if breakglass.MoveKind != move.Kind {
		t.Fatalf("breakglass.MoveKind %q is not move.Kind %q", breakglass.MoveKind, move.Kind)
	}
	r := newRepairRigWith(t, &repairIdentity{st: identitystate.Failed}, false, func(r *repairRig) { r.move = m })
	policy, err := authz.NewKindPolicy(noAppTiers{}, authz.WithMoveState(m))
	if err != nil {
		t.Fatal(err)
	}
	runner, err := jobs.NewAuthorizedRunner(r.f.jobsStore, r.f.nc, policy)
	if err != nil {
		t.Fatal(err)
	}
	runner.Register(noop(move.Kind))
	r.f.srv.runner = runner
	c := r.open(t, repairHost)

	b := wantConfirm(t, "no token", r.post("/api/repair/move", "", c))
	if b.Accounts == nil || *b.Accounts != 3 || b.StateToken != "tok-3" || b.Error != moveConfirmSentence(3) ||
		!strings.HasPrefix(b.Error, "This brings back the 3 accounts this cluster had before its sign-in update, with no passwords") {
		t.Errorf("no token: %+v", b)
	}
	if b = wantConfirm(t, "stale", r.post("/api/repair/move", `{"stateToken":"old"}`, c)); b.StateToken != "tok-3" {
		t.Errorf("stale: %+v", b)
	}
	if !strings.Contains(moveConfirmSentence(1), "the 1 account this cluster") {
		t.Errorf("N = 1: %q", moveConfirmSentence(1))
	}
	m.repairErr = errors.New("db")
	e := wantCoded(t, "state unread", r.post("/api/repair/move", "", c), http.StatusServiceUnavailable, codeIdentityNotReady)
	if e.Error != "The accounts from before the update couldn't be read. Try again." {
		t.Errorf("state unread: %q", e.Error)
	}
	m.repairErr = nil
	wantCoded(t, "a bad body", r.post("/api/repair/move", "{", c), http.StatusBadRequest, codeInvalidRequest)

	w := r.post("/api/repair/move", `{"stateToken":"tok-3"}`, c)
	if w.Code != http.StatusAccepted {
		t.Fatalf("confirmed: %d %s", w.Code, w.Body.String())
	}
	rows := r.f.rows(t, move.Kind)
	if len(rows) != 1 || rows[0].CreatedBy != "break-glass" || string(rows[0].Spec) != `{"repair":true,"stateToken":"tok-3"}` {
		t.Fatalf("rows %+v", rows)
	}
	var st breakglass.StateView
	if err := json.Unmarshal(r.state(c, repairHost).Body.Bytes(), &st); err != nil || len(st.Jobs) != 1 || st.Jobs[0].ID != rows[0].ID {
		t.Errorf("state jobs %+v %v", st.Jobs, err)
	}
	if recs := r.f.logs.withAttr("event", "breakglass.move_submitted"); len(recs) != 1 || recs[0].Level != slog.LevelWarn {
		t.Errorf("move_submitted records %d", len(recs))
	} else if id, _ := recAttr(recs[0], "job_id"); id != rows[0].ID {
		t.Errorf("job_id %q", id)
	}

	m.mu.Lock()
	m.r.Holds = false
	m.mu.Unlock()
	wantCoded(t, "not holding", r.post("/api/repair/move", `{"stateToken":"tok-3"}`, c), http.StatusForbidden, "job_move_state")
	m.tokenErr = errors.New("db")
	wantCoded(t, "the table's read fails", r.post("/api/repair/move", `{"stateToken":"tok-3"}`, c), http.StatusInternalServerError, codeJobCheckFailed)
	console := r.f.authenticateAs(t, "sub-admin", "admin", "admin")
	if w := r.post("/api/repair/move", `{"stateToken":"tok-3"}`, console); w.Code != http.StatusUnauthorized {
		t.Errorf("a console session: %d, want 401", w.Code)
	}
}
