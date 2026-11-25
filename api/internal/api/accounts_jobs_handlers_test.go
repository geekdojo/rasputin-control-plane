package api

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// The account change route (geekdojo/geekdojo-brain#994): the real
// accounts.Requests and kind table over a runner that records what is
// submitted, and a sign-in installed so a fresh change can be prepared.

// submitted records each job a request submitted.
type submitted struct {
	mu   sync.Mutex
	jobs []string
}

func (s *submitted) SubmitFor(_ context.Context, by authz.Submitter, kind string, _ any, prepare func(string) error) (*jobs.Job, error) {
	if prepare != nil {
		if err := prepare("job-1"); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs = append(s.jobs, kind+" by "+by.CreatedBy())
	return &jobs.Job{ID: "job-1", Kind: kind}, nil
}

// targetFacts are every account's facts: a complete viewer.
type targetFacts struct{ err error }

func (f targetFacts) Facts(_ context.Context, sub string) (authz.AccountFacts, error) {
	return authz.AccountFacts{Sub: sub, Roles: []string{"viewer"}, Enabled: true, HoldsSecondStep: true, HoldsRecoveryCodes: true}, f.err
}

func accountJobsRoute(t *testing.T, signIn bool) (*apiFixture, *submitted) {
	t.Helper()
	f := newAPIFixture(t)
	if signIn {
		table, err := doors.New("ci")
		if err != nil {
			t.Fatal(err)
		}
		actions := map[string]auth.Action{}
		for _, k := range accounts.FreshKinds {
			actions[k] = noopAction{}
		}
		si, err := auth.NewSignIn(auth.SignInDeps{Door: table.Home, ConsoleHost: "ci.local", ClientID: flows.ConsoleClient, Realm: "rasputin",
			Exchanger: unusedExchange{}, Verifier: unusedTokens{}, Ender: unusedEnder{}, Ready: readyNow{}, Sessions: f.sessions,
			FirstRun: f.authSvc, Claimer: unusedClaimer{}, Observer: unusedObserver{},
			Actions: actions, Clock: syncedClock{}, Now: time.Now, Rand: rand.Reader, Log: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		f.authSvc.SetSignIn(si)
	}
	kp, err := authz.NewKindPolicy(noAppFacts{})
	if err != nil {
		t.Fatal(err)
	}
	sub := &submitted{}
	rq, err := accounts.NewRequests(accounts.RequestsDeps{Authorizer: kp, Runner: sub, Held: accounts.NewHeld(), Facts: targetFacts{},
		Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetAccountRequests(rq)
	return f, sub
}

func postAccountJob(f *apiFixture, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/accounts/jobs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	return w
}

// TC-994-30: the route takes a role-less person's own changes (sign_out,
// set_display_name and rename_credential submit; remove_credential needs a
// fresh sign-in), refuses a viewer's set_roles for someone else with the
// kind table's code, and answers 401 with no session. TC-994-05 (the
// route's part): the fresh answer is the action's start.
func TestAccountJobs_TC994_30_TheRoute(t *testing.T) {
	f, sub := accountJobsRoute(t, true)
	me := f.authenticateAs(t, "sub-self", "self")
	for _, c := range []struct{ name, body string }{
		{"sign_out", `{"kind":"accounts.sign_out","spec":{"accountId":"sub-self"}}`},
		{"set_display_name", `{"kind":"accounts.set_display_name","spec":{"accountId":"sub-self"},"value":"Ana"}`},
		{"rename_credential", `{"kind":"accounts.rename_credential","spec":{"accountId":"sub-self","credentialId":"c1"},"value":"Phone"}`},
	} {
		w := postAccountJob(f, c.body, me)
		if w.Code != http.StatusAccepted || strings.TrimSpace(w.Body.String()) != `{"job":"job-1"}` {
			t.Errorf("%s: %d %s", c.name, w.Code, w.Body.String())
		}
	}
	if len(sub.jobs) != 3 {
		t.Errorf("submitted %v", sub.jobs)
	}
	w := postAccountJob(f, `{"kind":"accounts.remove_credential","spec":{"accountId":"sub-self","credentialId":"c1"}}`, me)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"next":"/api/auth/signin?action=accounts.remove_credential"}` ||
		!strings.Contains(w.Header().Get("Set-Cookie"), "pending") || len(sub.jobs) != 3 {
		t.Errorf("remove_credential: %d %s, jobs %v", w.Code, w.Body.String(), sub.jobs)
	}
	viewer := f.authenticateAs(t, "sub-v", "v", "viewer")
	w = postAccountJob(f, `{"kind":"accounts.set_roles","spec":{"accountId":"sub-self","role":"viewer"}}`, viewer)
	if e := coded(t, w); w.Code != http.StatusForbidden || e.Code != "job_not_permitted" {
		t.Errorf("a viewer's set_roles: %d %+v", w.Code, e)
	}
	if w := postAccountJob(f, `{"kind":"accounts.sign_out","spec":{"accountId":"sub-self"}}`, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d", w.Code)
	}
}

// TC-994-20 (the route's part): every malformed body is 400
// invalid_request with a fixed cause, an unknown kind 404, and no record
// carries what was submitted.
func TestAccountJobs_TC994_20_Input(t *testing.T) {
	f, sub := accountJobsRoute(t, true)
	admin := f.authenticateAs(t, "sub-alice", "alice", "admin")
	const secretish = "sentinel-value-994"
	for _, c := range []struct {
		name, body string
		status     int
		code       string
	}{
		{"unknown kind", `{"kind":"accounts.grant_designated_role","spec":{"accountId":"sub-bob"}}`, 404, "unknown_kind"},
		{"not JSON", `{"kind":`, 400, "invalid_request"},
		{"no kind", `{"spec":{"accountId":"sub-bob"}}`, 400, "invalid_request"},
		{"an unknown body field", `{"kind":"accounts.enable","spec":{"accountId":"sub-bob"},"extra":"` + secretish + `"}`, 400, "invalid_request"},
		{"too large", `{"kind":"accounts.set_display_name","spec":{"accountId":"sub-bob"},"value":"` + strings.Repeat("x", 9<<10) + `"}`, 400, "invalid_request"},
		{"an unknown spec field", `{"kind":"accounts.enable","spec":{"accountId":"sub-bob","x":"` + secretish + `"}}`, 400, "invalid_request"},
		{"no spec", `{"kind":"accounts.enable"}`, 400, "invalid_request"},
		{"a value it takes none of", `{"kind":"accounts.enable","spec":{"accountId":"sub-bob"},"value":"` + secretish + `"}`, 400, "invalid_request"},
		{"no value", `{"kind":"accounts.set_email","spec":{"accountId":"sub-bob"}}`, 400, "invalid_request"},
		{"a bad address", `{"kind":"accounts.set_email","spec":{"accountId":"sub-bob"},"value":"` + secretish + `"}`, 400, "invalid_request"},
		{"a long name", `{"kind":"accounts.set_display_name","spec":{"accountId":"sub-bob"},"value":"` + strings.Repeat("n", 256) + `"}`, 400, "invalid_request"},
		{"a control character", `{"kind":"accounts.set_display_name","spec":{"accountId":"sub-bob"},"value":"a\u0007` + secretish + `"}`, 400, "invalid_request"},
	} {
		w := postAccountJob(f, c.body, admin)
		if e := coded(t, w); w.Code != c.status || e.Code != c.code || e.CorrelationID == "" {
			t.Errorf("%s: %d %+v, want %d %s", c.name, w.Code, e, c.status, c.code)
		}
	}
	if len(sub.jobs) != 0 {
		t.Errorf("submitted %v", sub.jobs)
	}
	for _, r := range f.logs.recs {
		text := r.Message
		r.Attrs(func(a slog.Attr) bool { text += " " + a.Value.String(); return true })
		if strings.Contains(text, secretish) {
			t.Errorf("a record holds the submitted value: %s", text)
		}
	}
	if recs := f.logs.withAttr("cause", "value_email"); len(recs) != 1 {
		t.Errorf("%d value_email records", len(recs))
	}
}

// TC-994-21 (the route's part): with no sign-in a fresh change answers 503
// no_signin; with no requests installed every change answers 503
// identity_not_ready; a kind-table refusal is 403 job_<code>; a submit
// error is 503.
func TestAccountJobs_TC994_21_DependencyDown(t *testing.T) {
	f, _ := accountJobsRoute(t, false)
	admin := f.authenticateAs(t, "sub-alice", "alice", "admin")
	w := postAccountJob(f, `{"kind":"accounts.set_roles","spec":{"accountId":"sub-bob","role":"admin"}}`, admin)
	if e := coded(t, w); w.Code != http.StatusServiceUnavailable || e.Code != "identity_not_ready" || len(f.logs.withAttr("cause", "no_signin")) != 1 {
		t.Errorf("no sign-in: %d %+v", w.Code, e)
	}
	w = postAccountJob(f, `{"kind":"accounts.enable","spec":{"accountId":"sub-alice"}}`, admin)
	if e := coded(t, w); w.Code != http.StatusForbidden || e.Code != "job_own_account" {
		t.Errorf("own account: %d %+v", w.Code, e)
	}
	kp, _ := authz.NewKindPolicy(noAppFacts{})
	rq, err := accounts.NewRequests(accounts.RequestsDeps{Authorizer: kp, Runner: failingRunner{}, Held: accounts.NewHeld(), Facts: targetFacts{},
		Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetAccountRequests(rq)
	w = postAccountJob(f, `{"kind":"accounts.enable","spec":{"accountId":"sub-bob"}}`, admin)
	if e := coded(t, w); w.Code != http.StatusServiceUnavailable || e.Code != "identity_not_ready" {
		t.Errorf("a submit error: %d %+v", w.Code, e)
	}
	g := newAPIFixture(t)
	w = postAccountJob(g, `{"kind":"accounts.enable","spec":{"accountId":"sub-bob"}}`, g.authenticateAs(t, "sub-alice", "alice", "admin"))
	if e := coded(t, w); w.Code != http.StatusServiceUnavailable || e.Code != "identity_not_ready" {
		t.Errorf("unset: %d %+v", w.Code, e)
	}
}

type failingRunner struct{}

func (failingRunner) SubmitFor(context.Context, authz.Submitter, string, any, func(string) error) (*jobs.Job, error) {
	return nil, errors.New("the ledger is down")
}
