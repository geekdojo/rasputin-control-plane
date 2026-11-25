package identitytest

// Identity 4.12's account changes against the real identity service
// (geekdojo/geekdojo-brain#994; TC-994-36 to TC-994-41): inside
// TestConsole_AgainstPinnedKeycloak, the reset rig (the console rig with
// #991's accounts and #992's runner the kind table decides) layered on the
// console rig, with accounts.Requests, accounts.Changes, the designated-role
// grant and its observer as main wires them: the observer told of every
// console callback and, as a sink of the sign-in history drain, of every
// sign-in at either door. The fresh-gated kinds' action is the console
// sign-in's. Requests are decided as POST /api/accounts/jobs decides them
// (accounts.Requests, then the sign-in's PrepareAction for a fresh one);
// the route itself is TC-994-30's.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/sessions"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

type accountsRig struct {
	*resetRig
	requests *accounts.Requests
	// actor is an enabled administrator holding an authenticator app, with
	// a console session (cookie) and the app's secret (otpSecret).
	actor    auth.Principal
	actorPw  secret.Value
	actorOTP string
	cookie   secret.Value
	acctLog  *logkittest.Recorder
}

func newAccountsRig(t *testing.T, c *consoleRig) *accountsRig {
	t.Helper()
	r := &accountsRig{resetRig: resetOn(t, revokeOn(t, c))}
	log, rec := logkittest.New()
	r.acctLog = rec
	table := r.sites.Table
	mw, err := markers.New(markers.Deps{Admin: r.session, Realm: baselineRealm, Log: log, DoorOf: func(cl string) (flows.Door, bool) {
		switch {
		case slices.Contains(table.Home.Clients, cl):
			return flows.DoorHome, true
		case slices.Contains(table.App.Clients, cl):
			return flows.DoorApp, true
		}
		return "", false
	}})
	if err != nil {
		t.Fatal(err)
	}
	ender := sessions.Ender{Admin: r.session}
	fresh := accounts.NewFresh()
	changes, err := accounts.NewChanges(accounts.ChangesDeps{Guard: r.guard, Users: r.users, Access: r.access, Sessions: ender,
		Markers: mw, Designations: r.designations, Facts: r.ra, Revoker: r.rev, Removed: r.removed, Held: r.held, Fresh: fresh,
		Lock: r.lock, Log: log, StepTimeout: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	for _, wf := range changes.Workflows() {
		r.runner.Register(wf)
	}
	granter, err := accounts.NewGranter(accounts.GranterDeps{Designations: r.designations, Facts: r.ra, Markers: mw, Sessions: ender,
		Roles: r.users, Users: r.users, Access: r.access, Console: r.sessions, Lock: r.lock, Log: log, StepTimeout: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	r.runner.Register(granter.Workflow())
	kp, err := authz.NewKindPolicy(resetApps{})
	if err != nil {
		t.Fatal(err)
	}
	if r.requests, err = accounts.NewRequests(accounts.RequestsDeps{Authorizer: kp, Runner: r.runner, Held: r.held, Facts: r.ra, Log: log}); err != nil {
		t.Fatal(err)
	}
	action, err := accounts.NewFreshAction(r.runner, fresh)
	if err != nil {
		t.Fatal(err)
	}
	c.fresh.set(action)
	observer, err := accounts.NewObserver(accounts.ObserverDeps{Designations: r.designations, Facts: r.ra, Runner: r.runner, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	c.claim.set(nil, nil, observer)
	c.users.set(observer)

	// The actor, as tc30's administrator: an authenticator app and codes,
	// then admin, with the markers a second-step sign-in needs.
	const name = "acct-admin"
	id, pw := r.user(t, name)
	_, r.actorOTP = r.enrol(t, id, name, pw, true)
	r.grantRole(t, id, "admin")
	r.setAttrs(t, id, map[string][]string{flows.MarkerSecondStepHome: {"true"}, flows.MarkerSecondStepApp: {"true"},
		flows.MarkerSecondStepAny: {"true"}})
	r.actorPw = pw
	r.actor = auth.Principal{Sub: id, Name: name, Roles: []string{"admin"}, Session: auth.SessionRef{SID: "sid-acct-admin"}}
	if r.cookie, err = r.sessions.Create(t.Context(), r.actor); err != nil {
		t.Fatal(err)
	}
	return r
}

// otpCode is an authenticator-app code the service has not seen. A
// window whose three codes are spent waits for the next step: the codes
// are a clock's by nature.
func (r *accountsRig) otpCode(t *testing.T, secretB32 string) string {
	t.Helper()
	for {
		step := otpStep(time.Now())
		r.otp.mu.Lock()
		for _, s := range []int64{step, step + 1, step - 1} {
			code, err := totp(secretB32, s)
			if err != nil {
				r.otp.mu.Unlock()
				t.Fatal(err)
			}
			if !r.otp.used[secretB32+code] {
				r.otp.used[secretB32+code] = true
				r.otp.mu.Unlock()
				return code
			}
		}
		r.otp.mu.Unlock()
		for otpStep(time.Now()) == step {
			if t.Context().Err() != nil {
				t.Fatal("the test ended waiting for a fresh authenticator-app code")
			}
			time.Sleep(time.Second)
		}
	}
}

// ask decides a request for p as POST /api/accounts/jobs does, and for a
// fresh answer prepares the fresh sign-in, returning its pending cookie.
func (r *accountsRig) ask(t *testing.T, p auth.Principal, kind, spec, value string) (accounts.Answer, *http.Cookie, error) {
	t.Helper()
	in := accounts.RequestInput{Kind: kind, Spec: json.RawMessage(spec)}
	if value != "" {
		in.Value, in.HasValue = secret.New([]byte(value)), true
	}
	ans, err := r.requests.Request(t.Context(), p.Submitter(), p.Session.SID, in)
	if err != nil || ans.Fresh == nil {
		return ans, nil, err
	}
	req := httptest.NewRequest(http.MethodPost, "https://"+ConsoleHost+"/api/accounts/jobs", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), p))
	w := httptest.NewRecorder()
	if _, err := r.authSvc.PrepareAction(w, req, ans.Fresh.Kind, ans.Fresh); err != nil {
		t.Fatal(err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Value != "" {
			return ans, c, nil
		}
	}
	t.Fatal("PrepareAction set no cookie")
	return ans, nil, nil
}

// job is a submitted job once it has finished.
func (r *accountsRig) job(t *testing.T, id string) *jobs.Job {
	t.Helper()
	r.runner.Wait()
	j, err := r.ledger.GetJob(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

// submitted is ask's job, finished; the request must not need a fresh
// sign-in.
func (r *accountsRig) submitted(t *testing.T, p auth.Principal, kind, spec, value string) *jobs.Job {
	t.Helper()
	ans, _, err := r.ask(t, p, kind, spec, value)
	if err != nil || ans.Job == nil {
		t.Fatalf("%s: %+v, %v", kind, ans, err)
	}
	return r.job(t, ans.Job.ID)
}

// freshSignIn follows a prepared action through the fresh sign-in as the
// browser holding the console session cookie and pending would, signing in
// as name with pw and, when otpSecret is set, an authenticator code, and
// returns the job the action submitted, finished.
func (r *accountsRig) freshSignIn(t *testing.T, cookie secret.Value, pending *http.Cookie, kind, name string, pw secret.Value, otpSecret string) *jobs.Job {
	t.Helper()
	g := r.fresh(t)
	u, _ := url.Parse("https://" + ConsoleHost)
	g.jar.SetCookies(u, []*http.Cookie{{Name: auth.SessionCookieName, Value: string(cookie.Reveal()), Path: "/", Secure: true}, pending})
	a := g.follow("https://" + ConsoleHost + "/api/auth/signin?action=" + kind)
	if a.pageID() != "login-login" {
		t.Fatalf("the fresh sign-in reached %q (%d)", a.pageID(), a.status)
	}
	r.settle(t)
	a = g.submit(a, "kc-form-login", map[string]string{"username": name, "password": string(pw.Reveal())})
	if otpSecret != "" {
		if a.pageID() != pageOTP {
			t.Fatalf("the fresh sign-in's second step is %q", a.pageID())
		}
		r.settle(t)
		a = g.submit(a, "kc-otp-login-form", map[string]string{"otp": r.otpCode(t, otpSecret)})
	}
	if a.at == nil || !strings.HasPrefix(a.at.Path, "/tasks") || a.at.Query().Get("id") == "" {
		t.Fatalf("the fresh sign-in ended at %v, want the job's Tasks page", a.at)
	}
	return r.job(t, a.at.Query().Get("id"))
}

// consoleSignIn signs name in to the console through the launcher's route
// from a fresh address, with an authenticator code when the door asks for
// one, and returns the client and whether a code was asked for.
func (r *accountsRig) consoleSignIn(t *testing.T, name string, pw secret.Value, otpSecret string) (*goClient, bool) {
	t.Helper()
	g := r.fresh(t)
	a := g.follow("https://" + ConsoleHost + "/api/auth/signin")
	if a.pageID() != "login-login" {
		t.Fatalf("the console sign-in reached %q (%d)", a.pageID(), a.status)
	}
	r.settle(t)
	a = g.submit(a, "kc-form-login", map[string]string{"username": name, "password": string(pw.Reveal())})
	asked := a.pageID() == pageOTP
	if asked {
		if otpSecret == "" {
			return g, true
		}
		r.settle(t)
		g.submit(a, "kc-otp-login-form", map[string]string{"otp": r.otpCode(t, otpSecret)})
	}
	r.settle(t)
	return g, asked
}

// self is the account id signed in as itself on the identity session sid,
// with a console session.
func (r *accountsRig) self(t *testing.T, id, name, sid string, roles ...string) (auth.Principal, secret.Value) {
	t.Helper()
	p := auth.Principal{Sub: id, Name: name, Roles: roles, Session: auth.SessionRef{SID: sid}}
	c, err := r.sessions.Create(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	return p, c
}

// creds is the account's credentials: id, type and label.
func (r *accountsRig) creds(t *testing.T, id string) []struct{ ID, Type, UserLabel string } {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+id+"/credentials", nil)
	var cs []struct{ ID, Type, UserLabel string }
	if err := json.Unmarshal(out, &cs); err != nil {
		t.Fatal(err)
	}
	return cs
}

// credID is the account's credential of type typ.
func (r *accountsRig) credID(t *testing.T, id, typ string) string {
	t.Helper()
	for _, c := range r.creds(t, id) {
		if c.Type == typ {
			return c.ID
		}
	}
	t.Fatalf("no %s credential", typ)
	return ""
}

// consoleRoles is the account's console roles at the identity service.
func (r *accountsRig) consoleRoles(t *testing.T, id string) []string {
	t.Helper()
	roles, err := r.users.ConsoleRoles(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return roles
}

func spec(fields ...string) string {
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i+1 < len(fields); i += 2 {
		if i > 0 {
			b.WriteString(",")
		}
		v, _ := json.Marshal(fields[i+1])
		b.WriteString(`"` + fields[i] + `":` + string(v))
	}
	b.WriteString("}")
	return b.String()
}

// TC-994-36: C29 end to end. An administrator's set_roles operator for a
// password-only account, through the fresh sign-in, is a designation and
// gives no role; once the account holds an authenticator app and codes and
// signs in, it holds operator and its console session carries it.
func (r *accountsRig) tc36(t *testing.T) {
	const name = "acct-c29"
	id, pw := r.user(t, name)
	_, pending, err := r.ask(t, r.actor, accounts.KindSetRoles, spec("accountId", id, "role", "operator"), "")
	if err != nil || pending == nil {
		t.Fatalf("set_roles operator did not ask for a fresh sign-in: %v", err)
	}
	j := r.freshSignIn(t, r.cookie, pending, accounts.KindSetRoles, r.actor.Name, r.actorPw, r.actorOTP)
	x, ok, err := r.designations.Get(t.Context(), id)
	if j.Status != jobs.StatusSucceeded || err != nil || !ok || x.ConsoleRole != "operator" || slices.Contains(r.consoleRoles(t, id), "operator") {
		t.Fatalf("job %s %q, designation %+v %v, roles %v", j.Status, j.Error, x, ok, r.consoleRoles(t, id))
	}
	_, otp := r.enrol(t, id, name, pw, true)
	r.consoleSignIn(t, name, pw, otp)
	r.runner.Wait()
	r.settle(t)
	if !slices.Contains(r.consoleRoles(t, id), "operator") {
		t.Fatalf("after setup and a sign-in the account holds %v", r.consoleRoles(t, id))
	}
	if _, ok, _ := r.designations.Get(t.Context(), id); ok {
		t.Error("the designation was not cleared")
	}
	g, _ := r.consoleSignIn(t, name, pw, otp)
	status, m := me(t, g.c)
	roles, _ := m["roles"].([]any)
	if status != http.StatusOK || !slices.Contains(roles, any("operator")) {
		t.Errorf("/api/auth/me: %d %v", status, m)
	}
}

// TC-994-37: no privileged account removes its recovery codes or its only
// second step, each through a fresh sign-in; an unprivileged account
// removes its authenticator app, which is gone (T273), and its next
// password sign-in at the home door asks for no code.
func (r *accountsRig) tc37(t *testing.T) {
	const name = "acct-op"
	id, pw := r.user(t, name)
	_, otp := r.enrol(t, id, name, pw, true)
	r.grantRole(t, id, "operator")
	r.setAttrs(t, id, map[string][]string{flows.MarkerSecondStepHome: {"true"}, flows.MarkerSecondStepApp: {"true"}, flows.MarkerSecondStepAny: {"true"}})
	p, cookie := r.self(t, id, name, "sid-acct-op", "operator")
	before := len(r.creds(t, id))
	for _, c := range []struct{ typ, sentence string }{
		{"recovery-authn-codes", "An account with a privileged role keeps its recovery codes, so they weren't removed."},
		{"otp", "An account with a privileged role keeps at least one passkey, security key or authenticator app, so this one wasn't removed."},
	} {
		_, pending, err := r.ask(t, p, accounts.KindRemoveCredential, spec("accountId", id, "credentialId", r.credID(t, id, c.typ)), "")
		if err != nil || pending == nil {
			t.Fatalf("%s: no fresh sign-in asked for: %v", c.typ, err)
		}
		if j := r.freshSignIn(t, cookie, pending, accounts.KindRemoveCredential, name, pw, otp); j.Status != jobs.StatusFailed || j.Error != c.sentence {
			t.Errorf("%s: job %s %q, want %q", c.typ, j.Status, j.Error, c.sentence)
		}
	}
	if n := len(r.creds(t, id)); n != before {
		t.Errorf("the credential list went from %d to %d", before, n)
	}

	const plain = "acct-plain"
	pid, ppw := r.household(t, plain)
	_, potp := r.enrol(t, pid, plain, ppw, true)
	r.setAttrs(t, pid, map[string][]string{flows.MarkerSecondStepHome: {"true"}, flows.MarkerSecondStepApp: {"true"}, flows.MarkerSecondStepAny: {"true"}})
	pp, pcookie := r.self(t, pid, plain, "sid-acct-plain")
	app := r.credID(t, pid, "otp")
	_, pending, err := r.ask(t, pp, accounts.KindRemoveCredential, spec("accountId", pid, "credentialId", app), "")
	if err != nil || pending == nil {
		t.Fatalf("the control: no fresh sign-in asked for: %v", err)
	}
	if j := r.freshSignIn(t, pcookie, pending, accounts.KindRemoveCredential, plain, ppw, potp); j.Status != jobs.StatusSucceeded {
		t.Fatalf("the control: job %s %q", j.Status, j.Error)
	}
	for _, c := range r.creds(t, pid) {
		if c.ID == app {
			t.Error("T273: the removed authenticator app is still listed")
		}
	}
	if _, asked := r.consoleSignIn(t, plain, ppw, ""); asked {
		t.Error("the next password sign-in at the home door asked for a code")
	}
}

// TC-994-38: set_email needs iam; only confirm_email puts an address in an
// app's tokens (T274).
func (r *accountsRig) tc38(t *testing.T) {
	viewer := auth.Principal{Sub: "acct-viewer-sub", Roles: []string{"viewer"}, Session: auth.SessionRef{SID: "sid-v"}}
	_, _, err := r.ask(t, viewer, accounts.KindSetEmail, spec("accountId", r.actor.Sub), "v@example.test")
	var kr *authz.KindRefusal
	if !errors.As(err, &kr) || kr.Code != authz.CodeNotPermitted {
		t.Errorf("a viewer's set_email: %v, want job_not_permitted", err)
	}
	r.appEmailScope(t)
	const name = "acct-mail"
	id, pw := r.household(t, name)
	const addr = "acct-mail-new@example.test"
	if j := r.submitted(t, r.actor, accounts.KindSetEmail, spec("accountId", id), addr); j.Status != jobs.StatusSucceeded {
		t.Fatalf("set_email: %s %q", j.Status, j.Error)
	}
	idt, info := r.appClaims(t, name, pw)
	if idt["email"] != nil || info["email"] != nil {
		t.Errorf("before confirm_email the app got email %v / %v", idt["email"], info["email"])
	}
	if j := r.submitted(t, r.actor, accounts.KindConfirmEmail, spec("accountId", id), ""); j.Status != jobs.StatusSucceeded {
		t.Fatalf("confirm_email: %s %q", j.Status, j.Error)
	}
	idt, info = r.appClaims(t, name, pw)
	if idt["email"] != addr || info["email"] != addr {
		t.Errorf("after confirm_email the app got email %v / %v, want %s", idt["email"], info["email"], addr)
	}
}

// appEmailScope makes the test app's default scopes give email only
// through rasputin-app-email, as Identity 7.4's app clients will.
func (r *accountsRig) appEmailScope(t *testing.T) {
	t.Helper()
	api := r.admin(t)
	_, out := api.must(http.StatusOK, http.MethodGet, "/client-scopes", nil)
	var scopes []struct{ ID, Name string }
	if err := json.Unmarshal(out, &scopes); err != nil {
		t.Fatal(err)
	}
	app, _ := api.clientRep(doorTestApp)
	found := false
	for _, s := range scopes {
		switch s.Name {
		case "email":
			api.do(http.MethodDelete, "/clients/"+app+"/default-client-scopes/"+s.ID, nil)
		case "rasputin-app-email":
			found = true
			api.must(http.StatusNoContent, http.MethodPut, "/clients/"+app+"/default-client-scopes/"+s.ID, nil)
		}
	}
	if !found {
		t.Fatal("the realm has no rasputin-app-email client scope")
	}
}

// appClaims signs name in at the app door for the test app and returns its
// ID token's claims and its userinfo.
func (r *accountsRig) appClaims(t *testing.T, name string, pw secret.Value) (map[string]any, map[string]any) {
	t.Helper()
	g := r.fresh(t)
	r.settle(t)
	a := g.signIn(r.appAuth(doorTestApp, nil), name, pw)
	ans := g.send(http.MethodPost, r.appURL("/realms/rasputin/protocol/openid-connect/token"), url.Values{
		"grant_type": {"authorization_code"}, "code": {a.code(t)}, "client_id": {doorTestApp},
		"redirect_uri": {callbackOn(AppSiteHost)}, "code_verifier": {doorPKCE}}, nil)
	var tok struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if ans.status != http.StatusOK || json.Unmarshal(ans.body, &tok) != nil || tok.IDToken == "" {
		t.Fatalf("the exchange answered %d", ans.status)
	}
	parts := strings.Split(tok.IDToken, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var idt map[string]any
	if err := json.Unmarshal(payload, &idt); err != nil {
		t.Fatal(err)
	}
	ui := g.send(http.MethodGet, r.appURL("/realms/rasputin/protocol/openid-connect/userinfo"), nil,
		http.Header{"Authorization": {"Bearer " + tok.AccessToken}})
	var info map[string]any
	if ui.status != http.StatusOK || json.Unmarshal(ui.body, &info) != nil {
		t.Fatalf("userinfo answered %d", ui.status)
	}
	return idt, info
}

// TC-994-39: C24 and TS-21. Without a fresh sign-in, set_roles admin and
// remove_second_steps submit nothing, and through POST /api/jobs fail at
// their first step; following next through a fresh sign-in applies both.
func (r *accountsRig) tc39(t *testing.T) {
	const name = "acct-c24"
	id, pw := r.user(t, name)
	r.enrol(t, id, name, pw, true)
	roles := spec("accountId", id, "role", "admin")
	steps := spec("accountId", id)
	// Earlier cases' jobs of these kinds stay in the ledger: this case
	// counts only the ones its own requests would add.
	kinds := []string{accounts.KindSetRoles, accounts.KindRemoveSecondSteps}
	before := map[string]int{}
	for _, k := range kinds {
		before[k] = r.jobCount(t, k)
	}
	_, rolesPending, err := r.ask(t, r.actor, accounts.KindSetRoles, roles, "")
	if err != nil || rolesPending == nil {
		t.Fatalf("set_roles admin: %v", err)
	}
	if _, p, err := r.ask(t, r.actor, accounts.KindRemoveSecondSteps, steps, ""); err != nil || p == nil {
		t.Fatalf("remove_second_steps: %v", err)
	}
	for _, k := range kinds {
		if n := r.jobCount(t, k) - before[k]; n != 0 {
			t.Errorf("%s: %d jobs without the fresh sign-in", k, n)
		}
	}
	for _, c := range [][2]string{{accounts.KindSetRoles, roles}, {accounts.KindRemoveSecondSteps, steps}} {
		j, err := r.runner.SubmitOperatorSpec(t.Context(), c[0], json.RawMessage(c[1]), r.actor.Submitter())
		if err != nil {
			t.Fatal(err)
		}
		if j = r.job(t, j.ID); j.Status != jobs.StatusFailed {
			t.Errorf("%s through POST /api/jobs: %s", c[0], j.Status)
		}
	}
	if slices.Contains(r.consoleRoles(t, id), "admin") || r.credID(t, id, "otp") == "" {
		t.Fatal("the target changed without a fresh sign-in")
	}
	if j := r.freshSignIn(t, r.cookie, rolesPending, accounts.KindSetRoles, r.actor.Name, r.actorPw, r.actorOTP); j.Status != jobs.StatusSucceeded ||
		!slices.Contains(r.consoleRoles(t, id), "admin") {
		t.Fatalf("set_roles admin after the fresh sign-in: %s %q, roles %v", j.Status, j.Error, r.consoleRoles(t, id))
	}
	_, stepsPending, err := r.ask(t, r.actor, accounts.KindRemoveSecondSteps, steps, "")
	if err != nil || stepsPending == nil {
		t.Fatal(err)
	}
	j := r.freshSignIn(t, r.cookie, stepsPending, accounts.KindRemoveSecondSteps, r.actor.Name, r.actorPw, r.actorOTP)
	for _, c := range r.creds(t, id) {
		if markers.IsSecondStep(c.Type) {
			t.Errorf("a second step is left: %s", c.Type)
		}
	}
	x, _, _ := r.designations.Get(t.Context(), id)
	if j.Status != jobs.StatusSucceeded || slices.Contains(r.consoleRoles(t, id), "admin") || x.ConsoleRole != "admin" || x.Reason != accounts.ReasonReset {
		t.Errorf("remove_second_steps: %s %q, roles %v, designation %+v", j.Status, j.Error, r.consoleRoles(t, id), x)
	}
}

// TC-994-40: the Keycloak contracts relied on (T270 to T275; T273 is
// TC-994-37's control).
func (r *accountsRig) tc40(t *testing.T) {
	// T270: of two identity sessions, a self sign-out keeps the request's.
	const so = "acct-so"
	soID, soPw := r.household(t, so)
	r.appTokens(t, so, soPw, false)
	r.appTokens(t, so, soPw, false)
	sids := r.sessionIDs(t, soID)
	if len(sids) < 2 {
		t.Fatalf("%d identity sessions, want two", len(sids))
	}
	sp, _ := r.self(t, soID, so, sids[0])
	if j := r.submitted(t, sp, accounts.KindSignOut, spec("accountId", soID), ""); j.Status != jobs.StatusSucceeded {
		t.Fatalf("sign_out: %s %q", j.Status, j.Error)
	}
	if got := r.sessionIDs(t, soID); !slices.Equal(got, sids[:1]) {
		t.Errorf("T270: sessions %v after the sign-out, want %v", got, sids[:1])
	}

	// T271: the label rename_credential sets reads back.
	const cr = "acct-cred"
	crID, crPw := r.user(t, cr)
	r.enrol(t, crID, cr, crPw, true)
	cp, _ := r.self(t, crID, cr, "sid-acct-cred")
	app := r.credID(t, crID, "otp")
	if j := r.submitted(t, cp, accounts.KindRenameCredential, spec("accountId", crID, "credentialId", app), "CI phone"); j.Status != jobs.StatusSucceeded {
		t.Fatalf("rename_credential: %s %q", j.Status, j.Error)
	}
	for _, c := range r.creds(t, crID) {
		if c.ID == app && c.UserLabel != "CI phone" {
			t.Errorf("T271: the label reads %q", c.UserLabel)
		}
	}

	// T272: an account attack detection holds signs in after unlock. The
	// realm's failureFactor wrong passwords go straight to Keycloak, as
	// TC-987-15's do: through a door, the per-source throttle admits one
	// credential post per source until a drain pass sees its answer
	// (policy.Throttle.Admit), so the doors alone never reach the backstop
	// in a bounded test.
	const lk = "acct-lock"
	lkID, lkPw := r.user(t, lk)
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "", nil)
	var realm struct {
		BruteForceProtected bool `json:"bruteForceProtected"`
		FailureFactor       int  `json:"failureFactor"`
	}
	if err := json.Unmarshal(out, &realm); err != nil || !realm.BruteForceProtected || realm.FailureFactor < 1 || realm.FailureFactor > 1000 {
		t.Fatalf("the realm's brute-force settings: protected %v, failureFactor %d (%v)", realm.BruteForceProtected, realm.FailureFactor, err)
	}
	up := r.upstreamClient(t)
	page := up.follow(r.env.KeycloakUpstream().String() + "/realms/rasputin/protocol/openid-connect/auth?" +
		doorAuthQuery("rasputin-account", r.sites.Table.App.Host, nil))
	for range realm.FailureFactor {
		if page.pageID() != "login-login" {
			t.Fatalf("a wrong password led to %q", page.pageID())
		}
		page = up.submit(page, "kc-form-login", map[string]string{"username": lk, "password": "not the password"})
	}
	// Keycloak counts a failure on its own executor: wait on the hold,
	// bounded far outside normal so a missing hold fails in a minute.
	for deadline := time.Now().Add(time.Minute); !r.bruteForce(t, lkID).Disabled; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("attack detection does not hold the account after %d failures: %+v", realm.FailureFactor, r.bruteForce(t, lkID))
		}
	}
	if a := r.fresh(t).signIn(r.appAuth("rasputin-account", nil), lk, lkPw); a.loc != nil && a.loc.Path == callbackPath {
		t.Fatal("a held account signed in")
	}
	if j := r.submitted(t, r.actor, accounts.KindUnlock, spec("accountId", lkID), ""); j.Status != jobs.StatusSucceeded {
		t.Fatalf("unlock: %s %q", j.Status, j.Error)
	}
	if r.bruteForce(t, lkID).Disabled {
		t.Error("T272: attack detection still holds the account")
	}
	r.settle(t)
	if a := r.fresh(t).signIn(r.appAuth("rasputin-account", nil), lk, lkPw); a.loc == nil || a.loc.Path != callbackPath {
		t.Errorf("T272: after unlock the sign-in reached %q", a.pageID())
	}

	// T275: an address another account holds is the duplicate sentence.
	_, out = r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+soID, nil)
	var before struct{ Email string }
	_ = json.Unmarshal(out, &before)
	j := r.submitted(t, r.actor, accounts.KindSetEmail, spec("accountId", soID), cr+"@door.invalid")
	_, out = r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+soID, nil)
	var after struct{ Email string }
	_ = json.Unmarshal(out, &after)
	if j.Status != jobs.StatusFailed || j.Error != "Another account already uses that email address." || after.Email != before.Email {
		t.Errorf("T275: job %s %q, email %q (was %q)", j.Status, j.Error, after.Email, before.Email)
	}
}

// jobCount is how many jobs of kind the ledger holds.
func (r *accountsRig) jobCount(t *testing.T, kind string) int {
	t.Helper()
	js, err := r.ledger.ListJobsByKind(t.Context(), kind, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return len(js)
}

// sessionIDs are the account's online sessions, by id, sorted.
func (r *accountsRig) sessionIDs(t *testing.T, id string) []string {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+id+"/sessions", nil)
	var ss []struct{ ID string }
	if err := json.Unmarshal(out, &ss); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, s := range ss {
		ids = append(ids, s.ID)
	}
	slices.Sort(ids)
	return ids
}

// TC-994-41: an app-only designation completes at an app-door sign-in with
// no console sign-in in between (F-994-01).
func (r *accountsRig) tc41(t *testing.T) {
	const name = "acct-appadm"
	id, pw := r.user(t, name)
	_, pending, err := r.ask(t, r.actor, accounts.KindGrantAccess, spec("accountId", id, "level", "admin"), "")
	if err != nil || pending == nil {
		t.Fatalf("grant_access admin: %v", err)
	}
	j := r.freshSignIn(t, r.cookie, pending, accounts.KindGrantAccess, r.actor.Name, r.actorPw, r.actorOTP)
	x, _, _ := r.designations.Get(t.Context(), id)
	if j.Status != jobs.StatusSucceeded || x.AppRole != accounts.AppAdmin {
		t.Fatalf("job %s %q, designation %+v", j.Status, j.Error, x)
	}
	if p, _ := r.users.Read(t.Context(), id); p.AppRole != accounts.AppUser {
		t.Errorf("F-994-09: app access %q while designated, want user", p.AppRole)
	}
	r.mu.Lock()
	callbacks := len(r.callbackQueries)
	r.mu.Unlock()
	r.enrol(t, id, name, pw, true)
	r.settle(t)
	r.runner.Wait()
	if p, _ := r.users.Read(t.Context(), id); p.AppRole != accounts.AppAdmin {
		t.Errorf("after setup at the app door the account holds app access %q, want admin", p.AppRole)
	}
	if _, ok, _ := r.designations.Get(t.Context(), id); ok {
		t.Error("the designation was not cleared")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.callbackQueries) != callbacks {
		t.Error("the account reached the console's callback")
	}
}

// accountsCases runs Identity 4.12's CI cases on the console rig.
func accountsCases(t *testing.T, c *consoleRig) {
	r := newAccountsRig(t, c)
	t.Run("TC-994-36 C29 end to end", r.tc36)
	t.Run("TC-994-37 privileged accounts keep their codes and last second step", r.tc37)
	t.Run("TC-994-38 T274 only a confirmed email reaches apps", r.tc38)
	t.Run("TC-994-39 C24 TS-21 privileged changes need a fresh sign-in", r.tc39)
	t.Run("TC-994-40 T270 to T275", r.tc40)
	t.Run("TC-994-41 F-994-01 an app-only designation completes at the app door", r.tc41)
}
