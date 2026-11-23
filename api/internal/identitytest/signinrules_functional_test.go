package identitytest

// The sign-in rules against the real identity service
// (geekdojo/geekdojo-brain#987, Identity 4.5; TC-987-01 to TC-987-23): the
// definition in package flows, converged by the real converger, signed in
// through both doors by the Go door client and, for the passkey cases, the
// pinned Chrome's virtual authenticator.
//
// It starts an Env of its own, closed with proof in its cleanup. It skips
// without RASPUTIN_IDENTITY_HOME or RASPUTIN_IDENTITY_THEME and fails instead
// under RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job sets it.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/converge"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
)

func TestSignInRules_AgainstPinnedKeycloak(t *testing.T) {
	p := NewPackage(func() (Config, error) {
		c, err := ConfigFromEnv()
		c.DoorMode = true
		return c, err
	})
	if !p.RequireTheme(t) {
		return
	}
	env := p.Env(t)
	if env == nil {
		return
	}
	t.Cleanup(func() {
		if err := env.Close(context.Background()); err != nil {
			t.Errorf("identitytest: teardown proof failed: %v", err)
		}
	})
	importBaseline(t, env)
	r := newRulesRig(t, env)
	r.browser = func(t *testing.T) context.Context {
		ctx, _ := p.Browser(t)
		return ctx
	}

	// TC-987-20's page is opened first and answered last, so its wait
	// overlaps the other cases.
	var page20 recoveryPage
	t.Run("TC-987-20 open the recovery-codes page", func(t *testing.T) { page20 = r.tc20open(t) })
	t.Run("TC-987-17 the rig's converge from the baseline", func(t *testing.T) { r.tc17(t) })
	t.Run("TC-987-01 a privileged password alone gets no code at either door", func(t *testing.T) { r.tc01(t) })
	t.Run("TC-987-02 a household password alone", func(t *testing.T) { r.tc02(t) })
	t.Run("TC-987-03 an other-door passkey never blocks a password sign-in", func(t *testing.T) { r.tc03(t) })
	t.Run("TC-987-04 an operator's authenticator app, a recovery code standing in, and the password alone", func(t *testing.T) { r.tc04(t) })
	t.Run("TC-987-05 the authenticator app follows the clock-sync fact", func(t *testing.T) { r.tc05(t) })
	t.Run("TC-987-06 an Admin API edit locks control until converge", func(t *testing.T) { r.tc06(t) })
	t.Run("TC-987-07 sign-in names", func(t *testing.T) { r.tc07(t) })
	t.Run("TC-987-08 the administering variant", func(t *testing.T) { r.tc08(t) })
	t.Run("TC-987-09 recovery codes alone never ask for a code", func(t *testing.T) { r.tc09(t) })
	t.Run("TC-987-10 a passkey alone at its door", func(t *testing.T) { r.tc10(t) })
	t.Run("TC-987-11 BeforePrivilege writes the markers first", func(t *testing.T) { r.tc11(t) })
	t.Run("TC-987-12 every method at each door, and the gate on a cookie", func(t *testing.T) { r.tc12(t) })
	t.Run("TC-987-13 no page asks for a step the account lacks", func(t *testing.T) { r.tc13(t) })
	t.Run("TC-987-14 admins-first and network devices", func(t *testing.T) { r.tc14(t) })
	t.Run("TC-987-15 the per-account backstop", func(t *testing.T) { r.tc15(t) })
	t.Run("TC-987-16 a stricter client whose binding was removed is paused", func(t *testing.T) { r.tc16(t) })
	t.Run("TC-987-18 the password policy, sessions and email", func(t *testing.T) { r.tc18(t) })
	t.Run("TC-987-19 the passkey relying-party name", func(t *testing.T) { r.tc19(t) })
	t.Run("TC-987-21 K-ACR", func(t *testing.T) { r.tc21(t) })
	t.Run("TC-987-22 K-PROFILE", func(t *testing.T) { r.tc22(t) })
	t.Run("TC-987-23 K-DEFAULT-ACTION", func(t *testing.T) { r.tc23(t) })
	t.Run("TC-987-20 the recovery-codes page completes after 6 minutes", func(t *testing.T) { r.tc20finish(t, page20) })
}

// loginErrors counts the account's LOGIN_ERROR events. A denied sign-in's
// event names the account by its username only.
func (r *rulesRig) loginErrors(t *testing.T, a account) int {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/events?type=LOGIN_ERROR&max=1000", nil)
	var evs []struct {
		Details map[string]string `json:"details"`
	}
	if err := json.Unmarshal(out, &evs); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range evs {
		if e.Details["username"] == a.name {
			n++
		}
	}
	return n
}

// refused asserts the answer is the error page with sentence and no code.
func refused(t *testing.T, what string, a doorAnswer, sentence string) {
	t.Helper()
	if a.loc != nil && a.loc.Query().Get("code") != "" {
		t.Errorf("%s: got an authorization code, want a refusal", what)
		return
	}
	if got := errorText(a); got != sentence {
		t.Errorf("%s: page %q (%d) says %q, want %q", what, a.pageID(), a.status, got, sentence)
	}
}

// TC-987-01: an admin and an operator holding only a password get no code at
// the home door (console) or the app door (account), each refused with the
// privileged sentence, and each attempt is a LOGIN_ERROR.
func (r *rulesRig) tc01(t *testing.T) {
	for _, role := range []string{"admin", "operator"} {
		a := r.account(t, "tc01-"+role, nil)
		r.grantConsole(t, a, role)
		before := r.loginErrors(t, a)
		for _, d := range r.bothDoors() {
			got := r.fresh(t).signIn(d.auth(), a.name, a.pw)
			refused(t, role+" at the "+d.name, got, flows.SentencePrivileged)
		}
		if after := r.loginErrors(t, a); after-before != 2 {
			t.Errorf("%s: %d LOGIN_ERROR events for two refused sign-ins, want 2", role, after-before)
		}
	}
}

// totpCodes hands out authenticator-app codes the service has not seen
// (the realm refuses a code used once): the current step's, then the steps
// either side, its look-ahead window. The keys are secret and code.
type totpCodes struct {
	mu   sync.Mutex
	used map[string]bool
}

func (c *totpCodes) next(t *testing.T, secretB32 string) string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	step := otpStep(time.Now())
	for _, s := range []int64{step, step + 1, step - 1} {
		code, err := totp(secretB32, s)
		if err != nil {
			t.Fatal(err)
		}
		if !c.used[secretB32+code] {
			c.used[secretB32+code] = true
			return code
		}
	}
	t.Fatal("every authenticator-app code in the window was used")
	return ""
}

// enrol signs a at the home door through its required actions: the
// authenticator app and the recovery codes, either or both, and returns the
// secret and the codes.
func (r *rulesRig) enrol(t *testing.T, a account, otp, codes bool) (string, []string) {
	t.Helper()
	var actions []string
	if otp {
		actions = append(actions, flows.ActionConfigureTOTP)
	}
	if codes {
		actions = append(actions, flows.ActionRecoveryCodes)
	}
	r.requireActions(t, a, actions...)
	g := r.fresh(t)
	got := g.signIn(r.homeConsole(), a.name, a.pw)
	var secretB32 string
	var saved []string
	if otp {
		got, secretB32 = r.enrolTOTP(t, g, got)
	}
	if codes {
		got, saved = r.saveCodes(t, g, got)
	}
	got.code(t)
	r.settle(t) // the credential events reach the marker writer
	return secretB32, saved
}

// TC-987-04: an operator with an authenticator app and recovery codes signs
// in at each door with its password and a recovery code standing in, then
// with its password and a TOTP code; its password alone gets no code, and
// both options are offered inside the second step.
func (r *rulesRig) tc04(t *testing.T) {
	a := r.account(t, "tc04-operator", nil)
	secretB32, codes := r.enrol(t, a, true, true)
	for _, m := range []string{flows.MarkerSecondStepHome, flows.MarkerSecondStepApp, flows.MarkerSecondStepAny} {
		if got := r.attr(t, a, m); got != "true" {
			t.Fatalf("after the authenticator app was stored, %s is %q, want true", m, got)
		}
	}
	r.grantConsole(t, a, "operator")
	next := 0
	for _, d := range r.bothDoors() {
		g := r.fresh(t)
		step := g.signIn(d.auth(), a.name, a.pw)
		if step.pageID() != "login-login-otp" || !strings.Contains(string(step.body), "kc-select-try-another-way-form") {
			t.Fatalf("%s: the password led to %q, want the authenticator-code page offering another way", d.name, step.pageID())
		}
		rec := r.recoveryInstead(t, g, step)
		r.answerRecovery(t, g, rec, codes[next]).code(t)
		next++

		g = r.fresh(t)
		step = g.signIn(d.auth(), a.name, a.pw)
		if step.pageID() != "login-login-otp" {
			t.Fatalf("%s: the password led to %q, want the authenticator-code page", d.name, step.pageID())
		}
		r.answerOTP(t, g, step, secretB32).code(t)

		// The password alone: the second step is asked, and no code comes.
		g = r.fresh(t)
		alone := g.signIn(d.auth(), a.name, a.pw)
		if alone.loc != nil && alone.loc.Query().Get("code") != "" {
			t.Errorf("%s: the password alone got a code", d.name)
		} else if !isSecondStep(alone.pageID()) {
			t.Errorf("%s: the password alone led to %q, want a second step", d.name, alone.pageID())
		}
	}
}

// TC-987-08: at an administering client, an account whose passkey was made
// at the home door, holding a password-only app-door session made at
// another app, is asked to sign in afresh and for a second step, where a
// recovery code stands in; an account holding no second step is refused
// with the administering sentence and never sees a setup page.
func (r *rulesRig) tc08(t *testing.T) {
	bctx := r.browser(t)
	if bctx == nil {
		return
	}
	a := r.account(t, "tc08-member", map[string][]string{"rasputin_app_role": {"user"}})
	_, codes := r.enrol(t, a, false, true)
	r.registerKey(t, r.keyTab(t, bctx, "https://"+r.sites.Table.Home.Host), a, r.homeConsole(), false)
	g := r.fresh(t)
	g.signIn(r.appClient(rulesOtherApp), a.name, a.pw).code(t)
	if identityOf(g.jar, r.sites.Table.App.Host) == "" {
		t.Fatal("the other app's sign-in left no app-door session")
	}
	page := g.follow(r.appClient(rulesAdministering))
	if page.pageID() != "login-login" {
		t.Fatalf("the administering client opened %q with an app-door session, want the sign-in page", page.pageID())
	}
	step := r.post(t, g, page, "kc-form-login", map[string]string{"username": a.name, "password": string(a.pw.Reveal())})
	r.answerRecovery(t, g, r.recoveryInstead(t, g, step), codes[0]).code(t)

	none := r.account(t, "tc08-none", map[string][]string{"rasputin_app_role": {"user"}})
	got := r.fresh(t).signIn(r.appClient(rulesAdministering), none.name, none.pw)
	refused(t, "an account with no second step at the administering client", got, flows.SentenceAdministering)
	if strings.Contains(got.pageID(), "config-totp") || strings.Contains(got.pageID(), "webauthn-register") {
		t.Errorf("a setup page appeared: %q", got.pageID())
	}
}

// recoveryRemaining is the account's recovery-codes credential data.
func (r *rulesRig) recoveryRemaining(t *testing.T, a account) string {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+a.id+"/credentials", nil)
	var creds []struct {
		Type           string `json:"type"`
		CredentialData string `json:"credentialData"`
	}
	if err := json.Unmarshal(out, &creds); err != nil {
		t.Fatal(err)
	}
	for _, c := range creds {
		if c.Type == "recovery-authn-codes" {
			return c.CredentialData
		}
	}
	t.Fatal("the account holds no recovery codes")
	return ""
}

// TC-987-09: an unprivileged account holding only recovery codes signs in
// with its password at each door and is never shown a recovery-code page.
func (r *rulesRig) tc09(t *testing.T) {
	a := r.account(t, "tc09-codes", nil)
	r.enrol(t, a, false, true)
	for _, m := range flows.Markers {
		if got := r.attr(t, a, m); got != "" {
			t.Errorf("recovery codes set %s to %q, want it unset", m, got)
		}
	}
	before := r.recoveryRemaining(t, a)
	for _, d := range r.bothDoors() {
		got := r.fresh(t).signIn(d.auth(), a.name, a.pw)
		if isSecondStep(got.pageID()) {
			t.Errorf("%s: asked for %q", d.name, got.pageID())
			continue
		}
		got.code(t)
	}
	if after := r.recoveryRemaining(t, a); after != before {
		t.Errorf("the recovery codes changed from %s to %s", before, after)
	}
}

// flowSteps reads a top-level flow's executions and configs through the
// Admin API, flattened as package flows flattens the definition.
func (r *rulesRig) flowSteps(t *testing.T, alias string) []flows.Step {
	t.Helper()
	return flowStepsOf(t, r.admin(t), alias)
}

// flowStepsOf is flowSteps through api.
func flowStepsOf(t *testing.T, api adminAPI, alias string) []flows.Step {
	t.Helper()
	_, out := api.must(http.StatusOK, http.MethodGet, "/authentication/flows/"+alias+"/executions", nil)
	var execs []struct {
		Requirement, DisplayName, ProviderID, AuthenticationConfig string
		AuthenticationFlow                                         bool
		Level, Index                                               int
	}
	if err := json.Unmarshal(out, &execs); err != nil {
		t.Fatal(err)
	}
	var steps []flows.Step
	for _, e := range execs {
		s := flows.Step{Level: e.Level, Index: e.Index, Requirement: flows.Requirement(e.Requirement)}
		if e.AuthenticationFlow {
			s.Alias = e.DisplayName
		} else {
			s.Provider = e.ProviderID
		}
		if e.AuthenticationConfig != "" {
			_, c := api.must(http.StatusOK, http.MethodGet, "/authentication/config/"+e.AuthenticationConfig, nil)
			var cfg struct {
				Alias  string
				Config map[string]string
			}
			if err := json.Unmarshal(c, &cfg); err != nil {
				t.Fatal(err)
			}
			s.ConfigAlias, s.Config = cfg.Alias, cfg.Config
		}
		steps = append(steps, s)
	}
	return steps
}

// checkRules asserts every flow reads back as the definition renders it,
// and the realm's browser binding and the own clients' bindings hold.
func (r *rulesRig) checkRules(t *testing.T) {
	t.Helper()
	for _, v := range flows.Variants {
		if !flows.SameSteps(flows.Flatten(v.Alias(), flows.Flow(v)), r.flowSteps(t, v.Alias())) {
			t.Errorf("%s does not read back as its definition", v.Alias())
		}
	}
	realm := realmRep(t, r.admin(t))
	if realm["browserFlow"] != flows.RealmDefault.Alias() {
		t.Errorf("browserFlow = %v", realm["browserFlow"])
	}
}

// noRulesAlarm asserts no critical alert and no ERROR record of the
// integrity state.
func (r *rulesRig) noRulesAlarm(t *testing.T) {
	t.Helper()
	for _, a := range r.conv.Alerts(t.Context(), time.Now()) {
		if a.ID == converge.SignInRulesAlertID {
			t.Errorf("the critical alert is raised: %+v", a)
		}
	}
	if strings.Contains(r.rec.Text(), "identity.integrity.differs") || len(r.rec.Matching(slog.LevelError, "")) != 0 {
		t.Errorf("an ERROR was logged:\n%s", r.rec.Text())
	}
}

// TC-987-17 (fresh install): the rig's converge from the imported baseline,
// with no stored hash, left every flow as defined, the state intact, no
// critical alert and no ERROR; a second run writes nothing.
func (r *rulesRig) tc17(t *testing.T) {
	r.checkRules(t)
	r.noRulesAlarm(t)
	if fields, err := r.conv.Run(t.Context()); err != nil || len(fields) != 0 {
		t.Errorf("a second run: %v, %v; want nothing written", fields, err)
	}
	if r.conv.State() != converge.Intact {
		t.Errorf("state %s", r.conv.State())
	}
}

// TC-987-02: a household account (app role user) with only a password
// signs in at a gated app client and at the console, with no second step.
func (r *rulesRig) tc02(t *testing.T) {
	a := r.account(t, "tc02-household", map[string][]string{"rasputin_app_role": {"user"}})
	for what, auth := range map[string]string{"the gated app client": r.appClient(rulesAppClients), "the console": r.homeConsole()} {
		got := r.fresh(t).signIn(auth, a.name, a.pw)
		if isSecondStep(got.pageID()) {
			t.Errorf("%s asked for %s", what, got.pageID())
			continue
		}
		got.code(t)
	}
}

// TC-987-03: a passkey made at the app door sets the app door's markers
// only; the password then signs in at the home door with no second step,
// and at the app door it is asked for the passkey.
func (r *rulesRig) tc03(t *testing.T) {
	bctx := r.browser(t)
	if bctx == nil {
		return
	}
	a := r.account(t, "tc03-app-passkey", nil)
	k := r.keyTab(t, bctx, "https://"+r.sites.Table.App.Host)
	r.registerKey(t, k, a, r.appAccount(), false)
	for m, want := range map[string]string{
		flows.MarkerWebAuthnApp: "true", flows.MarkerSecondStepApp: "true", flows.MarkerSecondStepAny: "true",
		flows.MarkerWebAuthnHome: "", flows.MarkerSecondStepHome: "",
	} {
		if got := r.attr(t, a, m); got != want {
			t.Errorf("%s = %q, want %q", m, got, want)
		}
	}
	home := r.fresh(t).signIn(r.homeConsole(), a.name, a.pw)
	if isSecondStep(home.pageID()) {
		t.Fatalf("the home door asked for %s", home.pageID())
	}
	home.code(t)
	if got := r.passwordThenKey(t, k, a, r.appAccount(), false); got != "login-webauthn-authenticate" {
		t.Errorf("the app door's password led to %q, want the passkey step", got)
	}
}

// TC-987-05: with the clock not synced, converge disables CONFIGURE_TOTP
// and a sign-in never offers the authenticator app; once synced it is
// enabled and offered, with no critical alert and no integrity ERROR.
func (r *rulesRig) tc05(t *testing.T) {
	enabled := func() bool {
		_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/authentication/required-actions/"+flows.ActionConfigureTOTP, nil)
		var a struct{ Enabled bool }
		if err := json.Unmarshal(out, &a); err != nil {
			t.Fatal(err)
		}
		return a.Enabled
	}
	offered := func(name string) bool {
		a := r.account(t, name, nil)
		r.requireActions(t, a, flows.ActionConfigureTOTP)
		got := r.fresh(t).signIn(r.homeConsole(), a.name, a.pw)
		return got.pageID() == "login-login-config-totp"
	}
	r.setInputs(func(in *converge.Inputs) { in.ClockSynced = false })
	t.Cleanup(func() { r.setInputs(func(in *converge.Inputs) { in.ClockSynced = true }) })
	if _, err := r.conv.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if enabled() || offered("tc05-unsynced") {
		t.Error("unsynced: the authenticator app is enabled or offered")
	}
	r.setInputs(func(in *converge.Inputs) { in.ClockSynced = true })
	if _, err := r.conv.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !enabled() || !offered("tc05-synced") {
		t.Error("synced: the authenticator app is not enabled or not offered")
	}
	r.settle(t)
	r.noRulesAlarm(t)
}

// lockSession is a real auth.Service with one seeded console session and a
// stand-in mux holding the real route shapes, its gate the converger's.
type lockSession struct {
	mux   *http.ServeMux
	token string
}

func (r *rulesRig) lockSession(t *testing.T) lockSession {
	t.Helper()
	store, err := auth.OpenStore(t.Context(), filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	svc, err := auth.NewService(store, auth.Config{RPDisplayName: "Rasputin", RPID: "localhost", RPOrigins: []string{"https://localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetControlGate(r.conv.ControlGate, r.env.log)
	u := &auth.User{ID: []byte("tc06-user-id-001"), Name: "tc06", DisplayName: "TC06", CreatedAt: time.Now()}
	if err := store.CreateUser(t.Context(), u); err != nil {
		t.Fatal(err)
	}
	token := "tc06-session-token"
	if err := store.CreateSession(t.Context(), &auth.Session{Token: token, UserID: u.ID, CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour), LastActiveAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux := http.NewServeMux()
	for _, p := range []string{"GET /api/nodes", "POST /api/nodes/{id}/reboot", "GET /ws/bmc/{nodeId}/sol"} {
		mux.Handle(p, svc.RequireSession(ok))
	}
	return lockSession{mux: mux, token: token}
}

func (l lockSession) send(method, path string, upgrade bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(&http.Cookie{Name: "rasputin-session", Value: l.token})
	if upgrade {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
	}
	w := httptest.NewRecorder()
	l.mux.ServeHTTP(w, req)
	return w
}

// TC-987-06: disabling the app-clients variant's privileged Deny through the
// Admin API and draining raises the critical alert and locks control (a
// POST 423 with its code, the serial console refused, a GET 200); converge
// restores the flow, the alert clears and the POST passes.
func (r *rulesRig) tc06(t *testing.T) {
	l := r.lockSession(t)
	if w := l.send(http.MethodPost, "/api/nodes/n1/reboot", false); w.Code != http.StatusOK {
		t.Fatalf("intact: a control POST answered %d", w.Code)
	}
	api := r.admin(t)
	alias := flows.AppClients.Alias() + "-privileged-admin"
	_, out := api.must(http.StatusOK, http.MethodGet, "/authentication/flows/"+alias+"/executions", nil)
	var execs []map[string]any
	if err := json.Unmarshal(out, &execs); err != nil {
		t.Fatal(err)
	}
	deny := execs[len(execs)-1]
	if deny["providerId"] != flows.ProviderDeny {
		t.Fatalf("the branch's last execution is %v", deny["providerId"])
	}
	deny["requirement"] = "DISABLED"
	api.must(http.StatusNoContent, http.MethodPut, "/authentication/flows/"+alias+"/executions", deny)
	r.settle(t)
	var alert bool
	for _, a := range r.conv.Alerts(t.Context(), time.Now()) {
		if a.ID == converge.SignInRulesAlertID && a.Title == "Sign-in rules differ from Rasputin's settings. Administrator tools are locked until they are restored." {
			alert = true
		}
	}
	if !alert {
		t.Fatalf("no critical alert after the edit; state %s", r.conv.State())
	}
	w := l.send(http.MethodPost, "/api/nodes/n1/reboot", false)
	if w.Code != http.StatusLocked || !strings.Contains(w.Body.String(), `"code":"signin_rules_differ"`) ||
		!strings.Contains(w.Body.String(), "Administrator tools are locked because Rasputin's sign-in rules differ from its settings.") {
		t.Errorf("locked: a control POST answered %d %s", w.Code, w.Body)
	}
	if w := l.send(http.MethodGet, "/api/nodes", false); w.Code != http.StatusOK {
		t.Errorf("locked: a GET answered %d", w.Code)
	}
	if w := l.send(http.MethodGet, "/ws/bmc/n1/sol", true); w.Code != http.StatusLocked {
		t.Errorf("locked: the serial console's upgrade answered %d", w.Code)
	}
	if _, err := r.conv.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	r.settle(t)
	for _, a := range r.conv.Alerts(t.Context(), time.Now()) {
		if a.ID == converge.SignInRulesAlertID {
			t.Error("the alert stayed after converge")
		}
	}
	if w := l.send(http.MethodPost, "/api/nodes/n1/reboot", false); w.Code != http.StatusOK {
		t.Errorf("restored: a control POST answered %d", w.Code)
	}
	if !flows.SameSteps(flows.Flatten(flows.AppClients.Alias(), flows.Flow(flows.AppClients)), r.flowSteps(t, flows.AppClients.Alias())) {
		t.Error("the restored flow does not read back as its definition")
	}
}

// TC-987-07: ab registers at the home door; a, Ab, 1ab and a 33-character
// name are refused; renaming ab through the Admin API is refused and leaves
// it unchanged.
func (r *rulesRig) tc07(t *testing.T) {
	register := func(name string) doorAnswer {
		g := r.client(t, "127.0.0.40")
		a := g.follow(r.homeAuth(baselineConsole, map[string]string{"prompt": "create"}))
		if a.pageID() != "login-register" {
			t.Fatalf("prompt=create opened %q", a.pageID())
		}
		pw, err := randomSecret(r.env.h.cfg.Rand)
		if err != nil {
			t.Fatal(err)
		}
		defer pw.Destroy()
		return r.post(t, g, a, "kc-register-form", map[string]string{
			"username": name, "email": strings.ToLower(name) + "-tc07@rules.invalid", "firstName": "Name",
			"password": string(pw.Reveal()), "password-confirm": string(pw.Reveal()),
		})
	}
	register("ab").code(t)
	for _, name := range []string{"a", "Ab", "1ab", "a" + strings.Repeat("b", 32)} {
		got := register(name)
		if got.loc != nil && got.loc.Query().Get("code") != "" {
			t.Errorf("%q registered", name)
		}
	}
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users?exact=true&username=ab", nil)
	var users []map[string]any
	if err := json.Unmarshal(out, &users); err != nil || len(users) != 1 {
		t.Fatalf("ab: %d accounts", len(users))
	}
	id := users[0]["id"].(string)
	users[0]["username"] = "abc"
	status, _, _ := r.admin(t).do(http.MethodPut, "/users/"+id, users[0])
	_, again := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+id, nil)
	var after map[string]any
	_ = json.Unmarshal(again, &after)
	if status < 400 || after["username"] != "ab" {
		t.Errorf("the rename answered %d and left %v", status, after["username"])
	}
}

// TC-987-10: an unprivileged account and an admin, each with a passkey made
// at the home door, sign in there by the passkey alone.
func (r *rulesRig) tc10(t *testing.T) {
	bctx := r.browser(t)
	if bctx == nil {
		return
	}
	for _, role := range []string{"", "admin"} {
		a := r.account(t, "tc10-passkey"+role, nil)
		k := r.keyTab(t, bctx, "https://"+r.sites.Table.Home.Host)
		r.registerKey(t, k, a, r.homeConsole(), false)
		if role != "" {
			r.grantConsole(t, a, role)
		}
		r.passkeyAlone(t, k, r.homeConsole())
	}
}

// TC-987-11: BeforePrivilege writes both doors' second-step markers and
// _any for an account with a home-door passkey; once made admin, its
// password at the app door is asked for the second step, where a recovery
// code stands in. For an account with no second step it returns
// ErrNoSecondStep.
func (r *rulesRig) tc11(t *testing.T) {
	bctx := r.browser(t)
	if bctx == nil {
		return
	}
	a := r.account(t, "tc11-promoted", nil)
	_, codes := r.enrol(t, a, false, true)
	k := r.keyTab(t, bctx, "https://"+r.sites.Table.Home.Host)
	r.registerKey(t, k, a, r.homeConsole(), false)
	if err := r.marks.BeforePrivilege(t.Context(), a.id); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{flows.MarkerSecondStepHome, flows.MarkerSecondStepApp, flows.MarkerSecondStepAny} {
		if got := r.attr(t, a, m); got != "true" {
			t.Errorf("%s = %q before the grant", m, got)
		}
	}
	r.grantConsole(t, a, "admin")
	g := r.fresh(t)
	step := g.signIn(r.appAccount(), a.name, a.pw)
	r.answerRecovery(t, g, r.recoveryInstead(t, g, step), codes[0]).code(t)

	none := r.account(t, "tc11-none", nil)
	if err := r.marks.BeforePrivilege(t.Context(), none.id); !errors.Is(err, markers.ErrNoSecondStep) {
		t.Errorf("BeforePrivilege with no second step = %v", err)
	}
}

// TC-987-12: every method completes at each door, and the access gate runs
// when an identity-service cookie signs the person in.
func (r *rulesRig) tc12(t *testing.T) {
	household := r.account(t, "tc12-household", nil)
	totpAcct := r.account(t, "tc12-totp", nil)
	secretB32, codes := r.enrol(t, totpAcct, true, true)
	for _, d := range r.bothDoors() {
		r.fresh(t).signIn(d.auth(), household.name, household.pw).code(t)
		g := r.fresh(t)
		r.answerOTP(t, g, g.signIn(d.auth(), totpAcct.name, totpAcct.pw), secretB32).code(t)
	}
	for i, d := range r.bothDoors() {
		g := r.fresh(t)
		step := g.signIn(d.auth(), totpAcct.name, totpAcct.pw)
		r.answerRecovery(t, g, r.recoveryInstead(t, g, step), codes[i]).code(t) // the service asks for them in order
	}

	// The gate on a cookie sign-in: an account with no app access holds an
	// app-door session (from the account client, which has no gate) and
	// opens a gated app client.
	noAccess := r.account(t, "tc12-no-access", nil)
	g := r.fresh(t)
	g.signIn(r.appAuth("rasputin-account", map[string]string{"prompt": ""}), noAccess.name, noAccess.pw).code(t)
	r.settle(t)
	refused(t, "a cookie sign-in to a gated client", g.follow(r.appClient(rulesAppClients)), flows.SentenceNoAppAccess)

	bctx := r.browser(t)
	if bctx == nil {
		return
	}
	for _, d := range r.bothDoors() {
		origin := originOf(d.auth())
		pk := r.account(t, "tc12-passkey-"+strings.Fields(d.name)[0], nil)
		k := r.keyTab(t, bctx, origin)
		r.registerKey(t, k, pk, d.auth(), false)
		if got := r.passwordThenKey(t, k, pk, d.auth(), true); got != "rasputin-stub" {
			t.Errorf("%s: password and passkey led to %q", d.name, got)
		}
		r.passkeyAlone(t, k, d.auth())
		sk := r.account(t, "tc12-key-"+strings.Fields(d.name)[0], nil)
		k2 := r.keyTab(t, bctx, origin)
		r.registerKey(t, k2, sk, d.auth(), true)
		if got := r.passwordThenKey(t, k2, sk, d.auth(), true); got != "rasputin-stub" {
			t.Errorf("%s: password and security key led to %q", d.name, got)
		}
	}
}

// TC-987-13: for each account shape, privileged or not, a password sign-in
// at each door never asks for a step the account does not hold and never
// shows a setup page.
func (r *rulesRig) tc13(t *testing.T) {
	type shape struct {
		name  string
		setUp func(t *testing.T, a account)
		holds []string // the second-step pages the account can answer
	}
	shapes := []shape{
		{"none", func(*testing.T, account) {}, nil},
		{"codes", func(t *testing.T, a account) { r.enrol(t, a, false, true) }, []string{"login-login-recovery-authn-code-input"}},
		{"totp", func(t *testing.T, a account) { r.enrol(t, a, true, false) }, []string{"login-login-otp"}},
	}
	for _, sh := range shapes {
		for _, privileged := range []bool{false, true} {
			name := "tc13-" + sh.name
			if privileged {
				name += "-admin"
			}
			a := r.account(t, name, nil)
			sh.setUp(t, a)
			if privileged {
				r.grantConsole(t, a, "admin")
			}
			for _, d := range r.bothDoors() {
				got := r.fresh(t).signIn(d.auth(), a.name, a.pw)
				id := got.pageID()
				if strings.Contains(id, "config-totp") || strings.Contains(id, "webauthn-register") || strings.Contains(id, "recovery-authn-code-config") {
					t.Errorf("%s at the %s: a setup page %s", name, d.name, id)
				}
				if isSecondStep(id) && !slices.Contains(sh.holds, id) {
					t.Errorf("%s at the %s: asked for %s, which it does not hold", name, d.name, id)
				}
			}
		}
	}
	bctx := r.browser(t)
	if bctx == nil {
		return
	}
	for _, privileged := range []bool{false, true} {
		a := r.account(t, "tc13-home-passkey-"+map[bool]string{false: "user", true: "admin"}[privileged], nil)
		k := r.keyTab(t, bctx, "https://"+r.sites.Table.Home.Host)
		r.registerKey(t, k, a, r.homeConsole(), false)
		if privileged {
			if err := r.marks.BeforePrivilege(t.Context(), a.id); err != nil {
				t.Fatal(err)
			}
			r.grantConsole(t, a, "admin")
		}
		got := r.fresh(t).signIn(r.appAccount(), a.name, a.pw) // the passkey's other door
		if isSecondStep(got.pageID()) || strings.Contains(got.pageID(), "register") {
			t.Errorf("%s at the app door: asked for %s", a.name, got.pageID())
		}
		if got := r.passwordThenKey(t, k, a, r.homeConsole(), false); got != "login-webauthn-authenticate" {
			t.Errorf("%s at the home door: %s, want the passkey step", a.name, got)
		}
	}
}

// TC-987-14: an administrators-first client refuses a user with its
// sentence and admits an app admin after its second step, never on the
// password alone; a network-devices client refuses an account without
// grants with its sentence, and a gear-admin's password alone.
func (r *rulesRig) tc14(t *testing.T) {
	user := r.account(t, "tc14-user", map[string][]string{"rasputin_app_role": {"user"}})
	refused(t, "a user at the admins-first client", r.fresh(t).signIn(r.appClient(rulesAdminsFirst), user.name, user.pw), flows.SentenceAdminsFirst)
	admin := r.account(t, "tc14-app-admin", nil)
	secretB32, _ := r.enrol(t, admin, true, false)
	r.setAttributes(t, admin, map[string][]string{"rasputin_app_role": {"admin"}})
	g := r.fresh(t)
	step := g.signIn(r.appClient(rulesAdminsFirst), admin.name, admin.pw)
	r.answerOTP(t, g, step, secretB32).code(t)
	alone := r.fresh(t).signIn(r.appClient(rulesAdminsFirst), admin.name, admin.pw)
	if alone.loc != nil && alone.loc.Query().Get("code") != "" {
		t.Error("the app admin's password alone got a code")
	}
	noGrant := r.account(t, "tc14-no-grant", nil)
	refused(t, "no network grant", r.fresh(t).signIn(r.appClient(rulesNetworkDevices), noGrant.name, noGrant.pw), flows.SentenceNoNetworkAccess)
	gear := r.account(t, "tc14-gear-admin", map[string][]string{"rasputin_network": {"gear-admin"}})
	refused(t, "a gear-admin's password alone", r.fresh(t).signIn(r.appClient(rulesNetworkDevices), gear.name, gear.pw), flows.SentencePrivileged)
}

// upstreamClient signs in straight at Keycloak, past the doors and their
// per-source throttle, over the door's own client leaf.
func (r *rulesRig) upstreamClient(t *testing.T) *goClient {
	t.Helper()
	tr, err := r.env.DoorTransport()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tr.CloseIdleConnections)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &goClient{t: t, jar: jar, c: &http.Client{Transport: tr, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// TC-987-15: 99 wrong passwords, sent straight to Keycloak so the doors'
// per-source wait never applies, leave the right one working (no quick
// check); 100 hold the account; UNLOCK (the attack-detection reset) clears
// it; an app session made before stays valid throughout.
func (r *rulesRig) tc15(t *testing.T) {
	a := r.account(t, "tc15-backstop", nil)
	r.fresh(t).signIn(r.appAccount(), a.name, a.pw).code(t)
	sessions := r.sessionCount(t, a.id)
	if sessions != 1 {
		t.Fatalf("%d sessions before, want 1", sessions)
	}
	up := r.upstreamClient(t)
	authURL := r.env.KeycloakUpstream().String() + "/realms/rasputin/protocol/openid-connect/auth?" + doorAuthQuery("rasputin-account", r.sites.Table.App.Host, nil)
	wrong := func(n int) {
		page := up.follow(authURL)
		for range n {
			if page.pageID() != "login-login" {
				t.Fatalf("a wrong password led to %q", page.pageID())
			}
			page = up.submit(page, "kc-form-login", map[string]string{"username": a.name, "password": "wrong-password-0000"})
		}
	}
	wrong(99)
	r.awaitFailures(t, a.id, 99)
	up.signIn(authURL, a.name, a.pw).code(t)
	wrong(100)
	if bf := r.awaitFailures(t, a.id, 100); !bf.Disabled {
		t.Errorf("after 100 failures the account is not held: %+v", bf)
	}
	if got := up.signIn(authURL, a.name, a.pw); got.loc != nil && got.loc.Query().Get("code") != "" {
		t.Error("the right password signed in a held account")
	}
	if n := r.sessionCount(t, a.id); n < sessions {
		t.Errorf("the hold ended the app session: %d sessions", n)
	}
	r.admin(t).must(http.StatusNoContent, http.MethodDelete, "/attack-detection/brute-force/users/"+a.id, nil)
	up.signIn(authURL, a.name, a.pw).code(t)
	if n := r.sessionCount(t, a.id); n < sessions {
		t.Errorf("UNLOCK ended the app session: %d sessions", n)
	}
}

// TC-987-16: with the admins-first client's binding removed through the
// Admin API and drained, the app door refuses its authorization request
// with 503 and its sentence and forwards nothing for it; the account client
// still signs in; once converge restores the binding the client signs in
// under admins-first rules again.
func (r *rulesRig) tc16(t *testing.T) {
	api := r.admin(t)
	id, _ := api.clientRep(rulesAdminsFirst)
	api.must(http.StatusNoContent, http.MethodPut, "/clients/"+id, map[string]any{"authenticationFlowBindingOverrides": map[string]string{"browser": ""}})
	r.settle(t)
	before := r.forwarded(rulesAdminsFirst)
	got := r.fresh(t).follow(r.appClient(rulesAdminsFirst))
	if got.status != http.StatusServiceUnavailable || got.pageID() != "rasputin-door-refusal" ||
		got.sentence() != "Signing in to this app is paused because its sign-in settings changed. An administrator can see why in Rasputin's alerts." {
		t.Errorf("paused: %d %q %q", got.status, got.pageID(), got.sentence())
	}
	if n := r.forwarded(rulesAdminsFirst) - before; n != 0 {
		t.Errorf("the paused client's request reached Keycloak %d times", n)
	}
	if !strings.Contains(r.rec.Text(), "client_paused") {
		t.Error("no client_paused refusal record")
	}
	household := r.account(t, "tc16-household", nil)
	r.fresh(t).signIn(r.appAccount(), household.name, household.pw).code(t)
	if _, err := r.conv.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, rep := api.clientRep(rulesAdminsFirst)
	if b, _ := rep["authenticationFlowBindingOverrides"].(map[string]any); b["browser"] == nil || b["browser"] == "" {
		t.Fatalf("the binding was not restored: %v", rep["authenticationFlowBindingOverrides"])
	}
	user := r.account(t, "tc16-user", map[string][]string{"rasputin_app_role": {"user"}})
	refused(t, "a user under the restored admins-first rules", r.fresh(t).signIn(r.appClient(rulesAdminsFirst), user.name, user.pw), flows.SentenceAdminsFirst)
}

// TC-987-18: the password policy (15 to 128 characters, not the username or
// email), no remember-me, unique email, email sign-in, and the realm's
// lifetimes as rendered.
func (r *rulesRig) tc18(t *testing.T) {
	a := r.account(t, "tc18-policy", nil)
	set := func(pw string) int {
		status, _, _ := r.admin(t).do(http.MethodPut, "/users/"+a.id+"/reset-password", map[string]any{"type": "password", "value": pw, "temporary": false})
		return status
	}
	for pw, ok := range map[string]bool{
		strings.Repeat("x", 14): false, strings.Repeat("y", 15): true, strings.Repeat("z", 129): false,
		"tc18-policy" + strings.Repeat("-", 5): true, a.name + "-pad-pad": true,
	} {
		if got := set(pw) == http.StatusNoContent; got != ok {
			t.Errorf("a %d-character password: accepted %v, want %v", len(pw), got, ok)
		}
	}
	// The username and the email themselves, each at least 15 characters.
	long := r.account(t, "tc18-long-sign-in-name", nil)
	for _, pw := range []string{long.name, long.name + "@rules.invalid"} {
		status, _, _ := r.admin(t).do(http.MethodPut, "/users/"+long.id+"/reset-password", map[string]any{"type": "password", "value": pw, "temporary": false})
		if status == http.StatusNoContent {
			t.Errorf("the password %q (the username or email) was accepted", pw)
		}
	}
	page := r.fresh(t).follow(r.homeConsole())
	if strings.Contains(string(page.body), `name="rememberMe"`) {
		t.Error("the sign-in page offers remember-me")
	}
	status, _, _ := r.admin(t).do(http.MethodPost, "/users", map[string]any{"username": "tc18-dup", "email": long.name + "@rules.invalid", "enabled": true})
	if status != http.StatusConflict {
		t.Errorf("a duplicate email answered %d, want 409", status)
	}
	r.fresh(t).signIn(r.homeConsole(), long.name+"@rules.invalid", long.pw).code(t)
	realm := realmRep(t, r.admin(t))
	for k, want := range flows.RealmRules(flows.Inputs{}) {
		if strings.HasPrefix(k, "webAuthnPolicy") || k == "browserFlow" {
			continue
		}
		if !flows.SameJSON(realm[k], want) {
			t.Errorf("realm %s = %v, want %v", k, realm[k], want)
		}
	}
}

// TC-987-19: rp.name in each door's creation options is RPName, Rasputin,
// and both policies hold it; after the install name changes and converge
// runs, an earlier passkey still signs in and both policies still do.
func (r *rulesRig) tc19(t *testing.T) {
	bctx := r.browser(t)
	if bctx == nil {
		return
	}
	want := flows.RPName(flows.Inputs{InstallName: rulesInstall})
	var last *keyTab
	for _, d := range r.bothDoors() {
		a := r.account(t, "tc19-"+strings.Fields(d.name)[0], nil)
		k := r.keyTab(t, bctx, originOf(d.auth()))
		r.registerKey(t, k, a, d.auth(), false)
		if got := k.rpNames(); len(got) != 1 || got[0] != want || want == "" || want == "keycloak" {
			t.Errorf("%s: rp.name %q, want [%q]", d.name, got, want)
		}
		last = k
	}
	policies := func() {
		realm := realmRep(t, r.admin(t))
		for _, k := range []string{"webAuthnPolicyRpEntityName", "webAuthnPolicyPasswordlessRpEntityName"} {
			if realm[k] != want {
				t.Errorf("%s = %v, want %s", k, realm[k], want)
			}
		}
	}
	policies()
	r.setInputs(func(in *converge.Inputs) { in.InstallName = "Renamed CI" })
	t.Cleanup(func() { r.setInputs(func(in *converge.Inputs) { in.InstallName = rulesInstall }) })
	if _, err := r.conv.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	policies()
	r.passkeyAlone(t, last, r.appAccount())
}

// recoveryPage is TC-987-20's open recovery-codes page.
type recoveryPage struct {
	g      *goClient
	page   doorAnswer
	opened time.Time
}

// tc20open opens a first sign-in's recovery-codes page.
func (r *rulesRig) tc20open(t *testing.T) recoveryPage {
	a := r.account(t, "tc20-codes", nil)
	r.requireActions(t, a, flows.ActionRecoveryCodes)
	g := r.client(t, "127.0.0.41")
	page := g.signIn(r.homeConsole(), a.name, a.pw)
	if page.pageID() != "login-login-recovery-authn-code-config" {
		t.Fatalf("the first sign-in opened %q", page.pageID())
	}
	return recoveryPage{g: g, page: page, opened: time.Now()}
}

// recoveryWait is how long TC-987-20 leaves the page: past Keycloak's stock
// 5-minute action timeout, which the realm's 30-minute value replaces.
const recoveryWait = 6 * time.Minute

// tc20finish answers the page once it has been open longer than recoveryWait
// (a fact on the clock, which is what the case measures), then checks the
// realm holds 1800 seconds.
func (r *rulesRig) tc20finish(t *testing.T, p recoveryPage) {
	if p.g == nil {
		t.Fatal("the page was never opened")
	}
	if left := time.Until(p.opened.Add(recoveryWait)); left > 0 {
		timer := time.NewTimer(left)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-t.Context().Done():
			t.Fatal("the test ended before the page had been open 6 minutes")
		}
	}
	p.g.t = t // the client was made in the subtest that opened the page, which has ended
	got := r.post(t, p.g, p.page, "kc-recovery-codes-settings-form", nil)
	if strings.Contains(got.pageID(), "expired") {
		t.Fatalf("the page expired after %s", time.Since(p.opened))
	}
	got.code(t)
	t.Logf("the recovery-codes page completed after %s", time.Since(p.opened).Round(time.Second))
	if v := realmRep(t, r.admin(t))["accessCodeLifespanUserAction"]; !flows.SameJSON(v, 1800) {
		t.Errorf("accessCodeLifespanUserAction = %v, want 1800", v)
	}
}

// TC-987-21 (K-ACR): acr is the same in a password-and-second-step sign-in
// and a passkey-alone sign-in to the same client.
func (r *rulesRig) tc21(t *testing.T) {
	bctx := r.browser(t)
	if bctx == nil {
		return
	}
	a := r.account(t, "tc21-acr", map[string][]string{"rasputin_app_role": {"user"}})
	k := r.keyTab(t, bctx, "https://"+r.sites.Table.App.Host)
	r.registerKey(t, k, a, r.appClient(rulesAppClients), false)
	if got := r.passwordThenKey(t, k, a, r.appClient(rulesAppClients), true); got != "rasputin-stub" {
		t.Fatalf("password and passkey led to %q", got)
	}
	stepped := r.idTokenClaims(t, rulesAppClients, codeOf(t, evalT[string](k.tab, `location.href`)))
	alone := r.idTokenClaims(t, rulesAppClients, r.passkeyAlone(t, k, r.appClient(rulesAppClients)))
	if stepped["acr"] != alone["acr"] {
		t.Errorf("acr %v after a second step, %v after a passkey alone; K-ACR says they are equal", stepped["acr"], alone["acr"])
	}
	t.Logf("acr: %v", alone["acr"])
}

// TC-987-22 (K-PROFILE): a registration and a profile update that post the
// app role, a marker and a claim_ field set none of them.
func (r *rulesRig) tc22(t *testing.T) {
	api := r.admin(t)
	_, out := api.must(http.StatusOK, http.MethodGet, "/users/profile", nil)
	var profile map[string]any
	if err := json.Unmarshal(out, &profile); err != nil {
		t.Fatal(err)
	}
	profile["attributes"] = append(profile["attributes"].([]any), map[string]any{"name": "claim_x", "displayName": "claim_x",
		"permissions": map[string]any{"view": []any{"admin"}, "edit": []any{"admin"}}})
	if status, _, body := api.do(http.MethodPut, "/users/profile", profile); status/100 != 2 {
		t.Fatalf("adding claim_x answered %d: %.300s", status, body)
	}
	injected := map[string]string{"rasputin_app_role": "admin", flows.MarkerSecondStepAny: "true", "claim_x": "1"}
	g := r.client(t, "127.0.0.42")
	a := g.follow(r.homeAuth(baselineConsole, map[string]string{"prompt": "create"}))
	pw, err := randomSecret(r.env.h.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Destroy()
	fields := map[string]string{"username": "tc22-new", "email": "tc22-new@rules.invalid", "firstName": "New",
		"password": string(pw.Reveal()), "password-confirm": string(pw.Reveal())}
	for k, v := range injected {
		fields[k] = v
	}
	r.post(t, g, a, "kc-register-form", fields).code(t)
	_, out = api.must(http.StatusOK, http.MethodGet, "/users?exact=true&username=tc22-new", nil)
	var users []map[string]any
	if err := json.Unmarshal(out, &users); err != nil || len(users) != 1 {
		t.Fatal("the new account")
	}
	if attrs, _ := users[0]["attributes"].(map[string]any); len(attrs) != 0 {
		for k := range injected {
			if attrs[k] != nil {
				t.Errorf("registration set %s", k)
			}
		}
	}
	// A profile update: UPDATE_PROFILE enabled for this case, then put back
	// by converge.
	_, out = api.must(http.StatusOK, http.MethodGet, "/authentication/required-actions/UPDATE_PROFILE", nil)
	var ra map[string]any
	_ = json.Unmarshal(out, &ra)
	ra["enabled"] = true
	api.must(http.StatusNoContent, http.MethodPut, "/authentication/required-actions/UPDATE_PROFILE", ra)
	t.Cleanup(func() { _, _ = r.conv.Run(context.Background()) })
	u := r.account(t, "tc22-update", nil)
	r.requireActions(t, u, "UPDATE_PROFILE")
	g = r.fresh(t)
	page := g.signIn(r.homeConsole(), u.name, u.pw)
	if page.pageID() != "login-login-update-profile" {
		t.Fatalf("the update action opened %q", page.pageID())
	}
	upd := map[string]string{"firstName": "Updated", "email": u.name + "@rules.invalid"}
	for k, v := range injected {
		upd[k] = v
	}
	// Keycloak either drops the admin-only fields or refuses the post;
	// either way none is set.
	after := r.post(t, g, page, "kc-update-profile-form", upd)
	t.Logf("the profile update with admin-only fields led to %q (%d)", after.pageID(), after.status)
	if after.pageID() == "login-login-update-profile" {
		// Refused: the same update without them completes, so the refusal
		// was theirs.
		r.post(t, g, after, "kc-update-profile-form", map[string]string{"firstName": "Updated", "email": u.name + "@rules.invalid"}).code(t)
	} else {
		after.code(t)
	}
	attrs, _ := r.user(t, u)["attributes"].(map[string]any)
	for k := range injected {
		if attrs[k] != nil {
			t.Errorf("a profile update set %s", k)
		}
	}
}

// TC-987-23 (K-DEFAULT-ACTION): a required action whose default flag is on
// is put on a user created afterwards.
func (r *rulesRig) tc23(t *testing.T) {
	api := r.admin(t)
	path := "/authentication/required-actions/" + flows.ActionRecoveryCodes
	_, out := api.must(http.StatusOK, http.MethodGet, path, nil)
	var ra map[string]any
	_ = json.Unmarshal(out, &ra)
	ra["defaultAction"] = true
	api.must(http.StatusNoContent, http.MethodPut, path, ra)
	a := r.account(t, "tc23-default", nil)
	actions, _ := r.user(t, a)["requiredActions"].([]any)
	ra["defaultAction"] = false
	api.must(http.StatusNoContent, http.MethodPut, path, ra)
	if !slices.Contains(actions, any(flows.ActionRecoveryCodes)) {
		t.Errorf("requiredActions = %v, want %s", actions, flows.ActionRecoveryCodes)
	}
}
