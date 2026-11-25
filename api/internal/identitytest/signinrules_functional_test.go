package identitytest

// The sign-in rules against the real identity service
// (geekdojo/geekdojo-brain#987, Identity 4.5; TC-987-01 to TC-987-23): the
// definition in package flows, converged by the real converger, signed in
// through both doors by the Go door client and, for the passkey cases, the
// pinned Chrome's virtual authenticator.
//
// And the password deny list (geekdojo/geekdojo-brain#1145; TC-1145-14 to
// TC-1145-20): a missing list refused by the realm PUT with nothing stored,
// before the rig's first converge, then a listed password refused at every
// path that sets one at this SHA.
//
// It starts an Env of its own, closed with proof in its cleanup. It skips
// without RASPUTIN_IDENTITY_HOME or RASPUTIN_IDENTITY_THEME and fails instead
// under RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job sets it.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"html"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/converge"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
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
	// Before the rig's first converge: Keycloak caches a list it has loaded for
	// the life of the process, so the missing-list case runs in a process that
	// has never loaded it, and the upgrade case needs a password set before the
	// policy applies. setUpRules is the restored list's converge.
	t.Run("TC-1145-14 a missing list fails visibly and changes nothing", func(t *testing.T) { r.tc1145missing(t) })
	// TC-1145-19's given, on this test's t so its password outlives a subtest.
	listedBefore := r.tc1145given19(t)
	r.setUpRules(t)
	t.Run("TC-1145-14 the list restored: converge applies the policy", func(t *testing.T) { r.tc1145restored(t) })
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
	t.Run("TC-1145-15 account creation at the home door", func(t *testing.T) { r.tc1145registration(t) })
	t.Run("TC-1145-16 a password change at each door", func(t *testing.T) { r.tc1145change(t) })
	t.Run("TC-1145-17 an administrator's temporary password, then the change at each door", func(t *testing.T) { r.tc1145temporary(t) })
	t.Run("TC-1145-18 the Admin API reset, ASCII and non-ASCII", func(t *testing.T) { r.tc1145reset(t) })
	t.Run("TC-1145-19 a listed password set before the policy still signs in", func(t *testing.T) { r.tc1145upgrade(t, listedBefore) })
	t.Run("TC-1145-20 converge is stable with the deny list", func(t *testing.T) { r.tc1145stable(t) })
	t.Run("TC-987-19 the passkey relying-party name", func(t *testing.T) { r.tc19(t) })
	t.Run("TC-987-21 K-ACR", func(t *testing.T) { r.tc21(t) })
	t.Run("TC-987-22 K-PROFILE", func(t *testing.T) { r.tc22(t) })
	t.Run("TC-987-23 K-DEFAULT-ACTION", func(t *testing.T) { r.tc23(t) })
	t.Run("TC-1145-38 the breached-password warning at account creation", func(t *testing.T) { r.tc1145breachRegistration(t) })
	t.Run("TC-1145-39 the breached-password warning at the password change, each door", func(t *testing.T) { r.tc1145breachUpdate(t) })
	t.Run("TC-1145-40 offline, the breach check fails open", func(t *testing.T) { r.tc1145breachOffline(t) })
	t.Run("TC-991-31 TS-18 C23 a privileged grant ends the password-only session", func(t *testing.T) { r.tc991privileged(t) })
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
	path := filepath.Join(t.TempDir(), "auth.db")
	store, err := auth.OpenStore(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	designations, err := accounts.OpenDesignations(t.Context(), path, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = designations.Close() })
	sessions, err := auth.NewConsoleSessions(store, time.Now, rand.Reader, designations)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := auth.NewService(store, auth.Config{RPDisplayName: "Rasputin", RPID: "localhost", RPOrigins: []string{"https://localhost"},
		Sessions: sessions})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetControlGate(r.conv.ControlGate, r.env.log)
	cookie, err := sessions.Create(t.Context(), auth.Principal{Sub: "tc06-sub", Name: "tc06", Roles: []string{"admin"},
		Session: auth.SessionRef{SID: "tc06-sid"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cookie.Destroy)
	token := string(cookie.Reveal())
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux := http.NewServeMux()
	for _, p := range []string{"GET /api/nodes", "POST /api/nodes/{id}/reboot", "GET /ws/bmc/{nodeId}/sol"} {
		mux.Handle(p, svc.RequireSession(ok))
	}
	return lockSession{mux: mux, token: token}
}

func (l lockSession) send(method, path string, upgrade bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: l.token})
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
		k2 := r.keyTab(t, bctx, origin, true)
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
func (r *doorRig) upstreamClient(t *testing.T) *goClient {
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
	return &goClient{t: t, jar: jar, c: &http.Client{Transport: forwardedFor{tr}, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// forwardedFor names a documentation address as the client, which Keycloak
// in door mode takes from loopback, so the failures land on that source in
// the drained events and never on 127.0.0.1, the browser's.
type forwardedFor struct{ inner http.RoundTripper }

func (f forwardedFor) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("X-Forwarded-For", "192.0.2.15")
	return f.inner.RoundTrip(req)
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
	// "quokka-tangelo7" is 15 characters and not on the deny list (measured);
	// y×15 is on it (F-1145-12), so it would test the list, not the length.
	for pw, ok := range map[string]bool{
		strings.Repeat("x", 14): false, "quokka-tangelo7": true, strings.Repeat("z", 129): false,
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
	// prompt=login: each sign-in is made afresh, never by the session the
	// registration left in the tab.
	auth := r.appURL("/realms/rasputin/protocol/openid-connect/auth?" + doorAuthQuery(rulesAppClients, AppSiteHost, nil))
	r.registerKey(t, k, a, auth, false)
	if got := r.passwordThenKey(t, k, a, auth, true); got != "rasputin-stub" {
		t.Fatalf("password and passkey led to %q", got)
	}
	stepped := r.idTokenClaims(t, rulesAppClients, codeOf(t, evalT[string](k.tab, `location.href`)))
	alone := r.idTokenClaims(t, rulesAppClients, r.passkeyAlone(t, k, auth))
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

// ---- the password deny list (geekdojo/geekdojo-brain#1145) -----------------

// denylistSentence is the theme's invalidPasswordBlacklistedMessage.
const denylistSentence = "That password is too common. Choose another."

// errWriteSentence is converge's errWrite, the sentence a failed write
// returns.
const errWriteSentence = "A sign-in setting could not be written back to Rasputin's."

// listed returns two entries of the staged list, the packed file: the first
// lowercase ASCII letters-and-digits line of 15 to 128 bytes, and the first
// non-ASCII line of 15 to 128 UTF-16 units that is valid UTF-8, lowercase,
// unpadded and holds no replacement character, so neither the length rule
// nor a case or whitespace rule can be what refuses it.
func (r *rulesRig) listed(t *testing.T) (ascii, nonASCII secret.Value) {
	t.Helper()
	return listedEntries(t, r.env.kcHome)
}

// listedEntries are an ASCII and a non-ASCII entry of the staged deny list
// that the length rule accepts, lowercase and trimmed.
func listedEntries(t *testing.T, kcHome string) (ascii, nonASCII secret.Value) {
	t.Helper()
	f, err := os.Open(denylistPath(kcHome))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var a, n string
	sc := bufio.NewScanner(f)
	for sc.Scan() && (a == "" || n == "") {
		line := sc.Text()
		units := len(utf16.Encode([]rune(line)))
		ok := utf8.ValidString(line) && line == strings.ToLower(line) && line == strings.TrimSpace(line) &&
			!strings.ContainsRune(line, utf8.RuneError) && units >= 15 && units <= 128
		switch {
		case !ok:
		case a == "" && strings.Trim(line, "abcdefghijklmnopqrstuvwxyz0123456789") == "":
			a = line
		case n == "" && utf8.RuneCountInString(line) != len(line):
			n = line
		}
	}
	if err := sc.Err(); err != nil || a == "" || n == "" {
		t.Fatalf("the staged list gave no usable ASCII or non-ASCII entry (%v)", err)
	}
	return secret.New([]byte(a)), secret.New([]byte(n))
}

// shows reports whether the page carries the sentence.
func shows(a doorAnswer, sentence string) bool {
	return strings.Contains(html.UnescapeString(string(a.body)), sentence)
}

// TC-1145-14 (T170): before any converge, in a Keycloak that has never
// loaded the list, the staged list is hidden and a converger runs over the
// rig's session with a recorder of its own. It returns errWrite and logs one
// ERROR identity.converge.failed whose fields name realm.passwordPolicy; every
// realm field the rules own reads back as before, no hash is stored, and an
// existing account still signs in at the home door. The list is put back
// before the case ends; the rig's own first converge is the restored run.
func (r *rulesRig) tc1145missing(t *testing.T) {
	staged := denylistPath(r.env.kcHome)
	aside := staged + ".aside"
	if err := os.Rename(staged, aside); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Rename(aside, staged); err != nil {
			t.Fatalf("put the list back: %v", err)
		}
	}()
	api := r.admin(t)
	before := realmRep(t, api)
	if before["passwordPolicy"] == flows.PasswordPolicy {
		t.Fatal("given: the realm already holds the deny-list policy")
	}
	a := r.account(t, "tc1145-14-existing", nil)
	// Given: the console's redirect URI as converge will set it. The imported
	// baseline has none, so before the first converge the home door's
	// authorization request is refused for its redirect, not for any reason
	// this case is about.
	id, console := api.clientRep(baselineConsole)
	console["redirectUris"] = r.inputs().RedirectURIs[baselineConsole]
	api.must(http.StatusNoContent, http.MethodPut, "/clients/"+id, console)
	log, rec := logkittest.New()
	settings := &memSettings{m: map[string]string{}}
	conv, err := converge.New(converge.Deps{
		Admin: r.session, Settings: settings, Realm: baselineRealm, Lock: r.lock,
		Inputs: func(context.Context) (converge.Inputs, error) { return r.inputs(), nil },
		Now:    time.Now, Ready: func(context.Context) error { return nil }, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fields, err := conv.Run(t.Context()); err == nil || err.Error() != errWriteSentence {
		t.Errorf("converge with the list missing = %v, %v; want errWrite %q", fields, err, errWriteSentence)
	}
	if errs := rec.AtLevel(slog.LevelError); len(errs) != 1 {
		t.Errorf("%d ERROR records, want one:\n%s", len(errs), rec.Text())
	} else {
		ev, _ := logkittest.Attr(errs[0], "event")
		fields, _ := logkittest.Attr(errs[0], "fields")
		if ev != "identity.converge.failed" || !strings.Contains(fields, "realm.passwordPolicy") {
			t.Errorf("the ERROR is event %q with fields %q; want identity.converge.failed naming realm.passwordPolicy", ev, fields)
		}
	}
	after := realmRep(t, api)
	for k := range flows.RealmRules(flows.Inputs{}) {
		if !flows.SameJSON(before[k], after[k]) {
			t.Errorf("the refused realm PUT stored %s: %v, then %v", k, before[k], after[k])
		}
	}
	if got, _ := settings.Get(t.Context(), converge.HashKey); got != "" {
		t.Errorf("a failed converge stored the hash %q", got)
	}
	r.fresh(t).signIn(r.homeConsole(), a.name, a.pw).code(t)
}

// TC-1145-14, its second half: with the list back, the rig's first converge
// succeeded, the policy reads back as flows.PasswordPolicy and the hash is
// stored.
func (r *rulesRig) tc1145restored(t *testing.T) {
	if got := realmRep(t, r.admin(t))["passwordPolicy"]; got != flows.PasswordPolicy {
		t.Errorf("passwordPolicy = %v, want %q", got, flows.PasswordPolicy)
	}
	want := converge.NewDesired(r.inputs()).Hash()
	if got, _ := r.settings.Get(t.Context(), converge.HashKey); got != want {
		t.Errorf("the stored hash = %q, want %q", got, want)
	}
}

// tc1145given19 is TC-1145-19's given: an account whose password is a
// listed entry, set while the realm has no deny list.
func (r *rulesRig) tc1145given19(t *testing.T) account {
	ascii, _ := r.listed(t)
	return r.accountWith(t, "tc1145-19-upgraded", ascii, nil)
}

// TC-1145-19: once converge applied the policy, the account whose listed
// password was set before signs in with it at the home door and is not
// sent to a password change: existing passwords are not re-checked.
func (r *rulesRig) tc1145upgrade(t *testing.T, a account) {
	if a.id == "" {
		t.Fatal("given: no account was created before the policy")
	}
	r.fresh(t).signIn(r.homeConsole(), a.name, a.pw).code(t)
}

// TC-1145-15: account creation at the home door (prompt=create) with a
// listed password shows the sentence and creates no account; with an
// unlisted one it creates the account.
func (r *rulesRig) tc1145registration(t *testing.T) {
	listed, _ := r.listed(t)
	unlisted, err := randomSecret(r.env.h.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	defer unlisted.Destroy()
	register := func(name, ip string, pw secret.Value) doorAnswer {
		g := r.client(t, ip)
		a := g.follow(r.homeAuth(baselineConsole, map[string]string{"prompt": "create"}))
		if a.pageID() != "login-register" {
			t.Fatalf("prompt=create opened %q", a.pageID())
		}
		return r.post(t, g, a, "kc-register-form", map[string]string{
			"username": name, "email": name + "@rules.invalid", "firstName": "Listed",
			"password": string(pw.Reveal()), "password-confirm": string(pw.Reveal()),
		})
	}
	accounts := func(name string) int {
		_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users?exact=true&username="+name, nil)
		var users []map[string]any
		if err := json.Unmarshal(out, &users); err != nil {
			t.Fatal(err)
		}
		return len(users)
	}
	got := register("tc1145-15-listed", "127.0.0.43", listed)
	if got.loc != nil && got.loc.Query().Get("code") != "" {
		t.Error("a listed password registered")
	}
	if !shows(got, denylistSentence) {
		t.Errorf("the refusal page %q (%d) does not say %q", got.pageID(), got.status, denylistSentence)
	}
	if n := accounts("tc1145-15-listed"); n != 0 {
		t.Errorf("a listed password created %d accounts", n)
	}
	register("tc1145-15-unlisted", "127.0.0.44", unlisted).code(t)
	if n := accounts("tc1145-15-unlisted"); n != 1 {
		t.Errorf("an unlisted password created %d accounts, want 1", n)
	}
}

// changeAtDoor runs an UPDATE_PASSWORD page reached by signing a in with
// current at the door: a listed password is refused with the sentence and
// current still signs in; an unlisted one is accepted and then signs in.
func (r *rulesRig) changeAtDoor(t *testing.T, d doorCase, a account, current secret.Value) {
	t.Helper()
	listed, _ := r.listed(t)
	g := r.fresh(t)
	page := g.signIn(d.auth(), a.name, current)
	if page.pageID() != "login-login-update-password" {
		t.Fatalf("%s: signing in opened %q (%q), want the password change", d.name, page.pageID(), errorText(page))
	}
	got := r.post(t, g, page, "kc-passwd-update-form", map[string]string{
		"password-new": string(listed.Reveal()), "password-confirm": string(listed.Reveal())})
	if got.loc != nil && got.loc.Query().Get("code") != "" {
		t.Fatalf("%s: a listed password was accepted", d.name)
	}
	if got.pageID() != "login-login-update-password" || !shows(got, denylistSentence) {
		t.Errorf("%s: the refusal is page %q (%d), want the password change saying %q", d.name, got.pageID(), got.status, denylistSentence)
	}
	if p := r.fresh(t).signIn(d.auth(), a.name, current); p.pageID() != "login-login-update-password" {
		t.Errorf("%s: after the refusal the old password reached %q, want it still accepted", d.name, p.pageID())
	}
	next, err := randomSecret(r.env.h.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Destroy()
	r.post(t, g, got, "kc-passwd-update-form", map[string]string{
		"password-new": string(next.Reveal()), "password-confirm": string(next.Reveal())}).code(t)
	r.fresh(t).signIn(d.auth(), a.name, next).code(t)
}

// TC-1145-16: UPDATE_PASSWORD at each door.
func (r *rulesRig) tc1145change(t *testing.T) {
	for _, d := range r.bothDoors() {
		a := r.account(t, "tc1145-16-"+strings.Fields(d.name)[0], nil)
		r.requireActions(t, a, flows.ActionUpdatePassword)
		r.changeAtDoor(t, d, a, a.pw)
	}
}

// TC-1145-17: an administrator sets an unlisted temporary password through
// the Admin API (temporary=true, D15); signing in with it at each door
// leads to UPDATE_PASSWORD, which refuses a listed password and accepts an
// unlisted one.
func (r *rulesRig) tc1145temporary(t *testing.T) {
	for _, d := range r.bothDoors() {
		a := r.account(t, "tc1145-17-"+strings.Fields(d.name)[0], nil)
		temp, err := randomSecret(r.env.h.cfg.Rand)
		if err != nil {
			t.Fatal(err)
		}
		r.admin(t).must(http.StatusNoContent, http.MethodPut, "/users/"+a.id+"/reset-password",
			map[string]any{"type": "password", "value": string(temp.Reveal()), "temporary": true})
		r.changeAtDoor(t, d, a, temp)
		temp.Destroy()
	}
}

// TC-1145-18 (T171): the Admin API reset refuses a listed ASCII entry and a
// listed non-ASCII entry, and the old password still signs in after each;
// an unlisted 15-character password is then accepted with 204, so the list,
// not the length rule, is what refused.
//
// The refusal answers 500 unknown_error at this pin, not 400 with
// invalidPasswordBlacklistedMessage: Keycloak logs "Could not update
// password ... Reason: invalidPasswordBlacklistedMessage", then
// AdminRoot.getMessages finds no admin theme (the build disables the admin
// console) and the error response itself fails. Every password-policy
// refusal through the Admin API does the same, the length rules included
// (measured 2026-11-23). The credential is unchanged either way.
func (r *rulesRig) tc1145reset(t *testing.T) {
	ascii, nonASCII := r.listed(t)
	a := r.account(t, "tc1145-18-reset", nil)
	set := func(pw string) (int, []byte) {
		status, _, body := r.admin(t).do(http.MethodPut, "/users/"+a.id+"/reset-password",
			map[string]any{"type": "password", "value": pw, "temporary": false})
		return status, body
	}
	for what, pw := range map[string]secret.Value{"ASCII": ascii, "non-ASCII": nonASCII} {
		if status, body := set(string(pw.Reveal())); status < http.StatusBadRequest {
			t.Errorf("a listed %s entry answered %d %.300s; want a refusal", what, status, body)
		}
		r.fresh(t).signIn(r.homeConsole(), a.name, a.pw).code(t)
	}
	if status, body := set("quokka-tangelo7"); status != http.StatusNoContent {
		t.Errorf("an unlisted 15-character password answered %d %.300s; want 204", status, body)
	}
}

// TC-1145-20: with the policy converged, a run with no input change repairs
// nothing and logs no drift, and passwordPolicy reads back byte-equal.
func (r *rulesRig) tc1145stable(t *testing.T) {
	mark := len(r.rec.Records())
	if fields, err := r.conv.Run(t.Context()); err != nil || len(fields) != 0 {
		t.Errorf("a run with no input change: %v, %v; want nothing written", fields, err)
	}
	for _, rec := range r.rec.Records()[mark:] {
		if ev, _ := logkittest.Attr(rec, "event"); ev == "identity.converge.drift" {
			t.Errorf("the run logged drift: %s", rec.Message)
		}
	}
	if got := realmRep(t, r.admin(t))["passwordPolicy"]; got != flows.PasswordPolicy {
		t.Errorf("passwordPolicy = %v, want %q", got, flows.PasswordPolicy)
	}
}
