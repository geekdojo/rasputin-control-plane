package identitytest

// A signed-in person adds a passkey, a security key, an authenticator app or
// recovery codes to their own account against the real identity service
// (geekdojo/geekdojo-brain#1150, Identity 4.16; TC-1150-16 to TC-1150-23):
// the first-run rig, whose home door's policy reads the console's real
// SignIn as its issued actions, as main wires it. Each method is prepared
// through auth.Service.PrepareMethod for a person with a console session, and
// its fresh sign-in is followed through the real home door to the pinned
// Keycloak and back to the console's callback. The route's own answers are
// the api's unit tests' (TC-1150-12, TC-1150-13).
//
// It starts an Env of its own, so its first sign-up is the first-run claim,
// closed with proof in its cleanup. It skips without RASPUTIN_IDENTITY_HOME
// or RASPUTIN_IDENTITY_THEME and fails instead under
// RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job sets it.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// methodActionSentence is the home door's refusal of a kc_action the api did
// not issue.
const methodActionSentence = "This sign-in step wasn't started by Rasputin, so it was refused. Start again from Rasputin."

// methodsRig is the first-run rig with the sign-in methods' helpers.
type methodsRig struct {
	*firstRunRig
	browser context.Context
}

// launch is a prepared method: where the browser goes, and the console
// session and pending cookies it carries.
type launch struct {
	next             string
	session, pending *http.Cookie
}

// session mints a console session for the account, as a sign-in would.
func (r *methodsRig) session(t *testing.T, sub, name string) *http.Cookie {
	t.Helper()
	v, err := r.sessions.Create(t.Context(), auth.Principal{Sub: sub, Name: name, Session: auth.SessionRef{SID: "sid-1150-" + name}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Destroy)
	return &http.Cookie{Name: auth.SessionCookieName, Value: string(v.Reveal()), Path: "/", Secure: true}
}

// prepare is PrepareMethod for the person, with a fresh console session.
func (r *methodsRig) prepare(t *testing.T, sub, name string, m auth.Method) (launch, error) {
	t.Helper()
	l := launch{session: r.session(t, sub, name)}
	req := httptest.NewRequest(http.MethodPost, "https://"+ConsoleHost+"/api/me/sign-in-methods", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Sub: sub, Name: name}))
	w := httptest.NewRecorder()
	next, err := r.authSvc.PrepareMethod(w, req, m)
	if err != nil {
		return l, err
	}
	for _, c := range w.Result().Cookies() {
		if c.Value != "" {
			l.pending = &http.Cookie{Name: c.Name, Value: c.Value, Path: "/", Secure: true}
		}
	}
	if l.pending == nil {
		t.Fatal("PrepareMethod set no pending cookie")
	}
	l.next = "https://" + ConsoleHost + next
	return l, nil
}

// mustPrepare is prepare, failing on an error.
func (r *methodsRig) mustPrepare(t *testing.T, sub, name string, m auth.Method) launch {
	t.Helper()
	l, err := r.prepare(t, sub, name, m)
	if err != nil {
		t.Fatalf("PrepareMethod(%s) for %s: %v", m, name, err)
	}
	return l
}

// goWith is a Go client from a fresh home-network address holding l's
// cookies.
func (r *methodsRig) goWith(t *testing.T, l launch) *goClient {
	t.Helper()
	g, _ := r.next(t)
	u, _ := url.Parse("https://" + ConsoleHost)
	g.jar.SetCookies(u, []*http.Cookie{l.session, l.pending})
	return g
}

// passwordStep follows l in g to the door's sign-in page and posts the
// password, and returns the page right after it.
func (r *methodsRig) passwordStep(t *testing.T, g *goClient, l launch, name string, pw secret.Value) doorAnswer {
	t.Helper()
	a := g.follow(l.next)
	if a.pageID() != "login-login" {
		t.Fatalf("the method's fresh sign-in reached %q (%d) %q", a.pageID(), a.status, errorText(a))
	}
	r.settle(t)
	return g.submit(a, "kc-form-login", map[string]string{"username": name, "password": string(pw.Reveal())})
}

// landed asserts a Go client's answer is the console's launcher with the
// sentence key (none for ""), and that no console session was set.
func landed(t *testing.T, g *goClient, a doorAnswer, key string) {
	t.Helper()
	if a.pageID() != consoleLoginPage || a.at == nil || a.at.Host != ConsoleHost || a.at.Path != "/login" {
		t.Fatalf("ended on %q at %v (%d) %q, want the console's launcher", a.pageID(), a.at, a.status, errorText(a))
	}
	if got := a.at.Query().Get("signin"); got != key || (key == "" && a.at.RawQuery != "") {
		t.Errorf("landed on %s, want ?signin=%s", a.at, key)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, s := range g.sets {
		if strings.HasPrefix(s, auth.SessionCookieName+"=") && !strings.HasPrefix(s, auth.SessionCookieName+"=;") {
			t.Error("the method's return set a console session cookie")
		}
	}
}

// tabWith is a Chrome tab holding l's cookies on the console's name, with a
// virtual authenticator of transport.
func (r *methodsRig) tabWith(t *testing.T, l launch, transport webauthn.AuthenticatorTransport) *tab {
	t.Helper()
	tb := newTab(t, r.browser, "https://"+ConsoleHost)
	tb.beforeSubmit = r.settle
	ctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer cancel()
	var cookies []*network.CookieParam
	for _, c := range []*http.Cookie{l.session, l.pending} {
		cookies = append(cookies, &network.CookieParam{Name: c.Name, Value: c.Value, URL: "https://" + ConsoleHost + "/", Path: "/",
			Secure: true, HTTPOnly: true, SameSite: network.CookieSameSiteLax})
	}
	if _, err := chromedp.Call(ctx, network.SetCookies, network.SetCookiesParams{Cookies: cookies}); err != nil {
		t.Fatalf("Network.setCookies: %v", err)
	}
	if _, err := chromedp.Call(ctx, webauthn.Enable, webauthn.EnableParams{EnableUI: new(false)}); err != nil {
		t.Fatal(err)
	}
	addAuthenticator(t, tb, transport)
	return tb
}

// registerInTab follows l in tb, signs in as name, registers the key with
// button on the page right after the password, and returns the page the
// callback answered and its query.
func (r *methodsRig) registerInTab(t *testing.T, tb *tab, l launch, name string, pw secret.Value, button string) (string, string) {
	t.Helper()
	if got := tb.navigate(l.next); got != "login-login" {
		t.Fatalf("the method's fresh sign-in opened %q", got)
	}
	if got := signIn(tb, name, pw); got != "login-webauthn-register" {
		t.Fatalf("the page right after the password is %q, want login-webauthn-register", got)
	}
	tb.step(chromedp.SetValue(chromedp.ID("rasputin-passkey-name"), "1150 key"), "type the NAME")
	r.settle(t)
	got := tb.submit(chromedp.Click(chromedp.ID(button)), "register")
	return got, evalT[string](tb, `location.search`)
}

// sessionInTab is the console session cookie the tab holds.
func sessionInTab(t *testing.T, tb *tab) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer cancel()
	res, err := chromedp.Call(ctx, network.GetCookies, network.GetCookiesParams{URLs: []string{"https://" + ConsoleHost + "/"}})
	if err != nil {
		t.Fatalf("Network.getCookies: %v", err)
	}
	for _, c := range res.Cookies {
		if c.Name == auth.SessionCookieName {
			return c.Value
		}
	}
	return ""
}

// designatedWithCodes is an account with a password and recovery codes,
// designated admin and admin, signed in once so it holds the codes.
func (r *methodsRig) designatedWithCodes(t *testing.T, name string) (string, secret.Value) {
	t.Helper()
	id, pw := r.user(t, name, flows.ActionRecoveryCodes)
	if err := r.designations.Designate(t.Context(), accounts.Designation{Sub: id, ConsoleRole: string(authz.Admin),
		AppRole: accounts.AppAdmin, Reason: accounts.ReasonPrivileged}); err != nil {
		t.Fatal(err)
	}
	g, _ := r.next(t)
	a := g.signIn(consoleSignin(), name, pw)
	if a.pageID() != "login-login-recovery-authn-code-config" {
		t.Fatalf("%s: want the recovery-codes page, got %q (%d) %q", name, a.pageID(), a.status, errorText(a))
	}
	r.settle(t)
	if got := g.submit(a, "kc-recovery-codes-settings-form", nil); got.pageID() != consoleLoginPage {
		t.Fatalf("%s: saving the codes ended on %q", name, got.pageID())
	}
	r.settle(t)
	r.runner.Wait()
	return id, pw
}

// granted asserts the one grant job submitted since before finished
// granted, and the account holds console admin and app admin, has no
// console or identity session and is no longer designated.
func (r *methodsRig) granted(t *testing.T, id string, before int) {
	t.Helper()
	r.runner.Wait()
	js := r.grantJobs(t)
	if len(js) != before+1 {
		t.Fatalf("%d grant jobs since the start, want the one the callback submitted", len(js)-before)
	}
	if o := r.outcomes(t, js[before].ID); o[accounts.StepCheck] != "complete" || o[accounts.StepGrantRole] != "granted" || o[accounts.StepFinish] != "finished" {
		t.Errorf("the grant: %v (job %s %s)", o, js[before].Status, js[before].Error)
	}
	if roles, err := r.users.ConsoleRoles(t.Context(), id); err != nil || !slices.Contains(roles, string(authz.Admin)) {
		t.Errorf("console roles %v (%v), want admin", roles, err)
	}
	if p, err := r.users.Read(t.Context(), id); err != nil || p.AppRole != accounts.AppAdmin {
		t.Errorf("app access %q (%v), want admin", p.AppRole, err)
	}
	if n := r.sessionsOf(t, id); n != 0 {
		t.Errorf("%d console sessions after the grant, want none", n)
	}
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+id+"/sessions", nil)
	var idSessions []map[string]any
	if err := json.Unmarshal(out, &idSessions); err != nil || len(idSessions) != 0 {
		t.Errorf("%d identity sessions after the grant (%v), want none (C23)", len(idSessions), err)
	}
	if _, ok, _ := r.designations.Get(t.Context(), id); ok {
		t.Error("the designation was not cleared")
	}
}

// credential is one Admin API credential.
type credential struct {
	Type        string `json:"type"`
	CreatedDate int64  `json:"createdDate"`
}

func (r *methodsRig) credentials(t *testing.T, id string) []credential {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+id+"/credentials", nil)
	var cs []credential
	if err := json.Unmarshal(out, &cs); err != nil {
		t.Fatal(err)
	}
	return cs
}

// refusedAtDoor sends target from g and asserts the home door's 400 with the
// action sentence, a kc_action refusal record and nothing relayed.
func (r *methodsRig) refusedAtDoor(t *testing.T, what string, g *goClient, target string) {
	t.Helper()
	recs := len(r.doorRefusals())
	up := r.upstream.Load()
	a := g.send(http.MethodGet, target, nil, nil)
	if a.status != http.StatusBadRequest || !shows(a, methodActionSentence) {
		t.Errorf("%s: %d page %q %q, want the door's 400 with the action sentence", what, a.status, a.pageID(), errorText(a))
	}
	if n := r.upstream.Load() - up; n != 0 {
		t.Errorf("%s: %d requests relayed, want none", what, n)
	}
	if n := len(r.doorRefusals()) - recs; n != 1 {
		t.Errorf("%s: %d kc_action refusal records, want 1", what, n)
	}
}

// doorRefusals are the door's kc_action refusal records.
func (r *methodsRig) doorRefusals() []slog.Record {
	var out []slog.Record
	for _, rec := range r.apiRec.Records() {
		if v, _ := logkittest.Attr(rec, "refused"); v == "kc_action" {
			out = append(out, rec)
		}
	}
	return out
}

// authURL GETs l.next from g and returns the door URL it answers, unfollowed.
func authURL(t *testing.T, g *goClient, l launch) *url.URL {
	t.Helper()
	a := g.send(http.MethodGet, l.next, nil, nil)
	if a.status != http.StatusSeeOther || a.loc == nil {
		t.Fatalf("the method's start answered %d", a.status)
	}
	return a.at.ResolveReference(a.loc)
}

// ---- the test ----------------------------------------------------------------

func TestSignInMethods_AgainstPinnedKeycloak(t *testing.T) {
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
	r := &methodsRig{firstRunRig: newFirstRunRig(t, env)}
	browserCtx, _ := p.Browser(t)
	if browserCtx == nil {
		return
	}
	r.browser = browserCtx

	// First: the first account is the realm's first person, the claim.
	t.Run("TC-1150-16 C29 IA-F1 K-AIA the designated first account adds a passkey and is granted", func(t *testing.T) { r.tc16(t) })
	t.Run("TC-1150-17 a cancel grants nothing", func(t *testing.T) { r.tc17(t) })
	t.Run("TC-1150-18 a security key", func(t *testing.T) { r.tc18(t) })
	t.Run("TC-1150-19 an authenticator app while the clock is set", func(t *testing.T) { r.tc19(t) })
	t.Run("TC-1150-20 a role-less account adds recovery codes", func(t *testing.T) { r.tc20(t) })
	t.Run("TC-1150-21 the clock rule at the launcher and at the door", func(t *testing.T) { r.tc21(t) })
	t.Run("TC-1150-22 the door refuses every kc_action it did not issue", func(t *testing.T) { r.tc22(t) })
	t.Run("TC-1150-23 another person's sign-in in the first person's browser", func(t *testing.T) { r.tc23(t) })
}

// TC-1150-16: the first account, designated with recovery codes alone, adds
// a passkey: the page right after the password is the registration, the
// callback lands on the launcher with no new session, and the grant the
// callback submitted finishes granted.
func (r *methodsRig) tc16(t *testing.T) {
	a := r.newPerson(t, "tc1150-16")
	r.atConsole(t, a, r.saveCodes(t, a, r.register(t, a, r.openForm(t, a), "")))
	id := r.idOf(t, a.name)
	if d := r.designated(t); len(d) != 1 || d[0].Sub != id {
		t.Fatalf("designations %+v, want the first account's", d)
	}
	r.runner.Wait()
	before := len(r.grantJobs(t))
	l := r.mustPrepare(t, id, a.name, auth.MethodPasskey)
	tb := r.tabWith(t, l, webauthn.AuthenticatorTransportInternal)
	page, search := r.registerInTab(t, tb, l, a.name, a.pw, "rasputin-passkey-this-device")
	if page != consoleLoginPage || search != "" {
		t.Fatalf("the return landed on %q %q, want the launcher with no sentence", page, search)
	}
	if got := sessionInTab(t, tb); got != l.session.Value {
		t.Error("the return replaced the console session cookie")
	}
	r.granted(t, id, before)
}

// TC-1150-17: a designated account with codes alone cancels the passkey
// page: the launcher's cancel sentence, no session, no grant, the
// designation kept and no role.
func (r *methodsRig) tc17(t *testing.T) {
	const name = "tc1150-17"
	id, pw := r.designatedWithCodes(t, name)
	before := len(r.grantJobs(t))
	l := r.mustPrepare(t, id, name, auth.MethodPasskey)
	g := r.goWith(t, l)
	page := r.passwordStep(t, g, l, name, pw)
	if page.pageID() != "login-webauthn-register" {
		t.Fatalf("the page right after the password is %q, want login-webauthn-register", page.pageID())
	}
	r.settle(t)
	landed(t, g, g.submit(page, "kc-webauthn-settings-form", map[string]string{"cancel-aia": "true"}), "method-cancelled")
	r.runner.Wait()
	for _, j := range r.grantJobs(t)[before:] {
		if o := r.outcomes(t, j.ID); o[accounts.StepGrantRole] == "granted" {
			t.Errorf("a cancel's grant job granted: %v", o)
		}
	}
	if _, ok, _ := r.designations.Get(t.Context(), id); !ok {
		t.Error("the designation was cleared")
	}
	if roles, _ := r.users.ConsoleRoles(t.Context(), id); slices.Contains(roles, string(authz.Admin)) {
		t.Errorf("after a cancel the account holds %v", roles)
	}
}

// TC-1150-18: a designated account with codes adds a security key (USB) and
// is granted.
func (r *methodsRig) tc18(t *testing.T) {
	const name = "tc1150-18"
	id, pw := r.designatedWithCodes(t, name)
	before := len(r.grantJobs(t))
	l := r.mustPrepare(t, id, name, auth.MethodSecurityKey)
	tb := r.tabWith(t, l, webauthn.AuthenticatorTransportUsb)
	page, search := r.registerInTab(t, tb, l, name, pw, "rasputin-passkey-security-key")
	if page != consoleLoginPage || search != "" {
		t.Fatalf("the return landed on %q %q, want the launcher with no sentence", page, search)
	}
	if got := sessionInTab(t, tb); got != l.session.Value {
		t.Error("the return replaced the console session cookie")
	}
	r.granted(t, id, before)
}

// TC-1150-19: with the clock fact set, a designated account with codes adds
// an authenticator app and is granted.
func (r *methodsRig) tc19(t *testing.T) {
	const name = "tc1150-19"
	id, pw := r.designatedWithCodes(t, name)
	before := len(r.grantJobs(t))
	r.clock.synced.Store(true)
	l := r.mustPrepare(t, id, name, auth.MethodAuthenticatorApp)
	g := r.goWith(t, l)
	done, _ := r.enrolTOTP(t, g, r.passwordStep(t, g, l, name, pw))
	landed(t, g, done, "")
	if !slices.ContainsFunc(r.credentials(t, id), func(c credential) bool { return c.Type == "otp" }) {
		t.Error("no authenticator-app credential after the method")
	}
	r.granted(t, id, before)
}

// TC-1150-20: a role-less, undesignated account adds recovery codes: they
// are in its credential list, created after the start, and it gains no role
// and no grant job.
func (r *methodsRig) tc20(t *testing.T) {
	const name = "tc1150-20"
	id, pw := r.user(t, name)
	r.runner.Wait()
	before := len(r.grantJobs(t))
	start := time.Now().Truncate(time.Second)
	l := r.mustPrepare(t, id, name, auth.MethodRecoveryCodes)
	g := r.goWith(t, l)
	page := r.passwordStep(t, g, l, name, pw)
	if page.pageID() != "login-login-recovery-authn-code-config" {
		t.Fatalf("the page right after the password is %q, want the recovery-codes page", page.pageID())
	}
	r.settle(t)
	landed(t, g, g.submit(page, "kc-recovery-codes-settings-form", nil), "")
	if !slices.ContainsFunc(r.credentials(t, id), func(c credential) bool {
		return c.Type == "recovery-authn-codes" && c.CreatedDate >= start.UnixMilli()
	}) {
		t.Errorf("no recovery codes created after the start: %+v", r.credentials(t, id))
	}
	r.runner.Wait()
	if n := len(r.grantJobs(t)) - before; n != 0 {
		t.Errorf("%d grant jobs for a role-less account, want none", n)
	}
	if roles, _ := r.users.ConsoleRoles(t.Context(), id); len(roles) != 0 {
		t.Errorf("the account holds %v, want no role", roles)
	}
}

// TC-1150-21: with the clock fact off an authenticator app is not
// prepared; one prepared and started while it held is refused at the door
// once it no longer holds, though the realm still enables CONFIGURE_TOTP.
func (r *methodsRig) tc21(t *testing.T) {
	const name = "tc1150-21"
	id, _ := r.user(t, name)
	defer r.clock.synced.Store(true)
	r.clock.synced.Store(false)
	if _, err := r.prepare(t, id, name, auth.MethodAuthenticatorApp); !errors.Is(err, auth.ErrClockNotSet) {
		t.Errorf("with the clock fact off: %v, want ErrClockNotSet", err)
	}
	r.clock.synced.Store(true)
	l := r.mustPrepare(t, id, name, auth.MethodAuthenticatorApp)
	g := r.goWith(t, l)
	u := authURL(t, g, l)
	if u.Query().Get("kc_action") != flows.ActionConfigureTOTP {
		t.Fatalf("the start carries kc_action %q", u.Query().Get("kc_action"))
	}
	r.clock.synced.Store(false)
	r.refusedAtDoor(t, "CONFIGURE_TOTP after the clock fact turned off", g, u.String())
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/authentication/required-actions/"+flows.ActionConfigureTOTP, nil)
	var ra struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(out, &ra); err != nil || !ra.Enabled {
		t.Errorf("the realm no longer enables CONFIGURE_TOTP (%v): the door's refusal was not what stopped it", err)
	}
}

// TC-1150-22: the home door refuses a kc_action the launcher did not issue,
// a replay of one it did, and an issued state under another client or with
// another action, and an empty kc_action under a plain sign-in's state.
func (r *methodsRig) tc22(t *testing.T) {
	const name = "tc1150-22"
	id, _ := r.user(t, name)

	g0, _ := r.next(t)
	r.refusedAtDoor(t, "a hand-built request", g0, r.homeAuth(baselineConsole, map[string]string{
		"redirect_uri": "https://" + ConsoleHost + consoleCallback, "kc_action": flows.ActionSecurityKey}))

	l := r.mustPrepare(t, id, name, auth.MethodPasskey)
	g := r.goWith(t, l)
	u := authURL(t, g, l)
	if a := g.send(http.MethodGet, u.String(), nil, nil); a.status != http.StatusOK || a.pageID() != "login-login" {
		t.Fatalf("the issued request's first forward: %d %q", a.status, a.pageID())
	}
	r.refusedAtDoor(t, "a replay after the first forward", g, u.String())

	l2 := r.mustPrepare(t, id, name, auth.MethodPasskey)
	g2 := r.goWith(t, l2)
	u2 := authURL(t, g2, l2)
	edited := func(set map[string]string) string {
		v := *u2
		q := v.Query()
		for k, x := range set {
			q.Set(k, x)
		}
		v.RawQuery = q.Encode()
		return v.String()
	}
	r.refusedAtDoor(t, "the issued state under rasputin-mesh", g2, edited(map[string]string{"client_id": baselineMesh, "redirect_uri": callbackOn(ConsoleHost)}))
	r.refusedAtDoor(t, "the issued state with another action", g2, edited(map[string]string{"kc_action": flows.ActionSecurityKey}))
	if a := g2.send(http.MethodGet, u2.String(), nil, nil); a.status != http.StatusOK || a.pageID() != "login-login" {
		t.Errorf("after the refusals the issued request was not forwarded: %d %q", a.status, a.pageID())
	}

	g3, _ := r.next(t)
	plain := g3.send(http.MethodGet, consoleSignin(), nil, nil)
	if plain.loc == nil {
		t.Fatalf("the plain sign-in answered %d", plain.status)
	}
	pu := plain.at.ResolveReference(plain.loc)
	q := pu.Query()
	q.Set("kc_action", "")
	pu.RawQuery = q.Encode()
	r.refusedAtDoor(t, "an empty kc_action under a plain sign-in's state", g3, pu.String())
}

// TC-1150-23: another person signs in at the door in the first person's
// browser and completes the page shown: the action-failed sentence, no
// session, and the first person's credentials and roles unchanged.
func (r *methodsRig) tc23(t *testing.T) {
	alice, _ := r.user(t, "tc1150-23-alice")
	_, bobPW := r.user(t, "tc1150-23-bob")
	creds := len(r.credentials(t, alice))
	l := r.mustPrepare(t, alice, "tc1150-23-alice", auth.MethodPasskey)
	tb := r.tabWith(t, l, webauthn.AuthenticatorTransportInternal)
	page, search := r.registerInTab(t, tb, l, "tc1150-23-bob", bobPW, "rasputin-passkey-this-device")
	if page != consoleLoginPage || search != "?signin=action-failed" {
		t.Errorf("another person's return landed on %q %q, want the action-failed sentence", page, search)
	}
	if got := sessionInTab(t, tb); got != l.session.Value {
		t.Error("another person's return replaced the console session cookie")
	}
	if n := len(r.credentials(t, alice)); n != creds {
		t.Errorf("alice holds %d credentials, want %d", n, creds)
	}
	if roles, _ := r.users.ConsoleRoles(t.Context(), alice); len(roles) != 0 {
		t.Errorf("alice holds %v, want no role", roles)
	}
}
