package identitytest

// The forgotten-password paths against the real identity service
// (geekdojo/geekdojo-brain#992, Identity 4.10; TC-992-25 to TC-992-37): the
// revoke rig (the console rig, with #991's accounts as main wires them) with
// the reset returns at both doors, the converged reset flow, and the
// administrator's reset (accounts.reset_password) on a runner the kind table
// decides, its action registered on the console's sign-in.
//
// It starts an Env of its own, closed with proof in its cleanup. It skips
// without RASPUTIN_IDENTITY_HOME or RASPUTIN_IDENTITY_THEME and fails instead
// under RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job sets it.

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth/idtoken"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/pwpolicy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

// The reset pages, by page id.
const (
	pageChooseUser     = "login-login-reset-password"
	pageRecoveryCode   = "login-login-recovery-authn-code-input"
	pageUpdatePassword = "login-login-update-password"
	pageOTP            = "login-login-otp"
)

type resetRig struct {
	*revokeRig
	held     *accounts.Held
	resetter *accounts.Resetter
	runner   *jobs.Runner
	wf       jobs.Workflow
	otp      *totpCodes
	rec      *logkittest.Recorder
	n        atomic.Int64
	// client is a production identity client over the api's own leaf.
	idc *idclient.Client
}

type resetApps struct{}

func (resetApps) AppFacts(context.Context, string, string) (authz.AppFacts, error) {
	return authz.AppFacts{}, authz.ErrNoApp
}

func newResetRig(t *testing.T, env *Env) *resetRig {
	t.Helper()
	r := &resetRig{revokeRig: newRevokeRig(t, env), held: accounts.NewHeld(), otp: &totpCodes{used: map[string]bool{}}}
	log, rec := logkittest.New()
	r.rec = rec
	users, err := accounts.NewUsers(accounts.UsersDeps{Admin: r.session, Realm: baselineRealm, ConsoleClient: baselineConsole})
	if err != nil {
		t.Fatal(err)
	}
	checker, err := pwpolicy.New(filepath.Dir(denylistPath(env.kcHome)), flows.PasswordPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if r.wf, err = accounts.ResetPasswordWorkflow(accounts.ResetDeps{Users: users, Held: r.held, Checker: checker, Revoker: r.rev,
		Log: log, StepTimeout: 2 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	kp, err := authz.NewKindPolicy(resetApps{})
	if err != nil {
		t.Fatal(err)
	}
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	if r.runner, err = jobs.NewAuthorizedRunner(r.ledger, nc, kp); err != nil {
		t.Fatal(err)
	}
	r.runner.Register(r.wf)
	if r.resetter, err = accounts.NewResetter(accounts.ResetterDeps{Authorizer: kp, Users: users, Checker: checker, Log: log}); err != nil {
		t.Fatal(err)
	}
	action, err := accounts.NewResetAction(r.runner, r.held)
	if err != nil {
		t.Fatal(err)
	}
	r.action.set(action)
	leaf, err := env.CA().MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
	if err != nil {
		t.Fatal(err)
	}
	r.idc = productionClient(t, env, leaf)
	return r
}

// household is an account with a password and app access, and its id.
func (r *resetRig) household(t *testing.T, name string) (string, secret.Value) {
	t.Helper()
	id, pw := r.user(t, name)
	r.setAttrs(t, id, map[string][]string{"rasputin_app_role": {"user"}})
	return id, pw
}

func (r *resetRig) setAttrs(t *testing.T, id string, attrs map[string][]string) {
	t.Helper()
	api := r.admin(t)
	_, out := api.must(http.StatusOK, http.MethodGet, "/users/"+id, nil)
	var rep map[string]any
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	have, _ := rep["attributes"].(map[string]any)
	if have == nil {
		have = map[string]any{}
	}
	for k, v := range attrs {
		have[k] = v
	}
	rep["attributes"] = have
	api.must(http.StatusNoContent, http.MethodPut, "/users/"+id, rep)
}

// enrol gives the account recovery codes, and an authenticator app when
// otp, through its required actions at the app door, and returns the
// codes and the app's secret. It runs before any console role is granted.
func (r *resetRig) enrol(t *testing.T, id, name string, pw secret.Value, otp bool) ([]string, string) {
	t.Helper()
	actions := []string{flows.ActionRecoveryCodes}
	if otp {
		actions = append([]string{flows.ActionConfigureTOTP}, actions...)
	}
	api := r.admin(t)
	_, out := api.must(http.StatusOK, http.MethodGet, "/users/"+id, nil)
	var rep map[string]any
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	rep["requiredActions"] = actions
	api.must(http.StatusNoContent, http.MethodPut, "/users/"+id, rep)
	g := r.fresh(t)
	r.settle(t)
	a := g.signIn(r.appAuth("rasputin-account", nil), name, pw)
	secretB32 := ""
	if otp {
		if a.pageID() != "login-login-config-totp" {
			t.Fatalf("want the authenticator-app setup, got %q", a.pageID())
		}
		secretB32 = totpSecretOf(t, a)
		r.settle(t)
		a = g.submit(a, "kc-totp-settings-form", map[string]string{"totp": r.otp.next(t, secretB32), "userLabel": "Reset phone"})
	}
	if a.pageID() != "login-login-recovery-authn-code-config" {
		t.Fatalf("want the recovery-codes page, got %q", a.pageID())
	}
	fields, _ := g.form(a, "kc-recovery-codes-settings-form")
	codes := strings.Split(fields.Get("generatedRecoveryAuthnCodes"), ",")
	r.settle(t)
	g.submit(a, "kc-recovery-codes-settings-form", nil).code(t)
	r.settle(t)
	return codes, secretB32
}

// totpSecretOf reads the setup page's QR code's secret.
func totpSecretOf(t *testing.T, a doorAnswer) string {
	t.Helper()
	m := qrImgRE.FindSubmatch(a.body)
	if m == nil {
		t.Fatal("the setup page shows no QR code")
	}
	text, err := decodeQR(html.UnescapeString(string(m[1])))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("secret")
}

// chooseUser starts a reset at start and names the account, and returns
// the page after.
func (r *resetRig) chooseUser(t *testing.T, g *goClient, start, name string) doorAnswer {
	t.Helper()
	a := g.follow(start)
	if a.pageID() != pageChooseUser {
		t.Fatalf("the reset start reached %q (%d), want the choose-user page", a.pageID(), a.status)
	}
	r.settle(t)
	return g.submit(a, "kc-reset-password-form", map[string]string{"username": name})
}

// code enters a recovery code.
func (r *resetRig) code(t *testing.T, g *goClient, a doorAnswer, code string) doorAnswer {
	t.Helper()
	if a.pageID() != pageRecoveryCode {
		t.Fatalf("want the recovery-code page, got %q %q", a.pageID(), pageText(a))
	}
	r.settle(t)
	return g.submit(a, "kc-recovery-code-login-form", map[string]string{"recoveryCodeInput": code})
}

// newPassword answers UPDATE_PASSWORD with pw and returns the answer after
// every redirect: the console's launcher, or the app door's page.
func (r *resetRig) newPassword(t *testing.T, g *goClient, a doorAnswer, pw string) doorAnswer {
	t.Helper()
	if a.pageID() != pageUpdatePassword {
		t.Fatalf("want the new-password page, got %q %q", a.pageID(), pageText(a))
	}
	r.settle(t)
	return g.submit(a, "kc-passwd-update-form", map[string]string{"password-new": pw, "password-confirm": pw})
}

// pageText is a page's body, tags and all, unescaped.
func pageText(a doorAnswer) string { return html.UnescapeString(string(a.body)) }

// passwordCreated is the account's password credential's createdDate.
func (r *resetRig) passwordCreated(t *testing.T, id string) float64 {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+id+"/credentials", nil)
	var creds []struct {
		Type    string  `json:"type"`
		Created float64 `json:"createdDate"`
	}
	if err := json.Unmarshal(out, &creds); err != nil {
		t.Fatal(err)
	}
	for _, c := range creds {
		if c.Type == "password" {
			return c.Created
		}
	}
	t.Fatal("no password credential")
	return 0
}

// sessionCounts are the account's online sessions and its offline sessions
// at the test app.
func (r *resetRig) sessionCounts(t *testing.T, id string) (online, offline int) {
	t.Helper()
	api := r.admin(t)
	_, out := api.must(http.StatusOK, http.MethodGet, "/users/"+id+"/sessions", nil)
	var on []any
	_ = json.Unmarshal(out, &on)
	app, _ := api.clientRep(doorTestApp)
	_, out = api.must(http.StatusOK, http.MethodGet, "/users/"+id+"/offline-sessions/"+app, nil)
	var off []any
	_ = json.Unmarshal(out, &off)
	return len(on), len(off)
}

// signsIn reports whether name signs in at the app door with pw.
func (r *resetRig) signsIn(t *testing.T, name, pw string) bool {
	t.Helper()
	g := r.fresh(t)
	r.settle(t)
	a := g.signIn(r.appAuth("rasputin-account", nil), name, secret.New([]byte(pw)))
	r.settle(t)
	return a.loc != nil && a.loc.Path == callbackPath && a.loc.Query().Get("code") != ""
}

// strong is a fresh unlisted password the policy accepts.
func (r *resetRig) strong(what string) string {
	return "ochre " + what + " lantern quiver " + string(rune('a'+r.n.Add(1)%26)) + " 992"
}

// smtpSink counts TCP connections on a loopback port.
type smtpSink struct {
	ln    net.Listener
	conns atomic.Int64
}

func newSMTPSink(t *testing.T) *smtpSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpSink{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func TestReset_AgainstPinnedKeycloak(t *testing.T) {
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
	r := newResetRig(t, env)

	// TC-992-34: a mail server is set on the realm; no case reaches it.
	sink := newSMTPSink(t)
	_, port, _ := net.SplitHostPort(sink.ln.Addr().String())
	r.admin(t).must(http.StatusNoContent, http.MethodPut, "", map[string]any{
		"smtpServer": map[string]string{"host": "127.0.0.1", "port": port, "from": "reset@rasputin.invalid"}})

	t.Run("TC-992-35 the start links", func(t *testing.T) { r.tc35(t) })
	t.Run("TC-992-25 IA-F3 codeless, unknown and code-only privileged", func(t *testing.T) { r.tc25(t) })
	t.Run("TC-992-26 IA-F4 TS-21 the home door, and TC-992-36 the hint", func(t *testing.T) { r.tc26(t) })
	t.Run("TC-992-27 IA-F4 TS-21 the app door", func(t *testing.T) { r.tc27(t) })
	t.Run("TC-992-28 a privileged code reset", func(t *testing.T) { r.tc28(t) })
	t.Run("TC-992-29 the deny list at the new password", func(t *testing.T) { r.tc29(t) })
	t.Run("TC-992-33 TS-26 a held source still resets", func(t *testing.T) { r.tc33(t) })
	t.Run("TC-992-37 T200 the reset code's token", func(t *testing.T) { r.tc37(t) })
	t.Run("TC-992-30 the administrator's reset, and TC-992-31 C24", func(t *testing.T) { r.tc30(t) })
	t.Run("TC-992-32 T202 the 500 classification", func(t *testing.T) { r.tc32(t) })
	t.Run("TC-992-34 the mail sink", func(t *testing.T) {
		if n := sink.conns.Load(); n != 0 {
			t.Errorf("the mail sink saw %d connections, want 0", n)
		}
		if _, err := r.conv.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "", nil)
		var realm struct {
			SMTP map[string]any `json:"smtpServer"`
		}
		if err := json.Unmarshal(out, &realm); err != nil || len(realm.SMTP) != 0 {
			t.Errorf("smtpServer after converge: %v (%v)", realm.SMTP, err)
		}
	})
}

// TC-992-35: both attributes equal each door's start; the sign-in pages of
// the console, the mesh and an app-door client link "Forgot your
// password?" to their door's start, which reaches that door's choose-user
// page.
func (r *resetRig) tc35(t *testing.T) {
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "", nil)
	var realm struct {
		Attributes map[string]string `json:"attributes"`
	}
	if err := json.Unmarshal(out, &realm); err != nil {
		t.Fatal(err)
	}
	if realm.Attributes["rasputin.reset-home-url"] != r.resetHome || realm.Attributes["rasputin.reset-app-url"] != r.resetApp {
		t.Fatalf("reset attributes %q %q, want %q %q", realm.Attributes["rasputin.reset-home-url"],
			realm.Attributes["rasputin.reset-app-url"], r.resetHome, r.resetApp)
	}
	for _, c := range []struct{ what, auth, start string }{
		{"rasputin-console", r.homeAuth(baselineConsole, nil), r.resetHome},
		{"rasputin-mesh", r.homeAuth(baselineMesh, nil), r.resetHome},
		{"an app-door client", r.appAuth(doorTestApp, nil), r.resetApp},
	} {
		g := r.fresh(t)
		a := g.follow(c.auth)
		m := forgotRE.FindSubmatch(a.body)
		if m == nil || html.UnescapeString(string(m[1])) != c.start {
			t.Errorf("%s: the forgot-password link is %q, want %q", c.what, m, c.start)
			continue
		}
		if got := g.follow(c.start); got.pageID() != pageChooseUser {
			t.Errorf("%s: the link reached %q, want the choose-user page", c.what, got.pageID())
		}
	}
}

// TC-992-25: a codeless household account and an unknown name get the
// codeless sentence, the same text; a privileged account holding only
// codes gets the privileged sentence after its code; no password changes.
func (r *resetRig) tc25(t *testing.T) {
	codeless, _ := r.household(t, "reset-codeless")
	before := r.passwordCreated(t, codeless)
	a := r.chooseUser(t, r.fresh(t), r.resetHome, "reset-codeless")
	b := r.chooseUser(t, r.fresh(t), r.resetHome, "reset-no-such-name")
	if !strings.Contains(pageText(a), flows.SentenceResetNoCodes) || !strings.Contains(pageText(b), flows.SentenceResetNoCodes) {
		t.Errorf("codeless %q / unknown %q, want the codeless sentence", a.pageID(), b.pageID())
	}
	if a.sentence() != b.sentence() || errorText(a) != errorText(b) {
		t.Errorf("the codeless and unknown answers differ: %q / %q", a.sentence(), b.sentence())
	}
	id, pw := r.user(t, "reset-codes-admin")
	codes, _ := r.enrol(t, id, "reset-codes-admin", pw, false)
	r.grantRole(t, id, "admin")
	priorAdmin := r.passwordCreated(t, id)
	g := r.fresh(t)
	got := r.code(t, g, r.chooseUser(t, g, r.resetHome, "reset-codes-admin"), codes[0])
	if !strings.Contains(pageText(got), flows.SentenceResetPrivileged) {
		t.Errorf("a code-only administrator reached %q, want the privileged sentence", got.pageID())
	}
	if r.passwordCreated(t, codeless) != before || r.passwordCreated(t, id) != priorAdmin {
		t.Error("a refused reset changed a password")
	}
}

// grantRole maps a console role to the account.
func (r *resetRig) grantRole(t *testing.T, id, role string) {
	t.Helper()
	api := r.admin(t)
	cid, _ := api.clientRep(baselineConsole)
	_, out := api.must(http.StatusOK, http.MethodGet, "/clients/"+cid+"/roles/"+role, nil)
	var rep map[string]any
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	api.must(http.StatusNoContent, http.MethodPost, "/users/"+id+"/role-mappings/clients/"+cid, []any{rep})
	r.settle(t)
}

// fullReset is a household account with codes, a console session, an
// identity session and an offline session granted through #991's
// Access.Grant, reset at start with one code.
type fullReset struct {
	id, name   string
	oldPw      secret.Value
	newPw      string
	codes      []string
	console    *http.Client
	offline    string
	offlineCli *goClient
	end        doorAnswer
	resetter   *goClient
}

func (r *resetRig) resetFully(t *testing.T, what, start string) fullReset {
	t.Helper()
	f := fullReset{name: "reset-" + what}
	f.id, f.oldPw = r.fixture(t, f.name, "viewer")
	f.codes, _ = r.enrol(t, f.id, f.name, f.oldPw, false)
	if err := r.access.Grant(t.Context(), f.id, accounts.AppUser); err != nil {
		t.Fatal(err)
	}
	r.settle(t)
	f.console = r.signInGo(t, "127.0.7."+map[bool]string{true: "1", false: "2"}[what == "home"], f.name, f.oldPw)
	f.offline, f.offlineCli = r.appTokens(t, f.name, f.oldPw, true)
	if on, off := r.sessionCounts(t, f.id); on == 0 || off == 0 {
		t.Fatalf("before the reset: %d online and %d offline sessions, want some of each", on, off)
	}
	f.resetter = r.fresh(t)
	a := r.code(t, f.resetter, r.chooseUser(t, f.resetter, start, f.name), f.codes[0])
	if !strings.Contains(pageText(a), "Use at least 15 characters.") {
		t.Errorf("the new-password page's hint is not the policy's (TC-992-36)")
	}
	f.newPw = strings.Repeat("q", 9) + " unlisted" // 15 characters, on no list (TC-992-36)
	f.end = r.newPassword(t, f.resetter, a, f.newPw)
	r.settle(t)
	return f
}

// checkEnded is IA-F4 and TS-21 after a reset: the new password signs in
// and the old does not; the used code is refused; no online or offline
// session is left; the old offline refresh is refused; the old console
// cookie answers 401.
func (r *resetRig) checkEnded(t *testing.T, f fullReset, start string) {
	t.Helper()
	if on, off := r.sessionCounts(t, f.id); on != 0 || off != 0 {
		t.Errorf("after the reset: %d online and %d offline sessions, want none", on, off)
	}
	if got := r.refresh(t, f.offlineCli, f.offline); got == http.StatusOK {
		t.Error("the old offline refresh token still refreshes")
	}
	if code, _ := me(t, f.console); code != http.StatusUnauthorized {
		t.Errorf("/api/auth/me with the old console cookie: %d, want 401", code)
	}
	if !r.signsIn(t, f.name, f.newPw) {
		t.Error("the new password does not sign in")
	}
	if r.signsIn(t, f.name, string(f.oldPw.Reveal())) {
		t.Error("the old password still signs in")
	}
	g := r.fresh(t)
	again := r.code(t, g, r.chooseUser(t, g, start, f.name), f.codes[0])
	if again.pageID() == pageUpdatePassword {
		t.Error("the used recovery code was accepted again")
	}
}

func (r *resetRig) tc26(t *testing.T) {
	f := r.resetFully(t, "home", r.resetHome)
	if f.end.at == nil || f.end.at.Host != ConsoleHost || f.end.at.Query().Get("signin") != auth.ResetOutcomeDone {
		t.Fatalf("the home reset ended at %v (%q), want the launcher with signin=reset-done", f.end.at, f.end.pageID())
	}
	for _, c := range f.resetter.sets {
		if strings.HasPrefix(c, auth.SessionCookieName+"=") && !strings.HasPrefix(c, auth.SessionCookieName+"=;") {
			t.Error("the reset return set a console session cookie")
		}
	}
	r.checkEnded(t, f, r.resetHome)
}

func (r *resetRig) tc27(t *testing.T) {
	f := r.resetFully(t, "app", r.resetApp)
	if f.end.at == nil || f.end.at.Host != r.sites.Table.App.Host || !strings.Contains(pageText(f.end), "Your password is changed. Sign in with it and your second step.") {
		t.Fatalf("the app reset ended at %v (%q)", f.end.at, f.end.pageID())
	}
	// The reset's own identity session at the app door is gone: an app's
	// authorization request from the same browser gets the sign-in page.
	if a := f.resetter.follow(r.appAuth("rasputin-account", nil)); a.pageID() != "login-login" {
		t.Errorf("an app authorization after the reset reached %q, want the sign-in page", a.pageID())
	}
	r.checkEnded(t, f, r.resetApp)
}

// TC-992-28: an administrator with codes and an authenticator app gives
// one code, then its authenticator code, never offered a recovery code at
// the second step, and its new password signs in.
func (r *resetRig) tc28(t *testing.T) {
	id, pw := r.user(t, "reset-admin-otp")
	codes, otpSecret := r.enrol(t, id, "reset-admin-otp", pw, true)
	r.grantRole(t, id, "admin")
	g := r.fresh(t)
	step := r.code(t, g, r.chooseUser(t, g, r.resetHome, "reset-admin-otp"), codes[0])
	if step.pageID() != pageOTP {
		t.Fatalf("after the code: %q %q, want the authenticator-code page", step.pageID(), pageText(step))
	}
	if strings.Contains(strings.ToLower(pageText(step)), "recovery") {
		t.Error("the second step offers a recovery code")
	}
	r.settle(t)
	a := g.submit(step, "kc-otp-login-form", map[string]string{"otp": r.otp.next(t, otpSecret)})
	newPw := r.strong("admin")
	r.newPassword(t, g, a, newPw)
	r.settle(t)
	if after := r.passwordCreated(t, id); after == 0 {
		t.Error("no password after the reset")
	}
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+id+"/credentials", nil)
	if !strings.Contains(string(out), `"password"`) {
		t.Error("the administrator has no password credential")
	}
}

// TC-992-29: at the reset's new password, a listed password is refused
// with the deny list's sentence and an unlisted one is accepted.
func (r *resetRig) tc29(t *testing.T) {
	id, pw := r.household(t, "reset-listed")
	codes, _ := r.enrol(t, id, "reset-listed", pw, false)
	listed, _ := listedEntries(t, r.env.kcHome)
	defer listed.Destroy()
	g := r.fresh(t)
	a := r.code(t, g, r.chooseUser(t, g, r.resetHome, "reset-listed"), codes[0])
	before := r.passwordCreated(t, id)
	refused := r.newPassword(t, g, a, string(listed.Reveal()))
	if refused.pageID() != pageUpdatePassword || !strings.Contains(pageText(refused), "That password is too common. Choose another.") {
		t.Fatalf("a listed password reached %q, want the new-password page with the deny sentence", refused.pageID())
	}
	if r.passwordCreated(t, id) != before {
		t.Error("a listed password was set")
	}
	r.newPassword(t, g, refused, r.strong("listed"))
	r.settle(t)
	if r.passwordCreated(t, id) == before {
		t.Error("the unlisted password was not set")
	}
}

// TC-992-33: a source the door's throttle holds after a failed sign-in
// still completes a recovery-code reset.
func (r *resetRig) tc33(t *testing.T) {
	id, pw := r.household(t, "reset-held")
	codes, _ := r.enrol(t, id, "reset-held", pw, false)
	g := r.fresh(t)
	r.settle(t)
	g.signIn(r.homeAuth(baselineConsole, nil), "reset-held", secret.New([]byte("not the password at all")))
	r.settle(t)
	before := r.passwordCreated(t, id)
	a := r.code(t, g, r.chooseUser(t, g, r.resetHome, "reset-held"), codes[0])
	end := r.newPassword(t, g, a, r.strong("held"))
	if end.at == nil || end.at.Query().Get("signin") != auth.ResetOutcomeDone || r.passwordCreated(t, id) == before {
		t.Errorf("a held source's reset ended at %v, password changed %v", end.at, r.passwordCreated(t, id) != before)
	}
}

// resetCode walks a reset for name with code up to the reset-done
// redirect, without following it, and returns the redirect.
func (r *resetRig) resetCode(t *testing.T, name, code string) *url.URL {
	t.Helper()
	g := r.fresh(t)
	a := r.code(t, g, r.chooseUser(t, g, r.resetHome, name), code)
	form, action := g.form(a, "kc-passwd-update-form")
	newPw := r.strong("token")
	form.Set("password-new", newPw)
	form.Set("password-confirm", newPw)
	r.settle(t)
	ans := g.send(http.MethodPost, action, form, nil)
	for range 6 {
		if ans.loc == nil || ans.loc.Path == auth.ResetDonePath {
			break
		}
		ans = g.send(http.MethodGet, ans.at.ResolveReference(ans.loc).String(), nil, nil)
	}
	if ans.loc == nil || ans.loc.Path != auth.ResetDonePath || ans.loc.Query().Get("code") == "" {
		t.Fatalf("the reset's redirect is %v, want reset-done with a code", ans.loc)
	}
	return ans.loc
}

// TC-992-37 (T200): the reset code's redirect carries a code and no state;
// its token answer carries no id_token (ExchangeCode refuses it for that);
// it exchanges with no code_verifier, and the access token verifies with
// the door's iss, the reset client's azp, typ Bearer and the account's sub.
func (r *resetRig) tc37(t *testing.T) {
	id, pw := r.household(t, "reset-token")
	codes, _ := r.enrol(t, id, "reset-token", pw, false)
	home := r.sites.Table.Home
	x := func(loc *url.URL) idclient.CodeExchange {
		return idclient.CodeExchange{Realm: baselineRealm, ClientID: "rasputin-reset-home", NoVerifier: true,
			Code: secret.New([]byte(loc.Query().Get("code"))), RedirectURI: "https://" + ConsoleHost + auth.ResetDonePath, Forward: home.SetForwarded}
	}
	first := r.resetCode(t, "reset-token", codes[0])
	if first.Query().Has("state") {
		t.Error("the reset's redirect carries a state")
	}
	if _, err := r.idc.ExchangeCode(t.Context(), x(first)); !errors.Is(err, idclient.ErrProtocol) || !strings.Contains(err.Error(), "id token") {
		t.Errorf("ExchangeCode on a reset code: %v, want the answer to carry no id token", err)
	}
	raw, err := r.idc.ExchangeAccessToken(t.Context(), x(r.resetCode(t, "reset-token", codes[1])))
	if err != nil {
		t.Fatalf("ExchangeAccessToken: %v", err)
	}
	v, err := idtoken.New(t.Context(), home.Issuer, "rasputin-reset-home", r.idc.Forwarding(home.SetForwarded), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.AccessToken(t.Context(), raw)
	if err != nil || c.Issuer != home.Issuer || c.AuthorizedParty != "rasputin-reset-home" || c.Subject != id {
		t.Errorf("the access token: %+v %v", c, err)
	}
}

// tc30: the administrator posts nothing past its own check without a fresh
// sign-in (C24, TC-992-31); after it, the job sets the temporary password,
// ends every session of the target, and the target's next sign-in must
// choose a new password, after which the temporary one is refused.
func (r *resetRig) tc30(t *testing.T) {
	targetID, targetPw := r.household(t, "reset-target")
	adminName := "reset-iam-admin"
	adminID, adminPw := r.user(t, adminName)
	_, otpSecret := r.enrol(t, adminID, adminName, adminPw, true)
	r.grantRole(t, adminID, "admin")
	r.setAttrs(t, adminID, map[string][]string{flows.MarkerSecondStepHome: {"true"}, flows.MarkerSecondStepAny: {"true"}})
	targetBefore := r.passwordCreated(t, targetID)
	online, g := r.appTokens(t, "reset-target", targetPw, false)
	temp := r.strong("temporary")
	admin := auth.Principal{Sub: adminID, Name: adminName, Roles: []string{"admin"}, Session: auth.SessionRef{SID: "sid-reset-admin"}}
	if err := r.resetter.Check(t.Context(), admin.Submitter(), targetID, secret.New([]byte(temp))); err != nil {
		t.Fatalf("the check: %v", err)
	}
	cookie, err := r.sessions.Create(t.Context(), admin)
	if err != nil {
		t.Fatal(err)
	}
	prepare := func() *http.Cookie {
		req := httptest.NewRequest(http.MethodPost, "https://"+ConsoleHost+"/api/accounts/"+targetID+"/reset-password", nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), admin))
		w := httptest.NewRecorder()
		if _, err := r.authSvc.PrepareAction(w, req, accounts.ResetKind, &accounts.ResetPayload{Target: targetID, Password: secret.New([]byte(temp))}); err != nil {
			t.Fatal(err)
		}
		for _, c := range w.Result().Cookies() {
			if c.Value != "" {
				return c
			}
		}
		t.Fatal("PrepareAction set no cookie")
		return nil
	}
	// TC-992-31: prepared and never followed by a fresh sign-in.
	prepare()
	if js, _ := r.ledger.ListJobsByKind(t.Context(), accounts.ResetKind, 10); len(js) != 0 || r.passwordCreated(t, targetID) != targetBefore {
		t.Fatalf("%d jobs and a changed password without the fresh sign-in", len(js))
	}

	pending := prepare()
	ac := r.fresh(t)
	u, _ := url.Parse("https://" + ConsoleHost)
	ac.jar.SetCookies(u, []*http.Cookie{{Name: auth.SessionCookieName, Value: string(cookie.Reveal()), Path: "/", Secure: true}, pending})
	a := ac.follow("https://" + ConsoleHost + "/api/auth/signin?action=" + accounts.ResetKind)
	if a.pageID() != "login-login" {
		t.Fatalf("the fresh sign-in reached %q (%d)", a.pageID(), a.status)
	}
	r.settle(t)
	a = ac.submit(a, "kc-form-login", map[string]string{"username": adminName, "password": string(adminPw.Reveal())})
	if a.pageID() != pageOTP {
		t.Fatalf("the administrator's second step is %q", a.pageID())
	}
	r.settle(t)
	a = ac.submit(a, "kc-otp-login-form", map[string]string{"otp": r.otp.next(t, otpSecret)})
	if a.at == nil || !strings.HasPrefix(a.at.Path, "/tasks") {
		t.Fatalf("the fresh sign-in ended at %v, want the job's Tasks page", a.at)
	}
	jobID := a.at.Query().Get("id")
	r.runner.Wait()
	job, err := r.ledger.GetJob(t.Context(), jobID)
	if err != nil || job.Status != jobs.StatusSucceeded {
		t.Fatalf("the reset job: %v %+v", err, job)
	}
	if strings.Contains(string(job.Spec), temp) {
		t.Error("the job's spec holds the password")
	}
	if got := r.refresh(t, g, online); got == http.StatusOK {
		t.Error("the target's refresh still works after the reset")
	}
	// The target signs in with the temporary password and must choose one.
	tg := r.fresh(t)
	r.settle(t)
	first := tg.signIn(r.appAuth("rasputin-account", nil), "reset-target", secret.New([]byte(temp)))
	if first.pageID() != pageUpdatePassword {
		t.Fatalf("the temporary password's sign-in reached %q, want the new-password page", first.pageID())
	}
	own := r.strong("own")
	r.newPassword(t, tg, first, own)
	r.settle(t)
	if !r.signsIn(t, "reset-target", own) || r.signsIn(t, "reset-target", temp) {
		t.Error("after the forced change: the own password does not sign in, or the temporary one still does")
	}
}

// TC-992-32 (T202): Keycloak answers set_temporary's Admin API reset with
// 500 for a listed and for a 14-character password; the step fails with the
// rule's sentence and the credential is unchanged.
func (r *resetRig) tc32(t *testing.T) {
	id, _ := r.household(t, "reset-classify")
	listed, _ := listedEntries(t, r.env.kcHome)
	for _, c := range []struct{ pw, sentence string }{
		{string(listed.Reveal()), "That password is too common. Choose another."},
		{strings.Repeat("k", 14), "Use at least 15 characters."},
	} {
		before := r.passwordCreated(t, id)
		j, err := r.runner.SubmitFor(t.Context(), authz.SystemSubmitter("test"), accounts.ResetKind, accounts.ResetSpec{AccountID: id},
			func(jobID string) error { r.held.Put(jobID, secret.New([]byte(c.pw))); return nil })
		if err != nil {
			t.Fatal(err)
		}
		r.runner.Wait()
		job, _ := r.ledger.GetJob(t.Context(), j.ID)
		if job.Status != jobs.StatusFailed || job.Error != c.sentence {
			t.Errorf("%q: job %s %q, want failed with %q", c.sentence, job.Status, job.Error, c.sentence)
		}
		if r.passwordCreated(t, id) != before {
			t.Errorf("%q: the credential changed", c.sentence)
		}
	}
	for _, rec := range r.rec.Records() {
		if ev, _ := logkittest.Attr(rec, "event"); ev == "reset.refused_by_policy" && rec.Level != slog.LevelWarn {
			t.Errorf("reset.refused_by_policy at %s", rec.Level)
		}
	}
}

var (
	forgotRE = regexp.MustCompile(`id="rasputin-forgot-password" href="([^"]+)"`)
	qrImgRE  = regexp.MustCompile(`<img id="kc-totp-secret-qr-code" src="([^"]*)"`)
)
