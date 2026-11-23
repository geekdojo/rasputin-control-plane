package identitytest

// The sign-in theme walk (geekdojo/geekdojo-brain#988; TC-988-18 to
// TC-988-25): the repo's realm baseline, which selects the Rasputin login
// theme, imported into the pinned Keycloak with the built theme linked as
// themes/rasputin; then, in the pinned Chrome, every page the baseline and
// this walk's setup render, each held to TC-988-18's checks.
//
// The setup goes through the Admin API and stands in for later items: the
// install name, the three link attributes, registration and reset turned on,
// passkey sign-in turned on, two app clients and a SAML client, and users. It
// changes no authentication flow and no credential check.
//
// The front runs on https://localhost:<port>: WebAuthn refuses an IP address
// as its relying party. The clients' redirect URI and the SAML client's
// endpoint are on the front's origin and the tab answers them itself, so
// every request a page makes stays on one origin.
//
// It starts an Env of its own, closed with proof in its cleanup. It skips
// without RASPUTIN_IDENTITY_HOME or RASPUTIN_IDENTITY_THEME and fails instead
// under RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job sets it.

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/geekdojo/rasputin-control-plane/secret"
)

const (
	installName = "Hoodoo Home"
	appClient   = "immich"
	otherApp    = "rasputin-test-other-app"
	samlClient  = "rasputin-test-saml"
	samlSSOName = "rasputin-test"
	// A fixed PKCE S256 pair: the walk never exchanges the code.
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// walk is the state the walk's checks share.
type walk struct {
	env   *Env
	front string
	words forbiddenWords
	allow resourceAllowlist
	table map[string]pageEntry
	seen  map[string]bool
	admin func(t *testing.T) adminAPI
	attrs map[string]string // the three link attributes as set
	via   walkVia
}

// walkVia is the way the walk reaches the identity service: the front's
// defaults, or one sign-in door's (TC-985-39, geekdojo/geekdojo-brain#985),
// whose policy changes what the walk may ask.
type walkVia struct {
	// authExtra is set on every authorization request: the home door's
	// prompt=login.
	authExtra url.Values
	// signInClient is the client the walk signs in to, and resetClient the
	// one its reset page is for: a door serves only its own. clients are the
	// sign-in pages whose links are checked, and missingClients those checked
	// with each link attribute missing.
	signInClient, resetClient string
	clients, missingClients   []string
	// prefix starts every user name, so two walks share one realm.
	prefix string
	// frontChannel is the app's front-channel sign-out address.
	frontChannel string
	// door: delete_credential is refused (the door's policy), and the SAML
	// sign-in starts at the app (the door serves no IdP-initiated path).
	door bool
	// beforeSubmit is each tab's hook.
	beforeSubmit func(t *testing.T)
}

// frontVia is the front's way: every client, no extra parameter.
func frontVia(front string) walkVia {
	return walkVia{signInClient: baselineConsole, resetClient: baselineConsole, clients: signInClients,
		missingClients: []string{baselineConsole, appClient}, frontChannel: front + "/realms/" + baselineRealm}
}

// newTab is a tab on the walk's front, with the way's submit hook.
func (w *walk) newTab(t *testing.T, browserCtx context.Context) *tab {
	t.Helper()
	tb := newTab(t, browserCtx, w.front)
	tb.beforeSubmit = w.via.beforeSubmit
	return tb
}

func TestIdentity_ThemeWalk(t *testing.T) {
	p := NewPackage(func() (Config, error) {
		c, err := ConfigFromEnv()
		c.FrontHost = "localhost"
		return c, err
	})
	if !p.RequireTheme(t) {
		return
	}
	browserCtx, env := p.Browser(t)
	if env == nil {
		return
	}
	t.Cleanup(func() {
		if err := env.Close(context.Background()); err != nil {
			t.Errorf("identitytest: teardown proof failed: %v", err)
		}
	})
	importBaseline(t, env)

	table, err := buildPageTable(coverageTemplates(t))
	if err != nil {
		t.Fatalf("TC-988-19: %v", err)
	}
	var allow resourceAllowlist
	b, err := os.ReadFile(filepath.Join(env.h.cfg.ThemeDir, "resource-allowlist.json"))
	if err != nil || json.Unmarshal(b, &allow) != nil || len(allow.Login) == 0 {
		t.Fatalf("the built theme's resource-allowlist.json is missing or empty: %v", err)
	}
	front := env.FrontURL()
	w := &walk{
		env: env, front: front, words: loadForbiddenWords(t), allow: allow, table: table, seen: map[string]bool{},
		admin: func(t *testing.T) adminAPI { a, _ := baselineAdmin(t, env); a.t = t; return a },
		attrs: map[string]string{
			"rasputin.console-url":    front,
			"rasputin.reset-home-url": front + "/reset-home",
			"rasputin.reset-app-url":  front + "/reset-app",
		},
		via: frontVia(front),
	}
	w.setUp(t)

	t.Run("TC-988-23 links per client", func(t *testing.T) { w.linksPerClient(t, browserCtx) })
	t.Run("TC-988-24 a missing link attribute", func(t *testing.T) { w.missingAttributes(t, browserCtx) })
	t.Run("register, reset and error pages", func(t *testing.T) { w.otherDoorPages(t, browserCtx) })
	t.Run("TC-988-22 required actions, the second step and sign-out", func(t *testing.T) { w.requiredActions(t, browserCtx) })
	t.Run("update profile and front-channel sign-out", func(t *testing.T) { w.profileAndFrontChannel(t, browserCtx) })
	t.Run("TC-988-20 and TC-988-21 passkeys", func(t *testing.T) { w.passkeys(t, browserCtx) })
	t.Run("TC-988-25 SAML auto-post", func(t *testing.T) { w.saml(t, browserCtx) })

	// TC-988-19: every page marked walked was walked, and nothing else.
	var missed []string
	for _, id := range walkedPages {
		if !w.seen[id] {
			missed = append(missed, id)
		}
	}
	if len(missed) > 0 && !t.Failed() {
		t.Errorf("TC-988-19: the page table marks %v walked, but the walk never rendered them", missed)
	}
	for id, e := range w.table {
		switch e.status {
		case pageWalked:
			t.Logf("page table: %s walked", id)
		case pageDeferred:
			t.Logf("page table: %s deferred to %s", id, e.why)
		case pageNever:
			t.Logf("page table: %s never rendered: %s", id, e.why)
		}
	}
}

// ---- setup -----------------------------------------------------------------

func (w *walk) setUp(t *testing.T) {
	api := w.admin(t)
	_, out := api.must(http.StatusOK, http.MethodGet, "", nil)
	var realm map[string]any
	if err := json.Unmarshal(out, &realm); err != nil {
		t.Fatal(err)
	}
	attrs, _ := realm["attributes"].(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
	}
	for k, v := range w.attrs {
		attrs[k] = v
	}
	put := map[string]any{
		"displayName":          installName,
		"registrationAllowed":  true,
		"resetPasswordAllowed": true,
		"attributes":           attrs,
	}
	// Keycloak rebuilds a WebAuthn policy from the request, with defaults for
	// every field left out, so both are sent whole as read (capability row
	// T93), with the entity name set and passkey sign-in turned on.
	for k, v := range realm {
		if strings.HasPrefix(k, "webAuthnPolicy") {
			put[k] = v
		}
	}
	put["webAuthnPolicyRpEntityName"] = installName
	put["webAuthnPolicyPasswordlessRpEntityName"] = installName
	put["webAuthnPolicyPasswordlessPasskeysEnabled"] = true
	api.must(http.StatusNoContent, http.MethodPut, "", put)
	// The callback is added to each client's redirect URIs, never put in
	// their place, so a walk through each door shares one realm.
	callback := w.front + callbackPath
	for _, c := range []string{baselineConsole, baselineMesh, "rasputin-account", "rasputin-reset-home", "rasputin-reset-app"} {
		id, rep := api.clientRep(c)
		rep["redirectUris"] = withURI(rep["redirectUris"], callback)
		api.must(http.StatusNoContent, http.MethodPut, "/clients/"+id, rep)
	}
	w.ensureClient(t, api, map[string]any{
		"clientId": appClient, "name": "Immich", "enabled": true, "publicClient": true, "protocol": "openid-connect",
		"standardFlowEnabled": true, "redirectUris": []string{callback},
		"frontchannelLogout": true, "attributes": map[string]string{"frontchannel.logout.url": w.via.frontChannel},
	})
	w.ensureClient(t, api, map[string]any{
		"clientId": otherApp, "enabled": true, "publicClient": true, "protocol": "openid-connect",
		"standardFlowEnabled": true, "redirectUris": []string{callback},
	})
	w.ensureClient(t, api, map[string]any{
		"clientId": samlClient, "name": "Test SAML app", "enabled": true, "protocol": "saml", "frontchannelLogout": true,
		"redirectUris": []string{w.front + acsPath},
		"attributes": map[string]string{
			"saml_assertion_consumer_url_post": w.front + acsPath,
			"saml_idp_initiated_sso_url_name":  samlSSOName,
			"saml.client.signature":            "false",
			"saml.force.post.binding":          "true",
			"saml_name_id_format":              "username",
		},
	})
}

// withURI is a redirect URI list with u added once.
func withURI(list any, u string) []string {
	var out []string
	if l, ok := list.([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok && s != u {
				out = append(out, s)
			}
		}
	}
	return append(out, u)
}

// ensureClient creates rep's client, or, when an earlier walk created it,
// adds rep's redirect URIs to its own and sets rep's attributes on it.
func (w *walk) ensureClient(t *testing.T, api adminAPI, rep map[string]any) {
	t.Helper()
	clientID, _ := rep["clientId"].(string)
	_, out := api.must(http.StatusOK, http.MethodGet, "/clients?clientId="+url.QueryEscape(clientID), nil)
	var found []map[string]any
	if err := json.Unmarshal(out, &found); err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		api.must(http.StatusCreated, http.MethodPost, "/clients", rep)
		return
	}
	cur := found[0]
	uris := cur["redirectUris"]
	for _, u := range rep["redirectUris"].([]string) {
		uris = anyList(withURI(uris, u))
	}
	cur["redirectUris"] = uris
	attrs, _ := cur["attributes"].(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
	}
	if a, ok := rep["attributes"].(map[string]string); ok {
		for k, v := range a {
			attrs[k] = v
		}
	}
	cur["attributes"] = attrs
	id, _ := cur["id"].(string)
	api.must(http.StatusNoContent, http.MethodPut, "/clients/"+id, cur)
}

func anyList(l []string) []any {
	out := make([]any, len(l))
	for i, s := range l {
		out[i] = s
	}
	return out
}

// user creates a user with a full profile unless bare, a password, and the
// required actions; it returns the user's location and password.
func (w *walk) user(t *testing.T, name string, bare bool, actions ...string) (string, secret.Value) {
	t.Helper()
	password, err := randomSecret(w.env.h.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(password.Destroy)
	rep := map[string]any{
		"username": name, "enabled": true, "email": name + "@walk.invalid", "emailVerified": true,
		"requiredActions": append([]string{}, actions...),
		"credentials":     []map[string]any{{"type": "password", "value": string(password.Reveal()), "temporary": false}},
	}
	if !bare {
		rep["firstName"], rep["lastName"] = "Walk", "User"
	}
	loc, _ := w.admin(t).must(http.StatusCreated, http.MethodPost, "/users", rep)
	return loc, password
}

// issuer is realm rasputin's issuer on the front (Env.Issuer is the
// harness realm's).
func (w *walk) issuer() string { return w.front + "/realms/" + baselineRealm }

// authURL is the authorization request for client, its callback on the
// front's origin; extra adds parameters.
func (w *walk) authURL(client string, extra url.Values) string {
	q := url.Values{
		"client_id": {client}, "redirect_uri": {w.front + callbackPath}, "response_type": {"code"},
		"scope": {"openid"}, "state": {"walk"}, "nonce": {"walk"},
		"code_challenge": {pkceChallenge}, "code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		q[k] = v
	}
	for k, v := range w.via.authExtra {
		if _, set := extra[k]; !set {
			q[k] = v
		}
	}
	return w.issuer() + "/protocol/openid-connect/auth?" + q.Encode()
}

// visit opens u in tb, checks the page it lands on is want, and runs the
// page checks.
func (w *walk) visit(tb *tab, u, want string) {
	tb.t.Helper()
	m := tb.mark()
	tb.navigate(u)
	w.checkPage(tb, m, want)
}

// signIn submits the sign-in form on the login page tb shows and returns the
// next page id ("rasputin-stub" once the client's callback is reached).
func signIn(tb *tab, name string, password secret.Value) string {
	tb.t.Helper()
	return tb.fillAndSubmit(map[string]string{"username": name, "password": string(password.Reveal())}, "#kc-login")
}

// ---- TC-988-23 and TC-988-24 -------------------------------------------------

// links are what a sign-in page offers.
type links struct {
	Heading      string `json:"heading"`
	Forgot       string `json:"forgot"`
	Register     bool   `json:"register"`
	Repair       string `json:"repair"`
	RepairText   string `json:"repairText"`
	CreateAtHome string `json:"createAtHome"`
}

const linksJS = `(() => {
  const a = (id) => document.getElementById(id);
  return {
    heading: (document.querySelector('h1') || {}).innerText || '',
    forgot: a('rasputin-forgot-password') ? a('rasputin-forgot-password').getAttribute('href') : '',
    register: !!a('rasputin-register'),
    repair: a('rasputin-repair') ? a('rasputin-repair').querySelector('a').getAttribute('href') : '',
    repairText: a('rasputin-repair') ? a('rasputin-repair').textContent.replace(/\s+/g, ' ').trim() : '',
    createAtHome: a('rasputin-create-at-home') ? a('rasputin-create-at-home').textContent.replace(/\s+/g, ' ').trim() : '',
  };
})()`

// wantLinks is the table of ui.md §4.3 for client, given the attributes set.
func (w *walk) wantLinks(client string, attrs map[string]string) links {
	home := client == baselineConsole || client == baselineMesh || client == "rasputin-reset-home"
	l := links{Heading: "SIGN IN TO " + strings.ToUpper(installName)}
	if home {
		l.Forgot = attrs["rasputin.reset-home-url"]
	} else {
		l.Forgot = attrs["rasputin.reset-app-url"]
		if c := attrs["rasputin.console-url"]; c != "" {
			l.CreateAtHome = "No account yet? Create one on your home network at " + c + "."
		}
	}
	if client == appClient {
		l.Heading = "SIGN IN TO IMMICH"
	}
	if client == baselineConsole {
		l.Register = true
		if c := attrs["rasputin.console-url"]; c != "" {
			l.Repair = c + "/repair"
			l.RepairText = "Administrator, and sign-in is broken? Use a repair code"
		}
	}
	return l
}

func (w *walk) checkLinks(t *testing.T, tb *tab, client string, attrs map[string]string) {
	t.Helper()
	got := evalT[links](tb, linksJS)
	if want := w.wantLinks(client, attrs); got != want {
		t.Errorf("%s's sign-in page offers %+v, want %+v", client, got, want)
	}
}

var signInClients = []string{baselineConsole, baselineMesh, "rasputin-account", appClient, otherApp}

func (w *walk) linksPerClient(t *testing.T, browserCtx context.Context) {
	for _, c := range w.via.clients {
		t.Run(c, func(t *testing.T) {
			tb := w.newTab(t, browserCtx)
			w.visit(tb, w.authURL(c, nil), "login-login")
			w.checkLinks(t, tb, c, w.attrs)
		})
	}
}

func (w *walk) setAttributes(t *testing.T, attrs map[string]string) {
	t.Helper()
	api := w.admin(t)
	_, out := api.must(http.StatusOK, http.MethodGet, "", nil)
	var realm map[string]any
	if err := json.Unmarshal(out, &realm); err != nil {
		t.Fatal(err)
	}
	all, _ := realm["attributes"].(map[string]any)
	for k := range w.attrs {
		delete(all, k)
	}
	for k, v := range attrs {
		all[k] = v
	}
	api.must(http.StatusNoContent, http.MethodPut, "", map[string]any{"attributes": all})
}

func (w *walk) missingAttributes(t *testing.T, browserCtx context.Context) {
	defer w.setAttributes(t, w.attrs)
	for _, missing := range []string{"rasputin.console-url", "rasputin.reset-home-url", "rasputin.reset-app-url"} {
		attrs := map[string]string{}
		for k, v := range w.attrs {
			if k != missing {
				attrs[k] = v
			}
		}
		w.setAttributes(t, attrs)
		for _, c := range w.via.missingClients {
			t.Run(missing+" "+c, func(t *testing.T) {
				tb := w.newTab(t, browserCtx)
				w.visit(tb, w.authURL(c, nil), "login-login")
				w.checkLinks(t, tb, c, attrs)
			})
		}
	}
}

// ---- register, reset, error ---------------------------------------------------

func (w *walk) otherDoorPages(t *testing.T, browserCtx context.Context) {
	// Account creation is the console's only (ui.md §4.3).
	if w.via.signInClient == baselineConsole {
		tb := w.newTab(t, browserCtx)
		w.visit(tb, w.authURL(baselineConsole, nil), "login-login")
		m := tb.mark()
		if got := tb.submit(chromedp.Click(chromedp.ID("rasputin-register")), "press Create an account"); got != "login-register" {
			t.Fatalf("Create an account led to %q, want login-register", got)
		}
		w.checkPage(tb, m, "login-register")
		for _, want := range []string{"Rasputin never sends you email.", "Your sign-in name can't be changed later."} {
			if text := evalT[string](tb, `document.body.innerText`); !strings.Contains(text, want) {
				t.Errorf("login-register does not say %q", want)
			}
		}
	}

	tb := w.newTab(t, browserCtx)
	w.visit(tb, w.issuer()+"/login-actions/reset-credentials?client_id="+w.via.resetClient, "login-login-reset-password")

	tb = w.newTab(t, browserCtx)
	q := url.Values{"redirect_uri": {"https://elsewhere.invalid/cb"}}
	w.visit(tb, w.authURL(w.via.signInClient, q), "login-error")
}

// ---- required actions, the second step, sign-out (TC-988-22) ---------------

func (w *walk) requiredActions(t *testing.T, browserCtx context.Context) {
	name := w.via.prefix + "walk-hoodoo"
	client := w.via.signInClient
	loc, password := w.user(t, name, false, "UPDATE_PASSWORD", "CONFIGURE_TOTP", "CONFIGURE_RECOVERY_AUTHN_CODES")
	newPassword, err := randomSecret(w.env.h.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	defer newPassword.Destroy()
	tb := w.newTab(t, browserCtx)
	w.visit(tb, w.authURL(client, nil), "login-login")
	staleAction := evalT[string](tb, `document.getElementById('kc-form-login').action`)

	signIn(tb, name, password)

	// F-988-04: the sign-in form, posted again once used, is a stale page.
	var m mark
	var id string
	{
		pm := tb.mark()
		got := tb.submit(chromedp.Evaluate[chromedp.Void](`(() => {
			const f = document.createElement('form');
			f.method = 'post';
			f.action = `+jsString(staleAction)+`;
			for (const [k, v] of [['username', `+jsString(name)+`], ['password', 'stale']]) {
				const i = document.createElement('input'); i.type = 'hidden'; i.name = k; i.value = v; f.appendChild(i);
			}
			document.body.appendChild(f);
			f.submit();
		})()`), "post the used sign-in form again")
		if got != "login-login-page-expired" {
			t.Fatalf("posting the used sign-in form again shows %q, want login-page-expired", got)
		}
		w.checkPage(tb, pm, "login-login-page-expired")
		m = tb.mark()
		id = tb.submit(chromedp.Click(chromedp.ID("loginContinueLink")), "continue where you left off")
	}

	var secretB32 string
	for steps := 0; id != "rasputin-stub"; steps++ {
		if steps > 6 {
			t.Fatalf("the required actions did not end; last page %s", id)
		}
		w.checkPage(tb, m, id)
		m = tb.mark()
		switch id {
		case "login-login-update-password":
			id = tb.fillAndSubmit(map[string]string{"password-new": string(newPassword.Reveal()), "password-confirm": string(newPassword.Reveal())}, "#kc-passwd-update-form input[type=submit]")
		case "login-login-config-totp":
			secretB32 = w.configureTOTP(t, tb)
			id = tb.pageID()
		case "login-login-recovery-authn-code-config":
			w.saveRecoveryCodes(t, tb)
			id = tb.pageID()
		default:
			t.Fatalf("a required action led to %s", id)
		}
	}

	// The second step: sign in again; the authenticator app's code.
	tb = w.newTab(t, browserCtx)
	w.visit(tb, w.authURL(client, nil), "login-login")
	m = tb.mark()
	if got := signIn(tb, name, newPassword); got != "login-login-otp" {
		t.Fatalf("signing in with an authenticator app led to %s, want login-login-otp", got)
	}
	w.checkPage(tb, m, "login-login-otp")
	// The code the app shows one step on: the walk used this step's code to
	// set the app up, and a code works once.
	code, err := totp(secretB32, otpStep(w.env.h.cfg.Now())+1)
	if err != nil {
		t.Fatal(err)
	}
	if got := tb.fillAndSubmit(map[string]string{"otp": code}, "#kc-login"); got != "rasputin-stub" {
		t.Fatalf("the authenticator code led to %s, want the client's callback", got)
	}

	// Deleting a sign-in method asks first; the walk declines.
	_, out := w.admin(t).must(http.StatusOK, http.MethodGet, loc+"/credentials", nil)
	var creds []struct{ ID, Type string }
	if err := json.Unmarshal(out, &creds); err != nil {
		t.Fatal(err)
	}
	otpID := ""
	for _, c := range creds {
		if c.Type == "otp" {
			otpID = c.ID
		}
	}
	if otpID == "" {
		t.Fatal("the user holds no authenticator-app credential")
	}
	deleteURL := w.authURL(client, url.Values{"kc_action": {"delete_credential:" + otpID}})
	if w.via.door {
		// A door refuses delete_credential outright (signin-origin.md §5.2).
		if got := tb.navigate(deleteURL); got != "rasputin-door-refusal" {
			t.Fatalf("delete_credential through the door led to %s, want the door's refusal", got)
		}
	} else {
		w.visit(tb, deleteURL, "login-delete-credential")
		if got := tb.submit(chromedp.Click(chromedp.ID("kc-decline")), "decline the delete"); got != "rasputin-stub" {
			t.Fatalf("declining the delete led to %s", got)
		}
	}

	// Sign-out asks first, then says it is done.
	w.visit(tb, w.issuer()+"/protocol/openid-connect/logout?client_id="+client, "login-logout-confirm")
	m = tb.mark()
	if got := tb.submit(chromedp.Click(chromedp.ID("kc-logout")), "sign out"); got != "login-info" {
		t.Fatalf("signing out led to %s, want login-info", got)
	}
	w.checkPage(tb, m, "login-info")
}

// configureTOTP is TC-988-22's authenticator half: the QR code's issuer is
// the install name and the page names no app. It sets the app up and returns
// its secret.
func (w *walk) configureTOTP(t *testing.T, tb *tab) string {
	t.Helper()
	src := evalT[string](tb, `document.getElementById('kc-totp-secret-qr-code').getAttribute('src')`)
	text, err := decodeQR(src)
	if err != nil {
		t.Fatalf("TC-988-22: decode the QR code: %v", err)
	}
	u, err := url.Parse(text)
	if err != nil || u.Scheme != "otpauth" {
		t.Fatalf("TC-988-22: the QR code holds %q, not an otpauth URI", text)
	}
	if got := u.Query().Get("issuer"); got != installName {
		t.Errorf("TC-988-22: the otpauth issuer is %q, want %q", got, installName)
	}
	if hits := w.words.hits(evalT[string](tb, `document.body.innerText`)); len(hits) > 0 {
		t.Errorf("TC-988-22: the authenticator-app page names %v", hits)
	}
	secretB32 := u.Query().Get("secret")
	code, err := totp(secretB32, otpStep(w.env.h.cfg.Now()))
	if err != nil {
		t.Fatal(err)
	}
	tb.fillAndSubmit(map[string]string{"totp": code, "userLabel": "Walk phone"}, "#saveTOTPBtn")
	return secretB32
}

// saveRecoveryCodes is TC-988-22's recovery-code half: DOWNLOAD's file is
// named after the install, ticking the box enables the save button, and
// saving completes the step.
func (w *walk) saveRecoveryCodes(t *testing.T, tb *tab) {
	t.Helper()
	tb.step(chromedp.Click(chromedp.ID("downloadRecoveryCodes")), "press DOWNLOAD")
	// The download event arrives on the browser's connection; the click's
	// reply does not wait for it, so the walk reads it once the save is done.
	if evalT[bool](tb, `document.getElementById('saveRecoveryAuthnCodesBtn').disabled`) != true {
		t.Error("TC-988-22: the save button is enabled before the box is ticked")
	}
	tb.step(chromedp.Click(chromedp.ID("kcRecoveryCodesConfirmationCheck")), "tick the box")
	if evalT[bool](tb, `document.getElementById('saveRecoveryAuthnCodesBtn').disabled`) {
		t.Fatal("TC-988-22: ticking the box left the save button disabled")
	}
	tb.submit(chromedp.Click(chromedp.ID("saveRecoveryAuthnCodesBtn")), "save the recovery codes")
	tb.mu.Lock()
	downloads := append([]string(nil), tb.downloads...)
	tb.mu.Unlock()
	if want := installName + "-recovery-codes.txt"; !slices.Contains(downloads, want) {
		t.Errorf("TC-988-22: the downloads were %q, want %q", downloads, want)
	}
	for _, d := range downloads {
		if hits := w.words.hits(d); len(hits) > 0 {
			t.Errorf("TC-988-18: the download name %q reads %v", d, hits)
		}
	}
}

// ---- update profile, front-channel sign-out ----------------------------------

func (w *walk) profileAndFrontChannel(t *testing.T, browserCtx context.Context) {
	name := w.via.prefix + "walk-noname"
	_, password := w.user(t, name, true)
	tb := w.newTab(t, browserCtx)
	w.visit(tb, w.authURL(appClient, nil), "login-login")
	m := tb.mark()
	if got := signIn(tb, name, password); got != "login-login-update-profile" {
		t.Fatalf("a user with no name signing in led to %s, want login-update-profile", got)
	}
	w.checkPage(tb, m, "login-login-update-profile")
	if got := tb.submit(chromedp.Steps(
		chromedp.SetValue(chromedp.ID("firstName"), "Walk"),
		chromedp.SetValue(chromedp.ID("lastName"), "User"),
		chromedp.Click(chromedp.CSS("#kc-update-profile-form input[type=submit]")),
	), "save the profile"); got != "rasputin-stub" {
		t.Fatalf("saving the profile led to %s", got)
	}
	w.visit(tb, w.issuer()+"/protocol/openid-connect/logout?client_id="+appClient, "login-logout-confirm")
	m = tb.mark()
	if got := tb.submit(chromedp.Click(chromedp.ID("kc-logout")), "sign out"); got != "login-frontchannel-logout" {
		t.Fatalf("signing out of an app with front-channel sign-out led to %s, want login-frontchannel-logout", got)
	}
	w.checkPage(tb, m, "login-frontchannel-logout")
}

// ---- passkeys (TC-988-20, TC-988-21) -----------------------------------------

// createSpyJS records each navigator.credentials.create() call's hints and
// attachment through the exposed rasputinCreateSpy, before any page script
// runs; the theme's own wrapper then calls it with the options it built.
const createSpyJS = `(() => {
  const c = navigator.credentials;
  if (!c || !c.create) return;
  const real = c.create.bind(c);
  c.create = (o) => {
    const pk = (o && o.publicKey) || {};
    try { window.rasputinCreateSpy({ hints: pk.hints || [], attachment: (pk.authenticatorSelection || {}).authenticatorAttachment || '' }); } catch (e) {}
    return real(o);
  };
})();`

type createCall struct {
	Hints      []string `json:"hints"`
	Attachment string   `json:"attachment"`
}

func (w *walk) passkeyTab(t *testing.T, browserCtx context.Context, calls *[]createCall) *tab {
	t.Helper()
	tb := w.newTab(t, browserCtx)
	tb.step(chromedp.ExposeFunc("rasputinCreateSpy", func(_ context.Context, c createCall) (bool, error) {
		tb.mu.Lock()
		defer tb.mu.Unlock()
		*calls = append(*calls, c)
		return true, nil
	}), "expose the create() spy")
	ctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer cancel()
	if _, err := chromedp.Call(ctx, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{Source: createSpyJS}); err != nil {
		t.Fatal(err)
	}
	if _, err := chromedp.Call(ctx, webauthn.Enable, webauthn.EnableParams{EnableUI: new(false)}); err != nil {
		t.Fatal(err)
	}
	return tb
}

func addAuthenticator(t *testing.T, tb *tab, transport webauthn.AuthenticatorTransport) webauthn.AuthenticatorID {
	t.Helper()
	ctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer cancel()
	res, err := chromedp.Call(ctx, webauthn.AddVirtualAuthenticator, webauthn.AddVirtualAuthenticatorParams{Options: &webauthn.VirtualAuthenticatorOptions{
		Protocol: webauthn.AuthenticatorProtocolCtap2, Transport: transport,
		HasResidentKey: true, HasUserVerification: true, IsUserVerified: true, AutomaticPresenceSimulation: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return res.AuthenticatorID
}

func setVerified(t *testing.T, tb *tab, auth webauthn.AuthenticatorID, verified bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer cancel()
	if _, err := chromedp.Call(ctx, webauthn.SetUserVerified, webauthn.SetUserVerifiedParams{AuthenticatorID: auth, IsUserVerified: verified}); err != nil {
		t.Fatal(err)
	}
}

func (w *walk) passkeys(t *testing.T, browserCtx context.Context) {
	name := w.via.prefix + "walk-passkey"
	loc, password := w.user(t, name, false)
	choices := []struct {
		button, label string
		hint          protocol.PublicKeyCredentialHints
		transport     webauthn.AuthenticatorTransport
	}{
		{"rasputin-passkey-phone", "Walk phone", protocol.PublicKeyCredentialHintHybrid, webauthn.AuthenticatorTransportUsb},
		{"rasputin-passkey-security-key", "Walk key", protocol.PublicKeyCredentialHintSecurityKey, webauthn.AuthenticatorTransportUsb},
		{"rasputin-passkey-this-device", "Walk laptop", protocol.PublicKeyCredentialHintClientDevice, webauthn.AuthenticatorTransportInternal},
	}
	var last *tab
	for i, c := range choices {
		api := w.admin(t)
		_, out := api.must(http.StatusOK, http.MethodGet, loc, nil)
		var rep map[string]any
		if err := json.Unmarshal(out, &rep); err != nil {
			t.Fatal(err)
		}
		rep["requiredActions"] = []string{"webauthn-register-passwordless"}
		api.must(http.StatusNoContent, http.MethodPut, loc, rep)
		var calls []createCall
		tb := w.passkeyTab(t, browserCtx, &calls)
		auth := addAuthenticator(t, tb, c.transport)
		w.visit(tb, w.authURL(w.via.signInClient, nil), "login-login")
		m := tb.mark()
		if got := signIn(tb, name, password); got != "login-webauthn-register" {
			t.Fatalf("a passkey required action led to %s, want login-webauthn-register", got)
		}
		w.checkPage(tb, m, "login-webauthn-register")
		if i == 0 {
			// The WebAuthn error page, forced by an authenticator that cannot
			// verify the person, then its TRY AGAIN.
			setVerified(t, tb, auth, false)
			m = tb.mark()
			if got := tb.submit(chromedp.Click(chromedp.ID(c.button)), "register with an unverified authenticator"); got != "login-webauthn-error" {
				t.Fatalf("an unverified authenticator led to %s, want login-webauthn-error", got)
			}
			w.checkPage(tb, m, "login-webauthn-error")
			setVerified(t, tb, auth, true)
			m = tb.mark()
			if got := tb.submit(chromedp.Click(chromedp.ID("kc-try-again")), "TRY AGAIN"); got != "login-webauthn-register" {
				t.Fatalf("TRY AGAIN led to %s, want login-webauthn-register", got)
			}
			w.checkPage(tb, m, "login-webauthn-register")
			tb.mu.Lock()
			calls = nil
			tb.mu.Unlock()
		}
		tb.step(chromedp.SetValue(chromedp.ID("rasputin-passkey-name"), c.label), "type the NAME")
		if got := tb.submit(chromedp.Click(chromedp.ID(c.button)), "press "+c.button); got != "rasputin-stub" {
			t.Fatalf("%s led to %s, want the client's callback", c.button, got)
		}
		tb.mu.Lock()
		got := append([]createCall(nil), calls...)
		dialogs := tb.dialogs
		tb.mu.Unlock()
		want := createCall{Hints: []string{string(c.hint)}, Attachment: string(c.hint.AuthenticatorAttachment())}
		if len(got) != 1 || !slices.Equal(got[0].Hints, want.Hints) || got[0].Attachment != want.Attachment {
			t.Errorf("TC-988-20: %s's create() calls were %+v, want one with %+v", c.button, got, want)
		}
		if dialogs != 0 {
			t.Errorf("TC-988-20: %d browser dialogs opened, want none", dialogs)
		}
		last = tb
	}
	_, out := w.admin(t).must(http.StatusOK, http.MethodGet, loc+"/credentials", nil)
	var creds []struct{ Type, UserLabel string }
	if err := json.Unmarshal(out, &creds); err != nil {
		t.Fatal(err)
	}
	for _, c := range choices {
		if !slices.ContainsFunc(creds, func(cr struct{ Type, UserLabel string }) bool {
			return cr.Type == "webauthn-passwordless" && cr.UserLabel == c.label
		}) {
			t.Errorf("TC-988-20: no passkey saved under the typed name %q: %+v", c.label, creds)
		}
	}

	// TC-988-21: SIGN IN WITH A PASSKEY, with THIS DEVICE's passkey, through
	// rasputin-passkeys.js and the forked webauthnAuthenticate.js.
	tb := last
	m := tb.mark()
	id := tb.navigate(w.authURL(w.via.signInClient, url.Values{"prompt": {"login"}}))
	if id == "login-login" {
		w.checkPage(tb, m, "login-login")
		m = tb.mark()
		id = tb.submit(chromedp.Click(chromedp.ID("authenticateWebAuthnButton")), "press SIGN IN WITH A PASSKEY")
	}
	if id != "rasputin-stub" {
		t.Fatalf("TC-988-21: the passkey sign-in led to %s, want the client's callback", id)
	}
	_, errs := tb.since(m)
	for _, e := range errs {
		t.Errorf("TC-988-21: the passkey sign-in logged %s", e)
	}
}

// ---- SAML (TC-988-25) ---------------------------------------------------------

func (w *walk) saml(t *testing.T, browserCtx context.Context) {
	name := w.via.prefix + "walk-saml"
	_, password := w.user(t, name, false)

	// The page itself, with its auto-post held so the checks can run on it.
	tb := w.newTab(t, browserCtx)
	tb.hold("/js/rasputin-autosubmit.js", "// held by the walk so the page stays for its checks\n")
	w.visit(tb, w.samlStart(t), "login-login")
	m := tb.mark()
	if got := signIn(tb, name, password); got != "login-saml-post-form" {
		t.Fatalf("a SAML sign-in led to %s, want login-saml-post-form", got)
	}
	w.checkPage(tb, m, "login-saml-post-form")
	body := ""
	reqs, _ := tb.since(m)
	for _, r := range reqs {
		if !r.document {
			continue
		}
		ctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
		res, err := chromedp.Call(ctx, network.GetResponseBody, network.GetResponseBodyParams{RequestID: r.id})
		cancel()
		if err == nil && strings.Contains(string(res.Body), `data-page-id="login-saml-post-form"`) {
			body = string(res.Body)
		}
	}
	if body == "" {
		t.Fatal("TC-988-25: no response body of the SAML post page was recorded")
	}
	if strings.Contains(body, "<script>") || strings.Contains(body, "onload=") || strings.Contains(body, "<script type=\"module\">") {
		t.Error("TC-988-25: the SAML post page's body carries an inline script or handler")
	}
	if !strings.Contains(body, "/js/rasputin-autosubmit.js") {
		t.Error("TC-988-25: the SAML post page does not load rasputin-autosubmit.js")
	}

	// The real page: the POST it makes with no click.
	tb = w.newTab(t, browserCtx)
	w.visit(tb, w.samlStart(t), "login-login")
	signIn(tb, name, password)
	// The post page loads and then posts itself: wait for the fact, the
	// app's endpoint showing, not for a time.
	tb.step(chromedp.WaitVisible(chromedp.CSS(`body[data-page-id="rasputin-stub"]`)), "wait for the SAML auto-post to reach the app's endpoint")
	tb.mu.Lock()
	posts := append([]string(nil), tb.acsPosts...)
	tb.mu.Unlock()
	if len(posts) != 1 || !strings.Contains(posts[0], "SAMLResponse=") {
		t.Errorf("TC-988-25: the browser posted %d times to the app's endpoint, want once with a SAMLResponse", len(posts))
	}
}

// samlStart is the SAML sign-in's first address. At the front it is the
// IdP-initiated one; through a door, which serves only protocol/saml, it is
// an SP-initiated AuthnRequest in the redirect binding (unsigned and with no
// Destination, which the test client's settings accept: SamlService at
// 26.8.2 checks a Destination only when one is sent or a signature is
// required).
func (w *walk) samlStart(t *testing.T) string {
	if !w.via.door {
		return w.issuer() + "/protocol/saml/clients/" + samlSSOName
	}
	req := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
		` ID="_rasputin-walk" Version="2.0" IssueInstant="` + w.env.h.cfg.Now().UTC().Format("2006-01-02T15:04:05Z") + `"` +
		` AssertionConsumerServiceURL="` + w.front + acsPath + `" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">` +
		`<saml:Issuer>` + samlClient + `</saml:Issuer></samlp:AuthnRequest>`
	var b bytes.Buffer
	fw, err := flate.NewWriter(&b, flate.BestCompression)
	if err == nil {
		_, err = fw.Write([]byte(req))
	}
	if err == nil {
		err = fw.Close()
	}
	if err != nil {
		t.Fatalf("deflate the AuthnRequest: %v", err)
	}
	return w.issuer() + "/protocol/saml?" + url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(b.Bytes())}}.Encode()
}

// jsString is s as a JavaScript string literal.
func jsString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
