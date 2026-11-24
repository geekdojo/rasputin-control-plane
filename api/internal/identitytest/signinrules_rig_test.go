package identitytest

// The rig for the sign-in rules' functional cases
// (geekdojo/geekdojo-brain#987, Identity 4.5; TC-987-01 to TC-987-23): the
// baseline imported into the pinned Keycloak in door mode, the rules
// converged by the real converger over the api's own session, both doors
// built by door.Build with the converger as their binding check, and the
// sign-in history drain feeding the throttle, the marker writer and the
// converger's recheck.
//
// It duplicates about 60 lines of door_functional_test.go's newDoorRig,
// which another item holds; the two fold together once it lands.

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"

	apipkg "github.com/geekdojo/rasputin-control-plane/api/internal/api"
	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door"
	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/converge"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/markers"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The rig's test app clients, each bound to a variant through AppBindings.
const (
	rulesAppClients     = "rasputin-test-apps"
	rulesAdministering  = "rasputin-test-administering"
	rulesAdminsFirst    = "rasputin-test-admins-first"
	rulesNetworkDevices = "rasputin-test-network"
	rulesOtherApp       = "rasputin-test-other"
	rulesInstall        = "Rules CI"
)

// rulesAppBindings are the test clients' variants.
var rulesAppBindings = map[string]flows.Variant{
	rulesAppClients: flows.AppClients, rulesAdministering: flows.Administering,
	rulesAdminsFirst: flows.AdminsFirst, rulesNetworkDevices: flows.NetworkDevices, rulesOtherApp: flows.AppClients,
}

type rulesRig struct {
	*doorRig
	conv *converge.Converger
	// session and lock are the converger's Admin API session and realm
	// lock, for a second converger over the same realm (TC-1145-14).
	session  *idclient.Session
	lock     *sync.Mutex
	marks    *markers.Writer
	settings *memSettings
	rec      *logkittest.Recorder
	inMu     sync.Mutex
	in       converge.Inputs
	// upstream counts the requests the app door forwarded to Keycloak, by
	// client id of an authorization request (TC-987-16).
	upMu     sync.Mutex
	upstream map[string]int
	// otp hands out authenticator-app codes the service has not seen.
	otp *totpCodes
	// browser is the pinned Chrome's context for a subtest; it skips (or,
	// under required, fails) the subtest when the browser is missing.
	browser func(t *testing.T) context.Context
}

// rulesApps are the rig's app clients at the app door.
type rulesApps struct{}

func (rulesApps) AppClient(_ context.Context, id string) (policy.AppClient, bool, error) {
	_, ok := rulesAppBindings[id]
	return policy.AppClient{}, ok, nil
}

// doorBindings are TestDoor's bindings: the door table's clients and its
// four app clients are unpaused; any other client is paused, as a policy
// built without Bindings would pause it.
type doorBindings struct{ table doors.Table }

func (b doorBindings) ClientPaused(id string) bool {
	if slices.Contains(b.table.Home.Clients, id) || slices.Contains(b.table.App.Clients, id) {
		return false
	}
	_, ok, _ := doorApps{}.AppClient(context.Background(), id)
	return !ok
}

// recordingTransport counts each authorization request the door forwarded,
// by client.
type recordingTransport struct {
	inner http.RoundTripper
	r     *rulesRig
}

func (t recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/protocol/openid-connect/auth") {
		t.r.upMu.Lock()
		t.r.upstream[req.URL.Query().Get("client_id")]++
		t.r.upMu.Unlock()
	}
	return t.inner.RoundTrip(req)
}

func (r *rulesRig) forwarded(client string) int {
	r.upMu.Lock()
	defer r.upMu.Unlock()
	return r.upstream[client]
}

func (r *rulesRig) inputs() converge.Inputs {
	r.inMu.Lock()
	defer r.inMu.Unlock()
	return r.in
}

func (r *rulesRig) setInputs(f func(*converge.Inputs)) {
	r.inMu.Lock()
	defer r.inMu.Unlock()
	f(&r.in)
}

func newRulesRig(t *testing.T, env *Env) *rulesRig {
	t.Helper()
	r := &rulesRig{
		doorRig:  &doorRig{env: env, sink: &eventSink{}, passes: newPassWatch(), actions: &doorActions{}, cookiesIn: map[string][]string{}},
		settings: &memSettings{m: map[string]string{}}, upstream: map[string]int{}, otp: &totpCodes{used: map[string]bool{}},
	}
	log, rec := logkittest.New()
	r.rec = rec
	apiLeaf, err := env.CA().MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
	if err != nil {
		t.Fatal(err)
	}
	client := productionClient(t, env, apiLeaf)
	session, err := idclient.NewSession(idclient.SessionConfig{Login: client, Admin: client, Realm: baselineRealm,
		ClientID: baselineAdminClient, Log: env.log})
	if err != nil {
		t.Fatal(err)
	}
	r.session, r.lock = session, &sync.Mutex{}
	table, err := doors.New(DoorClusterID)
	if err != nil {
		t.Fatal(err)
	}
	r.in = converge.Inputs{InstallName: rulesInstall, ClockSynced: true, AppBindings: rulesAppBindings,
		RedirectURIs: map[string][]string{
			baselineConsole: {callbackOn(ConsoleHost)}, baselineMesh: {callbackOn(ConsoleHost)},
			"rasputin-reset-home": {callbackOn(ConsoleHost)},
			"rasputin-account":    {callbackOn(table.App.Host)}, "rasputin-reset-app": {callbackOn(table.App.Host)},
		}}
	r.conv, err = converge.New(converge.Deps{
		Admin: session, Settings: r.settings, Realm: baselineRealm, Lock: r.lock,
		Inputs: func(context.Context) (converge.Inputs, error) { return r.inputs(), nil },
		Now:    time.Now, Ready: func(context.Context) error { return nil }, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	doorOf := func(c string) (flows.Door, bool) {
		switch {
		case slices.Contains(table.Home.Clients, c):
			return flows.DoorHome, true
		case slices.Contains(table.App.Clients, c):
			return flows.DoorApp, true
		}
		_, ok := rulesAppBindings[c]
		return flows.DoorApp, ok
	}
	if r.marks, err = markers.New(markers.Deps{Admin: session, Realm: baselineRealm, DoorOf: doorOf, Log: log}); err != nil {
		t.Fatal(err)
	}
	if r.th, err = policy.NewThrottle(policy.ThrottleDeps{Table: table, Now: time.Now}); err != nil {
		t.Fatal(err)
	}
	r.drainer, err = events.New(events.Deps{Admin: session, Marks: &doorMarks{m: map[string]string{}}, Signal: events.NewSignal(time.Now),
		Realm: baselineRealm, UserSinks: []events.UserSink{r.th, r.sink, r.marks},
		AdminSinks: []events.AdminSink{r.conv}, PassSinks: []events.PassSink{r.th, r.conv, r.passes}, Log: env.log})
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.New(policy.Deps{Table: table, Readiness: doorReady{}, Throttle: r.th, AppClients: rulesApps{},
		Actions: r.actions, Network: doorNetwork{}, Waiting: doorWaiting{}, Now: time.Now, Bindings: r.conv})
	if err != nil {
		t.Fatal(err)
	}
	theme := env.h.cfg.ThemeDir
	raw, err := os.ReadFile(filepath.Join(theme, "resource-allowlist.json"))
	if err != nil {
		t.Fatal(err)
	}
	allow, err := door.ParseAllowlist(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.version, err = door.NewResourceVersion(client, env.log); err != nil {
		t.Fatal(err)
	}
	r.version.Learn(t.Context())
	relay, err := env.DoorTransport()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(relay.CloseIdleConnections)
	r.home, r.app, err = door.Build(table, door.Shared{
		ConsoleOrigin: "https://" + ConsoleHost, Policy: pol, Throttle: r.th, Transport: recordingTransport{inner: relay, r: r},
		Upstream: env.KeycloakUpstream(), Theme: allow, Assets: os.DirFS(filepath.Join(theme, "login", "resources")), Version: r.version,
		InstallName: func(context.Context) (string, error) { return rulesInstall, nil }, Dirty: r.drainer,
		IDs: func() string { return fmt.Sprintf("rules-%d", r.ids.Add(1)) }, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	stub := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, stubPage)
	})
	sites, err := apipkg.NewSites(apipkg.SitesConfig{
		Console: stub, Home: r.home, App: r.app,
		HomeHost: table.Home.Host, AppHost: table.App.Host, RequestLifetime: time.Minute, Now: time.Now,
		IDs: func() string { return fmt.Sprintf("rules-site-%d", r.ids.Add(1)) }, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.sites, err = env.ServeDoors(sites, stub)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.drainer.Run(ctx); close(done) }()
	vdone := make(chan struct{})
	go func() { r.version.Run(ctx); close(vdone) }()
	t.Cleanup(func() { cancel(); <-done; <-vdone })
	r.setUpClients(t)
	return r
}

// setUpClients opens registration and creates the test app clients. The
// rig's first converge is setUpRules, which the test calls after the cases
// that need the realm before any converge (TC-1145-14, TC-1145-19).
func (r *rulesRig) setUpClients(t *testing.T) {
	t.Helper()
	api := r.admin(t)
	_, out := api.must(http.StatusOK, http.MethodGet, "", nil)
	var realm map[string]any
	if err := json.Unmarshal(out, &realm); err != nil {
		t.Fatal(err)
	}
	api.must(http.StatusNoContent, http.MethodPut, "", map[string]any{"registrationAllowed": true})
	for _, id := range slices.Sorted(maps.Keys(rulesAppBindings)) {
		api.must(http.StatusCreated, http.MethodPost, "/clients", map[string]any{
			"clientId": id, "enabled": true, "publicClient": true, "protocol": "openid-connect",
			"standardFlowEnabled": true, "redirectUris": []string{callbackOn(AppSiteHost)},
			"attributes": map[string]string{"pkce.code.challenge.method": "S256"},
		})
	}
}

// setUpRules converges the rules: the rig's first converge.
func (r *rulesRig) setUpRules(t *testing.T) {
	t.Helper()
	if _, err := r.conv.Run(t.Context()); err != nil {
		t.Fatalf("converge the rules: %v", err)
	}
	if s := r.conv.State(); s != converge.Intact {
		t.Fatalf("after converge the integrity state is %s, want intact", s)
	}
	r.settle(t)
}

// account is a test account: its id, name and password.
type account struct {
	id, name string
	pw       secret.Value
}

// account creates an account with a password, a name and an email, and the
// given attributes.
func (r *rulesRig) account(t *testing.T, name string, attrs map[string][]string) account {
	t.Helper()
	pw, err := randomSecret(r.env.h.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	return r.accountWith(t, name, pw, attrs)
}

// accountWith creates an account with the password pw, a name and an
// email, and the given attributes.
func (r *rulesRig) accountWith(t *testing.T, name string, pw secret.Value, attrs map[string][]string) account {
	t.Helper()
	t.Cleanup(pw.Destroy)
	body := map[string]any{
		"username": name, "enabled": true, "email": name + "@rules.invalid", "emailVerified": true, "firstName": "Rules",
		"credentials": []map[string]any{{"type": "password", "value": string(pw.Reveal()), "temporary": false}},
	}
	if attrs != nil {
		body["attributes"] = attrs
	}
	loc, _ := r.admin(t).must(http.StatusCreated, http.MethodPost, "/users", body)
	return account{id: loc[strings.LastIndex(loc, "/")+1:], name: name, pw: pw}
}

// grantConsole gives the account a console role.
func (r *rulesRig) grantConsole(t *testing.T, a account, role string) {
	t.Helper()
	api := r.admin(t)
	id, _ := api.clientRep(baselineConsole)
	_, out := api.must(http.StatusOK, http.MethodGet, "/clients/"+id+"/roles/"+role, nil)
	var rep map[string]any
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	api.must(http.StatusNoContent, http.MethodPost, "/users/"+a.id+"/role-mappings/clients/"+id, []any{rep})
}

// setAttributes sets attributes on the account, keeping its others.
func (r *rulesRig) setAttributes(t *testing.T, a account, attrs map[string][]string) {
	t.Helper()
	api := r.admin(t)
	user := r.user(t, a)
	have, _ := user["attributes"].(map[string]any)
	if have == nil {
		have = map[string]any{}
	}
	for k, v := range attrs {
		have[k] = v
	}
	user["attributes"] = have
	api.must(http.StatusNoContent, http.MethodPut, "/users/"+a.id, user)
}

// user is the account's representation.
func (r *rulesRig) user(t *testing.T, a account) map[string]any {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+a.id, nil)
	var u map[string]any
	if err := json.Unmarshal(out, &u); err != nil {
		t.Fatal(err)
	}
	return u
}

// attr is the account's attribute's first value, "" for none.
func (r *rulesRig) attr(t *testing.T, a account, name string) string {
	t.Helper()
	attrs, _ := r.user(t, a)["attributes"].(map[string]any)
	vs, _ := attrs[name].([]any)
	if len(vs) == 0 {
		return ""
	}
	s, _ := vs[0].(string)
	return s
}

// requireActions sets the account's required actions.
func (r *rulesRig) requireActions(t *testing.T, a account, actions ...string) {
	t.Helper()
	user := r.user(t, a)
	user["requiredActions"] = actions
	r.admin(t).must(http.StatusNoContent, http.MethodPut, "/users/"+a.id, user)
}

// The doors' authorization requests for the rig's clients.
func (r *rulesRig) homeConsole() string { return r.homeAuth(baselineConsole, nil) }
func (r *rulesRig) appAccount() string  { return r.appAuth("rasputin-account", nil) }
func (r *rulesRig) appClient(id string) string {
	return r.appURL("/realms/rasputin/protocol/openid-connect/auth?" + doorAuthQuery(id, AppSiteHost, map[string]string{"prompt": ""}))
}

// doorOf is a door's sign-in for a test case: its name and its
// authorization request.
type doorCase struct {
	name string
	auth func() string
}

func (r *rulesRig) bothDoors() []doorCase {
	return []doorCase{{"home door", r.homeConsole}, {"app door", r.appAccount}}
}

// errorText is an error page's sentence, unescaped.
func errorText(a doorAnswer) string {
	if m := errorTextRE.FindSubmatch(a.body); m != nil {
		return strings.TrimSpace(html.UnescapeString(string(m[1])))
	}
	return ""
}

var errorTextRE = regexp.MustCompile(`(?s)<p class="instruction kc-feedback-text">(.*?)</p>`)

// enrolTOTP answers the authenticator-app setup page and returns the
// secret.
func (r *rulesRig) enrolTOTP(t *testing.T, g *goClient, a doorAnswer) (doorAnswer, string) {
	t.Helper()
	if a.pageID() != "login-login-config-totp" {
		t.Fatalf("want the authenticator-app setup page, got %q (%d) %q", a.pageID(), a.status, errorText(a))
	}
	m := regexp.MustCompile(`<img id="kc-totp-secret-qr-code" src="([^"]*)"`).FindSubmatch(a.body)
	if m == nil {
		t.Fatal("the setup page shows no QR code")
	}
	text, err := decodeQR(html.UnescapeString(string(m[1])))
	if err != nil {
		t.Fatalf("decode the QR code: %v", err)
	}
	u, err := url.Parse(text)
	if err != nil || u.Scheme != "otpauth" {
		t.Fatalf("the QR code holds no otpauth URI")
	}
	secretB32 := u.Query().Get("secret")
	code := r.otp.next(t, secretB32)
	return r.post(t, g, a, "kc-totp-settings-form", map[string]string{"totp": code, "userLabel": "Rules phone"}), secretB32
}

// saveCodes answers the recovery-codes page and returns the codes.
func (r *rulesRig) saveCodes(t *testing.T, g *goClient, a doorAnswer) (doorAnswer, []string) {
	t.Helper()
	if a.pageID() != "login-login-recovery-authn-code-config" {
		t.Fatalf("want the recovery-codes page, got %q (%d) %q", a.pageID(), a.status, errorText(a))
	}
	fields, _ := g.form(a, "kc-recovery-codes-settings-form")
	codes := strings.Split(fields.Get("generatedRecoveryAuthnCodes"), ",")
	if len(codes) < 2 {
		t.Fatalf("the recovery-codes page holds %d codes", len(codes))
	}
	return r.post(t, g, a, "kc-recovery-codes-settings-form", nil), codes
}

// tryAnotherWay asks for the other ways from a second-step page and picks
// the recovery code.
func (r *rulesRig) recoveryInstead(t *testing.T, g *goClient, a doorAnswer) doorAnswer {
	t.Helper()
	if a.pageID() == "login-login-recovery-authn-code-input" {
		return a
	}
	sel := r.post(t, g, a, "kc-select-try-another-way-form", nil)
	if sel.pageID() != "login-select-authenticator" {
		t.Fatalf("try another way opened %q, want the chooser", sel.pageID())
	}
	_, action := g.form(sel, "kc-select-credential-form")
	for _, m := range regexp.MustCompile(`(?s)<button[^>]*name="authenticationExecution"[^>]*value="([^"]+)"[^>]*>(.*?)</button>`).FindAllSubmatch(sel.body, -1) {
		if strings.Contains(strings.ToLower(string(m[2])), "recovery") {
			r.settle(t)
			b := g.send(http.MethodPost, action, url.Values{"authenticationExecution": {string(m[1])}}, nil)
			if b.status >= 300 && b.status < 400 && b.loc != nil {
				return g.follow(b.at.ResolveReference(b.loc).String())
			}
			return b
		}
	}
	t.Fatalf("the chooser offers no recovery code: %.2000s", sel.body)
	return doorAnswer{}
}

// answerRecovery enters a recovery code on the recovery-code page.
func (r *rulesRig) answerRecovery(t *testing.T, g *goClient, a doorAnswer, code string) doorAnswer {
	t.Helper()
	if a.pageID() != "login-login-recovery-authn-code-input" {
		t.Fatalf("want the recovery-code page, got %q %q", a.pageID(), errorText(a))
	}
	return r.post(t, g, a, "kc-recovery-code-login-form", map[string]string{"recoveryCodeInput": code})
}

// answerOTP enters the authenticator app's current code.
func (r *rulesRig) answerOTP(t *testing.T, g *goClient, a doorAnswer, secretB32 string) doorAnswer {
	t.Helper()
	if a.pageID() != "login-login-otp" {
		t.Fatalf("want the authenticator-code page, got %q %q", a.pageID(), errorText(a))
	}
	code := r.otp.next(t, secretB32)
	return r.post(t, g, a, "kc-otp-login-form", map[string]string{"otp": code})
}

// post submits a page's form once the source's last credential post has
// been drained, as the per-source throttle requires (one post at a time).
func (r *rulesRig) post(t *testing.T, g *goClient, a doorAnswer, form string, fields map[string]string) doorAnswer {
	t.Helper()
	r.settle(t)
	return g.submit(a, form, fields)
}

// client is a fresh Go client from a loopback address of its own.
func (r *rulesRig) fresh(t *testing.T) *goClient {
	t.Helper()
	n := r.ids.Add(1)
	return r.client(t, netip.AddrFrom4([4]byte{127, 0, byte(1 + n/250), byte(1 + n%250)}).String())
}

// isSecondStep reports whether a page asks for a second step.
func isSecondStep(id string) bool {
	return id == "login-login-otp" || id == "login-login-recovery-authn-code-input" || id == "login-webauthn-authenticate" ||
		id == "login-select-authenticator"
}

// ---- the browser: passkeys and security keys --------------------------------

// rpSpyJS reports the relying-party name of each create() call.
const rpSpyJS = `(() => {
  const c = navigator.credentials;
  if (!c || !c.create) return;
  const real = c.create.bind(c);
  c.create = (o) => {
    try { window.rasputinRPSpy(((o && o.publicKey && o.publicKey.rp) || {}).name || ''); } catch (e) {}
    return real(o);
  };
})();`

// keyTab is a browser tab with a virtual authenticator, which records each
// create() call's relying-party name.
type keyTab struct {
	*tab
	auth webauthn.AuthenticatorID
	mu   sync.Mutex
	rp   []string
}

func (k *keyTab) rpNames() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.rp)
}

// keyTab opens a tab at origin with a virtual authenticator: a platform
// one, or with securityKey a USB one, which a security-key request asks
// for. Every page the tab opens keeps its conditional passkey request from
// the authenticator (conditionalWaitsJS), as a person who has not chosen
// from the autofill list, so the authenticator answers only a request a
// step makes: the button a step presses, never the page by itself.
func (r *rulesRig) keyTab(t *testing.T, browserCtx context.Context, origin string, securityKey ...bool) *keyTab {
	t.Helper()
	k := &keyTab{tab: newTab(t, browserCtx, origin)}
	k.step(chromedp.ExposeFunc("rasputinRPSpy", func(_ context.Context, name string) (bool, error) {
		k.mu.Lock()
		defer k.mu.Unlock()
		k.rp = append(k.rp, name)
		return true, nil
	}), "expose the RP spy")
	ctx, cancel := context.WithTimeout(k.ctx, stepTimeout)
	defer cancel()
	for _, js := range []string{rpSpyJS, conditionalWaitsJS} {
		if _, err := chromedp.Call(ctx, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{Source: js}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := chromedp.Call(ctx, webauthn.Enable, webauthn.EnableParams{EnableUI: new(false)}); err != nil {
		t.Fatal(err)
	}
	transport := webauthn.AuthenticatorTransportInternal
	if len(securityKey) > 0 && securityKey[0] {
		transport = webauthn.AuthenticatorTransportUsb
	}
	k.auth = addAuthenticator(t, k.tab, transport)
	return k
}

// origin is the door's origin for an authorization request.
func originOf(u string) string {
	p, _ := url.Parse(u)
	return "https://" + p.Host
}

// registerKey signs a in at auth with its password through a required
// action that registers a passkey (or, with securityKey, a second-step
// security key) on k's authenticator, and waits until the credential event
// reached the marker writer.
func (r *rulesRig) registerKey(t *testing.T, k *keyTab, a account, auth string, securityKey bool) {
	t.Helper()
	action, button := flows.ActionPasskeyRegister, "rasputin-passkey-this-device"
	if securityKey {
		action, button = flows.ActionSecurityKey, "rasputin-passkey-security-key"
	}
	r.requireActions(t, a, action)
	if id := k.navigate(auth); id != "login-login" {
		t.Fatalf("the sign-in opened %q", id)
	}
	r.settle(t)
	if got := r.tabSignIn(k, a); got != "login-webauthn-register" {
		t.Fatalf("the registration action led to %q (%q), want login-webauthn-register", got, alertOf(k.tab))
	}
	k.step(chromedp.SetValue(chromedp.ID("rasputin-passkey-name"), "Rules key"), "type the NAME")
	r.settle(t)
	if got := k.submit(chromedp.Click(chromedp.ID(button)), "register"); got != "rasputin-stub" {
		t.Fatalf("registering led to %q, want the client's callback", got)
	}
	r.settle(t)
}

// passkeyAlone signs in at auth by a passkey tap alone and returns the
// callback's code.
func (r *rulesRig) passkeyAlone(t *testing.T, k *keyTab, auth string) string {
	t.Helper()
	m := k.mark()
	r.settle(t)
	id := openForPasskey(t, k.tab, k.auth, auth)
	if id == "login-login" {
		id = pressPasskey(t, k.tab, k.auth)
	}
	if id != "rasputin-stub" {
		t.Fatalf("the passkey sign-in led to %q", id)
	}
	reqs, _ := k.since(m)
	posts := 0
	for _, rq := range reqs {
		if rq.method == http.MethodPost && strings.Contains(rq.url, "/login-actions/authenticate") {
			posts++
		}
	}
	if posts != 1 {
		t.Errorf("a passkey sign-in posted %d times to the sign-in step, want only the passkey's", posts)
	}
	return codeOf(t, evalT[string](k.tab, `location.href`))
}

// passwordThenKey signs in at auth with a's password in k and returns the
// page it led to; with answer, it answers a WebAuthn step with k's
// authenticator and returns the callback's page.
func (r *rulesRig) passwordThenKey(t *testing.T, k *keyTab, a account, auth string, answer bool) string {
	t.Helper()
	if id := k.navigate(auth); id != "login-login" {
		t.Fatalf("the sign-in opened %q", id)
	}
	r.settle(t)
	got := r.tabSignIn(k, a)
	if !answer || got != "login-webauthn-authenticate" {
		return got
	}
	r.settle(t)
	return pressPasskey(t, k.tab, k.auth)
}

// tabSignIn submits the sign-in page with a's password, and its name when
// the page asks for one: an app-door session the tab holds keeps the
// person and asks for the password alone.
func (r *rulesRig) tabSignIn(k *keyTab, a account) string {
	k.t.Helper()
	k.step(chromedp.Evaluate[chromedp.Void](`(() => {
  const u = document.getElementById('username'); if (u) u.value = `+jsString(a.name)+`;
  document.getElementById('password').value = `+jsString(string(a.pw.Reveal()))+`;
})()`), "fill the form")
	return k.submit(chromedp.Click(chromedp.CSS("#kc-login")), "sign in")
}

// alertOf is the page's alert or error sentence, for a failure message.
func alertOf(tb *tab) string {
	return evalT[string](tb, `((document.querySelector('.rasp-alert-text') || document.querySelector('.kc-feedback-text') || {}).textContent || '').trim()`)
}

// codeOf is the code in a callback URL.
func codeOf(t *testing.T, u string) string {
	t.Helper()
	p, err := url.Parse(u)
	if err != nil || p.Query().Get("code") == "" {
		t.Fatalf("not a callback with a code: %s", redactURL(u))
	}
	return p.Query().Get("code")
}

// idTokenClaims exchanges a test app client's code at the app door and
// returns its ID token's claims.
func (r *rulesRig) idTokenClaims(t *testing.T, client, code string) map[string]any {
	t.Helper()
	g := r.fresh(t)
	a := g.send(http.MethodPost, r.appURL("/realms/rasputin/protocol/openid-connect/token"), url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {client},
		"redirect_uri": {callbackOn(AppSiteHost)}, "code_verifier": {doorPKCE},
	}, nil)
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if a.status != http.StatusOK || json.Unmarshal(a.body, &tok) != nil || tok.IDToken == "" {
		t.Fatalf("the code exchange answered %d", a.status)
	}
	return jwtClaims(t, tok.IDToken)
}
