package identitytest

// The sign-in doors against the real identity service
// (geekdojo/geekdojo-brain#985, Identity 4.3; TC-985-36 to TC-985-45): the
// repo's realm baseline imported into the pinned Keycloak, run in door mode
// (no hostname, the forwarded headers trusted from loopback, as rasputin-os's
// keycloak.conf), with the built login theme; both doors built by door.Build
// over the rasputin-door leaf's own pool, the sign-in history drain and the
// throttle running on a rasputin-admin session; and the pinned Chrome and Go
// clients reaching sso-ci.local, signin.ci.internal, ci.local and
// app.ci.internal by name on port 443.
//
// The doors are not mounted by the api yet (Identity 4.4): this test serves
// them itself. The test's policy collaborators stand in for later items: every
// app client the test registers is the app door's (7.3), the launcher has
// issued UPDATE_PASSWORD (the launcher), and registration admits 127.0.0.0/24
// outside a test tailnet range while nobody waits (4.8).
//
// It starts an Env of its own, closed with proof in its cleanup. It skips
// without RASPUTIN_IDENTITY_HOME or RASPUTIN_IDENTITY_THEME and fails instead
// under RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job sets it.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door"
	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest/signin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

const (
	doorTestApp   = "rasputin-test-app"
	doorPKCE      = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 §B's verifier
	doorChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	doorInstall   = "Door CI"
)

// The rig's test tailnet range, inside loopback so a Go client can dial from
// it.
var doorTailnet = netip.MustParsePrefix("127.0.0.64/26")

// TestRenderKeycloakConf_DoorMode: door mode writes no hostname and trusts
// the forwarded headers from loopback only.
func TestRenderKeycloakConf_DoorMode(t *testing.T) {
	pw := secret.New([]byte("pw"))
	defer pw.Destroy()
	conf := string(renderKeycloakConf(kcPaths{}, kcPorts{}, "", pw))
	for _, want := range []string{"hostname-strict=false\n", "hostname-backchannel-dynamic=false\n", "proxy-headers=xforwarded\n", "proxy-trusted-addresses=127.0.0.1/32\n"} {
		if !strings.Contains(conf, want) {
			t.Errorf("door mode keycloak.conf lacks %q", want)
		}
	}
	if strings.Contains(conf, "\nhostname=") {
		t.Error("door mode keycloak.conf sets a hostname")
	}
	if !strings.Contains(string(renderKeycloakConf(kcPaths{}, kcPorts{}, "https://x", pw)), "hostname=https://x\n") {
		t.Error("the front's keycloak.conf lost its hostname")
	}
}

// ---- the rig ---------------------------------------------------------------

type doorRig struct {
	env     *Env
	sites   *DoorSites
	home    *door.Handler
	app     *door.Handler
	th      *policy.Throttle
	drainer *events.Drainer
	version *door.ResourceVersion
	sink    *eventSink
	passes  *passWatch
	actions *doorActions
	// cookiesIn are the Cookie headers each door received, before its rules.
	cookiesMu sync.Mutex
	cookiesIn map[string][]string
	ids       atomic.Int64
}

// eventSink keeps every user event the drain delivered.
type eventSink struct {
	mu  sync.Mutex
	got []events.UserEvent
}

func (s *eventSink) UserEvent(_ context.Context, e events.UserEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, e)
}

func (s *eventSink) all() []events.UserEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]events.UserEvent(nil), s.got...)
}

// passWatch waits on the drain's pass ends, a fact.
type passWatch struct {
	mu    sync.Mutex
	cond  *sync.Cond
	ended uint64
}

func newPassWatch() *passWatch {
	p := &passWatch{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *passWatch) PassStarted(context.Context, uint64) {}

func (p *passWatch) PassEnded(_ context.Context, n uint64) {
	p.mu.Lock()
	p.ended = max(p.ended, n)
	p.mu.Unlock()
	p.cond.Broadcast()
}

// settle marks the drain and returns once a pass that started after the
// call has ended: every credential post answered before it is released, and
// every event stored before it is delivered. Only the test's context bounds
// it.
func (r *doorRig) settle(t *testing.T) {
	t.Helper()
	want := r.drainer.Pass() + 1
	r.drainer.MarkDirty()
	done := make(chan struct{})
	go func() {
		r.passes.mu.Lock()
		for r.passes.ended < want {
			r.passes.cond.Wait()
		}
		r.passes.mu.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-t.Context().Done():
		r.passes.cond.Broadcast()
		t.Fatalf("the test ended before drain pass %d ended", want)
	}
}

type doorReady struct{}

func (doorReady) Ready(context.Context) error { return nil }

type doorApps struct{}

func (doorApps) AppClient(_ context.Context, id string) (policy.AppClient, bool, error) {
	// The theme walk's two apps and its SAML device are app-door clients too.
	return policy.AppClient{}, id == doorTestApp || id == appClient || id == otherApp || id == samlClient, nil
}

type doorActions struct{ issued atomic.Bool }

func (a *doorActions) Issued(_ context.Context, r policy.ActionRequest) (bool, error) {
	return a.issued.Load() && r.Action == "UPDATE_PASSWORD" && r.Client == baselineConsole, nil
}

type doorNetwork struct{}

func (doorNetwork) Facts(context.Context) (policy.NetworkFacts, error) {
	return policy.NetworkFacts{HomeSubnets: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/24")}, Tailnet: []netip.Prefix{doorTailnet}}, nil
}

type doorWaiting struct{}

func (doorWaiting) Full(context.Context) (bool, error) { return false, nil }

type doorMarks struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *doorMarks) Get(_ context.Context, k string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[k], nil
}

func (s *doorMarks) Set(_ context.Context, k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
	return nil
}

func (r *doorRig) recordCookies(name string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.cookiesMu.Lock()
		r.cookiesIn[name] = append(r.cookiesIn[name], req.Header.Get("Cookie"))
		r.cookiesMu.Unlock()
		h.ServeHTTP(w, req)
	})
}

// consolePage is ci.local's stand-in console: it sets the console's session
// cookie and frames a home-door page.
func consolePage(home string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "__Host-rasputin-session", Value: "console-session", Path: "/", Secure: true,
			HttpOnly: true, SameSite: http.SameSiteLaxMode})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><title>Console</title></head><body data-page-id="rasputin-console">`+
			`<h1>Console</h1><iframe id="framed" src="%s"></iframe></body></html>`, html.EscapeString(home))
	})
}

func newDoorRig(t *testing.T, env *Env) *doorRig {
	t.Helper()
	r := &doorRig{env: env, sink: &eventSink{}, passes: newPassWatch(), actions: &doorActions{}, cookiesIn: map[string][]string{}}
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
	table, err := doors.New(DoorClusterID)
	if err != nil {
		t.Fatal(err)
	}
	if r.th, err = policy.NewThrottle(policy.ThrottleDeps{Table: table, Now: time.Now}); err != nil {
		t.Fatal(err)
	}
	r.drainer, err = events.New(events.Deps{Admin: session, Marks: &doorMarks{m: map[string]string{}}, Signal: events.NewSignal(time.Now),
		Realm: baselineRealm, UserSinks: []events.UserSink{r.th, r.sink}, PassSinks: []events.PassSink{r.th, r.passes}, Log: env.log})
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.New(policy.Deps{Table: table, Readiness: doorReady{}, Throttle: r.th, AppClients: doorApps{},
		Actions: r.actions, Network: doorNetwork{}, Waiting: doorWaiting{}, Now: time.Now})
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
	// The resource version, learned from the running service as the doors
	// learn it in production (Identity 4.4 wires BecameReady to Stale).
	if r.version, err = door.NewResourceVersion(client, env.log); err != nil {
		t.Fatal(err)
	}
	r.version.Learn(t.Context())
	if _, known := r.version.Current(); !known {
		t.Fatal("the doors could not learn the identity service's resource version")
	}
	relay, err := env.DoorTransport()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(relay.CloseIdleConnections)
	r.home, r.app, err = door.Build(table, door.Shared{
		ConsoleOrigin: "https://" + ConsoleHost, Policy: pol, Throttle: r.th, Transport: relay,
		Upstream: env.KeycloakUpstream(), Theme: allow, Assets: os.DirFS(filepath.Join(theme, "login", "resources")), Version: r.version,
		InstallName: func(context.Context) (string, error) { return doorInstall, nil }, Dirty: r.drainer,
		IDs: func() string { return fmt.Sprintf("door-%d", r.ids.Add(1)) }, Log: env.log,
	})
	if err != nil {
		t.Fatal(err)
	}
	stub := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, stubPage)
	})
	r.sites, err = env.ServeDoors(r.recordCookies("home", r.home), r.recordCookies("app", r.app),
		consolePage("https://"+table.Home.Host+"/realms/rasputin/protocol/openid-connect/auth?"+doorAuthQuery(baselineConsole, "https://"+ConsoleHost, nil)), stub)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.drainer.Run(ctx); close(done) }()
	vdone := make(chan struct{})
	go func() { r.version.Run(ctx); close(vdone) }()
	t.Cleanup(func() { cancel(); <-done; <-vdone })
	r.setUpRealm(t)
	r.settle(t)
	return r
}

// admin is realm rasputin's Admin API with a fresh token.
func (r *doorRig) admin(t *testing.T) adminAPI {
	t.Helper()
	a, _ := baselineAdmin(t, r.env)
	return a
}

// callback is a client's redirect URI on the origin its door returns to.
func callbackOn(host string) string { return "https://" + host + callbackPath }

func (r *doorRig) setUpRealm(t *testing.T) {
	t.Helper()
	api := r.admin(t)
	_, out := api.must(http.StatusOK, http.MethodGet, "", nil)
	var realm map[string]any
	if err := json.Unmarshal(out, &realm); err != nil {
		t.Fatal(err)
	}
	put := map[string]any{"displayName": doorInstall, "registrationAllowed": true, "resetPasswordAllowed": true}
	for k, v := range realm {
		if strings.HasPrefix(k, "webAuthnPolicy") {
			put[k] = v
		}
	}
	put["webAuthnPolicyRpEntityName"] = doorInstall
	put["webAuthnPolicyPasswordlessRpEntityName"] = doorInstall
	put["webAuthnPolicyPasswordlessPasskeysEnabled"] = true
	api.must(http.StatusNoContent, http.MethodPut, "", put)
	for client, host := range map[string]string{
		baselineConsole: ConsoleHost, baselineMesh: ConsoleHost, "rasputin-reset-home": ConsoleHost,
		"rasputin-account": r.sites.Table.App.Host, "rasputin-reset-app": r.sites.Table.App.Host,
	} {
		id, rep := api.clientRep(client)
		rep["redirectUris"] = []string{callbackOn(host)}
		api.must(http.StatusNoContent, http.MethodPut, "/clients/"+id, rep)
	}
	api.must(http.StatusCreated, http.MethodPost, "/clients", map[string]any{
		"clientId": doorTestApp, "enabled": true, "publicClient": true, "protocol": "openid-connect",
		"standardFlowEnabled": true, "redirectUris": []string{callbackOn(AppSiteHost)},
		"attributes": map[string]string{"pkce.code.challenge.method": "S256"},
	})
}

// user creates a user with a full profile and a password and returns its id
// and password.
func (r *doorRig) user(t *testing.T, name string, actions ...string) (string, secret.Value) {
	t.Helper()
	pw, err := randomSecret(r.env.h.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pw.Destroy)
	loc, _ := r.admin(t).must(http.StatusCreated, http.MethodPost, "/users", map[string]any{
		"username": name, "enabled": true, "email": name + "@door.invalid", "emailVerified": true,
		"firstName": "Door", "lastName": "User", "requiredActions": append([]string{}, actions...),
		"credentials": []map[string]any{{"type": "password", "value": string(pw.Reveal()), "temporary": false}},
	})
	return loc[strings.LastIndex(loc, "/")+1:], pw
}

type bruteForce struct {
	Disabled    bool `json:"disabled"`
	NumFailures int  `json:"numFailures"`
}

func (r *doorRig) bruteForce(t *testing.T, userID string) bruteForce {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/attack-detection/brute-force/users/"+userID, nil)
	var bf bruteForce
	if err := json.Unmarshal(out, &bf); err != nil {
		t.Fatal(err)
	}
	return bf
}

// awaitFailures waits, on the fact itself, until userID's failure count
// reaches at least n (Keycloak records it on its own executor), bounded only
// by the test's context, and returns it.
func (r *doorRig) awaitFailures(t *testing.T, userID string, n int) bruteForce {
	t.Helper()
	for {
		bf := r.bruteForce(t, userID)
		if bf.NumFailures >= n {
			return bf
		}
		if t.Context().Err() != nil {
			t.Fatalf("the test ended before %s's failures reached %d: %+v", userID, n, bf)
		}
	}
}

// ---- the Go door client ----------------------------------------------------

// doorAuthQuery is an authorization request's query for client, its callback
// on host, with extra set over it ("" deletes).
func doorAuthQuery(client, callbackHost string, extra map[string]string) string {
	q := url.Values{"client_id": {client}, "redirect_uri": {callbackOn(strings.TrimPrefix(callbackHost, "https://"))},
		"response_type": {"code"}, "scope": {"openid"}, "state": {"door-state"}, "nonce": {"door-nonce"},
		"code_challenge": {doorChallenge}, "code_challenge_method": {"S256"}, "prompt": {"login"}}
	for k, v := range extra {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return q.Encode()
}

// goClient is a cookie-keeping Go client from one loopback address, which
// records every Set-Cookie it is sent.
type goClient struct {
	t    *testing.T
	c    *http.Client
	jar  *cookiejar.Jar
	mu   sync.Mutex
	sets []string
}

func (r *doorRig) client(t *testing.T, local string) *goClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	g := &goClient{t: t, jar: jar}
	g.c = r.sites.Client(netip.MustParseAddr(local), jar)
	return g
}

// doorAnswer is one response, its body read.
type doorAnswer struct {
	status int
	header http.Header
	body   []byte
	loc    *url.URL
	at     *url.URL
}

func (a doorAnswer) pageID() string {
	if m := pageIDRE.FindSubmatch(a.body); m != nil {
		return string(m[1])
	}
	return ""
}

// sentence is a door page's alert text, unescaped.
func (a doorAnswer) sentence() string {
	if m := alertRE.FindSubmatch(a.body); m != nil {
		return html.UnescapeString(string(m[1]))
	}
	return ""
}

var (
	pageIDRE = regexp.MustCompile(`data-page-id="([^"]+)"`)
	alertRE  = regexp.MustCompile(`<span class="rasp-alert-text">([^<]*)</span>`)
)

func (g *goClient) send(method, target string, form url.Values, hdr http.Header) doorAnswer {
	g.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(g.t.Context(), method, target, body)
	if err != nil {
		g.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if h := hdr.Get("Host"); h != "" {
		req.Host = h
	}
	resp, err := g.c.Do(req)
	if err != nil {
		g.t.Fatalf("%s %s: %v", method, redactURL(target), err)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if err != nil {
		g.t.Fatal(err)
	}
	g.mu.Lock()
	g.sets = append(g.sets, resp.Header.Values("Set-Cookie")...)
	g.mu.Unlock()
	a := doorAnswer{status: resp.StatusCode, header: resp.Header, body: b, at: req.URL}
	if l, err := resp.Location(); err == nil {
		a.loc = l
	}
	return a
}

func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "(unparsable)"
	}
	u.RawQuery = ""
	return u.String()
}

// follow GETs target and follows redirects until a page, or a redirect to a
// callback, which it returns as the answer with loc set.
func (g *goClient) follow(target string) doorAnswer {
	g.t.Helper()
	a := g.send(http.MethodGet, target, nil, nil)
	for range 12 {
		if a.status < 300 || a.status >= 400 || a.loc == nil || a.loc.Path == callbackPath {
			return a
		}
		a = g.send(http.MethodGet, a.at.ResolveReference(a.loc).String(), nil, nil)
	}
	g.t.Fatalf("too many redirects from %s", redactURL(target))
	return a
}

// submit posts the page's form id with fields set over its own, then follows.
func (g *goClient) submit(a doorAnswer, formID string, fields map[string]string) doorAnswer {
	g.t.Helper()
	form, action := g.form(a, formID)
	for k, v := range fields {
		form.Set(k, v)
	}
	b := g.send(http.MethodPost, action, form, nil)
	if b.status >= 300 && b.status < 400 && b.loc != nil && b.loc.Path != callbackPath {
		return g.follow(b.at.ResolveReference(b.loc).String())
	}
	return b
}

// form is the page's form id: its fields and its absolute action.
func (g *goClient) form(a doorAnswer, formID string) (url.Values, string) {
	g.t.Helper()
	re := regexp.MustCompile(`(?s)<form[^>]*id="` + regexp.QuoteMeta(formID) + `"[^>]*>(.*?)</form>`)
	m := re.FindSubmatch(a.body)
	if m == nil {
		g.t.Fatalf("the page %s has no form %s", a.pageID(), formID)
	}
	act := regexp.MustCompile(`action="([^"]*)"`).FindSubmatch(m[0])
	if act == nil {
		g.t.Fatalf("the form %s has no action", formID)
	}
	action, err := a.at.Parse(html.UnescapeString(string(act[1])))
	if err != nil {
		g.t.Fatal(err)
	}
	fields := url.Values{}
	for _, in := range regexp.MustCompile(`<input[^>]*>`).FindAll(m[1], -1) {
		name := regexp.MustCompile(`name="([^"]*)"`).FindSubmatch(in)
		if name == nil || bytes.Contains(in, []byte(`type="submit"`)) || bytes.Contains(in, []byte(`type="checkbox"`)) {
			continue
		}
		val := regexp.MustCompile(`value="([^"]*)"`).FindSubmatch(in)
		v := ""
		if val != nil {
			v = html.UnescapeString(string(val[1]))
		}
		if fields.Get(string(name[1])) == "" {
			fields.Set(string(name[1]), v)
		}
	}
	return fields, action.String()
}

// signIn is a password sign-in from the authorization request at target:
// the login page, then the form. It returns the answer to the post, followed.
func (g *goClient) signIn(target, user string, pw secret.Value) doorAnswer {
	g.t.Helper()
	a := g.follow(target)
	if a.pageID() != "login-login" {
		g.t.Fatalf("the sign-in reached %q (%d), want login-login", a.pageID(), a.status)
	}
	return g.submit(a, "kc-form-login", map[string]string{"username": user, "password": string(pw.Reveal())})
}

// code is a callback redirect's code, failing unless the answer is one with
// the request's state.
func (a doorAnswer) code(t *testing.T) string {
	t.Helper()
	if a.loc == nil || a.loc.Path != callbackPath || a.loc.Query().Get("state") != "door-state" || a.loc.Query().Get("code") == "" {
		t.Fatalf("not a callback with a code: %d %q, page %q %q", a.status, redactURL(fmt.Sprint(a.loc)), a.pageID(), a.sentence())
	}
	return a.loc.Query().Get("code")
}

// subOf exchanges a test app code at the app door and returns the ID token's
// subject.
func (r *doorRig) subOf(t *testing.T, g *goClient, code string) string {
	t.Helper()
	a := g.send(http.MethodPost, "https://"+r.sites.Table.App.Host+"/realms/rasputin/protocol/openid-connect/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {doorTestApp},
		"redirect_uri": {callbackOn(AppSiteHost)}, "code_verifier": {doorPKCE},
	}, nil)
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if a.status != http.StatusOK || json.Unmarshal(a.body, &tok) != nil || tok.IDToken == "" {
		t.Fatalf("the code exchange at the app door answered %d", a.status)
	}
	parts := strings.Split(tok.IDToken, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	return c.Sub
}

func (r *doorRig) homeURL(path string) string { return "https://" + r.sites.Table.Home.Host + path }
func (r *doorRig) appURL(path string) string  { return "https://" + r.sites.Table.App.Host + path }

func (r *doorRig) homeAuth(client string, extra map[string]string) string {
	return r.homeURL("/realms/rasputin/protocol/openid-connect/auth?" + doorAuthQuery(client, ConsoleHost, extra))
}

func (r *doorRig) appAuth(client string, extra map[string]string) string {
	cb := r.sites.Table.App.Host
	if client == doorTestApp {
		cb = AppSiteHost
	}
	return r.appURL("/realms/rasputin/protocol/openid-connect/auth?" + doorAuthQuery(client, cb, extra))
}

// homePolicy and appPolicy are the doors' exact relayed script policies;
// the app door's names the resource version the doors learned.
func homePolicy() string {
	return "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
}

func (r *doorRig) appPolicy() string {
	v := r.learned()
	host := r.sites.Table.App.Host
	return "script-src https://" + host + "/resources/" + v + "/login/rasputin/ https://" + host +
		"/resources/" + v + "/common/keycloak/; object-src 'none'; base-uri 'none'; frame-ancestors 'self'"
}

// learned is the resource version the doors learned.
func (r *doorRig) learned() string {
	v, _ := r.version.Current()
	return v
}

// ---- the test ----------------------------------------------------------------

func TestDoor_AgainstPinnedKeycloak(t *testing.T) {
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
	r := newDoorRig(t, env)
	browserCtx, _ := p.Browser(t)
	if browserCtx == nil {
		return
	}

	t.Run("TC-985-36 SO-5 forged forwarding never changes an issuer", func(t *testing.T) { r.so5(t) })
	t.Run("TC-985-37 SO-6 door binding", func(t *testing.T) { r.so6(t, browserCtx) })
	t.Run("TC-985-38 SO-10 script policy and framing", func(t *testing.T) { r.so10(t, browserCtx) })
	t.Run("TC-985-39 SO-11 and K-CSP through each door", func(t *testing.T) { r.so11(t, browserCtx) })
	t.Run("TC-985-40 SO-13 home door response shape and account creation", func(t *testing.T) { r.so13(t) })
	t.Run("TC-985-41 K-COOKIE", func(t *testing.T) { r.kCookie(t) })
	t.Run("TC-985-42 TS-26 a waiting address and the account", func(t *testing.T) { r.ts26(t, browserCtx) })
	t.Run("TC-985-43 the burst through the real door", func(t *testing.T) { r.burst(t) })
	t.Run("TC-985-44 K-EVENTS", func(t *testing.T) { r.kEvents(t) })
	t.Run("TC-985-45 TC-1127-15 through both doors", func(t *testing.T) { r.floods(t) })
}

// TC-985-36: forged Host, X-Forwarded-Host, -Port, -Prefix and Forwarded
// leave each door's discovery issuer exactly the door table's.
func (r *doorRig) so5(t *testing.T) {
	g := r.client(t, "127.0.0.11")
	for _, d := range []struct{ host, issuer string }{
		{r.sites.Table.Home.Host, r.sites.Table.Home.Issuer}, {r.sites.Table.App.Host, r.sites.Table.App.Issuer},
	} {
		for name, hdr := range map[string]http.Header{
			"none":               nil,
			"Host":               {"Host": {"evil.example:8443"}},
			"X-Forwarded-Host":   {"X-Forwarded-Host": {"evil.example"}},
			"X-Forwarded-Port":   {"X-Forwarded-Port": {"8443"}},
			"X-Forwarded-Prefix": {"X-Forwarded-Prefix": {"/evil"}},
			"Forwarded":          {"Forwarded": {"for=6.6.6.6;host=evil.example;proto=http"}},
		} {
			a := g.send(http.MethodGet, "https://"+d.host+"/realms/rasputin/.well-known/openid-configuration", nil, hdr)
			var disc struct {
				Issuer string `json:"issuer"`
			}
			if a.status != http.StatusOK || json.Unmarshal(a.body, &disc) != nil {
				t.Fatalf("%s %s: discovery answered %d", d.host, name, a.status)
			}
			if disc.Issuer != d.issuer || strings.Contains(disc.Issuer, ":443") {
				t.Errorf("%s with forged %s: issuer %q, want exactly %q", d.host, name, disc.Issuer, d.issuer)
			}
		}
	}
}

// doorPage opens u in a fresh tab and returns the tab, its page id, the
// document's status and its alert sentence.
func doorPage(t *testing.T, browserCtx context.Context, origin, u string) (*tab, string, int64, string) {
	t.Helper()
	tb := newTab(t, browserCtx, origin)
	m := tb.mark()
	id := tb.navigate(u)
	var status int64
	reqs, _ := tb.since(m)
	for _, rq := range reqs {
		if rq.document {
			status = rq.status
		}
	}
	text := evalT[string](tb, `(document.querySelector('.rasp-alert-text') || {}).textContent || ''`)
	return tb, id, status, text
}

// TC-985-37: a client at the wrong door, a missing or repeated client_id,
// registration at the app door or from a tailnet address, each refused with
// a sentence.
func (r *doorRig) so6(t *testing.T, browserCtx context.Context) {
	home, app := "https://"+r.sites.Table.Home.Host, "https://"+r.sites.Table.App.Host
	for what, c := range map[string]struct{ origin, u string }{
		"rasputin-mesh at the app door":  {app, r.appAuth(baselineMesh, nil)},
		"an app client at the home door": {home, r.homeURL("/realms/rasputin/protocol/openid-connect/auth?" + doorAuthQuery(doorTestApp, AppSiteHost, nil))},
		"no client_id":                   {home, r.homeAuth(baselineConsole, map[string]string{"client_id": ""})},
		"a repeated client_id":           {home, r.homeAuth(baselineConsole, nil) + "&client_id=" + baselineConsole},
	} {
		_, id, status, text := doorPage(t, browserCtx, c.origin, c.u)
		if id != "rasputin-door-refusal" || status != http.StatusBadRequest || !isDoorSentence(text) {
			t.Errorf("%s: page %q, status %d, %q; want the 400 refusal with a sentence", what, id, status, text)
		}
	}
	_, id, status, _ := doorPage(t, browserCtx, app, r.appURL("/realms/rasputin/protocol/openid-connect/registrations?"+doorAuthQuery(baselineConsole, ConsoleHost, map[string]string{"prompt": "create"})))
	if id != "rasputin-door-refusal" || status != http.StatusNotFound {
		t.Errorf("registration at the app door: page %q, status %d; want the 404 door page", id, status)
	}
	g := r.client(t, "127.0.0.65")
	a := g.follow(r.homeAuth(baselineConsole, map[string]string{"prompt": "create"}))
	if a.status != http.StatusForbidden || !isDoorSentence(a.sentence()) {
		t.Errorf("registration from a tailnet address: %d %q, want 403 with a sentence", a.status, a.sentence())
	}
}

func isDoorSentence(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && s[0] >= 'A' && s[0] <= 'Z' && strings.HasSuffix(s, ".")
}

// TC-985-38: with a console session in the same browser, a home-door page
// carries 'self' and no framing, the console cannot frame it, no console
// cookie reaches it, the app door's page names its two theme paths, and the
// other bundles answer 404 at both doors.
func (r *doorRig) so10(t *testing.T, browserCtx context.Context) {
	tb := newTab(t, browserCtx, "https://"+ConsoleHost)
	m := tb.mark()
	if id := tb.navigate("https://" + ConsoleHost + "/"); id != "rasputin-console" {
		t.Fatalf("the console page is %q", id)
	}
	// The page's load event waited for its frame. ci.local and sso-ci.local
	// are two sites, so under site isolation the frame can live in a process
	// and a target of its own, which the page's frame tree does not list: the
	// frames are the tree's children and the tab's iframe targets together.
	if n := evalT[int](tb, `document.querySelectorAll('iframe#framed').length`); n != 1 {
		t.Fatalf("the console page holds %d frame elements, want its one", n)
	}
	frames, framed, errs := r.consoleFrames(t, tb, m)
	if framed {
		t.Errorf("the console framed the home door's page: its frames %q (console log %q)", frames, errs)
	}
	// The block itself, positively: the browser blocked the home door's page
	// in the frame for its frame-ancestors, and says so in the embedding
	// page's console ("Framing 'https://sso-ci.local/' violates the following
	// Content Security Policy directive: "frame-ancestors 'none'". The
	// request has been blocked.", in the pinned Chrome's words).
	refused := slices.ContainsFunc(errs, func(e string) bool {
		return strings.Contains(e, r.sites.Table.Home.Host) && strings.Contains(e, "frame-ancestors 'none'") &&
			(strings.Contains(e, "has been blocked") || strings.Contains(e, "Refused to frame"))
	})
	if !refused {
		t.Errorf("the browser did not refuse the console's frame of the home door for its frame-ancestors: frames %q, console log %q", frames, errs)
	}
	t.Logf("the console's frames %q; refused by frame-ancestors: %v", frames, refused)
	tb.navigate(r.homeAuth(baselineConsole, nil))
	r.cookiesMu.Lock()
	for _, c := range r.cookiesIn["home"] {
		if strings.Contains(c, "rasputin-session") {
			t.Errorf("a console cookie reached the home door: %q", c)
		}
	}
	r.cookiesMu.Unlock()

	g := r.client(t, "127.0.0.12")
	a := g.follow(r.homeAuth(baselineConsole, nil))
	if csp := a.header.Values("Content-Security-Policy"); len(csp) != 1 || csp[0] != homePolicy() {
		t.Errorf("the home door's sign-in page CSP %q, want %q", csp, homePolicy())
	}
	b := g.follow(r.appAuth("rasputin-account", nil))
	if csp := b.header.Values("Content-Security-Policy"); len(csp) != 1 || csp[0] != r.appPolicy() {
		t.Errorf("the app door's sign-in page CSP %q, want %q", csp, r.appPolicy())
	}
	for _, host := range []string{r.sites.Table.Home.Host, r.sites.Table.App.Host} {
		for _, p := range []string{"/resources/" + r.learned() + "/admin/keycloak.v2/main.js",
			"/resources/" + r.learned() + "/account/keycloak.v3/main.js", "/resources/rasputin/login/en"} {
			if a := g.send(http.MethodGet, "https://"+host+p, nil, nil); a.status != http.StatusNotFound {
				t.Errorf("%s%s answered %d, want 404", host, p, a.status)
			}
		}
	}
}

// consoleFrames are the frames the console page holds, in its own process
// (its frame tree) and out of it (the tab's iframe targets), whether one in
// its tree committed the home door's own page, and the console log since m.
// An out-of-process frame's target URL is the address it was sent to, which
// a blocked frame keeps too, so the block is read from the console log.
func (r *doorRig) consoleFrames(t *testing.T, tb *tab, m mark) ([]string, bool, []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer cancel()
	tree, err := chromedp.Call(ctx, page.GetFrameTree, cdp.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	var frames []string
	framed := false
	home := "https://" + r.sites.Table.Home.Host + "/"
	for _, c := range tree.FrameTree.ChildFrames {
		frames = append(frames, "frame "+redactURL(c.Frame.URL)+" unreachable "+redactURL(c.Frame.UnreachableURL))
		framed = framed || (strings.HasPrefix(c.Frame.URL, home) && c.Frame.UnreachableURL == "")
	}
	targets, err := chromedp.Call(ctx, target.GetTargets, target.GetTargetsParams{Filter: target.Filter{{Type: "iframe"}}})
	if err != nil {
		t.Fatal(err)
	}
	bc := chromedp.FromContext(tb.ctx).BrowserContextID
	for _, ti := range targets.TargetInfos {
		if ti.Type == "iframe" && ti.BrowserContextID == bc {
			frames = append(frames, "target "+redactURL(ti.URL))
		}
	}
	_, errs := tb.since(m)
	return frames, framed, errs
}

// violationSpy reports each securitypolicyviolation through an exposed
// binding, before any page script runs.
const violationSpy = `document.addEventListener('securitypolicyviolation', (e) => {
  try { window.rasputinCSPViolation(e.violatedDirective + ' ' + e.blockedURI); } catch (x) {}
});`

var resourceVersionRE = regexp.MustCompile(`/resources/([^/]+)/(login|common)/`)

// TC-985-39: the theme's pages through each door: every response class's
// headers, no inline script, no policy violation in the walk, the resource
// version the live server serves, and no /resources/ redirect.
func (r *doorRig) so11(t *testing.T, browserCtx context.Context) {
	// r.user returns the user's id; the sign-in is by name.
	const name = "door-walk"
	_, pw := r.user(t, name)
	for _, d := range []struct {
		host, client, reset, policy string
	}{
		{r.sites.Table.Home.Host, baselineConsole, "rasputin-reset-home", homePolicy()},
		{r.sites.Table.App.Host, "rasputin-account", "rasputin-reset-app", r.appPolicy()},
	} {
		origin := "https://" + d.host
		callbackHost := ConsoleHost
		if d.host == r.sites.Table.App.Host {
			callbackHost = d.host
		}
		auth := origin + "/realms/rasputin/protocol/openid-connect/auth?" + doorAuthQuery(d.client, callbackHost, nil)
		pages := map[string]string{
			"login-login":                auth,
			"login-login-reset-password": origin + "/realms/rasputin/login-actions/reset-credentials?client_id=" + d.reset,
			"login-error":                origin + "/realms/rasputin/protocol/openid-connect/auth?" + doorAuthQuery(d.client, callbackHost, map[string]string{"redirect_uri": "https://elsewhere.invalid/cb"}),
			"login-logout-confirm":       origin + "/realms/rasputin/protocol/openid-connect/logout?client_id=" + d.client,
		}
		if d.client == baselineConsole {
			pages["login-register"] = origin + "/realms/rasputin/protocol/openid-connect/auth?" + doorAuthQuery(d.client, callbackHost, map[string]string{"prompt": "create"})
		}
		var violations []string
		var vmu sync.Mutex
		tb := newTab(t, browserCtx, origin)
		tb.step(chromedp.ExposeFunc("rasputinCSPViolation", func(_ context.Context, v string) (bool, error) {
			vmu.Lock()
			violations = append(violations, v)
			vmu.Unlock()
			return true, nil
		}), "expose the violation spy")
		ctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
		if _, err := chromedp.Call(ctx, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{Source: violationSpy}); err != nil {
			t.Fatal(err)
		}
		cancel()
		m := tb.mark()
		for want, u := range pages {
			if id := tb.navigate(u); id != want {
				t.Errorf("%s: %s opened %q, want %q", d.host, redactURL(u), id, want)
			}
			r.auditPage(t, tb, d.host, d.policy)
		}
		// A full sign-in through the door, to its client's callback.
		r.settle(t)
		tb.navigate(auth)
		if id := tb.fillAndSubmit(map[string]string{"username": name, "password": string(pw.Reveal())}, "#kc-login"); id != "rasputin-stub" {
			t.Errorf("%s: the sign-in led to %q, want the client's callback", d.host, id)
		}
		reqs, errs := tb.since(m)
		for _, e := range errs {
			if strings.Contains(e, "Content Security Policy") || strings.Contains(e, "Refused to") {
				t.Errorf("%s: the console shows %s", d.host, e)
			}
		}
		served := map[string]bool{}
		for _, rq := range reqs {
			u, err := url.Parse(rq.url)
			if err != nil || !strings.HasPrefix(u.Path, "/resources/") {
				continue
			}
			if mm := resourceVersionRE.FindStringSubmatch(u.Path); mm != nil {
				served[mm[1]] = true
			}
			if rq.status >= 300 && rq.status < 400 {
				t.Errorf("%s: %s answered a redirect %d", d.host, u.Path, rq.status)
			}
		}
		// K-CSP: the version the doors learned is the one the live server
		// writes into its pages.
		if len(served) != 1 || !served[r.learned()] {
			t.Errorf("%s: the pages loaded theme files under the versions %v, want only %s, the version the doors learned (K-CSP)", d.host, served, r.learned())
		}
		vmu.Lock()
		if len(violations) != 0 {
			t.Errorf("%s: %d policy violations in the walk: %q", d.host, len(violations), violations)
		}
		vmu.Unlock()
	}
	r.themeWalks(t, browserCtx)
}

// themeWalks runs #988's theme walk through each door (TC-985-39): every
// page it renders, under that door's script policy, held to TC-988-18's
// checks, which fail on a console error, a policy violation among them. A
// door serves only its own clients, so each door walks the pages its
// clients reach; together they render every page the walk does at the
// front, but delete-credential, which a door refuses outright
// (signin-origin.md §5.2).
func (r *doorRig) themeWalks(t *testing.T, browserCtx context.Context) {
	table, err := buildPageTable(coverageTemplates(t))
	if err != nil {
		t.Fatal(err)
	}
	var allow resourceAllowlist
	b, err := os.ReadFile(filepath.Join(r.env.h.cfg.ThemeDir, "resource-allowlist.json"))
	if err != nil || json.Unmarshal(b, &allow) != nil {
		t.Fatalf("the built theme's resource-allowlist.json: %v", err)
	}
	seen := map[string]bool{}
	words := loadForbiddenWords(t)
	console := "https://" + ConsoleHost
	for _, d := range []struct {
		name string
		host string
		via  walkVia
		run  []string
	}{
		{"home door", r.sites.Table.Home.Host, walkVia{
			authExtra: url.Values{"prompt": {"login"}}, signInClient: baselineConsole, resetClient: "rasputin-reset-home",
			clients: []string{baselineConsole, baselineMesh}, missingClients: []string{baselineConsole}, prefix: "home-",
		}, []string{"links", "missing", "other", "required", "passkeys"}},
		{"app door", r.sites.Table.App.Host, walkVia{
			signInClient: "rasputin-account", resetClient: "rasputin-reset-app",
			clients: []string{"rasputin-account", appClient, otherApp}, missingClients: []string{appClient}, prefix: "app-",
		}, []string{"links", "missing", "other", "required", "profile", "passkeys", "saml"}},
	} {
		front := "https://" + d.host
		d.via.door = true
		d.via.frontChannel = front + callbackPath
		d.via.beforeSubmit = r.settle
		w := &walk{
			env: r.env, front: front, words: words, allow: allow, table: table, seen: seen,
			admin: func(t *testing.T) adminAPI { a, _ := baselineAdmin(t, r.env); a.t = t; return a },
			attrs: map[string]string{
				"rasputin.console-url":    console,
				"rasputin.reset-home-url": console + "/reset-home",
				"rasputin.reset-app-url":  "https://" + r.sites.Table.App.Host + "/reset-app",
			},
			via: d.via,
		}
		w.setUp(t)
		steps := map[string]func(*testing.T){
			"links":    func(t *testing.T) { w.linksPerClient(t, browserCtx) },
			"missing":  func(t *testing.T) { w.missingAttributes(t, browserCtx) },
			"other":    func(t *testing.T) { w.otherDoorPages(t, browserCtx) },
			"required": func(t *testing.T) { w.requiredActions(t, browserCtx) },
			"profile":  func(t *testing.T) { w.profileAndFrontChannel(t, browserCtx) },
			"passkeys": func(t *testing.T) { w.passkeys(t, browserCtx) },
			"saml":     func(t *testing.T) { w.saml(t, browserCtx) },
		}
		for _, step := range d.run {
			t.Run(d.name+" "+step, steps[step])
		}
	}
	var missed []string
	for _, id := range walkedPages {
		if id != "login-delete-credential" && !seen[id] {
			missed = append(missed, id)
		}
	}
	if len(missed) > 0 && !t.Failed() {
		t.Errorf("the walks through the doors never rendered %v", missed)
	}
}

// auditPage checks the shown page and fetches its address again with a Go
// client for its raw headers.
func (r *doorRig) auditPage(t *testing.T, tb *tab, host, policy string) {
	t.Helper()
	inline := evalT[int](tb, `document.querySelectorAll('script:not([src])').length + [...document.querySelectorAll('*')].filter((e) => [...e.attributes].some((a) => a.name.startsWith('on'))).length`)
	if inline != 0 {
		t.Errorf("%s %s: %d inline scripts or handlers", host, tb.pageID(), inline)
	}
	u := evalT[string](tb, `location.href`)
	if strings.Contains(u, callbackPath) {
		return
	}
	g := r.client(t, "127.0.0.13")
	a := g.send(http.MethodGet, u, nil, nil)
	h := a.header
	if v := h.Values("Content-Security-Policy"); len(v) != 1 || (v[0] != policy && !strings.HasPrefix(v[0], "script-src 'none'")) {
		t.Errorf("%s %s: CSP %q, want exactly one, the door's", host, redactURL(u), v)
	}
	if len(h.Values("X-Frame-Options")) > 1 || h.Get("Strict-Transport-Security") != "" || h.Get("Alt-Svc") != "" ||
		h.Get("Content-Security-Policy-Report-Only") != "" {
		t.Errorf("%s %s: headers %v", host, redactURL(u), h)
	}
}

// TC-985-40: the home door refuses form_post, a request object and an
// authorization request without prompt=login; account creation with
// prompt=create completes with the single-sign-on cookies stripped and
// resumes no session.
func (r *doorRig) so13(t *testing.T) {
	g := r.client(t, "127.0.0.14")
	for name, extra := range map[string]map[string]string{
		"form_post": {"response_mode": "form_post"}, "a request object": {"request": "eyJhbGciOiJub25lIn0.e30."},
		"no prompt": {"prompt": ""}, "prompt=none": {"prompt": "none"},
	} {
		if a := g.send(http.MethodGet, r.homeAuth(baselineConsole, extra), nil, nil); a.status != http.StatusBadRequest {
			t.Errorf("%s at the home door answered %d, want 400", name, a.status)
		}
	}
	// A session for another person in the same jar first.
	otherID, otherPW := r.user(t, "door-so13-other")
	r.settle(t)
	g.signIn(r.homeAuth(baselineConsole, nil), "door-so13-other", otherPW).code(t)
	before := r.sessionCount(t, otherID)

	a := g.follow(r.homeAuth(baselineConsole, map[string]string{"prompt": "create"}))
	if a.pageID() != "login-register" {
		t.Fatalf("prompt=create opened %q (%d), want login-register", a.pageID(), a.status)
	}
	pw, err := randomSecret(r.env.h.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Destroy()
	r.settle(t)
	done := g.submit(a, "kc-register-form", map[string]string{
		"username": "door-so13-new", "email": "door-so13-new@door.invalid", "firstName": "New", "lastName": "Person",
		"password": string(pw.Reveal()), "password-confirm": string(pw.Reveal()),
	})
	done.code(t)
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users?exact=true&username=door-so13-new", nil)
	var users []struct{ ID string }
	if err := json.Unmarshal(out, &users); err != nil || len(users) != 1 {
		t.Fatalf("the new account: %v", err)
	}
	if n := r.sessionCount(t, users[0].ID); n != 1 {
		t.Errorf("the new account has %d sessions, want 1", n)
	}
	if after := r.sessionCount(t, otherID); after != before {
		t.Errorf("the other person's sessions went from %d to %d: the registration resumed a session", before, after)
	}
}

func (r *doorRig) sessionCount(t *testing.T, userID string) int {
	t.Helper()
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+userID+"/sessions", nil)
	var s []json.RawMessage
	if err := json.Unmarshal(out, &s); err != nil {
		t.Fatal(err)
	}
	return len(s)
}

// identityOf is the jar's KEYCLOAK_IDENTITY value for host, under either
// name.
func identityOf(jar *cookiejar.Jar, host string) string {
	u := &url.URL{Scheme: "https", Host: host, Path: "/realms/rasputin/"}
	for _, c := range jar.Cookies(u) {
		if c.Name == "KEYCLOAK_IDENTITY" || c.Name == "__Host-KEYCLOAK_IDENTITY" {
			return c.Value
		}
	}
	return ""
}

// TC-985-41: a cookie tossed from a sibling app site or another port of the
// home door's host signs nobody in and locks nobody out, with and without a
// door session; the app door's Set-Cookie inventory carries the five as
// __Host-; an issued kc_action with prompt=login completes at the home door.
func (r *doorRig) kCookie(t *testing.T) {
	victimID, victimPW := r.user(t, "door-victim")
	_, attackerPW := r.user(t, "door-attacker")
	app := r.sites.Table.App.Host

	// The attacker's own session at the app door, whose identity cookie it
	// tosses.
	attacker := r.client(t, "127.0.0.21")
	r.settle(t)
	attacker.signIn(r.appAuth(doorTestApp, map[string]string{"prompt": ""}), "door-attacker", attackerPW).code(t)
	tossed := identityOf(attacker.jar, app)
	if tossed == "" {
		t.Fatal("the attacker holds no identity cookie at the app door")
	}
	toss := func(g *goClient) {
		g.jar.SetCookies(&url.URL{Scheme: "https", Host: AppSiteHost, Path: "/"}, []*http.Cookie{
			{Name: "KEYCLOAK_IDENTITY", Value: tossed, Domain: "ci.internal", Path: "/", Secure: true},
			{Name: "AUTH_SESSION_ID", Value: "tossed", Domain: "ci.internal", Path: "/", Secure: true},
		})
	}
	// Without a session: the tossed cookie signs nobody in.
	v := r.client(t, "127.0.0.22")
	toss(v)
	if a := v.follow(r.appAuth(doorTestApp, map[string]string{"prompt": ""})); a.pageID() != "login-login" {
		t.Errorf("a visitor with only a tossed identity cookie reached %q (%d), want the sign-in page", a.pageID(), a.status)
	}
	// With the victim's own session: the victim, not the attacker.
	r.settle(t)
	signed := v.signIn(r.appAuth(doorTestApp, map[string]string{"prompt": ""}), "door-victim", victimPW)
	if sub := r.subOf(t, v, signed.code(t)); sub != victimID {
		t.Errorf("the victim's sign-in with a tossed cookie present signed in %q, want the victim %q", sub, victimID)
	}
	toss(v)
	again := v.follow(r.appAuth(doorTestApp, map[string]string{"prompt": ""}))
	if sub := r.subOf(t, v, again.code(t)); sub != victimID {
		t.Errorf("a resumed session after a toss is %q, want the victim %q", sub, victimID)
	}
	// The inventory of a full app-door sign-in.
	v.mu.Lock()
	sets := append([]string(nil), v.sets...)
	v.mu.Unlock()
	seen := map[string]bool{}
	for _, l := range sets {
		c, err := http.ParseSetCookie(l)
		if err != nil {
			continue
		}
		seen[c.Name] = true
		for _, n := range []string{"KEYCLOAK_IDENTITY", "AUTH_SESSION_ID", "KC_RESTART", "KEYCLOAK_REMEMBER_ME", "KEYCLOAK_LOCALE"} {
			if c.Name == n {
				t.Errorf("the app door sent %s unprefixed", n)
			}
			if c.Name == "__Host-"+n && (c.Path != "/" || !c.Secure || c.Domain != "") {
				t.Errorf("the app door sent %s as %+v", c.Name, c)
			}
		}
	}
	if !seen["__Host-AUTH_SESSION_ID"] || !seen["__Host-KEYCLOAK_IDENTITY"] {
		t.Errorf("the app door's Set-Cookie inventory %v lacks __Host-AUTH_SESSION_ID or __Host-KEYCLOAK_IDENTITY", seen)
	}

	// The home door: a cookie tossed from another port of sso-ci.local, with
	// and without a session.
	homeHost := r.sites.Table.Home.Host
	ha := r.client(t, "127.0.0.23")
	r.settle(t)
	ha.signIn(r.homeAuth(baselineConsole, nil), "door-attacker", attackerPW).code(t)
	homeTossed := identityOf(ha.jar, homeHost)
	hv := r.client(t, "127.0.0.24")
	hv.jar.SetCookies(&url.URL{Scheme: "https", Host: homeHost, Path: "/"}, []*http.Cookie{
		{Name: "KEYCLOAK_IDENTITY", Value: homeTossed, Path: "/realms/rasputin/", Secure: true},
		{Name: "KEYCLOAK_SESSION", Value: "tossed", Path: "/realms/rasputin/", Secure: true},
	})
	if a := hv.follow(r.homeAuth(baselineConsole, nil)); a.pageID() != "login-login" {
		t.Errorf("at the home door a tossed identity cookie reached %q, want the sign-in page", a.pageID())
	}
	r.settle(t)
	hv.signIn(r.homeAuth(baselineConsole, nil), "door-victim", victimPW).code(t)

	// An application-initiated action the launcher issued, at the home door,
	// with prompt=login and no single-sign-on cookie upstream.
	r.actions.issued.Store(true)
	defer r.actions.issued.Store(false)
	newPW, err := randomSecret(r.env.h.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	defer newPW.Destroy()
	aia := r.client(t, "127.0.0.25")
	r.settle(t)
	step := aia.signIn(r.homeAuth(baselineConsole, map[string]string{"kc_action": "UPDATE_PASSWORD"}), "door-victim", victimPW)
	if step.pageID() != "login-login-update-password" {
		t.Fatalf("the issued action led to %q (%d), want login-update-password", step.pageID(), step.status)
	}
	aia.submit(step, "kc-passwd-update-form", map[string]string{"password-new": string(newPW.Reveal()), "password-confirm": string(newPW.Reveal())}).code(t)
}

// credentialPost posts the sign-in form on a with password and returns the
// answer, unfollowed.
func (g *goClient) credentialPost(a doorAnswer, user, password string) doorAnswer {
	g.t.Helper()
	form, action := g.form(a, "kc-form-login")
	form.Set("username", user)
	form.Set("password", password)
	return g.send(http.MethodPost, action, form, nil)
}

// TC-985-42: failures from 127.0.0.1 until it waits; the account then signs
// in by password from 127.0.0.2, and by passkey from 127.0.0.1 during its
// wait; it is never disabled.
func (r *doorRig) ts26(t *testing.T, browserCtx context.Context) {
	const name = "door-ts26"
	id, pw := r.user(t, name, "webauthn-register-passwordless")
	homeOrigin := "https://" + r.sites.Table.Home.Host

	// A passkey for the account, registered in the browser at the home door.
	tb := newTab(t, browserCtx, homeOrigin)
	ctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	if _, err := chromedp.Call(ctx, webauthn.Enable, webauthn.EnableParams{EnableUI: new(false)}); err != nil {
		t.Fatal(err)
	}
	cancel()
	auth := addAuthenticator(t, tb, webauthn.AuthenticatorTransportInternal)
	r.settle(t)
	tb.navigate(r.homeAuth(baselineConsole, nil))
	if got := signIn(tb, name, pw); got != "login-webauthn-register" {
		t.Fatalf("the passkey required action led to %q", got)
	}
	tb.step(chromedp.SetValue(chromedp.ID("rasputin-passkey-name"), "Door laptop"), "type the NAME")
	if got := tb.submit(chromedp.Click(chromedp.ID("rasputin-passkey-this-device")), "register the passkey"); got != "rasputin-stub" {
		t.Fatalf("registering the passkey led to %q", got)
	}

	// Wrong passwords from 127.0.0.1, one at a time, until it waits: the
	// fourth failure from an address sets its first wait (D22), so it waits
	// after at most four. The browser shares 127.0.0.1, so an earlier case's
	// failure there counts too.
	g := r.client(t, "127.0.0.1")
	page := g.follow(r.homeAuth(baselineConsole, nil))
	waiting := false
	for i := 0; i <= 4 && !waiting; i++ {
		r.settle(t)
		a := g.credentialPost(page, name, "wrong-"+fmt.Sprint(i))
		switch {
		case a.status == http.StatusTooManyRequests && i > 0:
			waiting = true
		case a.status != http.StatusOK || a.pageID() != "login-login":
			t.Fatalf("wrong password %d answered %d %q", i+1, a.status, a.pageID())
		default:
			page = a
		}
	}
	if !waiting {
		t.Fatal("127.0.0.1 was not waiting after four wrong passwords")
	}
	r.settle(t)
	a := g.credentialPost(page, name, string(pw.Reveal()))
	if a.status != http.StatusTooManyRequests || a.header.Get("Retry-After") == "" {
		t.Fatalf("the right password from the waiting address answered %d (Retry-After %q), want 429", a.status, a.header.Get("Retry-After"))
	}
	// The account from another address.
	r.client(t, "127.0.0.2").signIn(r.homeAuth(baselineConsole, nil), name, pw).code(t)
	// A passkey from the waiting address.
	m := tb.mark()
	got := openForPasskey(t, tb, auth, r.homeAuth(baselineConsole, nil))
	if got == "login-login" {
		got = pressPasskey(t, tb, auth)
	}
	if got != "rasputin-stub" {
		_, errs := tb.since(m)
		t.Fatalf("a passkey sign-in from the waiting address led to %q (%v)", got, errs)
	}
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "/users/"+id, nil)
	var u struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(out, &u); err != nil || !u.Enabled {
		t.Errorf("the account is not enabled: %s", out)
	}
	if bf := r.bruteForce(t, id); bf.Disabled {
		t.Errorf("attack detection holds the account: %+v", bf)
	}
}

// TC-985-43: fifty parallel wrong passwords from one address through each
// door leave at most 4 failures, and the account usable from another
// address.
func (r *doorRig) burst(t *testing.T) {
	id, pw := r.user(t, "door-burst")
	for _, d := range []struct {
		auth, local string
	}{{r.homeAuth(baselineConsole, nil), "127.0.0.31"}, {r.appAuth("rasputin-account", nil), "127.0.0.32"}} {
		g := r.client(t, d.local)
		page := g.follow(d.auth)
		var wg sync.WaitGroup
		statuses := make([]int, 50)
		for i := range statuses {
			wg.Add(1)
			go func() {
				defer wg.Done()
				statuses[i] = g.credentialPost(page, "door-burst", "wrong").status
			}()
		}
		wg.Wait()
		forwarded := 0
		for _, s := range statuses {
			if s != http.StatusTooManyRequests {
				forwarded++
			}
		}
		t.Logf("%s: %d of 50 posts reached the identity service", d.local, forwarded)
	}
	bf := r.awaitFailures(t, id, 1)
	r.settle(t)
	if bf = r.bruteForce(t, id); bf.NumFailures > 4 || bf.Disabled {
		t.Errorf("after the bursts: %+v, want at most 4 failures and not held", bf)
	}
	r.client(t, "127.0.0.33").signIn(r.homeAuth(baselineConsole, nil), "door-burst", pw).code(t)
}

// TC-985-44: a wrong password through each door stores a LOGIN_ERROR whose
// ipAddress is the address the door wrote; events come newest first; more
// than 100 events, some in one millisecond, page with first and max and each
// id reaches the drain's sink once.
func (r *doorRig) kEvents(t *testing.T) {
	_, _ = r.user(t, "door-events")
	for _, d := range []struct {
		auth, local, client string
	}{{r.homeAuth(baselineConsole, nil), "127.0.0.41", baselineConsole}, {r.appAuth("rasputin-account", nil), "127.0.0.42", "rasputin-account"}} {
		g := r.client(t, d.local)
		page := g.follow(d.auth)
		r.settle(t)
		g.credentialPost(page, "door-events", "wrong")
		r.settle(t)
		found := false
		for _, e := range r.sink.all() {
			if e.Type == "LOGIN_ERROR" && e.ClientID == d.client && e.IP == netip.MustParseAddr(d.local) {
				found = true
			}
		}
		if !found {
			t.Errorf("no LOGIN_ERROR for %s with ipAddress %s reached the drain", d.client, d.local)
		}
	}
	// 120 failed code exchanges straight to the identity service, so the
	// throttle is not in their way; each stores one error event.
	start := time.Now().Add(-time.Second).UnixMilli()
	direct := &http.Client{Transport: &http.Transport{TLSClientConfig: r.env.ClientTLS()}}
	t.Cleanup(direct.CloseIdleConnections)
	var wg sync.WaitGroup
	for range 120 {
		wg.Add(1)
		// Each is open on the drain's signal while it runs, as every request
		// the doors relay is: these bypass the doors.
		end := r.drainer.Begin()
		go func() {
			defer wg.Done()
			defer end()
			form := url.Values{"grant_type": {"authorization_code"}, "code": {"not-a-code"}, "client_id": {doorTestApp},
				"redirect_uri": {callbackOn(AppSiteHost)}}
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, r.env.KeycloakURL()+"/realms/rasputin/protocol/openid-connect/token",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if resp, err := direct.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	// The test's own Admin API token is minted before the drain settles: its
	// client_credentials login stores a CLIENT_LOGIN event (saved by
	// default at 26.8.2), which the settle's pass then takes. Its reads below
	// store nothing.
	api := r.admin(t)
	r.settle(t)
	// The stored events, read page by page.
	type stored struct {
		ID   string `json:"id"`
		Time int64  `json:"time"`
		Type string `json:"type"`
	}
	var all []stored
	for first := 0; ; first += 100 {
		_, out := api.must(http.StatusOK, http.MethodGet, fmt.Sprintf("/events?first=%d&max=100", first), nil)
		var pageOf []stored
		if err := json.Unmarshal(out, &pageOf); err != nil {
			t.Fatal(err)
		}
		all = append(all, pageOf...)
		if len(pageOf) < 100 {
			break
		}
	}
	for i := 1; i < len(all); i++ {
		if all[i].Time > all[i-1].Time {
			t.Fatalf("events are not newest first at %d: %d after %d", i, all[i].Time, all[i-1].Time)
		}
	}
	delivered := map[string]int{}
	for _, e := range r.sink.all() {
		delivered[e.ID]++
	}
	recent, sameMS := 0, 0
	for i, e := range all {
		if e.Time < start {
			continue
		}
		recent++
		if e.ID == "" {
			t.Fatal("a stored event carries no id")
		}
		if n := delivered[e.ID]; n != 1 {
			t.Errorf("event %s (%s at %d) reached the sink %d times, want once", e.ID, e.Type, e.Time, n)
		}
		if i > 0 && all[i-1].Time == e.Time {
			sameMS++
		}
	}
	if recent <= 100 {
		t.Fatalf("%d events stored since the start, want more than 100 so the drain pages", recent)
	}
	t.Logf("K-EVENTS: %d recent events over %d pages, %d sharing a millisecond with the one before", recent, len(all)/100+1, sameMS)
}

// TC-985-45: TC-1127-15's floods through each real door leave
// service-account-rasputin-admin with no failure, while a control user's one
// wrong password reads 1.
func (r *doorRig) floods(t *testing.T) {
	n := baselineFailureFactor(t) + 1
	bogus, err := randomSecret(r.env.h.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	defer bogus.Destroy()
	wrong, err := randomSecret(r.env.h.cfg.Rand)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Destroy()
	controlID, _ := r.user(t, "door-control")
	sentence := "This account can't sign in here. Sign in with your own account."
	refusal := func(body []byte) bool {
		return bytes.Contains(body, []byte(`data-page-id="rasputin-door-refusal"`)) && strings.Contains(html.UnescapeString(string(body)), sentence)
	}
	var form *signin.Client
	for _, d := range []struct{ host, client, callback string }{
		{r.sites.Table.Home.Host, baselineConsole, callbackOn(ConsoleHost)},
		{r.sites.Table.App.Host, "rasputin-account", callbackOn(r.sites.Table.App.Host)},
	} {
		c := r.client(t, "127.0.0.51")
		counts, seen, f := adminFlood(t, r.env, "https://"+d.host, c.c.Transport, refusal, n, d.client, d.callback, bogus, wrong)
		for kind, k := range counts {
			if k < n {
				t.Errorf("%s %s: %d requests, want %d", d.host, kind, k, n)
			}
		}
		if seen.count() != 4*n {
			t.Errorf("%s: %d answers carried the door's refusal, want %d", d.host, seen.count(), 4*n)
		}
		form = f
	}
	r.settle(t)
	if _, err := form.PasswordCodeFlow(t.Context(), "door-control", wrong); err == nil {
		t.Fatal("the control user's wrong password signed in")
	}
	if bf := r.awaitFailures(t, controlID, 1); bf.NumFailures != 1 {
		t.Errorf("the control user's failures %+v, want 1", bf)
	}
	api := r.admin(t)
	cid, _ := api.clientRep(baselineAdminClient)
	_, out := api.must(http.StatusOK, http.MethodGet, "/clients/"+cid+"/service-account-user", nil)
	var sa struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out, &sa); err != nil || sa.ID == "" {
		t.Fatal("rasputin-admin's service account")
	}
	if bf := r.bruteForce(t, sa.ID); bf.NumFailures != 0 || bf.Disabled {
		t.Errorf("%s after the floods: %+v, want no failure and not held", serviceAccountUser, bf)
	}
}
