package identitytest

// The console's sign-in through the home door against the real identity
// service (geekdojo/geekdojo-brain#989, Identity 4.7; TC-989-32 to
// TC-989-39): the repo's realm baseline imported into the pinned Keycloak in
// door mode and converged by the real converger with the console's redirect
// URI and back-channel URL, both doors built by door.Build, and on ci.local
// the api's own auth service: the launcher's route, the callback, the
// session gate and the back-channel route, with the sign-in history drain
// delivering admin events to the role-change sink. The pinned Chrome and Go
// clients reach every name on port 443.
//
// What stands in: the console's pages are two stub pages (/login with the
// launcher's SIGN IN link, and /), because the UI export is the console
// stack test's (TestIdentitySystemd_ConsoleSignIn); and the back-channel URL
// names this rig's port, where the appliance's names 443.
//
// It starts an Env of its own, closed with proof in its cleanup. It skips
// without RASPUTIN_IDENTITY_HOME or RASPUTIN_IDENTITY_THEME and fails instead
// under RASPUTIN_IDENTITY_FUNCTIONAL=required, as CI's backend job sets it.

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	apipkg "github.com/geekdojo/rasputin-control-plane/api/internal/api"
	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door"
	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth/idtoken"
	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/converge"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/flows"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/sessions"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest/signin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

const (
	consoleInstall  = "Console CI"
	consoleCallback = "/api/auth/callback"
	// consoleLoginPage and consoleHomePage are the stub pages' ids.
	consoleLoginPage = "rasputin-console-login"
	consoleHomePage  = "rasputin-console-home"
	// strictCookie and laxCookie are test cookies the stub launcher sets on
	// ci.local, for SO-18's cross-site return.
	strictCookie = "rig-strict"
	laxCookie    = "rig-lax"
)

// consoleRig is the door rig with the real console on ci.local.
type consoleRig struct {
	*doorRig
	conv     *converge.Converger
	settings *memSettings
	sessions *auth.ConsoleSessions
	// designations is the one accounts.Designations, as main opens it
	// (geekdojo/geekdojo-brain#990).
	designations *accounts.Designations
	authSvc      *auth.Service
	session      *idclient.Session
	dbPath       string
	apiRec       *logkittest.Recorder

	mu sync.Mutex
	// backchannel is the URL the console client's back-channel names, set
	// once the sites listen.
	backchannel string
	// callbackCookies and callbackQueries are what each callback carried.
	callbackCookies []string
	callbackQueries []url.Values
	// logoutTokens are the logout tokens posted to the back-channel route.
	logoutTokens []string
	// idTokens are the ID tokens the console's exchanges returned.
	idTokens []string
	// adminEvents are the admin events the drain delivered.
	adminEvents []events.AdminEvent
	// cookies are every console session cookie value a client was given.
	cookies []string
	// resetHome and resetApp are each door's reset start
	// (geekdojo/geekdojo-brain#992).
	resetHome, resetApp string
	// action is the sign-in's accounts.reset_password action, set by the
	// reset rig once its runner exists.
	action lateAction
	// claim and reg are the first-run claim's and registration's
	// collaborators (geekdojo/geekdojo-brain#990), set by the first-run rig;
	// until then first run is off and registration's facts are the door
	// rig's fixed ones.
	claim lateClaim
	reg   lateRegistration
}

// lateClaim is the sign-in's first-run predicate, claimer and observer, set
// after the sign-in is built. Unset, first run is off and the observer is
// told nothing.
type lateClaim struct {
	mu       sync.Mutex
	first    func(context.Context) (bool, error)
	claimer  auth.Claimer
	observer auth.Observer
}

func (l *lateClaim) set(first func(context.Context) (bool, error), c auth.Claimer, o auth.Observer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.first, l.claimer, l.observer = first, c, o
}

func (l *lateClaim) FirstRun(ctx context.Context) (bool, error) {
	l.mu.Lock()
	f := l.first
	l.mu.Unlock()
	if f == nil {
		return false, nil
	}
	return f(ctx)
}

func (l *lateClaim) Earliest(ctx context.Context) (string, error) {
	l.mu.Lock()
	c := l.claimer
	l.mu.Unlock()
	if c == nil {
		return "", errors.New("no claimer is set in this rig")
	}
	return c.Earliest(ctx)
}

func (l *lateClaim) SignedIn(ctx context.Context, sub string) {
	l.mu.Lock()
	o := l.observer
	l.mu.Unlock()
	if o != nil {
		o.SignedIn(ctx, sub)
	}
}

// lateRegistration is the door policy's registration collaborators, each
// replaceable while the doors run. Unset, they are the door rig's fixed
// ones: loopback is home, nothing waits, and no email or name is taken.
type lateRegistration struct {
	mu      sync.Mutex
	network policy.Network
	waiting policy.Waiting
	emails  policy.Emails
	removed policy.RemovedNames
}

func (l *lateRegistration) get() (policy.Network, policy.Waiting, policy.Emails, policy.RemovedNames) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, w, e, r := l.network, l.waiting, l.emails, l.removed
	if n == nil {
		n = doorNetwork{}
	}
	if w == nil {
		w = doorWaiting{}
	}
	if e == nil {
		e = noEmails{}
	}
	if r == nil {
		r = noRemovedNames{}
	}
	return n, w, e, r
}

func (l *lateRegistration) Facts(ctx context.Context) (policy.NetworkFacts, error) {
	n, _, _, _ := l.get()
	return n.Facts(ctx)
}

func (l *lateRegistration) Full(ctx context.Context) (bool, error) {
	_, w, _, _ := l.get()
	return w.Full(ctx)
}

func (l *lateRegistration) EmailInUse(ctx context.Context, email string) (bool, error) {
	_, _, e, _ := l.get()
	return e.EmailInUse(ctx, email)
}

func (l *lateRegistration) Removed(ctx context.Context, name, email string) (bool, error) {
	_, _, _, r := l.get()
	return r.Removed(ctx, name, email)
}

// lateAction is a fresh-sign-in action set after the sign-in is built: the
// reset's runner is built on top of this rig.
type lateAction struct {
	mu sync.Mutex
	a  auth.Action
}

func (l *lateAction) set(a auth.Action) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.a = a
}

func (l *lateAction) Run(ctx context.Context, p auth.Principal, payload auth.ActionPayload) (string, error) {
	l.mu.Lock()
	a := l.a
	l.mu.Unlock()
	if a == nil {
		return "", errors.New("no action is set in this rig")
	}
	return a.Run(ctx, p, payload)
}

// recordingExchanger keeps each ID token the console's exchange returns,
// for TC-989-38's claims and TC-989-39's scan.
type recordingExchanger struct {
	inner auth.Exchanger
	r     *consoleRig
}

func (x recordingExchanger) ExchangeCode(ctx context.Context, c idclient.CodeExchange) (secret.Value, error) {
	v, err := x.inner.ExchangeCode(ctx, c)
	if err == nil {
		x.r.mu.Lock()
		x.r.idTokens = append(x.r.idTokens, string(v.Reveal()))
		x.r.mu.Unlock()
	}
	return v, err
}

// adminEnder ends an identity session through the rig's Admin API session.
type adminEnder struct{ s *idclient.Session }

func (e adminEnder) EndSession(ctx context.Context, sid string) error {
	_, err := e.s.Admin(ctx, http.MethodDelete, "/admin/realms/"+baselineRealm+"/sessions/"+url.PathEscape(sid), nil, nil)
	return err
}

// adminEventLog records each admin event the drain delivers.
type adminEventLog struct{ r *consoleRig }

func (l adminEventLog) AdminEvent(_ context.Context, e events.AdminEvent) {
	l.r.mu.Lock()
	l.r.adminEvents = append(l.r.adminEvents, e)
	l.r.mu.Unlock()
}

type consoleApps struct{}

func (consoleApps) AppClient(_ context.Context, id string) (policy.AppClient, bool, error) {
	return policy.AppClient{}, id == doorTestApp, nil
}

// launcherPage is the stub launcher: it sets the two test cookies and
// links SIGN IN to the launcher's route.
const launcherPage = `<!doctype html><html lang="en"><head><title>Rasputin</title><link rel="icon" href="data:,"></head>` +
	`<body data-page-id="` + consoleLoginPage + `"><a id="signin" href="/api/auth/signin">SIGN IN</a></body></html>`

const homePage = `<!doctype html><html lang="en"><head><title>Rasputin</title><link rel="icon" href="data:,"></head>` +
	`<body data-page-id="` + consoleHomePage + `"><h1>Console</h1></body></html>`

// console is the handler on ci.local: the auth service's routes, a gated
// route, the stub pages, and the recording around the callback and the
// back-channel.
func (r *consoleRig) console() http.Handler {
	mux := http.NewServeMux()
	r.authSvc.RegisterRoutes(mux)
	mux.Handle("GET /api/nodes", r.authSvc.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "[]")
	})))
	page := func(body string, cookies bool) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			if cookies {
				http.SetCookie(w, &http.Cookie{Name: strictCookie, Value: "1", Path: "/", Secure: true, SameSite: http.SameSiteStrictMode})
				http.SetCookie(w, &http.Cookie{Name: laxCookie, Value: "1", Path: "/", Secure: true, SameSite: http.SameSiteLaxMode})
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, body)
		}
	}
	mux.HandleFunc("GET /login", page(launcherPage, true))
	mux.HandleFunc("GET /{$}", page(homePage, false))
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == consoleCallback:
			r.mu.Lock()
			r.callbackCookies = append(r.callbackCookies, req.Header.Get("Cookie"))
			r.callbackQueries = append(r.callbackQueries, req.URL.Query())
			r.mu.Unlock()
		case strings.HasPrefix(req.URL.Path, "/api/identity/backchannel/"):
			b, err := io.ReadAll(io.LimitReader(req.Body, 1<<16))
			if err == nil {
				if form, err := url.ParseQuery(string(b)); err == nil {
					r.mu.Lock()
					r.logoutTokens = append(r.logoutTokens, form.Get("logout_token"))
					r.mu.Unlock()
				}
			}
			req.Body = io.NopCloser(bytes.NewReader(b))
		}
		mux.ServeHTTP(w, req)
	})
}

// convergeFailure is the fields and key providers named by the api log's
// last record of a failed converge, for a failure message: a run that fails
// returns only its sentence.
func (r *consoleRig) convergeFailure() string {
	recs := r.apiRec.Records()
	for i := len(recs) - 1; i >= 0; i-- {
		fields, ok := logkittest.Attr(recs[i], "fields")
		keys, kok := logkittest.Attr(recs[i], "key_providers")
		if ok || kok {
			return " (" + recs[i].Message + " fields=" + fields + " key_providers=" + keys + ")"
		}
	}
	return " (no converge record names its fields)"
}

func (r *consoleRig) inputs() converge.Inputs {
	first, _ := r.claim.FirstRun(context.Background())
	r.mu.Lock()
	defer r.mu.Unlock()
	return converge.Inputs{InstallName: consoleInstall, ClockSynced: true, FirstRun: first,
		AppBindings: map[string]flows.Variant{doorTestApp: flows.AppClients},
		RedirectURIs: map[string][]string{
			baselineConsole: {"https://" + ConsoleHost + consoleCallback}, baselineMesh: {callbackOn(ConsoleHost)},
			"rasputin-reset-home": {"https://" + ConsoleHost + auth.ResetDonePath},
			"rasputin-account":    {callbackOn(r.sites.Table.App.Host)},
			"rasputin-reset-app":  {"https://" + r.sites.Table.App.Host + auth.ResetDonePath},
		},
		BackchannelLogoutURLs: map[string]string{baselineConsole: r.backchannel},
		ResetHomeURL:          r.resetHome, ResetAppURL: r.resetApp,
	}
}

func newConsoleRig(t *testing.T, env *Env) *consoleRig {
	t.Helper()
	r := &consoleRig{
		doorRig:  &doorRig{env: env, sink: &eventSink{}, passes: newPassWatch(), actions: &doorActions{}, cookiesIn: map[string][]string{}},
		settings: &memSettings{m: map[string]string{}},
	}
	log, rec := logkittest.New()
	r.apiRec = rec
	apiLeaf, err := env.CA().MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
	if err != nil {
		t.Fatal(err)
	}
	client := productionClient(t, env, apiLeaf)
	if r.session, err = idclient.NewSession(idclient.SessionConfig{Login: client, Admin: client, Realm: baselineRealm,
		ClientID: baselineAdminClient, Log: log}); err != nil {
		t.Fatal(err)
	}
	table, err := doors.New(DoorClusterID)
	if err != nil {
		t.Fatal(err)
	}

	// The api's auth service and the console's sign-in, as main wires them.
	r.dbPath = filepath.Join(t.TempDir(), "rasputin.db")
	store, err := auth.OpenStore(t.Context(), r.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if r.designations, err = accounts.OpenDesignations(t.Context(), r.dbPath, time.Now); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.designations.Close() })
	if r.sessions, err = auth.NewConsoleSessions(store, time.Now, rand.Reader, r.designations); err != nil {
		t.Fatal(err)
	}
	if r.authSvc, err = auth.NewService(store, auth.Config{RPID: ConsoleHost, RPOrigins: []string{"https://" + ConsoleHost},
		Sessions: r.sessions}); err != nil {
		t.Fatal(err)
	}
	verifier, err := idtoken.New(t.Context(), table.Home.Issuer, baselineConsole, client.Forwarding(table.Home.SetForwarded), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	si, err := auth.NewSignIn(auth.SignInDeps{
		Door: table.Home, ConsoleHost: ConsoleHost, ClientID: baselineConsole, Realm: baselineRealm,
		Exchanger: recordingExchanger{inner: client, r: r}, Verifier: verifier, Ender: adminEnder{s: r.session},
		Ready: doorReady{}, Sessions: r.sessions, FirstRun: &r.claim, Claimer: &r.claim, Observer: &r.claim,
		Actions: map[string]auth.Action{"accounts.reset_password": &r.action},
		Now:     time.Now, Rand: rand.Reader, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.authSvc.SetSignIn(si)
	// The reset returns, as main wires them (#992): each door's own
	// verifier, #991's ender and the console sessions.
	ender := sessions.Ender{Admin: r.session}
	resetDone := func(d doors.Door, name, resetClient, redirect string) *auth.ResetDone {
		v, err := idtoken.New(t.Context(), d.Issuer, resetClient, client.Forwarding(d.SetForwarded), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		rd, err := auth.NewResetDone(auth.ResetDoneDeps{Door: d, DoorName: name, ClientID: resetClient, RedirectURI: redirect,
			Realm: baselineRealm, Exchanger: client, Verifier: v, Identity: ender, Console: r.sessions, Log: log})
		if err != nil {
			t.Fatal(err)
		}
		return rd
	}
	homeReturn, appReturn := "https://"+ConsoleHost+auth.ResetDonePath, "https://"+table.App.Host+auth.ResetDonePath
	r.authSvc.SetResetDone(resetDone(table.Home, "home", "rasputin-reset-home", homeReturn))
	appReset := resetDone(table.App, "app", "rasputin-reset-app", appReturn)
	r.resetHome = auth.ResetStartURL(table.Home, "rasputin-reset-home", homeReturn)
	r.resetApp = auth.ResetStartURL(table.App, "rasputin-reset-app", appReturn)
	roleSink, err := auth.NewRoleChangeSink(r.sessions, log)
	if err != nil {
		t.Fatal(err)
	}

	if r.conv, err = converge.New(converge.Deps{
		Admin: r.session, Settings: r.settings, Realm: baselineRealm, Lock: &sync.Mutex{},
		Inputs: func(context.Context) (converge.Inputs, error) { return r.inputs(), nil },
		Now:    time.Now, Ready: func(context.Context) error { return nil }, Log: log,
	}); err != nil {
		t.Fatal(err)
	}
	if r.th, err = policy.NewThrottle(policy.ThrottleDeps{Table: table, Now: time.Now}); err != nil {
		t.Fatal(err)
	}
	r.drainer, err = events.New(events.Deps{Admin: r.session, Marks: &doorMarks{m: map[string]string{}}, Signal: events.NewSignal(time.Now),
		Realm: baselineRealm, UserSinks: []events.UserSink{r.th, r.sink},
		AdminSinks: []events.AdminSink{r.conv, roleSink, adminEventLog{r: r}}, PassSinks: []events.PassSink{r.th, r.conv, r.passes}, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.New(policy.Deps{Table: table, Readiness: doorReady{}, Throttle: r.th, AppClients: consoleApps{},
		Actions: r.actions, Network: &r.reg, Waiting: &r.reg, Removed: &r.reg, Emails: &r.reg, Now: time.Now, Bindings: r.conv})
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
	if r.version, err = door.NewResourceVersion(client, log); err != nil {
		t.Fatal(err)
	}
	r.version.Learn(t.Context())
	relay, err := env.DoorTransport()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(relay.CloseIdleConnections)
	r.home, r.app, err = door.Build(table, door.Shared{
		ConsoleOrigin: "https://" + ConsoleHost, Policy: pol, Throttle: r.th, Transport: relay,
		Upstream: env.KeycloakUpstream(), Theme: allow, Assets: os.DirFS(filepath.Join(theme, "login", "resources")), Version: r.version,
		InstallName: func(context.Context) (string, error) { return consoleInstall, nil }, Dirty: r.drainer,
		IDs: func() string { return fmt.Sprintf("console-%d", r.ids.Add(1)) }, Breach: neverListed{}, ResetDone: appReset, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	stub := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, stubPage)
	})
	sites, err := apipkg.NewSites(apipkg.SitesConfig{
		Console: r.console(), Home: r.home, App: r.app,
		HomeHost: table.Home.Host, AppHost: table.App.Host, RequestLifetime: time.Minute, Now: time.Now,
		IDs: func() string { return fmt.Sprintf("console-site-%d", r.ids.Add(1)) }, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.sites, err = env.ServeDoors(sites, stub); err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(r.sites.Sites.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.backchannel = "https://127.0.0.1:" + port + "/api/identity/backchannel/" + baselineConsole
	r.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.drainer.Run(ctx); close(done) }()
	vdone := make(chan struct{})
	go func() { r.version.Run(ctx); close(vdone) }()
	t.Cleanup(func() { cancel(); <-done; <-vdone })

	api := r.admin(t)
	api.must(http.StatusCreated, http.MethodPost, "/clients", map[string]any{
		"clientId": doorTestApp, "enabled": true, "publicClient": true, "protocol": "openid-connect",
		"standardFlowEnabled": true, "redirectUris": []string{callbackOn(AppSiteHost)},
		"attributes": map[string]string{"pkce.code.challenge.method": "S256"},
	})
	if _, err := r.conv.Run(t.Context()); err != nil {
		t.Fatalf("converge with the console's inputs: %v%s", err, r.convergeFailure())
	}
	r.settle(t)
	return r
}

// fixture is a synthetic account with a password and a console role, and
// its id.
func (r *consoleRig) fixture(t *testing.T, name, role string) (string, secret.Value) {
	t.Helper()
	id, pw := r.user(t, name)
	api := r.admin(t)
	cid, _ := api.clientRep(baselineConsole)
	_, out := api.must(http.StatusOK, http.MethodGet, "/clients/"+cid+"/roles/"+role, nil)
	var rep map[string]any
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	api.must(http.StatusNoContent, http.MethodPost, "/users/"+id+"/role-mappings/clients/"+cid, []any{rep})
	r.settle(t)
	return id, pw
}

// signInGo signs name in through the launcher's route with the Go client
// from local, and returns the client and its jar.
func (r *consoleRig) signInGo(t *testing.T, local, name string, pw secret.Value) *http.Client {
	t.Helper()
	tr := r.sites.Client(netip.MustParseAddr(local), nil).Transport
	jar, pages, err := signin.ConsoleSignIn(t.Context(), signin.Console{Origin: "https://" + ConsoleHost, Transport: tr, Logger: r.env.log}, name, pw)
	if err != nil {
		t.Fatalf("console sign-in of %s (pages %v): %v", name, pages, err)
	}
	r.settle(t)
	c := &http.Client{Transport: tr, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	u, _ := url.Parse("https://" + ConsoleHost)
	for _, ck := range jar.Cookies(u) {
		if ck.Name == auth.SessionCookieName {
			r.mu.Lock()
			r.cookies = append(r.cookies, ck.Value)
			r.mu.Unlock()
		}
	}
	return c
}

// me is GET /api/auth/me's status and body.
func me(t *testing.T, c *http.Client) (int, map[string]any) {
	t.Helper()
	resp, err := c.Get("https://" + ConsoleHost + "/api/auth/me")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

// gated is a gated route's status.
func gated(t *testing.T, c *http.Client) int {
	t.Helper()
	resp, err := c.Get("https://" + ConsoleHost + "/api/nodes")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// rows counts the console session rows through a second handle on the
// database file.
func (r *consoleRig) rows(t *testing.T) int {
	t.Helper()
	db := r.db(t)
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM console_sessions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// db is a second handle on the console's database file.
func (r *consoleRig) db(t *testing.T) *sql.DB {
	t.Helper()
	db, err := dbutil.Open(t.Context(), r.dbPath, "SELECT 1", "console-check")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// ---- the test ----------------------------------------------------------------

var (
	consoleRec    *logkittest.Recorder
	consoleRecLog *slog.Logger
)

func TestConsole_AgainstPinnedKeycloak(t *testing.T) {
	p := NewPackage(func() (Config, error) {
		c, err := ConfigFromEnv()
		c.DoorMode = true
		if err == nil {
			consoleRecLog, consoleRec = logkittest.New()
			c.Logger = slog.New(slog.NewMultiHandler(c.Logger.Handler(), consoleRecLog.Handler()))
		}
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
	r := newConsoleRig(t, env)
	browserCtx, _ := p.Browser(t)
	if browserCtx == nil {
		return
	}
	// viewer: the sign-in rules refuse a password alone for admin and
	// operator (TC-987-01), and these cases sign in with a password.
	id, pw := r.fixture(t, "console-fixture", "viewer")
	// An app-door user too, for TS-20's app-door sign-in (TC-987-02's
	// household account).
	api := r.admin(t)
	_, out := api.must(http.StatusOK, http.MethodGet, "/users/"+id, nil)
	var rep map[string]any
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	rep["attributes"] = map[string][]string{"rasputin_app_role": {"user"}}
	api.must(http.StatusNoContent, http.MethodPut, "/users/"+id, rep)

	t.Run("TC-989-37 converge writes the console's address", func(t *testing.T) { r.tc37(t) })
	t.Run("TC-989-32 SO-18 the cross-site return", func(t *testing.T) { r.tc32(t, browserCtx, "console-fixture", pw) })
	t.Run("TC-989-36 TS-20 one subject, and an app-door code refused", func(t *testing.T) { r.tc36(t, "console-fixture", pw) })
	t.Run("TC-989-33 IA-F7 a role change ends the session", func(t *testing.T) { r.tc33(t) })
	t.Run("TC-989-34 IA-F7 the back-channel logout", func(t *testing.T) { r.tc34(t) })
	t.Run("TC-989-35 IA-F7 no token in rasputin.db", func(t *testing.T) { r.tc35(t) })
	t.Run("TC-989-38 T161 the upstream shapes", func(t *testing.T) { r.tc38(t) })
	t.Run("TC-989-39 the sentinel scan", func(t *testing.T) { r.tc39(t, pw) })
	t.Run("TC-1000-20 TC-1000-21 IA-F6 TS-20 console tokens and capabilities", func(t *testing.T) { r.tc1000(t, id, pw) })
}

// TC-989-37: converge's own write sets rasputin.console-url to the
// console's origin, and the home door's repair link and the app door's
// "No account yet?" sentence render it.
func (r *consoleRig) tc37(t *testing.T) {
	_, out := r.admin(t).must(http.StatusOK, http.MethodGet, "", nil)
	var realm struct {
		Attributes map[string]string `json:"attributes"`
	}
	if err := json.Unmarshal(out, &realm); err != nil {
		t.Fatal(err)
	}
	if got := realm.Attributes["rasputin.console-url"]; got != "https://"+ConsoleHost {
		t.Fatalf("rasputin.console-url = %q, want https://%s", got, ConsoleHost)
	}
	g := r.client(t, "127.0.0.40")
	home := g.follow("https://" + ConsoleHost + "/api/auth/signin")
	if home.pageID() != "login-login" || !bytes.Contains(home.body, []byte(`id="rasputin-repair"`)) ||
		!bytes.Contains(home.body, []byte(`href="https://`+ConsoleHost+`/repair"`)) {
		t.Errorf("the home door's sign-in page (%s) has no repair link to the console", home.pageID())
	}
	app := r.client(t, "127.0.0.41").follow(r.appAuth(doorTestApp, nil))
	want := "No account yet? Create one on your home network at https://" + ConsoleHost + "."
	if !strings.Contains(html.UnescapeString(string(app.body)), want) {
		t.Errorf("the app door's sign-in page (%s) lacks %q", app.pageID(), want)
	}
}

// TC-989-32 (issue TC-06): Chromium signs the fixture in from
// https://ci.local/login through sso-ci.local and lands in the console with
// a session; the callback received the Lax cookies and not the Strict test
// cookie; no console cookie is Strict.
func (r *consoleRig) tc32(t *testing.T, browserCtx context.Context, name string, pw secret.Value) {
	tb := newTab(t, browserCtx, "https://"+ConsoleHost)
	tb.beforeSubmit = r.settle
	if got := tb.navigate("https://" + ConsoleHost + "/login"); got != consoleLoginPage {
		t.Fatalf("the launcher is %q", got)
	}
	r.mu.Lock()
	before := len(r.callbackCookies)
	r.mu.Unlock()
	if got := tb.submit(chromedp.Click(chromedp.ID("signin")), "press SIGN IN"); got != "login-login" {
		t.Fatalf("SIGN IN led to %q", got)
	}
	if got := signIn(tb, name, pw); got != consoleLoginPage {
		t.Fatalf("the sign-in returned to %q, want the console's launcher", got)
	}
	if q := evalT[string](tb, `location.search`); q != "" {
		t.Fatalf("the sign-in came back with %q; the api logged: %s", q, r.signinEvents())
	}
	r.mu.Lock()
	cookies := append([]string(nil), r.callbackCookies[before:]...)
	r.mu.Unlock()
	if len(cookies) != 1 {
		t.Fatalf("%d callbacks, want 1", len(cookies))
	}
	sent := cookieNames(cookies[0])
	if !slices.Contains(sent, "__Host-rasputin-pending") || !slices.Contains(sent, laxCookie) {
		t.Errorf("the callback received %v; want the pending cookie and the Lax test cookie", sent)
	}
	if slices.Contains(sent, strictCookie) {
		t.Errorf("the cross-site return carried the Strict test cookie: %v", sent)
	}
	ctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer cancel()
	res, err := chromedp.Call(ctx, network.GetCookies, network.GetCookiesParams{URLs: []string{"https://" + ConsoleHost + "/"}})
	if err != nil {
		t.Fatalf("Network.getCookies: %v", err)
	}
	all := res.Cookies
	session := false
	for _, c := range all {
		if !strings.HasPrefix(c.Name, "__Host-rasputin-") {
			continue
		}
		if c.SameSite != network.CookieSameSiteLax {
			t.Errorf("console cookie %s is SameSite=%s, want Lax", c.Name, c.SameSite)
		}
		if c.Name == auth.SessionCookieName {
			session = true
			r.mu.Lock()
			r.cookies = append(r.cookies, c.Value)
			r.mu.Unlock()
		}
	}
	if !session {
		t.Fatal("the browser holds no console session")
	}
	if status := fetchStatus(tb, "/api/auth/me"); status != http.StatusOK {
		t.Errorf("/api/auth/me in the browser answered %v, want 200", status)
	}
}

// fetchStatus is the status the page's own fetch of path answers.
func fetchStatus(tb *tab, path string) int {
	tb.t.Helper()
	ctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer cancel()
	v, err := chromedp.Run(ctx, chromedp.Evaluate[float64](`fetch(`+strconv.Quote(path)+`, {credentials: 'same-origin'}).then((r) => r.status)`,
		chromedp.EvalAwaitPromise))
	if err != nil {
		tb.t.Fatalf("fetch %s in the page: %v", path, err)
	}
	return int(v)
}

// signinEvents are the api's sign-in records, for a failure message: the
// event and its reason, never a value.
func (r *consoleRig) signinEvents() string {
	var out []string
	for _, rec := range r.apiRec.Records() {
		ev, _ := logkittest.Attr(rec, "event")
		if strings.HasPrefix(ev, "signin.") {
			reason, _ := logkittest.Attr(rec, "reason")
			out = append(out, ev+" "+reason)
		}
	}
	return strings.Join(out, "; ")
}

// cookieNames are the names in a Cookie header.
func cookieNames(h string) []string {
	var out []string
	for _, c := range (&http.Request{Header: http.Header{"Cookie": {h}}}).Cookies() {
		out = append(out, c.Name)
	}
	return out
}

// TC-989-36 (TS-20): the console session's subject is the one an app-door
// sign-in of the same account gets; a callback carrying the app door's code
// and issuer is refused and mints nothing.
func (r *consoleRig) tc36(t *testing.T, name string, pw secret.Value) {
	c := r.signInGo(t, "127.0.0.42", name, pw)
	status, body := me(t, c)
	if status != http.StatusOK {
		t.Fatalf("/api/auth/me = %d", status)
	}
	g := r.client(t, "127.0.0.43")
	code := g.signIn(r.appAuth(doorTestApp, nil), name, pw).code(t)
	if sub := r.subOf(t, g, code); sub != body["sub"] {
		t.Errorf("the app door's subject %q is not the console's %q", sub, body["sub"])
	}
	r.settle(t)

	rows := r.rows(t)
	for _, iss := range []string{r.sites.Table.App.Issuer, r.sites.Table.Home.Issuer} {
		appCode := r.client(t, "127.0.0.44").signIn(r.appAuth(doorTestApp, nil), name, pw).code(t)
		r.settle(t)
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		b := &http.Client{Transport: r.sites.Client(netip.MustParseAddr("127.0.0.45"), nil).Transport, Jar: jar,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := b.Get("https://" + ConsoleHost + "/api/auth/signin")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		loc, err := resp.Location()
		if err != nil {
			t.Fatal(err)
		}
		q := url.Values{"state": {loc.Query().Get("state")}, "code": {appCode}, "iss": {iss}}
		resp, err = b.Get("https://" + ConsoleHost + consoleCallback + "?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if got := resp.Header.Get("Location"); got != "/login?signin=failed" {
			t.Errorf("an app-door code with iss %s: %d %s, want the failed sentence", iss, resp.StatusCode, got)
		}
		if n := r.rows(t); n != rows {
			t.Errorf("an app-door code minted a session: %d rows, had %d", n, rows)
		}
	}
}

// TC-989-33 (IA-F7): a role mapping added through the api's own Admin API
// session reaches the role-change sink through the drain, and the
// fixture's next gated request answers 401. A fixture of its own: the
// role it gains (operator) makes a password alone refused afterwards.
func (r *consoleRig) tc33(t *testing.T) {
	id, pw := r.fixture(t, "console-fixture-role", "viewer")
	c := r.signInGo(t, "127.0.0.46", "console-fixture-role", pw)
	if got := gated(t, c); got != http.StatusOK {
		t.Fatalf("a gated route before the change: %d", got)
	}
	cid, _ := r.admin(t).clientRep(baselineConsole)
	var role map[string]any
	if _, err := r.session.Admin(t.Context(), http.MethodGet, "/admin/realms/"+baselineRealm+"/clients/"+cid+"/roles/operator", nil, &role); err != nil {
		t.Fatal(err)
	}
	if _, err := r.session.Admin(t.Context(), http.MethodPost, "/admin/realms/"+baselineRealm+"/users/"+id+"/role-mappings/clients/"+cid, []any{role}, nil); err != nil {
		t.Fatal(err)
	}
	r.settle(t)
	if got := gated(t, c); got != http.StatusUnauthorized {
		t.Errorf("a gated route after the role change: %d, want 401", got)
	}
	if status, _ := me(t, c); status != http.StatusUnauthorized {
		t.Errorf("/api/auth/me after the role change: %d", status)
	}
}

// TC-989-34 (issue TC-04): an Admin API logout of the user makes the real
// identity service post a logout token to the back-channel route; the
// sid's row is gone and the next request answers 401.
func (r *consoleRig) tc34(t *testing.T) {
	id, pw := r.fixture(t, "console-fixture-logout", "viewer")
	c := r.signInGo(t, "127.0.0.47", "console-fixture-logout", pw)
	if got := gated(t, c); got != http.StatusOK {
		t.Fatalf("a gated route before the logout: %d", got)
	}
	r.mu.Lock()
	before := len(r.logoutTokens)
	r.mu.Unlock()
	rows := r.rows(t)
	if _, err := r.session.Admin(t.Context(), http.MethodPost, "/admin/realms/"+baselineRealm+"/users/"+id+"/logout", nil, nil); err != nil {
		t.Fatal(err)
	}
	// The identity service posts the logout token before its Admin API call
	// answers; the counter is the fact.
	r.mu.Lock()
	hits := len(r.logoutTokens) - before
	r.mu.Unlock()
	if hits < 1 {
		t.Fatalf("the back-channel route received %d logout tokens, want at least 1", hits)
	}
	if got := gated(t, c); got != http.StatusUnauthorized {
		t.Errorf("a gated route after the logout: %d, want 401", got)
	}
	if n := r.rows(t); n >= rows {
		t.Errorf("rows %d after the logout, had %d", n, rows)
	}
	recs := r.apiRec.Records()
	ended := false
	for _, rec := range recs {
		if ev, _ := logkittest.Attr(rec, "event"); ev == "backchannel.ended" {
			ended = true
		}
	}
	if !ended {
		t.Error("the api logged no backchannel.ended record")
	}
}

// TC-989-35 (issue TC-03): rasputin.db holds no JWT, no token and no
// cookie value.
func (r *consoleRig) tc35(t *testing.T) {
	db := r.db(t)
	if _, err := db.ExecContext(t.Context(), `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	needles := []string{"eyJ"}
	r.mu.Lock()
	needles = append(needles, r.idTokens...)
	needles = append(needles, r.logoutTokens...)
	needles = append(needles, r.cookies...)
	r.mu.Unlock()
	if len(needles) < 4 {
		t.Fatalf("only %d needles: the scan would prove nothing", len(needles))
	}
	scanned := 0
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(r.dbPath + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for i, n := range needles {
			if n != "" && bytes.Contains(b, []byte(n)) {
				t.Errorf("rasputin.db%s holds needle %d of %d", suffix, i+1, len(needles))
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no database file was scanned")
	}
}

// TC-989-38 (T161): the shapes at Keycloak 26.8.2 the sign-in relies on.
func (r *consoleRig) tc38(t *testing.T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.callbackQueries) == 0 || len(r.idTokens) == 0 || len(r.logoutTokens) == 0 {
		t.Fatalf("callbacks %d, ID tokens %d, logout tokens %d: the cases above did not run", len(r.callbackQueries), len(r.idTokens), len(r.logoutTokens))
	}
	for _, q := range r.callbackQueries {
		if q.Get("code") != "" && q.Get("iss") != r.sites.Table.Home.Issuer && q.Get("iss") != r.sites.Table.App.Issuer {
			t.Errorf("an authorization response carried iss %q", q.Get("iss"))
		}
	}
	if q := r.callbackQueries[0]; q.Get("iss") != r.sites.Table.Home.Issuer {
		t.Errorf("the first authorization response's iss = %q, want the home door's", q.Get("iss"))
	}
	for _, tok := range r.idTokens {
		c := jwtClaims(t, tok)
		if c["sid"] == nil || c["auth_time"] == nil || c["rasputin_roles"] == nil {
			t.Errorf("an ID token lacks sid, auth_time or rasputin_roles: keys %v", keysOf(c))
		}
	}
	for _, tok := range r.logoutTokens {
		c := jwtClaims(t, tok)
		ev, _ := c["events"].(map[string]any)
		if c["exp"] == nil || c["sid"] == nil || ev == nil || ev["http://schemas.openid.net/event/backchannel-logout"] == nil {
			t.Errorf("a logout token lacks exp, sid or the back-channel event: keys %v", keysOf(c))
		}
	}
	found := false
	for _, e := range r.adminEvents {
		if e.ResourceType == "CLIENT_ROLE_MAPPING" && strings.HasPrefix(e.ResourcePath, "users/") && strings.Contains(e.ResourcePath, "/role-mappings/") {
			found = true
		}
	}
	if !found {
		t.Errorf("no CLIENT_ROLE_MAPPING admin event carried resourcePath users/<id>/role-mappings/...: %+v", r.adminEvents)
	}
}

func keysOf(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// TC-989-39 (LOG-SECRETS): at the end of the suite, the fixture password,
// the tokens and the session cookies appear in no api log, rig log (the
// identity service's output included) or database file.
func (r *consoleRig) tc39(t *testing.T, pw secret.Value) {
	r.mu.Lock()
	needles := []string{string(pw.Reveal())}
	needles = append(needles, r.idTokens...)
	needles = append(needles, r.logoutTokens...)
	needles = append(needles, r.cookies...)
	r.mu.Unlock()
	texts := map[string]string{"the api log": r.apiRec.Text()}
	if consoleRec != nil {
		texts["the rig log"] = consoleRec.Text()
	}
	for _, suffix := range []string{"", "-wal"} {
		if b, err := os.ReadFile(r.dbPath + suffix); err == nil {
			texts["rasputin.db"+suffix] = string(b)
		}
	}
	if len(needles) < 4 || len(texts) < 3 || len(r.apiRec.Records()) == 0 {
		t.Fatalf("needles %d, sources %d, api records %d: the scan would prove nothing", len(needles), len(texts), len(r.apiRec.Records()))
	}
	for where, text := range texts {
		for i, n := range needles {
			if len(n) < 8 {
				t.Fatalf("needle %d is %d bytes, too short to scan for", i+1, len(n))
			}
			if strings.Contains(text, n) {
				t.Errorf("%s holds needle %d of %d (%d bytes); the value is not printed", where, i+1, len(needles), len(n))
			}
		}
	}
}

// TC-1000-20 and TC-1000-21 (IA-F6, TS-20; geekdojo/geekdojo-brain#1000).
// It runs last: TC-989-38 requires rasputin_roles on every captured ID
// token, and the role-less fixture's token carries none.
//
// TC-1000-21: capabilities come from console roles alone, and app access
// adds none. The viewer fixture's /api/auth/me is exactly [view self]; a
// role-less fixture holding rasputin_app_role=user signs in through the
// console's real route and gets exactly [self].
//
// TC-1000-20: every captured console ID token carries no groups,
// rasputin_app_role, resource_access or realm_access, no claim_* key and
// no rasputin_* key but rasputin_roles. The viewer fixture's tokens, which
// it holds rasputin_app_role=user for, carry rasputin_roles ["viewer"]; the
// role-less fixture's carry none, or an empty list.
func (r *consoleRig) tc1000(t *testing.T, viewerID string, viewerPW secret.Value) {
	const roleless = "console-fixture-roleless"
	rolelessID, pw := r.user(t, roleless)
	r.appRoleUser(t, rolelessID)
	r.settle(t)
	for _, c := range []struct {
		name string
		pw   secret.Value
		from string
		want []string
	}{
		{"console-fixture", viewerPW, "127.0.0.60", []string{"view", "self"}},
		{roleless, pw, "127.0.0.61", []string{"self"}},
	} {
		status, body := me(t, r.signInGo(t, c.from, c.name, c.pw))
		if status != http.StatusOK {
			t.Fatalf("TC-1000-21 %s: /api/auth/me = %d", c.name, status)
		}
		if got := stringList(body["capabilities"]); !slices.Equal(got, c.want) {
			t.Errorf("TC-1000-21 %s: capabilities %v, want exactly %v", c.name, body["capabilities"], c.want)
		}
	}

	r.mu.Lock()
	tokens := slices.Clone(r.idTokens)
	r.mu.Unlock()
	viewers, roleLess := 0, 0
	for i, tok := range tokens {
		c := jwtClaims(t, tok)
		for k := range c {
			switch {
			case k == "groups", k == "rasputin_app_role", k == "resource_access", k == "realm_access",
				strings.HasPrefix(k, "claim_"), strings.HasPrefix(k, "rasputin_") && k != "rasputin_roles":
				t.Errorf("TC-1000-20: console ID token %d of %d carries %s", i+1, len(tokens), k)
			}
		}
		switch c["sub"] {
		case viewerID:
			viewers++
			if got := stringList(c["rasputin_roles"]); !slices.Equal(got, []string{"viewer"}) {
				t.Errorf("TC-1000-20: a viewer fixture token's rasputin_roles = %v, want [viewer]", c["rasputin_roles"])
			}
		case rolelessID:
			roleLess++
			if got := stringList(c["rasputin_roles"]); len(got) != 0 {
				t.Errorf("TC-1000-20: the role-less fixture's rasputin_roles = %v, want none", c["rasputin_roles"])
			}
		}
	}
	if viewers == 0 || roleLess == 0 {
		t.Errorf("TC-1000-20: %d ID tokens, %d of the viewer fixture and %d of the role-less one: the assertions above proved nothing", len(tokens), viewers, roleLess)
	}
}

// appRoleUser gives the account id rasputin_app_role=user: app access.
func (r *consoleRig) appRoleUser(t *testing.T, id string) {
	t.Helper()
	api := r.admin(t)
	_, out := api.must(http.StatusOK, http.MethodGet, "/users/"+id, nil)
	var rep map[string]any
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	rep["attributes"] = map[string][]string{"rasputin_app_role": {"user"}}
	api.must(http.StatusNoContent, http.MethodPut, "/users/"+id, rep)
}

// stringList is a JSON list of strings, nil for anything else.
func stringList(v any) []string {
	vs, _ := v.([]any)
	var out []string
	for _, x := range vs {
		s, ok := x.(string)
		if !ok {
			return nil
		}
		out = append(out, s)
	}
	return out
}
