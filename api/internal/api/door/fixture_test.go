package door

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// upReq is one request the fake identity service received.
type upReq struct {
	method, path, query, host, body string
	header                          http.Header
}

// upstream is the fake identity service: a TLS server recording every
// request and answering with handler (200 HTML by default).
type upstream struct {
	srv     *httptest.Server
	mu      sync.Mutex
	reqs    []upReq
	handler http.HandlerFunc
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.reqs = append(u.reqs, upReq{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, host: r.Host,
			body: string(b), header: r.Header.Clone()})
		h := u.handler
		u.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><title>upstream</title>"))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.reqs)
}

func (u *upstream) last(t *testing.T) upReq {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.reqs) == 0 {
		t.Fatal("the upstream received nothing")
	}
	return u.reqs[len(u.reqs)-1]
}

func (u *upstream) setHandler(h http.HandlerFunc) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.handler = h
}

// The fakes behind the policy.
type fakeReady struct {
	mu  sync.Mutex
	err error
}

func (f *fakeReady) Ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

// noneBound pauses no client: these tests are about the door, not the
// sign-in rules' bindings (geekdojo/geekdojo-brain#987).
type noneBound struct{}

func (noneBound) ClientPaused(string) bool { return false }

type fakeApps struct {
	m   map[string]policy.AppClient
	err error
}

func (f *fakeApps) AppClient(_ context.Context, id string) (policy.AppClient, bool, error) {
	a, ok := f.m[id]
	return a, ok, f.err
}

type fakeActions struct {
	issued bool
	err    error
	got    []policy.ActionRequest
}

func (f *fakeActions) Issued(_ context.Context, a policy.ActionRequest) (bool, error) {
	f.got = append(f.got, a)
	return f.issued, f.err
}

type fakeNetwork struct {
	facts policy.NetworkFacts
	err   error
}

func (f *fakeNetwork) Facts(context.Context) (policy.NetworkFacts, error) { return f.facts, f.err }

type fakeWaiting struct {
	full bool
	err  error
}

func (f *fakeWaiting) Full(context.Context) (bool, error) { return f.full, f.err }

// countDirty counts the drain's marks, and the requests begun and ended on
// its signal.
type countDirty struct{ n, begun, ended atomic.Int64 }

func (c *countDirty) MarkDirty() { c.n.Add(1) }

func (c *countDirty) Begin() func() {
	c.begun.Add(1)
	return func() { c.ended.Add(1) }
}

// testAssets are a built theme's login/resources css and img files.
var testAssets = fstest.MapFS{
	"css/tokens.css":                {Data: []byte(":root{--rasp-bg:#000}")},
	"css/components.css":            {Data: []byte(".rasp-btn{}")},
	"css/signin.css":                {Data: []byte(".rasp-card{}")},
	"css/fonts/JetBrainsMono.woff2": {Data: []byte("wOF2font")},
	"img/brand.svg":                 {Data: []byte("<svg/>")},
	"img/favicon.svg":               {Data: []byte("<svg id=f/>")},
	"js/rasputin-page.js":           {Data: []byte("never served from here")},
}

const testAllowlist = `{"keycloak":"26.8.2","login":["css/signin.css","js/rasputin-page.js","img/brand.svg"],"common":["vendor/rfc4648/rfc4648.js"]}`

const consoleOrigin = "https://ci.local"

// The fixture's own home-network peer, and the throttle's clock.
const peer = "192.0.2.1:40000"

type fixture struct {
	t         *testing.T
	table     doors.Table
	up        *upstream
	home, app *Handler
	th        *policy.Throttle
	now       time.Time
	ready     *fakeReady
	apps      *fakeApps
	actions   *fakeActions
	network   *fakeNetwork
	waiting   *fakeWaiting
	dirty     *countDirty
	vsrc      *fakeVersionSource
	version   *ResourceVersion
	vrec      *logkittest.Recorder
	rec       *logkittest.Recorder
	name      string
	nameErr   error
	ids       atomic.Int64
	policySvc *policy.Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	table, err := doors.New("ci")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		t: t, table: table, up: newUpstream(t), now: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC),
		ready: &fakeReady{}, apps: &fakeApps{m: map[string]policy.AppClient{"immich": {}}}, actions: &fakeActions{},
		network: &fakeNetwork{facts: policy.NetworkFacts{
			HomeSubnets: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
			Tailnet:     []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")},
			Nodes:       []netip.Addr{netip.MustParseAddr("192.0.2.50")},
		}},
		waiting: &fakeWaiting{}, dirty: &countDirty{}, name: "Hoodoo Home",
	}
	f.th, err = policy.NewThrottle(policy.ThrottleDeps{Table: table, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	f.policySvc, err = policy.New(policy.Deps{Table: table, Readiness: f.ready, Throttle: f.th, AppClients: f.apps,
		Actions: f.actions, Network: f.network, Waiting: f.waiting, Now: func() time.Time { return f.now },
		Bindings: noneBound{}})
	if err != nil {
		t.Fatal(err)
	}
	f.vsrc = &fakeVersionSource{v: testVersion}
	vlog, vrec := logkittest.New()
	f.vrec = vrec
	if f.version, err = NewResourceVersion(f.vsrc, vlog); err != nil {
		t.Fatal(err)
	}
	f.version.Learn(context.Background())
	f.home, f.app = f.build(t)
	return f
}

// testVersion is the resource version the fixture's identity service
// reports, and testLoginPath the login theme path under it.
const testVersion = "ab12c"

var testLoginPath, _ = themePaths(testVersion)

// fakeVersionSource is the identity service's resource version as the probe
// reads it.
type fakeVersionSource struct {
	mu    sync.Mutex
	v     string
	err   error
	reads int
}

func (s *fakeVersionSource) ResourceVersion(_ context.Context, file string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if file != versionProbeFile {
		return "", errors.New("unexpected probe file " + file)
	}
	return s.v, s.err
}

func (s *fakeVersionSource) set(v string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v, s.err = v, err
}

func (f *fixture) shared(t *testing.T) Shared {
	t.Helper()
	allow, err := ParseAllowlist([]byte(testAllowlist))
	if err != nil {
		t.Fatal(err)
	}
	up, err := url.Parse(f.up.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	log, rec := logkittest.New()
	f.rec = rec
	return Shared{
		ConsoleOrigin: consoleOrigin, Policy: f.policySvc, Throttle: f.th, Transport: f.up.srv.Client().Transport,
		Upstream: up, Theme: allow, Assets: testAssets, Version: f.version,
		InstallName: func(context.Context) (string, error) { return f.name, f.nameErr },
		Dirty:       f.dirty,
		IDs:         func() string { return "corr-" + strconv.FormatInt(f.ids.Add(1), 10) },
		Log:         log,
	}
}

func (f *fixture) build(t *testing.T) (*Handler, *Handler) {
	t.Helper()
	home, app, err := Build(f.table, f.shared(t))
	if err != nil {
		t.Fatal(err)
	}
	return home, app
}

// handler is the door's handler.
func (f *fixture) door(k Kind) *Handler {
	if k == Home {
		return f.home
	}
	return f.app
}

// req is one request to a door.
type req struct {
	method, target string
	form           url.Values
	body           string
	ctype          string
	header         http.Header
	remote         string
}

func (f *fixture) do(k Kind, r req) *httptest.ResponseRecorder {
	f.t.Helper()
	var body io.Reader
	switch {
	case r.form != nil:
		body = strings.NewReader(r.form.Encode())
		if r.ctype == "" {
			r.ctype = "application/x-www-form-urlencoded"
		}
	case r.body != "":
		body = strings.NewReader(r.body)
	}
	if r.method == "" {
		r.method = http.MethodGet
	}
	hr := httptest.NewRequest(r.method, "/", body)
	hr.RequestURI = r.target
	u, err := url.ParseRequestURI(r.target)
	if err == nil {
		hr.URL = u
	}
	hr.Host = f.door(k).cfg.Door.Host
	if r.ctype != "" {
		hr.Header.Set("Content-Type", r.ctype)
	}
	for k, vs := range r.header {
		for _, v := range vs {
			hr.Header.Add(k, v)
		}
	}
	hr.RemoteAddr = peer
	if r.remote != "" {
		hr.RemoteAddr = r.remote
	}
	w := httptest.NewRecorder()
	f.door(k).ServeHTTP(w, hr)
	return w
}

// isDoorPage reports whether the answer is the door's own page.
func isDoorPage(w *httptest.ResponseRecorder) bool {
	return strings.Contains(w.Body.String(), `data-page-id="rasputin-door-`)
}

// homeClient and appClient are a client of each door.
func doorClient(k Kind) string {
	if k == Home {
		return policy.ConsoleClient
	}
	return "rasputin-account"
}

// authQuery is a valid authorization request's query for client, with
// extra set over it ("" deletes).
func authQuery(client string, extra map[string]string) string {
	q := url.Values{"client_id": {client}, "response_type": {"code"}, "prompt": {"login"}, "state": {"st"},
		"redirect_uri": {"https://ci.local/api/auth/callback"}, "scope": {"openid"}}
	for k, v := range extra {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return q.Encode()
}

// wantRefused fails unless w is a door page with status and nothing more
// reached the upstream than before.
func (f *fixture) wantRefused(w *httptest.ResponseRecorder, status, before int, what string) {
	f.t.Helper()
	if w.Code != status || !isDoorPage(w) {
		f.t.Errorf("%s: %d (door page %v), want %d with the door page; body %.200q", what, w.Code, isDoorPage(w), status, w.Body.String())
	}
	if n := f.up.count(); n != before {
		f.t.Errorf("%s: forwarded (%d upstream requests, want %d)", what, n, before)
	}
}

// wantForwarded fails unless w came from the upstream.
func (f *fixture) wantForwarded(w *httptest.ResponseRecorder, before int, what string) {
	f.t.Helper()
	if n := f.up.count(); n != before+1 {
		f.t.Errorf("%s: %d upstream requests, want %d; answered %d %.200q", what, n, before+1, w.Code, w.Body.String())
	}
}
