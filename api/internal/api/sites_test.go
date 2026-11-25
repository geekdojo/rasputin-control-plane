package api

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door"
	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/events"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// The :443 site dispatcher's tests (geekdojo/geekdojo-brain#986). Every door
// case runs against a real TLS server serving NewSites, with one leaf per
// name, and real door.Build handlers relaying to a fake identity service, so
// the per-request deadline is set as it is in production (F-986-03). The
// client sets the TLS server name and the Host header separately.

const (
	sitesCID        = "ci"
	sitesConsole    = "ci.local"
	sitesVersion    = "ab12c"
	sitesLoginTheme = "/resources/" + sitesVersion + "/login/rasputin/"
)

// sitesUpstream is the fake identity service: it counts requests and sends
// Strict-Transport-Security on every answer, which no door may relay.
type sitesUpstream struct {
	srv *httptest.Server
	n   atomic.Int64
}

func newSitesUpstream(t *testing.T) *sitesUpstream {
	t.Helper()
	u := &sitesUpstream{}
	u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.n.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		q := r.URL.Query()
		switch {
		case q.Get("stream") == "1":
			// An answer larger than any socket buffer: it streams until the
			// relay stops reading.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			chunk := []byte(strings.Repeat("x", 64<<10))
			for {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		case q.Get("state") == "redirect":
			http.Redirect(w, r, "/realms/rasputin/login-actions/authenticate", http.StatusFound)
		case strings.HasSuffix(r.URL.Path, "openid-configuration"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"issuer":"https://sso-ci.local/realms/rasputin"}`)
		case strings.HasPrefix(r.URL.Path, "/resources/"):
			w.Header().Set("Content-Type", "text/css")
			_, _ = io.WriteString(w, ".rasp-card{}")
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, `<!doctype html><title>upstream</title><body data-page-id="upstream"></body>`)
		}
	}))
	u.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(u.srv.Close)
	return u
}

// sitesVersionSource reports the fixture's resource version.
type sitesVersionSource struct{}

func (sitesVersionSource) ResourceVersion(context.Context, string) (string, error) {
	return sitesVersion, nil
}

type sitesReady struct{}

func (sitesReady) Ready(context.Context) error { return nil }

// openSignal is the real drain signal, with its requests counted: one is
// open from Begin until its end is called.
type openSignal struct {
	sig          *events.Signal
	begun, ended atomic.Int64
}

func (o *openSignal) Begin() func() {
	end := o.sig.Begin()
	o.begun.Add(1)
	var once sync.Once
	return func() { once.Do(func() { end(); o.ended.Add(1) }) }
}

func (o *openSignal) MarkDirty() { o.sig.MarkDirty() }

func (o *openSignal) open() int64 { return o.begun.Load() - o.ended.Load() }

// counted counts the requests h receives and signals each return.
type counted struct {
	h        http.Handler
	n        atomic.Int64
	returned chan struct{}
}

func newCounted(h http.Handler) *counted { return &counted{h: h, returned: make(chan struct{}, 16)} }

func (c *counted) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.n.Add(1)
	defer func() {
		select {
		case c.returned <- struct{}{}:
		default: // only TC-986-10 waits on returns, for two requests
		}
	}()
	c.h.ServeHTTP(w, r)
}

// sitesOpts shape the rig.
type sitesOpts struct {
	console  http.Handler // nil: a counting stand-in answering "console"
	nilDoors bool         // Home and App nil
	doorsOff bool         // no door hosts
	lifetime time.Duration
}

type sitesRig struct {
	t         *testing.T
	table     doors.Table
	up        *sitesUpstream
	console   *counted
	home, app *counted
	signal    *openSignal
	srv       *httptest.Server
	roots     *x509.CertPool
	rec       *logkittest.Recorder
	handler   http.Handler
	ids       atomic.Int64
}

// consoleStandIn answers every request with "console", and at /ws/jobs
// takes the connection over as a WebSocket would and echoes lines.
func consoleStandIn() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws/jobs" && r.Header.Get("Upgrade") == "websocket" {
			conn, rw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_ = rw.Flush()
			for {
				line, err := rw.ReadString('\n')
				if err != nil {
					return
				}
				_, _ = rw.WriteString(line)
				_ = rw.Flush()
			}
		}
		_, _ = io.WriteString(w, "console")
	})
}

func newSitesRig(t *testing.T, o sitesOpts) *sitesRig {
	t.Helper()
	table, err := doors.New(sitesCID)
	if err != nil {
		t.Fatal(err)
	}
	r := &sitesRig{t: t, table: table, up: newSitesUpstream(t), signal: &openSignal{sig: events.NewSignal(time.Now)}}
	if o.console == nil {
		o.console = consoleStandIn()
	}
	if o.lifetime == 0 {
		o.lifetime = time.Minute
	}
	r.console = newCounted(o.console)
	log, rec := logkittest.New()
	r.rec = rec
	homeH, appH := r.buildDoors(log)
	r.home, r.app = newCounted(homeH), newCounted(appH)
	cfg := SitesConfig{Console: r.console, Home: r.home, App: r.app, HomeHost: table.Home.Host, AppHost: table.App.Host,
		RequestLifetime: o.lifetime, Now: time.Now, IDs: func() string { return "corr-" + strconv.FormatInt(r.ids.Add(1), 10) }, Log: log}
	if o.nilDoors {
		cfg.Home, cfg.App = nil, nil
	}
	if o.doorsOff {
		cfg.HomeHost, cfg.AppHost = "", ""
	}
	r.handler, err = NewSites(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.serve(t)
	return r
}

// buildDoors builds both doors as production does, over the fake upstream.
func (r *sitesRig) buildDoors(log *slog.Logger) (http.Handler, http.Handler) {
	t := r.t
	th, err := policy.NewThrottle(policy.ThrottleDeps{Table: r.table, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.New(policy.Deps{Table: r.table, Readiness: sitesReady{}, Throttle: th, AppClients: policy.NoAppClients{},
		Actions: policy.NoActionsIssued{}, Network: policy.RegistrationClosed{}, Waiting: policy.RegistrationClosed{}, Removed: sitesRemoved{}, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	allow, err := door.ParseAllowlist([]byte(`{"keycloak":"26.8.2","login":["css/signin.css"],"common":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	v, err := door.NewResourceVersion(sitesVersionSource{}, log)
	if err != nil {
		t.Fatal(err)
	}
	v.Learn(context.Background())
	up, err := url.Parse(r.up.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	home, app, err := door.Build(r.table, door.Shared{
		ConsoleOrigin: "https://" + sitesConsole, Policy: pol, Throttle: th, Transport: r.up.srv.Client().Transport,
		Upstream: up, Theme: allow, Version: v, Dirty: r.signal, Log: log,
		Assets: fstest.MapFS{
			"css/tokens.css": {Data: []byte(":root{}")}, "css/components.css": {Data: []byte(".b{}")},
			"css/signin.css": {Data: []byte(".c{}")}, "img/favicon.svg": {Data: []byte("<svg/>")},
		},
		InstallName: func(context.Context) (string, error) { return "CI", nil },
		IDs:         func() string { return "door-" + strconv.FormatInt(r.ids.Add(1), 10) },
		Breach:      struct{ door.Breach }{}, // never called: no case here posts a new password
		ResetDone:   sitesResetDone{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return home, app
}

// serve starts the TLS server: one leaf per name, chosen by SNI, the
// console's for every other name and for none.
func (r *sitesRig) serve(t *testing.T) {
	dir := t.TempDir()
	ca := tlscatest.Controlplane(t, filepath.Join(dir, "trust"))
	leaf := func(name string, spec tlsca.LeafSpec) tls.Certificate {
		p, err := ca.MintLeafToDisk(filepath.Join(dir, name), spec)
		if err != nil {
			t.Fatal(err)
		}
		c, err := tls.LoadX509KeyPair(p.CertPath, p.KeyPath)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	byName := map[string]tls.Certificate{}
	for _, h := range []string{r.table.Home.Host, r.table.App.Host} {
		byName[h] = leaf(h, tlsca.LeafSpec{Usage: tlsca.UsageServer, CommonName: h, DNSNames: []string{h}})
	}
	console := leaf("console", tlsca.LeafSpec{Usage: tlsca.UsageServer, CommonName: sitesConsole,
		DNSNames: []string{sitesConsole, "localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}})
	r.roots = x509.NewCertPool()
	r.roots.AddCert(ca.Cert)
	r.srv = httptest.NewUnstartedServer(r.handler)
	r.srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{console},
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c, ok := byName[siteName(h.ServerName)]; ok {
				return &c, nil
			}
			return &console, nil
		}}
	r.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	r.srv.StartTLS()
	t.Cleanup(r.srv.Close)
}

// tlsConfig is a client config sending sni ("" sends none: the address is
// an IP literal).
func (r *sitesRig) tlsConfig(sni string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: r.roots, ServerName: sni}
}

// answer is one response, its body read.
type answer struct {
	status int
	header http.Header
	body   string
}

// pageID is a page's data-page-id.
func (a answer) pageID() string {
	if m := regexp.MustCompile(`data-page-id="([^"]+)"`).FindStringSubmatch(a.body); m != nil {
		return m[1]
	}
	return ""
}

// sentence is a page's alert sentence, unescaped.
func (a answer) sentence() string {
	if m := regexp.MustCompile(`<span class="rasp-alert-text">([^<]*)</span>`).FindStringSubmatch(a.body); m != nil {
		return html.UnescapeString(m[1])
	}
	return ""
}

// coded is a coded error body.
func (a answer) coded() codedError {
	var c codedError
	_ = json.Unmarshal([]byte(a.body), &c)
	return c
}

// do sends one request with TLS server name sni and Host host.
func (r *sitesRig) do(sni, host, method, target string, hdr http.Header) answer {
	r.t.Helper()
	tr := &http.Transport{TLSClientConfig: r.tlsConfig(sni), DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(r.t.Context(), method, "https://"+r.srv.Listener.Addr().String()+target, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	req.Host = host
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	resp, err := (&http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}).Do(req)
	if err != nil {
		r.t.Fatalf("%s %s (SNI %q, Host %q): %v", method, target, sni, host, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		r.t.Fatal(err)
	}
	return answer{status: resp.StatusCode, header: resp.Header, body: string(b)}
}

// counts are the requests each handler and the upstream received.
func (r *sitesRig) counts() [4]int64 {
	return [4]int64{r.home.n.Load(), r.app.n.Load(), r.console.n.Load(), r.up.n.Load()}
}

// authQuery is a valid authorization request at door k, its state "st".
func authQuery(k door.Kind, extra string) string { return authQueryState(k, "st") + extra }

// authQueryState is a valid authorization request at door k with state.
func authQueryState(k door.Kind, state string) string {
	client := policy.ConsoleClient
	if k == door.App {
		client = "rasputin-account"
	}
	q := url.Values{"client_id": {client}, "response_type": {"code"}, "prompt": {"login"}, "state": {state},
		"redirect_uri": {"https://ci.local/api/auth/callback"}, "scope": {"openid"}}
	return "/realms/rasputin/protocol/openid-connect/auth?" + q.Encode()
}

// want421 fails unless a is the coded 421 with its sentence and no HSTS.
func want421(t *testing.T, what string, a answer) {
	t.Helper()
	c := a.coded()
	if a.status != http.StatusMisdirectedRequest || c.Code != codeMisdirectedRequest || c.Error != sentenceMisdirected || c.CorrelationID == "" {
		t.Errorf("%s: %d %q, want 421 %s with its sentence", what, a.status, a.body, codeMisdirectedRequest)
	}
	assertNoHSTS(t, what, a.header)
}

// TC-986-01: SNI sso-ci.local with Host ci.local answers the coded 421, with
// no HSTS; no door, no console and no upstream sees it; one WARN record names
// the two sites' kinds, never the names.
func TestSites_HomeSNIWithConsoleHostIs421(t *testing.T) {
	r := newSitesRig(t, sitesOpts{})
	a := r.do(r.table.Home.Host, sitesConsole, http.MethodGet, "/realms/rasputin/.well-known/openid-configuration", nil)
	want421(t, "SNI home, Host console", a)
	if c := r.counts(); c != [4]int64{} {
		t.Errorf("home, app, console, upstream saw %v, want none", c)
	}
	recs := r.rec.Matching(slog.LevelWarn, "api: request refused")
	if len(recs) != 1 {
		t.Fatalf("%d refusal records, want 1:\n%s", len(recs), r.rec.Text())
	}
	for k, want := range map[string]string{"code": codeMisdirectedRequest, "sni_site": "home", "host_site": "console", "correlation_id": a.coded().CorrelationID} {
		if v, _ := logkittest.Attr(recs[0], k); v != want {
			t.Errorf("record %s = %q, want %q", k, v, want)
		}
	}
	if text := r.rec.Text(); strings.Contains(text, sitesConsole) {
		t.Errorf("the record names a host: %s", text)
	}
}

// TC-986-02: every cross-site pair, both doors included, answers 421 and
// reaches no handler.
func TestSites_EveryCrossSitePairIs421(t *testing.T) {
	r := newSitesRig(t, sitesOpts{})
	home, app := r.table.Home.Host, r.table.App.Host
	for _, p := range [][2]string{
		{app, sitesConsole}, {sitesConsole, home}, {sitesConsole, app},
		{home, app}, {app, home}, {"", home}, {"", app},
	} {
		want421(t, fmt.Sprintf("SNI %q Host %q", p[0], p[1]), r.do(p[0], p[1], http.MethodGet, "/realms/rasputin/.well-known/openid-configuration", nil))
	}
	if c := r.counts(); c != [4]int64{} {
		t.Errorf("home, app, console, upstream saw %v, want none", c)
	}
}

// TC-986-03: a matching name reaches its site, whatever its case, a trailing
// dot or :443 on the Host; with no SNI every non-door Host is the console.
func TestSites_EachSiteByName(t *testing.T) {
	r := newSitesRig(t, sitesOpts{})
	home, app := r.table.Home.Host, r.table.App.Host
	disc := "/realms/rasputin/.well-known/openid-configuration"
	for _, c := range []struct {
		sni, host string
		at        *counted
	}{
		{home, home, r.home}, {strings.ToUpper(home), home + ".", r.home}, {home, strings.ToUpper(home) + ":443", r.home},
		{app, app, r.app}, {app, app + ".:443", r.app},
		{sitesConsole, sitesConsole, r.console}, {sitesConsole, "CI.LOCAL.:443", r.console},
		{"", sitesConsole, r.console}, {"", "192.168.1.5", r.console}, {"", "[::1]", r.console}, {"", "localhost", r.console},
		{"", sitesCID, r.console}, {"", "rasputin.local", r.console},
	} {
		before, up := c.at.n.Load(), r.up.n.Load()
		a := r.do(c.sni, c.host, http.MethodGet, disc, nil)
		if c.at.n.Load() != before+1 {
			t.Errorf("SNI %q Host %q: did not reach its site (%d %q)", c.sni, c.host, a.status, a.body)
		}
		if c.at == r.console {
			if a.body != "console" {
				t.Errorf("SNI %q Host %q: %q, want the console", c.sni, c.host, a.body)
			}
		} else if a.status != http.StatusOK || r.up.n.Load() != up+1 {
			t.Errorf("SNI %q Host %q: %d, not relayed by its door", c.sni, c.host, a.status)
		}
	}
	// A trailing dot on the server name never reaches a Go server from a Go
	// client, so the name rule is asked directly.
	if siteName("SSO-CI.LOCAL.") != home {
		t.Errorf("siteName did not fold %q", "SSO-CI.LOCAL.")
	}
}

// consoleWithUI is the real console handler over a UI export holding
// 404.html.
func consoleWithUI(t *testing.T) (http.Handler, string) {
	t.Helper()
	f := newAPIFixture(t)
	dir := t.TempDir()
	notFound := "<html>console not found</html>"
	for name, body := range map[string]string{"index.html": "<html>index</html>", "404.html": notFound} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f.srv.SetUIDir(dir)
	return f.srv.Handler(), notFound
}

// TC-986-04: the door paths at the console's names, IP literals and
// localhost answer the console's own 404 page and never reach the identity
// service.
func TestSites_ConsoleHostServesNoDoorPath(t *testing.T) {
	console, notFound := consoleWithUI(t)
	r := newSitesRig(t, sitesOpts{console: console})
	for _, path := range []string{
		"/realms/rasputin/.well-known/openid-configuration", "/realms/rasputin/protocol/openid-connect/auth",
		sitesLoginTheme + "x.css", "/_signin/x.css",
	} {
		for _, c := range [][2]string{{sitesConsole, sitesConsole}, {"", "192.168.1.5"}, {"", "[::1]"}, {"", "localhost"}, {"", sitesCID}} {
			a := r.do(c[0], c[1], http.MethodGet, path, nil)
			if a.status != http.StatusNotFound || a.body != notFound {
				t.Errorf("%s at %q: %d %.80q, want the console's 404 page", path, c[1], a.status, a.body)
			}
		}
	}
	if n := r.up.n.Load(); n != 0 {
		t.Errorf("the identity service saw %d requests", n)
	}
}

// TC-986-05: the console's routes at each door host answer that door's 404
// page; the console sees nothing and no rasputin- cookie is set.
func TestSites_DoorHostsServeNoConsoleRoute(t *testing.T) {
	r := newSitesRig(t, sitesOpts{})
	ws := http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}, "Sec-Websocket-Version": {"13"}, "Sec-Websocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="}}
	for _, d := range []struct {
		host, want string
	}{
		{r.table.Home.Host, "https://" + sitesConsole},
		{r.table.App.Host, "Sign in from the app you were using."},
	} {
		for _, path := range []string{"/", "/api/jobs", "/api/auth/status", "/healthz", "/ws/jobs", "/observability/x"} {
			var hdr http.Header
			if path == "/ws/jobs" {
				hdr = ws
			}
			a := r.do(d.host, d.host, http.MethodGet, path, hdr)
			if a.status != http.StatusNotFound || a.pageID() != "rasputin-door-refusal" || !strings.Contains(a.sentence(), d.want) {
				t.Errorf("%s at %s: %d %q %q, want the door's 404 page naming %q", path, d.host, a.status, a.pageID(), a.sentence(), d.want)
			}
			for _, c := range a.header.Values("Set-Cookie") {
				if strings.Contains(c, "rasputin-") {
					t.Errorf("%s at %s set %q", path, d.host, c)
				}
			}
		}
	}
	if n := r.console.n.Load(); n != 0 {
		t.Errorf("the console saw %d requests", n)
	}
}

// wantNotReady fails unless a is the door's not-ready page.
func wantNotReady(t *testing.T, what string, a answer, path string) {
	t.Helper()
	if a.status != http.StatusServiceUnavailable || a.pageID() != "rasputin-door-not-ready" || a.sentence() != sentenceSigninUnavailable ||
		!strings.Contains(a.body, `id="rasputin-try-again" href="`+html.EscapeString(path)+`"`) {
		t.Errorf("%s: %d %q, want the 503 not-ready page with TRY AGAIN to %s", what, a.status, a.body, path)
	}
	if got := a.header.Get("Content-Security-Policy"); got != notReadyPolicy {
		t.Errorf("%s: policy %q", what, got)
	}
	if a.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("%s: no nosniff", what)
	}
	assertNoHSTS(t, what, a.header)
}

// TC-986-08 (to the approved plan's F-986-05: an HTML page, its code in the
// WARN record): with no doors built, each door site answers the 503
// not-ready page with TRY AGAIN, and the console still answers.
func TestSites_DoorsNotBuiltAnswerTheNotReadyPage(t *testing.T) {
	console, _ := consoleWithUI(t)
	r := newSitesRig(t, sitesOpts{console: console, nilDoors: true})
	path := "/realms/rasputin/.well-known/openid-configuration?x=1"
	for _, h := range []string{r.table.Home.Host, r.table.App.Host} {
		wantNotReady(t, h, r.do(h, h, http.MethodGet, path, nil), path)
	}
	recs := r.rec.Matching(slog.LevelWarn, "api: request refused")
	if len(recs) != 2 {
		t.Fatalf("%d refusal records, want 2:\n%s", len(recs), r.rec.Text())
	}
	for _, rec := range recs {
		if v, _ := logkittest.Attr(rec, "code"); v != codeSigninUnavailable {
			t.Errorf("record code %q", v)
		}
		if v, _ := logkittest.Attr(rec, "correlation_id"); v == "" {
			t.Error("record has no correlation id")
		}
	}
	if a := r.do(sitesConsole, sitesConsole, http.MethodGet, "/healthz", nil); a.status != http.StatusOK || !strings.Contains(a.body, `"ok"`) {
		t.Errorf("console /healthz: %d %q", a.status, a.body)
	}
	if n := r.up.n.Load(); n != 0 {
		t.Errorf("the identity service saw %d requests", n)
	}
}

// TC-986-09: with the doors off every name is the console's; no 421.
func TestSites_DoorsOffIsTheConsoleEverywhere(t *testing.T) {
	r := newSitesRig(t, sitesOpts{doorsOff: true})
	pairs := [][2]string{
		{r.table.Home.Host, sitesConsole}, {sitesConsole, r.table.Home.Host}, {r.table.Home.Host, r.table.Home.Host},
		{r.table.App.Host, r.table.App.Host}, {"", r.table.App.Host}, {sitesConsole, sitesConsole},
	}
	for _, p := range pairs {
		if a := r.do(p[0], p[1], http.MethodGet, "/", nil); a.status != http.StatusOK || a.body != "console" {
			t.Errorf("SNI %q Host %q: %d %q, want the console", p[0], p[1], a.status, a.body)
		}
	}
	if n := r.console.n.Load(); n != int64(len(pairs)) {
		t.Errorf("console saw %d of %d", n, len(pairs))
	}
}

// TC-986-10: a door request is bounded by its lifetime: a client that never
// reads a large answer, and one that sends its body slowly, each has its
// door handler return and the drain signal's request closed, and the
// connection closed; a console WebSocket held open through the same server
// outlives ten lifetimes.
func TestSites_DoorRequestLifetime(t *testing.T) {
	const lifetime = 100 * time.Millisecond
	r := newSitesRig(t, sitesOpts{lifetime: lifetime})
	addr := r.srv.Listener.Addr().String()
	dial := func(sni string) *tls.Conn {
		c, err := tls.Dial("tcp", addr, r.tlsConfig(sni))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	returned := func(what string) {
		t.Helper()
		select {
		case <-r.home.returned:
		case <-t.Context().Done():
			t.Fatalf("%s: the door handler never returned", what)
		}
		if n := r.signal.open(); n != 0 {
			t.Errorf("%s: %d requests still open on the drain signal", what, n)
		}
	}
	closed := func(what string, c *tls.Conn) {
		t.Helper()
		// One read call's I/O bound, far outside the server's: the server
		// closes the connection once the handler has returned.
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, err := io.Copy(io.Discard, c)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Errorf("%s: the connection is still open", what)
		}
	}

	// The console's WebSocket, opened first.
	opened := time.Now()
	wsConn := dial(sitesConsole)
	if _, err := io.WriteString(wsConn, "GET /ws/jobs HTTP/1.1\r\nHost: "+sitesConsole+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	ws := bufio.NewReader(wsConn)
	if resp, err := http.ReadResponse(ws, nil); err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("the console WebSocket: %v %v", resp, err)
	}

	// A reader that never reads a streamed answer. Once the write deadline
	// fails a write, net/http closes the connection, and crypto/tls bounds
	// that close's alert by its own 5 s, so the handler returns within the
	// lifetime plus that bound, never later.
	host := r.table.Home.Host
	c := dial(host)
	if _, err := io.WriteString(c, "GET "+authQuery(door.Home, "&stream=1")+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	returned("a reader that never reads")
	if r.signal.begun.Load() != 1 {
		t.Errorf("the streamed answer opened %d requests on the signal, want 1", r.signal.begun.Load())
	}
	closed("a reader that never reads", c)

	// An uploader that sends a tenth of its body, then stops.
	c = dial(host)
	if _, err := io.WriteString(c, "POST "+authQuery(door.Home, "")+" HTTP/1.1\r\nHost: "+host+
		"\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\n\r\nusername="); err != nil {
		t.Fatal(err)
	}
	returned("a slow uploader")
	closed("a slow uploader", c)

	// The WebSocket still echoes, ten lifetimes after it opened. This wait
	// is the case's own measure; nothing in the code under test waits on it.
	if left := 10*lifetime - time.Since(opened); left > 0 {
		<-time.After(left)
	}
	if _, err := io.WriteString(wsConn, "ping\n"); err != nil {
		t.Fatalf("the console WebSocket was closed: %v", err)
	}
	if line, err := ws.ReadString('\n'); err != nil || line != "ping\n" {
		t.Errorf("the console WebSocket answered %q, %v", line, err)
	}
}

// TC-986-11 (to the approved plan's F-986-05: the HTML page): a writer that
// supports no deadline answers the not-ready page and the door is not
// called.
func TestSites_NoDeadlineIsNotReady(t *testing.T) {
	r := newSitesRig(t, sitesOpts{})
	req := httptest.NewRequest(http.MethodGet, "/realms/rasputin/.well-known/openid-configuration", nil)
	req.Host = r.table.Home.Host
	req.TLS = &tls.ConnectionState{ServerName: r.table.Home.Host}
	w := httptest.NewRecorder()
	r.handler.ServeHTTP(w, req)
	b, _ := io.ReadAll(w.Result().Body)
	wantNotReady(t, "a writer with no deadlines", answer{status: w.Code, header: w.Header(), body: string(b)}, req.URL.RequestURI())
	if n := r.home.n.Load(); n != 0 {
		t.Errorf("the door was called %d times", n)
	}
	if v, _ := logkittest.Attr(r.rec.Matching(slog.LevelWarn, "api: request refused")[0], "code"); v != codeSigninUnavailable {
		t.Errorf("record code %q", v)
	}
}

// The not-ready page's TRY AGAIN never names another host.
func TestSites_TryAgainStaysOnTheSite(t *testing.T) {
	r := newSitesRig(t, sitesOpts{nilDoors: true})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.URL.Path = "//evil.example/x"
	req.Host = r.table.Home.Host
	req.TLS = &tls.ConnectionState{ServerName: r.table.Home.Host}
	w := httptest.NewRecorder()
	r.handler.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), `id="rasputin-try-again" href="/"`) {
		t.Errorf("TRY AGAIN: %s", w.Body.String())
	}
}

// TC-986-12: NewSites refuses each missing or invalid collaborator, naming
// it, and accepts nil doors with both hosts set.
func TestNewSites_RefusesMissingCollaborators(t *testing.T) {
	log, _ := logkittest.New()
	full := func() SitesConfig {
		return SitesConfig{Console: http.NotFoundHandler(), HomeHost: "sso-ci.local", AppHost: "signin.ci.internal",
			RequestLifetime: time.Minute, Now: time.Now, IDs: func() string { return "id" }, Log: log}
	}
	for field, mutate := range map[string]func(*SitesConfig){
		"Console":         func(c *SitesConfig) { c.Console = nil },
		"Now":             func(c *SitesConfig) { c.Now = nil },
		"IDs":             func(c *SitesConfig) { c.IDs = nil },
		"Log":             func(c *SitesConfig) { c.Log = nil },
		"RequestLifetime": func(c *SitesConfig) { c.RequestLifetime = 0 },
		"HomeHost":        func(c *SitesConfig) { c.AppHost = "" },
	} {
		c := full()
		mutate(&c)
		if _, err := NewSites(c); err == nil || !strings.Contains(err.Error(), field) {
			t.Errorf("%s: err = %v, want one naming it", field, err)
		}
	}
	c := full()
	c.RequestLifetime = -time.Second
	if _, err := NewSites(c); err == nil || !strings.Contains(err.Error(), "RequestLifetime") {
		t.Errorf("a negative lifetime: %v", err)
	}
	c = full()
	c.HomeHost = ""
	if _, err := NewSites(c); err == nil {
		t.Error("an app host with no home host was accepted")
	}
	if _, err := NewSites(full()); err != nil {
		t.Errorf("nil doors with both hosts: %v", err)
	}
}

// sitesRemoved is a removed-name list holding no name.
type sitesRemoved struct{}

func (sitesRemoved) Removed(context.Context, string, string) (bool, error) { return false, nil }

// sitesResetDone is the app door's reset return: route enumeration only
// needs it to answer.
type sitesResetDone struct{}

func (sitesResetDone) Finish(context.Context, url.Values) (string, string) {
	return "reset-failed", "Rasputin couldn't confirm the password reset."
}
