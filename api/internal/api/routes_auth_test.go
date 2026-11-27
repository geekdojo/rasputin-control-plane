package api

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Route-enumeration auth test (geekdojo/geekdojo-brain#108; gate 2,
// geekdojo/geekdojo-brain#489).
//
// It reads the routes off the recording mux the server itself routes with
// (routes(), bootstrapRoutes(), obsIngestRoutes()), requests every one with no
// session, and requires 401 — unless the pattern is in openRoutes, where each
// entry says why the route is meant to answer without a session. So:
//
//   - a new route registered without the session gate fails this test until
//     someone either gates it or argues for it in openRoutes;
//   - an openRoutes entry that matches no registered route fails (stale), and
//     so does one whose route answers 401 anyway (it does not need to be open,
//     so it must not sit on the list).
//
// The per-role matrix is routes_matrix_test.go (geekdojo/geekdojo-brain#1002):
// it reuses enumerateRoutes and routeProbe, reads each route's class off the
// same recording mux, and checks it against a literal table with one session
// per role. Keep the enumeration authoritative — derive probes from the mux,
// never from a copied list.

// openRoutes is the allowlist of routes on Handler() that deliberately answer
// without a session. Keyed by the exact registered pattern; the value is the
// reason, in one line. Adding an entry is a security decision — say why.
var openRoutes = map[string]string{
	"GET /healthz": "liveness probe; part of the documented install contract (AGENTS.md)",

	"GET /api/auth/status":  "drives the launcher before anyone signs in: firstRun and ready, and the caller's own user; never a count",
	"POST /api/auth/logout": "clears the caller's own session cookie; nothing to protect",
	// TC-990-06 and TC-990-26: account creation at the home door (#990);
	// register/* is gone.
	"GET /api/auth/signup":        "starts account creation at the home door (prompt=create), whose return is a sign-in at the callback; it only redirects and stores a pending record, and the door decides who may create an account",
	"POST /api/auth/login/begin":  "the pre-update passkey sign-in, gone: answers 410 and does no ceremony work (geekdojo/geekdojo-brain#989)",
	"POST /api/auth/login/finish": "the pre-update passkey sign-in, gone: answers 410 and does no ceremony work (geekdojo/geekdojo-brain#989)",
	// TC-1005-24: the move's bridge (geekdojo/geekdojo-brain#1005), open
	// because its person holds no credential the identity service knows.
	"POST /api/auth/bridge/begin":    "starts a pre-update passkey ceremony; stores only its challenge under a fresh host-only cookie, capped and bounded",
	"POST /api/auth/bridge/finish":   "verifies a pre-update passkey with user verification; yields only a single-use grant for that account's first password, never a session",
	"GET /api/auth/bridge":           "whether /login offers the bridge, and the caller's own grant's names; no count and no other account",
	"POST /api/auth/bridge/password": "needs the caller's own live grant; submits only accounts.set_first_password for that account, which the kind table decides",
	// TC-989-27: the console's sign-in through the home door (#989).
	"GET /api/auth/signin": "starts the home-door sign-in, the way a session is obtained; it only redirects and stores a pending record; with ?action= it resolves the caller's own session and answers 401 without one",
	// TC-992-22: the reset clients' return (geekdojo/geekdojo-brain#992).
	"GET /api/auth/reset-done":                "both reset clients' return; it exchanges the code, ends the person's sessions and mints none",
	"GET /api/auth/callback":                  "the home door's return; a session is minted only for a verified ID token matching the pending record",
	"POST /api/identity/backchannel/{client}": "the identity service's back-channel logout; acts only on a logout token verified against the client's issuer",

	"GET /api/setup/state": "the setup wizard reads step state before any passkey exists; carries no secrets",

	"GET /api/mesh/ios-profile": "controlplane CA public cert (iOS profile envelope); must install before the first HTTPS passkey ceremony",
	"GET /mesh-ca.pem":          "controlplane CA public cert; must install before the first HTTPS passkey ceremony",
	"GET /mesh-ca.crt":          "controlplane CA public cert (Windows envelope); must install before the first HTTPS passkey ceremony",

	"GET /flash.sh":                   "static, secret-free node flasher script run from a laptop with no session",
	"GET /api/cluster/node-image":     "public OS image URL + checksum for the laptop-side flasher",
	"GET /api/cluster/firewall-image": "public firewall image URL + checksum for the laptop-side flasher",
	"GET /api/restore/candidates":     "restore-before-first-boot: a re-flashed controlplane has no users; answers 409 once an operator exists",
	"POST /api/restore":               "restore-before-first-boot: a re-flashed controlplane has no users; answers 409 once an operator exists",
	"GET /api/bundles/{sha}":          "content-addressed update bundle fetched by node agents, which carry no session; the SHA-256 is the capability",
	"GET /api/bundles/{sha}/sig":      "detached signature for the content-addressed bundle above; public by construction",
	"/":                               "static web UI export; pages hold no data and fetch everything through gated /api routes",

	// geekdojo/geekdojo-brain#321: break-glass, open because sign-in is what is broken.
	"POST /api/auth/break-glass": "redeems a one-time repair code from the body; the code is the authentication; two-origin check; five wrong per source refuse it",
	"GET /api/repair/ways":       "the ways to get a repair code on this control plane (screen, serial only without the BMC-host marker, the ssh command); no secret, no session",
}

// probePathFor overrides the placeholder path for a route whose own parser
// refuses a malformed path (400) before it reaches its authentication. The
// backup transport endpoints live on the node listener only; a well-formed
// path makes the probe meet the key check and its 401.
var probePathFor = map[string]string{
	"PUT " + backupxfer.IngestPathPrefix: backupxfer.IngestPathPrefix + "probe/" + probeMember,
	"GET " + backupxfer.EgressPathPrefix: backupxfer.EgressPathPrefix + "probe/" + probeMember,
}

const probeMember = proto.BackupVolumesDir + "/probe/probe" + proto.BackupMemberSuffix

// routeProbe is one concrete request derived from a registered pattern.
type routeProbe struct {
	pattern string // the pattern as registered
	method  string
	path    string
}

// probeMethods are the methods a method-less pattern is probed with — it
// matches every method, so each must be refused.
var probeMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// enumerateRoutes turns registered ServeMux patterns into concrete requests:
// every {wildcard} gets a placeholder segment, a trailing-slash prefix pattern
// gets a segment appended so the probe is inside the subtree, and a
// method-less pattern is probed with each of probeMethods.
func enumerateRoutes(t *testing.T, patterns []string) []routeProbe {
	t.Helper()
	var out []routeProbe
	for _, p := range patterns {
		method, path, hasMethod := strings.Cut(p, " ")
		if !hasMethod {
			method, path = "", p
		}
		if !strings.HasPrefix(path, "/") {
			t.Fatalf("pattern %q: host-qualified patterns are not handled by this test; extend enumerateRoutes", p)
		}
		concrete := concretePath(path)
		if override, ok := probePathFor[p]; ok {
			concrete = override
		}
		methods := []string{method}
		if method == "" {
			methods = probeMethods
		}
		for _, m := range methods {
			out = append(out, routeProbe{pattern: p, method: m, path: concrete})
		}
	}
	return out
}

func concretePath(path string) string {
	// {$} anchors a pattern to its exact trailing-slash path: no segment to
	// append, unlike a prefix pattern.
	if exact, ok := strings.CutSuffix(path, "{$}"); ok {
		return fillWildcards(exact)
	}
	out := fillWildcards(path)
	if strings.HasSuffix(out, "/") && out != "/" {
		out += "probe"
	}
	return out
}

func fillWildcards(path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		switch {
		case strings.HasPrefix(s, "{") && strings.HasSuffix(s, "...}"):
			segs[i] = "probe/probe"
		case strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}"):
			segs[i] = "probe"
		}
	}
	return strings.Join(segs, "/")
}

// newProbeRequest builds a sessionless request; /ws/ routes get the WebSocket
// upgrade headers so the gate is exercised on the handshake a browser sends.
func newProbeRequest(pr routeProbe) *http.Request {
	req := httptest.NewRequest(pr.method, pr.path, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	if strings.HasPrefix(pr.path, "/ws/") {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		// Any 16 bytes, base64-encoded, is a well-formed handshake key.
		req.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString([]byte("route-probe-key!")))
	}
	return req
}

// routeFixture is an api fixture with a UI dir, so the "/" fallback route is
// registered exactly as on an appliance.
func routeFixture(t *testing.T) *apiFixture {
	t.Helper()
	f := newAPIFixture(t)
	uiDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(uiDir, "index.html"), []byte("<html>index</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.srv.SetUIDir(uiDir)
	// The backup transport endpoints answer 503 until wired, which would say
	// nothing about their gate. Wire them as main.go does, over one authority,
	// so a probe of the node listener meets its key check.
	authority, err := backupxfer.NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetBackupIngest(backupxfer.New(authority, backupxfer.DefaultConcurrency, slog.New(slog.DiscardHandler)))
	f.srv.SetAppRestore(&storage.RestoreAppConfig{}, storage.NewRestoreEgress(authority, storage.NewRestoreSessions(), slog.New(slog.DiscardHandler)))
	f.handler = f.srv.Handler()
	return f
}

// doorOpenRoutes is the open-route registry the stale check reads: openRoutes
// plus every sign-in door route with its reason (geekdojo/geekdojo-brain#985,
// F-985-19). A door request carries no Rasputin session, so each door pattern
// is an open route; the reason text lives once, on the door's Route. It fails
// on a pattern that collides with an openRoutes entry, or one the two doors
// give different reasons.
func doorOpenRoutes(t *testing.T) (all map[string]string, doorPatterns map[string]bool) {
	t.Helper()
	all = map[string]string{}
	for p, why := range openRoutes {
		all[p] = why
	}
	doorPatterns = map[string]bool{}
	for _, k := range []door.Kind{door.Home, door.App} {
		for _, r := range door.Routes(k) {
			if why, ok := all[r.Pattern]; ok && (!doorPatterns[r.Pattern] || why != r.Reason) {
				t.Fatalf("door route %q collides with the open-route entry %q", r.Pattern, why)
			}
			all[r.Pattern] = r.Reason
			doorPatterns[r.Pattern] = true
		}
	}
	return all, doorPatterns
}

// TC-986-06: route enumeration sees each site's mux. Every door pattern,
// made concrete, answers at its own door through NewSites over a real TLS
// server, relayed to the identity service or served as a door page: never
// 401, never 503 and never the console. A pattern only the other door serves
// answers this door's 404 page, and every pattern at the console's name
// answers the console's own 404 page.
func TestDoorRoutesAnswerAtTheirOwnDoor(t *testing.T) {
	console, notFound := consoleWithUI(t)
	r := newSitesRig(t, sitesOpts{console: console})
	probed := 0
	for _, d := range []struct {
		kind, other door.Kind
		host        string
	}{{door.Home, door.App, r.table.Home.Host}, {door.App, door.Home, r.table.App.Host}} {
		own := map[string]bool{}
		for _, rt := range door.Routes(d.kind) {
			own[rt.Pattern] = true
			probed++
			path := concretePath(rt.Pattern)
			consoleBefore, upBefore := r.console.n.Load(), r.up.n.Load()
			a := r.do(d.host, d.host, rt.Methods[0], path, nil)
			relayed := r.up.n.Load() == upBefore+1
			if a.status == http.StatusUnauthorized || a.status == http.StatusServiceUnavailable || r.console.n.Load() != consoleBefore ||
				(!relayed && !strings.HasPrefix(a.pageID(), "rasputin-door-")) {
				t.Errorf("%s %s at %s: %d %q (relayed %v), want the door's answer", rt.Methods[0], path, d.host, a.status, a.pageID(), relayed)
			}
			a = r.do(sitesConsole, sitesConsole, http.MethodGet, path, nil)
			if _, also := openRoutes["GET "+rt.Pattern]; also {
				// The console serves the same path for its own door: the home
				// reset client's return (geekdojo/geekdojo-brain#992).
				if a.status == http.StatusNotFound || strings.HasPrefix(a.pageID(), "rasputin-door-") {
					t.Errorf("%s at %s: %d %q, want the console's own route", path, sitesConsole, a.status, a.pageID())
				}
				continue
			}
			if a.status != http.StatusNotFound || a.body != notFound {
				t.Errorf("%s at %s: %d, want the console's 404 page", path, sitesConsole, a.status)
			}
		}
		for _, rt := range door.Routes(d.other) {
			if own[rt.Pattern] {
				continue
			}
			path := concretePath(rt.Pattern)
			if a := r.do(d.host, d.host, http.MethodGet, path, nil); a.status != http.StatusNotFound || a.pageID() != "rasputin-door-refusal" {
				t.Errorf("%s (the other door's) at %s: %d %q, want this door's 404 page", path, d.host, a.status, a.pageID())
			}
		}
	}
	if want := len(door.Routes(door.Home)) + len(door.Routes(door.App)); probed != want || probed < 15 {
		t.Fatalf("probed %d door patterns, want %d", probed, want)
	}
	if n := r.console.n.Load(); n != int64(probed) {
		t.Errorf("the console saw %d requests, want only the %d at its own name", n, probed)
	}
}

// TC-985-35: every door pattern sits in the registry with its reason.
func TestDoorRoutesAreOpenRoutesWithReasons(t *testing.T) {
	all, doorPatterns := doorOpenRoutes(t)
	if len(doorPatterns) < 15 {
		t.Fatalf("%d door patterns in the registry", len(doorPatterns))
	}
	for p := range doorPatterns {
		if strings.TrimSpace(all[p]) == "" {
			t.Errorf("door route %q has no reason", p)
		}
	}
}

func TestEveryRouteRequiresSessionUnlessAllowlisted(t *testing.T) {
	f := routeFixture(t)
	allOpen, doorPatterns := doorOpenRoutes(t)
	patterns := f.srv.routes().Patterns()
	if len(patterns) < 100 {
		// A guard on the enumeration itself: if registration stops going
		// through the recording mux, this test would otherwise pass vacuously.
		t.Fatalf("enumerated only %d routes; is Handler still registering through routeMux?", len(patterns))
	}

	registered := map[string]bool{}
	for _, p := range patterns {
		if registered[p] {
			t.Errorf("pattern %q registered twice", p)
		}
		registered[p] = true
	}

	// Stale allowlist: every entry must name a registered route. The door
	// routes are registered on the doors' own handlers, which NewSites serves
	// at each door's own name (sites.go), so they count as registered here and
	// skip the console's 401 probe; TestDoorRoutesAnswerAtTheirOwnDoor probes
	// them at their doors.
	for p := range doorPatterns {
		registered[p] = true
	}
	var stale []string
	for p := range allOpen {
		if !registered[p] {
			stale = append(stale, p)
		}
	}
	sort.Strings(stale)
	for _, p := range stale {
		t.Errorf("openRoutes entry %q matches no registered route; remove it", p)
	}

	gated, open := 0, 0
	for _, pr := range enumerateRoutes(t, patterns) {
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, newProbeRequest(pr))
		_, allowlisted := openRoutes[pr.pattern]
		switch {
		case allowlisted && w.Code == http.StatusUnauthorized:
			t.Errorf("%s %s (pattern %q) is allowlisted as open but answers 401 without a session; remove it from openRoutes",
				pr.method, pr.path, pr.pattern)
		case allowlisted:
			open++
		case w.Code != http.StatusUnauthorized:
			t.Errorf("%s %s (pattern %q) answered %d without a session, want 401. Gate it with the session middleware, "+
				"or add it to openRoutes with the reason it must be open.", pr.method, pr.path, pr.pattern, w.Code)
		default:
			gated++
		}
	}
	t.Logf("%d routes: %d probes refused without a session, %d probes on allowlisted open routes", len(patterns), gated, open)
}

// The bootstrap listener is plain HTTP. Its own routes are all open by design
// (bootstrap.go's exposure invariant), and every route Handler() gates must be
// unreachable through it: bounced to HTTPS before it touches the API mux.
func TestBootstrapListenerServesNoGatedRoute(t *testing.T) {
	f := routeFixture(t)

	bootstrapOpen := map[string]string{
		"GET /healthz":              "liveness over plain HTTP for the QEMU smoke and TLS-less probes",
		"GET /api/setup/state":      "the /trust page reads the cluster name before the controlplane CA is trusted (bootstrap.go); carries no secrets",
		"GET /mesh-ca.pem":          "controlplane CA public cert for the first-run trust page",
		"GET /mesh-ca.crt":          "controlplane CA public cert (Windows envelope) for the first-run trust page",
		"GET /api/mesh/ios-profile": "controlplane CA public cert (iOS profile) for the first-run trust page",
		"/":                         "fallback: the /trust page and static assets, otherwise a 302 to https",
	}
	for _, p := range f.srv.bootstrapRoutes().Patterns() {
		if _, ok := bootstrapOpen[p]; !ok {
			t.Errorf("bootstrap listener registers %q, which is outside its exposure invariant (bootstrap.go)", p)
		}
		if reason, ok := openRoutes[p]; p != "/" && (!ok || reason == "") {
			t.Errorf("bootstrap route %q is not open on the main handler; the plain-HTTP surface must be a subset of it", p)
		}
	}

	boot := f.srv.BootstrapHandler()
	for _, pr := range enumerateRoutes(t, f.srv.routes().Patterns()) {
		if _, ok := openRoutes[pr.pattern]; ok {
			continue
		}
		w := httptest.NewRecorder()
		boot.ServeHTTP(w, newProbeRequest(pr))
		redirected := w.Code == http.StatusFound && strings.HasPrefix(w.Header().Get("Location"), "https://")
		// An asset-shaped path (the backup members end in .rasputin-archive)
		// goes to the static export instead, which has no such file.
		staticMiss := w.Code == http.StatusNotFound && bootstrapUIPath(pr.path)
		if !redirected && !staticMiss {
			t.Errorf("bootstrap %s %s (gated pattern %q): got %d Location=%q, want a 302 to https",
				pr.method, pr.path, pr.pattern, w.Code, w.Header().Get("Location"))
		}
	}
}

// Every node-listener route authenticates by the key the caller presented;
// a request with no TLS state must be refused. A server whose listener was
// never given the node admission gate (WireObsIngest) refuses everything with
// 503 before it looks at the certificate: fail closed.
func TestObsIngestRoutesRequireClientCert(t *testing.T) {
	f := routeFixture(t)
	patterns := f.srv.obsIngestRoutes().Patterns()
	if len(patterns) == 0 {
		t.Fatal("no obs ingress routes enumerated")
	}
	for _, gated := range []bool{false, true} {
		f.srv.nodeGate = nil
		if gated {
			f.srv.nodeGate = newIngestConns(f.srv.inv.Registry(), slog.New(slog.DiscardHandler))
		}
		want := http.StatusServiceUnavailable
		if gated {
			want = http.StatusUnauthorized
		}
		h := f.srv.ObsIngestHandler()
		for _, pr := range enumerateRoutes(t, patterns) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, newProbeRequest(pr))
			if w.Code != want {
				t.Errorf("obs ingress (gated=%v) %s %s answered %d without a client certificate, want %d",
					gated, pr.method, pr.path, w.Code, want)
			}
		}
	}
}

// TC-516-08: backup transfer is served on the node listener only. The public
// mux registers neither route, the node-listener mux registers both, and a
// PUT and a GET to those paths through Handler(), with a live credential for
// an open generation, are refused without the ingest landing or recording
// anything.
func TestBackupTransferIsNotOnThePublicListener(t *testing.T) {
	transfer := []string{"PUT " + backupxfer.IngestPathPrefix, "GET " + backupxfer.EgressPathPrefix}
	public := patternSet(routeFixture(t).srv.routes().Patterns())
	node := patternSet((&Server{}).obsIngestRoutes().Patterns())
	for _, p := range transfer {
		if public[p] {
			t.Errorf("the public listener registers %s", p)
		}
		if !node[p] {
			t.Errorf("the node listener does not register %s", p)
		}
	}

	f := routeFixture(t)
	logger, records := logkittest.New()
	authority, err := backupxfer.NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	ing := backupxfer.New(authority, 1, logger)
	f.srv.SetBackupIngest(ing)
	f.srv.SetAppRestore(&storage.RestoreAppConfig{}, storage.NewRestoreEgress(authority, storage.NewRestoreSessions(), logger))
	h := f.srv.Handler()
	const gen = "20261004T120000Z-JOB51600-full"
	if _, err := ing.Open(filepath.Join(t.TempDir(), proto.BackupGenerationsDir), gen, "job-516"); err != nil {
		t.Fatal(err)
	}
	member := proto.BackupMemberPath("vaultwarden", "vaultwarden-data")
	cred, err := ing.Mint(backupxfer.Grant{Generation: gen, Member: member, NodeID: "n1", JobID: "job-516", MaxBytes: 1 << 20}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodPut, http.MethodGet} {
		prefix := backupxfer.IngestPathPrefix
		if method == http.MethodGet {
			prefix = backupxfer.EgressPathPrefix
		}
		req := httptest.NewRequest(method, prefix+gen+"/"+member, strings.NewReader("sealed bytes"))
		req.Header.Set("Authorization", "Bearer "+cred)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code >= 200 && w.Code < 300 {
			t.Errorf("%s %s through the public handler = %d, want a refusal", method, prefix, w.Code)
		}
	}
	if _, ok := ing.Landed(gen, member); ok {
		t.Error("the ingest landed a member sent to the public listener")
	}
	if n := len(records.Records()); n != 0 {
		t.Errorf("the transfer endpoints wrote %d record(s) for requests to the public listener:\n%s", n, records.Text())
	}
}

func patternSet(ps []string) map[string]bool {
	m := map[string]bool{}
	for _, p := range ps {
		m[p] = true
	}
	return m
}

func TestConcretePath(t *testing.T) {
	for in, want := range map[string]string{
		"/api/jobs":                      "/api/jobs",
		"/api/jobs/{id}/steps":           "/api/jobs/probe/steps",
		"/api/backup/ingest/":            "/api/backup/ingest/probe",
		"/observability/":                "/observability/probe",
		"/":                              "/",
		"/files/{rest...}":               "/files/probe/probe",
		"/exact/{$}":                     "/exact/",
		"/api/bmc/{nodeId}/power/{verb}": "/api/bmc/probe/power/probe",
	} {
		if got := concretePath(in); got != want {
			t.Errorf("concretePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TC-985-20: the observability proxy, which strips the api's own cookies
// through auth.StripCookies, also drops their __Host- and __Secure- names,
// so Grafana never receives __Host-rasputin-session.
func TestObsProxy_StripsPrefixedOwnCookies(t *testing.T) {
	var got atomic.Value // []string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Values("Cookie"))
		w.WriteHeader(http.StatusOK)
	}))
	defer stub.Close()
	sup := &fakeSupGrafana{healthy: true, vmURL: "http://x", grafanaURL: stub.URL}
	sink, _ := obs.NewVMSink(obs.VMSinkConfig{Supervisor: sup})
	srv := &Server{obs: obs.NewStatus(sup, sink, nil)}
	req := httptest.NewRequest(http.MethodGet, "/observability/api/search", nil)
	req.Header.Set("Cookie", "__Host-rasputin-session=s3cret; grafana_session=g1; __Secure-rasputin-pending=p; rasputin-repair=r")
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Sub: "sub-alice", Name: "alice"}))
	w := httptest.NewRecorder()
	srv.handleObservabilityProxy(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	cookies, _ := got.Load().([]string)
	if joined := strings.Join(cookies, "; "); joined != "grafana_session=g1" {
		t.Errorf("Cookie at Grafana = %q, want grafana_session=g1", joined)
	}
}
