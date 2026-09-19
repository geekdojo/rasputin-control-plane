package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
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
// Extending it to roles (geekdojo/geekdojo-brain#320): enumerateRoutes and
// routeProbe are the reusable half. A per-role matrix replaces the single
// "401 unless open" expectation with a table from pattern to required
// capability, runs the same probes with one session per role, and expects 403
// where the role lacks the capability. Keep the enumeration authoritative —
// derive probes from the mux, never from a copied list.

// openRoutes is the allowlist of routes on Handler() that deliberately answer
// without a session. Keyed by the exact registered pattern; the value is the
// reason, in one line. Adding an entry is a security decision — say why.
var openRoutes = map[string]string{
	"GET /healthz": "liveness probe; part of the documented install contract (AGENTS.md)",

	"GET /api/auth/status":            "drives the first-run flow before any passkey exists; reports only whether users exist",
	"POST /api/auth/logout":           "clears the caller's own session cookie; nothing to protect",
	"POST /api/auth/register/begin":   "first-run registration; once a user exists it requires a session itself (auth/handlers.go)",
	"POST /api/auth/register/finish":  "completes a ceremony begin already gated; needs the pending cookie begin issued",
	"POST /api/auth/register/step-up": "continues a ceremony begin already gated: 400 without begin's pending cookie, and 401 unless the session that began it is still signed in (auth/handlers.go)",
	"POST /api/auth/login/begin":      "the passkey login ceremony — the way a session is obtained",
	"POST /api/auth/login/finish":     "the passkey login ceremony — the way a session is obtained",

	"GET /api/setup/state": "the setup wizard reads step state before any passkey exists; carries no secrets",

	"GET /api/mesh/ios-profile": "Mesh CA public cert (iOS profile envelope); must install before the first HTTPS passkey ceremony",
	"GET /mesh-ca.pem":          "Mesh CA public cert; must install before the first HTTPS passkey ceremony",
	"GET /mesh-ca.crt":          "Mesh CA public cert (Windows envelope); must install before the first HTTPS passkey ceremony",

	"GET /flash.sh":                   "static, secret-free node flasher script run from a laptop with no session",
	"GET /api/cluster/node-image":     "public OS image URL + checksum for the laptop-side flasher",
	"GET /api/cluster/firewall-image": "public firewall image URL + checksum for the laptop-side flasher",
	"GET /api/restore/candidates":     "restore-before-first-boot: a re-flashed controlplane has no users; answers 409 once an operator exists",
	"POST /api/restore":               "restore-before-first-boot: a re-flashed controlplane has no users; answers 409 once an operator exists",
	"GET /api/bundles/{sha}":          "content-addressed update bundle fetched by node agents, which carry no session; the SHA-256 is the capability",
	"GET /api/bundles/{sha}/sig":      "detached signature for the content-addressed bundle above; public by construction",
	"/":                               "static web UI export; pages hold no data and fetch everything through gated /api routes",
}

// probePathFor overrides the placeholder path for a route whose own parser
// refuses a malformed path (400) before it reaches its credential check. The
// backup transport endpoints are not behind the session gate — their callers
// are node agents — and authenticate with a per-member bearer credential; a
// well-formed path makes the probe meet that check and its 401.
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
	// so the probes meet the per-member credential check they rely on.
	authority, err := backupxfer.NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetBackupIngest(backupxfer.New(authority, backupxfer.DefaultConcurrency))
	f.srv.SetAppRestore(&storage.RestoreAppConfig{}, storage.NewRestoreEgress(authority, storage.NewRestoreSessions()))
	f.handler = f.srv.Handler()
	return f
}

func TestEveryRouteRequiresSessionUnlessAllowlisted(t *testing.T) {
	f := routeFixture(t)
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

	// Stale allowlist: every entry must name a registered route.
	var stale []string
	for p := range openRoutes {
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
		"GET /api/setup/state":      "the /trust page reads the cluster name before the Mesh CA is trusted (bootstrap.go); carries no secrets",
		"GET /mesh-ca.pem":          "Mesh CA public cert for the first-run trust page",
		"GET /mesh-ca.crt":          "Mesh CA public cert (Windows envelope) for the first-run trust page",
		"GET /api/mesh/ios-profile": "Mesh CA public cert (iOS profile) for the first-run trust page",
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

// Every obs-ingress route authenticates by the verified client certificate;
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
		f.srv.ingestGated = gated
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
