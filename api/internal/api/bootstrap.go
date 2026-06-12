package api

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
)

// BootstrapHandler returns the handler main.go mounts on the PLAIN-HTTP
// listener when the api also serves HTTPS (RASPUTIN_HTTPS_ADDR set). At
// that point plain HTTP stops being the primary surface and becomes a
// bootstrap/escape hatch with three jobs:
//
//  1. First-run trust bootstrap: a fresh appliance's Mesh CA isn't in any
//     browser yet, so https:// greets the operator with a cert warning.
//     Instead, http://rasputin.local lands on the UI's /trust page (no
//     warning possible over plain HTTP), which serves the CA-download
//     endpoints and walks the operator through installing it. The page's
//     "Continue securely" link then crosses over to https://.
//  2. GET /healthz stays reachable over HTTP for the QEMU smoke test and
//     dumb LB probes that don't speak TLS or trust the Mesh CA.
//  3. Everything else 302s to the same path on https:// (port stripped),
//     so bookmarks and API clients migrate themselves.
//
// Exposure invariant: the only handlers reachable here are handleHealth,
// the two CA-download endpoints (already unauthenticated on the main
// handler — the CA cert is public material), and the static UI files
// needed to render /trust. No session-gated or mutating route gains a
// plain-HTTP surface: anything not allowlisted is redirected before it
// touches the API mux, and the redirect target is the fully-gated HTTPS
// handler.
//
// When RASPUTIN_HTTPS_ADDR is unset, main.go never calls this and the
// HTTP listener serves Handler() exactly as before.
func (s *Server) BootstrapHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /mesh-ca.pem", s.handleMeshCAPEM)
	mux.HandleFunc("GET /api/mesh/ios-profile", s.handleMeshIOSProfile)
	mux.HandleFunc("/", s.handleBootstrapFallback)
	return mux
}

// handleBootstrapFallback decides, for every path the bootstrap mux
// doesn't explicitly own: serve a static UI file, send the operator to
// the trust page, or bounce to HTTPS.
func (s *Server) handleBootstrapFallback(w http.ResponseWriter, r *http.Request) {
	p := path.Clean("/" + r.URL.Path)
	isRead := r.Method == http.MethodGet || r.Method == http.MethodHead

	// The landing invariant: an operator typing http://rasputin.local
	// must reach the trust page, not a cert error. Redirecting "/" to
	// https:// here would BE that cert error on a fresh device, so the
	// hop stays on plain HTTP.
	if p == "/" && isRead {
		http.Redirect(w, r, "/trust", http.StatusFound)
		return
	}

	// Static export files for the trust page: the page route itself plus
	// asset paths (_next/* bundles, favicon, fonts — anything with a file
	// extension; page routes are extensionless). Serving all assets, not
	// just the trust page's chunk list, keeps this free of Next.js build
	// internals; assets are public-by-design (see uiHandler).
	if isRead && s.uiDir != "" && bootstrapUIPath(p) {
		uiHandler{fsys: os.DirFS(s.uiDir)}.ServeHTTP(w, r)
		return
	}

	redirectToHTTPS(w, r)
}

// bootstrapUIPath reports whether p may be served from the static export
// over plain HTTP: the trust page route, or any asset-shaped path.
func bootstrapUIPath(p string) bool {
	if p == "/trust" {
		return true
	}
	if strings.HasPrefix(p, "/_next/") {
		return true
	}
	// Asset files (favicon.ico, *.txt RSC payloads, fonts) carry an
	// extension; app routes (/login, /firewall/rules) never do. API and
	// WS paths never reach here with an extension either — /api and /ws
	// trees are extensionless by construction.
	return strings.Contains(path.Base(p), ".")
}

// redirectToHTTPS 302s to the same path+query on https://<host> with any
// port stripped — the HTTPS listener sits on :443, so "rasputin.local:80"
// must become plain "rasputin.local". 302 (not 308) on purpose: a non-GET
// hitting this surface should NOT be transparently replayed against the
// authed listener; clients downgrade to GET and land on a read-only page.
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]" // re-bracket a bare IPv6 literal
	}
	u := url.URL{Scheme: "https", Host: host, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	http.Redirect(w, r, u.String(), http.StatusFound)
}
