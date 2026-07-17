package api

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
)

// handleObservabilityProxy is the api's reverse proxy in front of
// Grafana. The route is registered as "/observability/" so every
// downstream path (including assets, API calls, WebSocket upgrades)
// goes through here.
//
// Flow per request:
//
//  1. Session middleware (existing reqd wrapper) already validated the
//     cookie before this handler runs.
//  2. We pull the authenticated user out of the request context and
//     forward it as X-Webauth-User — Grafana's auth.proxy.enabled = true
//     mode treats that header as a trusted identity assertion and
//     auto-creates the Grafana user on first sight.
//  3. The Director clears any client-supplied X-Webauth-* headers so a
//     malicious user can't pass themselves off as someone else by
//     poking at the cookie-protected endpoint.
//
// Grafana's grafana.ini is rendered with `serve_from_sub_path = true`
// and `root_url = .../observability/`, so it generates links that work
// behind the proxy.
//
// When obs / Grafana is disabled, the proxy returns 503 instead of
// 502'ing on an unreachable upstream — keeps the operator-visible
// error specific.
func (s *Server) handleObservabilityProxy(w http.ResponseWriter, r *http.Request) {
	// Gate on the operator's stored opt-in, not on an empty VMBaseURL —
	// that older check only worked because a disabled stack meant a nil
	// supervisor. The supervisor is always constructed since Slice 1.6.
	if !s.obs.GrafanaEnabled(r.Context()) {
		writeError(w, http.StatusServiceUnavailable,
			"observability proxy: dashboards unavailable — observability is turned off for this control plane")
		return
	}
	target, err := url.Parse(s.obs.GrafanaBaseURL(r.Context()))
	if err != nil {
		log.Printf("api/obs proxy: bad Grafana URL: %v", err)
		writeError(w, http.StatusInternalServerError, "observability proxy: misconfigured")
		return
	}
	user, _ := auth.UserFromContext(r.Context())
	username := "rasputin-operator"
	if user != nil && user.Name != "" {
		username = user.Name
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Strip every X-Webauth-* a client might have set so they
		// can't claim a different identity than the session cookie's.
		for k := range req.Header {
			if strings.HasPrefix(strings.ToLower(k), "x-webauth-") {
				req.Header.Del(k)
			}
		}
		req.Header.Set("X-Webauth-User", username)
		// Grafana behind serve_from_sub_path expects the original
		// path. httputil leaves r.URL.Path untouched after Director,
		// which is what we want — the /observability prefix stays.
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		log.Printf("api/obs proxy: upstream error: %v", err)
		writeError(w, http.StatusBadGateway, "observability upstream: "+err.Error())
	}
	proxy.ServeHTTP(w, r)
}
