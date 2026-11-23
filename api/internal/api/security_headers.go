package api

import "net/http"

// Security response headers carried by every response the api writes, on all
// three listeners (Handler, BootstrapHandler, ObsIngestHandler).
const (
	// contentSecurityPolicy is the baseline policy, on every response the
	// api writes. It is written for the web UI, the only HTML the api serves,
	// but a console page replaces its script-src with the page's own (see
	// pagePolicy in ui_policy.go), so here it governs only responses that are
	// not console pages: JSON, files and redirects, where script-src 'none'
	// has no effect. Each relaxation is something the shipped UI needs:
	//
	//   - style-src 'unsafe-inline': the prerendered HTML carries style="..."
	//     attributes (React inline styles).
	//   - font-src data:: the UI bundles JetBrains Mono (ui/styles/fonts,
	//     loaded same-origin), and a data: font is what some browsers use for
	//     a fallback glyph. No font or style comes from another host
	//     (geekdojo/geekdojo-brain#988).
	//   - img-src data: blob:: inline SVG/data-URL images and client-built
	//     downloads.
	//   - connect-src 'self': fetch and the /ws/* WebSockets are same-origin
	//     in production ('self' matches ws:/wss: to the same host). The dev
	//     UI on :3000 is served by next dev, not by the api, so this header
	//     never reaches it.
	//
	// frame-ancestors 'none' (with X-Frame-Options: DENY for older browsers)
	// forbids framing everywhere except the Grafana proxy — see
	// sameOriginFraming.
	contentSecurityPolicy = cspHead + "script-src 'none'; " + cspTail

	// cspHead and cspTail are every directive of the baseline except
	// script-src, which sits between them; a page policy shares them.
	cspHead = "default-src 'self'; "
	cspTail = "style-src 'self' 'unsafe-inline'; " +
		"font-src 'self' data:; " +
		"img-src 'self' data: blob:; " +
		"connect-src 'self'; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"frame-ancestors 'none'"

	// referrerPolicy keeps the cluster's hostnames and paths out of the
	// Referer the UI's outbound links (GitHub, the docs site) would send.
	referrerPolicy = "same-origin"
)

// securityHeaders sets the security response headers on every response and
// then calls next. They are set before next runs, so a handler that needs a
// narrower exception overrides them (sameOriginFraming does).
//
// Strict-Transport-Security is deliberately never sent, on any listener. Each
// installation has its own controlplane CA, first trusted from the plain-HTTP /trust
// page, and a controlplane re-flashed without restoring its identity mints a
// new one. A browser holding HSTS for the cluster's name would refuse to let
// the operator click through the new certificate and would upgrade the /trust
// page itself to https — cutting off the way to install the new CA.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("Referrer-Policy", referrerPolicy)
		next.ServeHTTP(w, r)
	})
}

// sameOriginFraming is the one exception to the no-framing policy: responses
// from the /observability/ Grafana proxy may be framed by the api's own
// origin, and by nothing else. The web UI does not frame Grafana (it links to
// it), but Grafana's own pages frame Grafana (panel embeds); framing by any
// other origin stays refused. grafana.ini's allow_embedding (obs/supervisor.go)
// only stops Grafana sending its own X-Frame-Options: deny, so this header is
// the framing policy the browser sees.
//
// It replaces the baseline CSP rather than adding frame-ancestors to it,
// because the baseline's script and style rules are written for the web UI
// and would break Grafana's frontend. The proxy's responses are Grafana's
// pages, and Grafana owns their content policy: grafana.ini turns on its own
// script policy (obs.GrafanaCSPTemplate), which Grafana adds beside this one
// on every response that passes its CSP middleware.
//
// It is mounted inside the session gate, so the exception covers only
// authenticated responses that actually come from the proxy.
func sameOriginFraming(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Content-Security-Policy", "frame-ancestors 'self'")
		next.ServeHTTP(w, r)
	})
}

// cspWithScriptSrc is the baseline policy with its script-src replaced by src.
func cspWithScriptSrc(src string) string {
	return cspHead + "script-src " + src + "; " + cspTail
}
