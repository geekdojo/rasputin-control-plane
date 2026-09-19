package api

import "net/http"

// Security response headers carried by every response the api writes, on all
// three listeners (Handler, BootstrapHandler, ObsIngestHandler).
const (
	// contentSecurityPolicy is the baseline policy. It is written for the web
	// UI, because the UI is the only HTML the api serves; on a JSON or file
	// response it is inert. Each relaxation is something the shipped UI needs:
	//
	//   - script-src 'unsafe-inline': the UI is a Next.js static export. Its
	//     pages carry inline <script> tags (the RSC flight payload, and the
	//     theme bootstrap in app/layout.tsx), and a static export has no
	//     server to mint a per-request nonce. Hashes would have to be computed
	//     per build; that is a later tightening, not a baseline.
	//   - script-src 'wasm-unsafe-eval': the backup-key passphrase KDF is
	//     Argon2id from hash-wasm (ui/lib/passphrase-kdf.ts), which compiles
	//     WebAssembly. It permits WebAssembly compilation only, not eval().
	//   - style-src 'unsafe-inline': the prerendered HTML carries style="..."
	//     attributes (React inline styles).
	//   - fonts.googleapis.com / fonts.gstatic.com: globals.css imports
	//     JetBrains Mono from Google Fonts.
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
	contentSecurityPolicy = "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; " +
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
		"font-src 'self' https://fonts.gstatic.com data:; " +
		"img-src 'self' data: blob:; " +
		"connect-src 'self'; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"frame-ancestors 'none'"

	// strictTransportSecurity is sent only on a response that went out over
	// TLS (see securityHeaders). No includeSubDomains: app hostnames are not
	// the api's to make promises about.
	//
	// The max-age is one day, deliberately short. Each installation has its
	// own Mesh CA, and a controlplane re-flashed without restoring its
	// identity mints a new one. A browser holding an HSTS entry for the cluster's name then
	// refuses to let the operator click through the untrusted certificate, and
	// upgrades http://<cluster>/trust — the page that installs the new CA — to
	// https. A day bounds that lockout; the trust page stays reachable by IP
	// address meanwhile, since browsers never apply HSTS to IP literals.
	strictTransportSecurity = "max-age=86400"

	// referrerPolicy keeps the cluster's hostnames and paths out of the
	// Referer the UI's outbound links (GitHub, the docs site) would send.
	referrerPolicy = "same-origin"
)

// securityHeaders sets the security response headers on every response and
// then calls next. They are set before next runs, so a handler that needs a
// narrower exception overrides them (sameOriginFraming does).
//
// HSTS goes out only when the request arrived over TLS. The same Handler
// serves the plain-HTTP listener whenever HTTPS is off (every dev run), and
// HSTS over plain HTTP is at best ignored and at worst a promise the host
// cannot keep; r.TLS is the per-request fact that says which listener this is.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("Referrer-Policy", referrerPolicy)
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", strictTransportSecurity)
		}
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
// pages, and Grafana owns their content policy.
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
