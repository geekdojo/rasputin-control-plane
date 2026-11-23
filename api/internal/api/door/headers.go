package door

import (
	"net/http"
	"strings"
)

// replacedHeaders are the upstream's security headers the door deletes from
// every response before it sets its own: HSTS (dec 26: none on either door)
// and Alt-Svc are never sent, the others are replaced, never appended.
var replacedHeaders = []string{
	"Strict-Transport-Security", "Alt-Svc", "Content-Security-Policy",
	"Content-Security-Policy-Report-Only", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
}

// javaPageHashes are the exact script hashes for pages the identity service
// builds in Java that the theme cannot reach, per pin. At 26.8.2 the CI walk
// records no policy violation without any; a hash is added only with the
// violation that needs it.
var javaPageHashes = []string{}

// policies are one door's script policies: the relayed pages', built per
// answer from the resource version known then, and the door's own pages'.
type policies struct {
	app        bool
	host, tail string
	own, frame string
}

// policiesFor builds door's policies for host (signin-origin.md §5.3, C32):
// at the home door 'self', which there admits only the theme files the
// allowlist serves; at the app door, which shares its origin with "Your
// account", only the two theme paths under the learned resource version.
// Neither has form-action.
func policiesFor(door Kind, host string) policies {
	frameAncestors, frame := "'none'", "DENY"
	if door == App {
		frameAncestors, frame = "'self'", "SAMEORIGIN"
	}
	tail := "; object-src 'none'; base-uri 'none'; frame-ancestors " + frameAncestors
	return policies{app: door == App, host: host, tail: tail, own: "script-src 'none'" + tail, frame: frame}
}

// relayed is the relayed pages' policy under resource version v, when known.
// With none known the app door names no theme path, so its pages run no
// script until the version is learned (the theme files answer 404 then too).
func (p policies) relayed(v string, known bool) string {
	var scripts []string
	switch {
	case !p.app:
		scripts = []string{"'self'"}
	case known:
		login, common := themePaths(v)
		scripts = []string{"https://" + p.host + login, "https://" + p.host + common}
	}
	for _, h := range javaPageHashes {
		scripts = append(scripts, "'"+h+"'")
	}
	if len(scripts) == 0 {
		scripts = []string{"'none'"}
	}
	return "script-src " + strings.Join(scripts, " ") + p.tail
}

// setHeaders replaces the security headers on h with exactly one of each,
// under csp.
func (p policies) setHeaders(h http.Header, csp string) {
	for _, k := range replacedHeaders {
		h.Del(k)
	}
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Frame-Options", p.frame)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
}

// setPageHeaders sets the door's own pages' headers.
func (h *Handler) setPageHeaders(hdr http.Header) { h.pol.setHeaders(hdr, h.pol.own) }
