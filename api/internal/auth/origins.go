package auth

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// OriginAllowlist is the one set of browser origins the api accepts. It is
// the WebAuthn RP origin list (Config.RPOrigins), normalized once, and it
// feeds every origin decision the api makes:
//
//   - the WebAuthn ceremonies (the go-webauthn RP config),
//   - CORS (which origins get Access-Control-Allow-Origin),
//   - http.CrossOriginProtection's trusted origins,
//   - the WebSocket upgrade's OriginPatterns, and
//   - the Origin check in RequireSession.
//
// On an appliance the list is the cluster's own https origin, so nothing is
// allowed cross-origin. A dev run lists the Next dev server and the api's own
// port; that is the same allowlist, not a bypass.
type OriginAllowlist struct {
	origins []string
	set     map[string]struct{}
}

// NewOriginAllowlist normalizes raw (see NormalizeOrigin) and de-duplicates
// it, keeping first-seen order. Any entry that is not a plain http(s) origin
// is an error: a malformed entry would otherwise silently match nothing and
// lock the operator out, or be read loosely and match too much.
func NewOriginAllowlist(raw []string) (*OriginAllowlist, error) {
	a := &OriginAllowlist{set: make(map[string]struct{}, len(raw))}
	for _, r := range raw {
		o, err := NormalizeOrigin(r)
		if err != nil {
			return nil, err
		}
		if _, dup := a.set[o]; dup {
			continue
		}
		a.set[o] = struct{}{}
		a.origins = append(a.origins, o)
	}
	return a, nil
}

// NormalizeOrigin returns origin as scheme://host[:port]: scheme and host
// lowercased, the scheme's default port dropped, a bare trailing "/"
// tolerated. It refuses anything else — a scheme other than http or https,
// userinfo, a path, a query or fragment, an empty host, and the opaque
// origin "null".
func NormalizeOrigin(origin string) (string, error) {
	s := strings.TrimSpace(origin)
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("origin %q: %w", origin, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("origin %q: scheme must be http or https", origin)
	}
	if u.Opaque != "" || u.User != nil || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("origin %q: want scheme://host[:port] and nothing else", origin)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("origin %q: no host", origin)
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6 literal without a port
	}
	return scheme + "://" + host, nil
}

// Origins returns the normalized origins, in configuration order. A nil
// allowlist holds none.
func (a *OriginAllowlist) Origins() []string {
	if a == nil {
		return nil
	}
	return append([]string(nil), a.origins...)
}

// Allows reports whether origin — an Origin request header value — is on the
// list. The comparison is on the whole normalized origin, scheme included:
// http://<cluster>.local is not https://<cluster>.local.
func (a *OriginAllowlist) Allows(origin string) bool {
	if a == nil {
		return false
	}
	o, err := NormalizeOrigin(origin)
	if err != nil {
		return false
	}
	_, ok := a.set[o]
	return ok
}

// WebSocketOriginPatterns returns the list in the form coder/websocket's
// AcceptOptions.OriginPatterns takes. Each pattern carries its scheme, so the
// library matches "scheme://host" rather than the host alone, and path.Match
// metacharacters (an IPv6 literal's brackets) are escaped so each pattern
// matches exactly its own origin.
//
// The library still authorizes any Origin whose host equals the request's
// Host, whatever its scheme; RequireSession's Origin check, which every /ws
// route sits behind, is what closes that.
func (a *OriginAllowlist) WebSocketOriginPatterns() []string {
	origins := a.Origins()
	out := make([]string, 0, len(origins))
	r := strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`)
	for _, o := range origins {
		out = append(out, r.Replace(o))
	}
	return out
}

// requestOriginAllowed is the Origin check RequireSession runs. A request
// without an Origin header passes: browsers send one on every cross-origin
// request and on every WebSocket handshake, and non-browser clients (curl,
// scripts) send none. A request that carries one must carry an allowed one,
// in every copy.
func (a *OriginAllowlist) requestOriginAllowed(r *http.Request) bool {
	for _, o := range r.Header.Values("Origin") {
		if !a.Allows(o) {
			return false
		}
	}
	return true
}
