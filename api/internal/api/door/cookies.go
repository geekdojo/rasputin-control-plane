package door

import (
	"net/http"
	"slices"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
)

// keycloakCookies are the identity service's own cookie names at the pin
// (Keycloak 26.8.2, CookieType): the only names that go upstream.
var keycloakCookies = []string{
	"AUTH_SESSION_ID", "KC_AUTH_SESSION_HASH", "KC_RESTART", "KEYCLOAK_IDENTITY",
	"KEYCLOAK_SESSION", "KEYCLOAK_LOCALE", "KEYCLOAK_REMEMBER_ME", "KC_STATE_CHECKER",
}

// renamedCookies are the app door's session cookies, renamed to __Host-
// names on the way out and back on the way in, so no app on the door's site
// can set one (signin-origin.md §5.3). KC_AUTH_SESSION_HASH and
// KEYCLOAK_SESSION keep their names: the base passkey script reads the first
// by name.
var renamedCookies = []string{"KEYCLOAK_IDENTITY", "AUTH_SESSION_ID", "KC_RESTART", "KEYCLOAK_REMEMBER_ME", "KEYCLOAK_LOCALE"}

// ssoCookies are the single-sign-on cookies the home door strips on the way
// in: every home-door flow signs in afresh.
var ssoCookies = []string{"KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION", "KEYCLOAK_REMEMBER_ME"}

const hostPrefix = "__Host-"

// inboundCookies rewrites h's Cookie header for upstream: the api's own
// cookies are dropped; at the app door the five session cookies are taken
// only from their __Host- names, renamed back, and an unprefixed copy is
// dropped; at the home door the single-sign-on cookies are dropped; only
// Keycloak's names remain; and every copy of a name that arrives twice is
// dropped, so the worst a tossed cookie does is restart the page.
func inboundCookies(door Kind, h http.Header) {
	if len(h.Values("Cookie")) == 0 {
		return
	}
	type kv struct{ name, value string }
	var kept []kv
	count := map[string]int{}
	for _, c := range (&http.Request{Header: h}).Cookies() {
		name := c.Name
		if auth.IsOwnCookie(name) {
			continue
		}
		switch door {
		case App:
			if base, ok := strings.CutPrefix(name, hostPrefix); ok {
				if !slices.Contains(renamedCookies, base) {
					continue
				}
				name = base
			} else if slices.Contains(renamedCookies, name) {
				continue
			}
		case Home:
			if slices.Contains(ssoCookies, name) {
				continue
			}
		}
		if !slices.Contains(keycloakCookies, name) {
			continue
		}
		count[name]++
		kept = append(kept, kv{name, c.Value})
	}
	h.Del("Cookie")
	var parts []string
	for _, c := range kept {
		if count[c.name] == 1 {
			parts = append(parts, c.name+"="+c.value)
		}
	}
	if len(parts) > 0 {
		h.Set("Cookie", strings.Join(parts, "; "))
	}
}

// outboundCookies rewrites the upstream's Set-Cookie lines: an api-own
// cookie, or a line that does not parse, is dropped; at the app door the
// five session cookies become __Host-<name> with Path=/, Secure and no
// Domain, their other attributes kept; every other line is unchanged.
func outboundCookies(door Kind, h http.Header) {
	lines := h.Values("Set-Cookie")
	if len(lines) == 0 {
		return
	}
	var out []string
	for _, line := range lines {
		c, err := http.ParseSetCookie(line)
		if err != nil || auth.IsOwnCookie(c.Name) {
			continue
		}
		if door == App && slices.Contains(renamedCookies, c.Name) {
			c.Name = hostPrefix + c.Name
			c.Path, c.Domain, c.Secure = "/", "", true
			out = append(out, c.String())
			continue
		}
		out = append(out, line)
	}
	h.Del("Set-Cookie")
	for _, l := range out {
		h.Add("Set-Cookie", l)
	}
}
