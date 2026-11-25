package door

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
)

// validTarget is a request target route accepts at door: the path with each
// wildcard filled and the parameters its checks need.
func validTarget(k Kind, rt Route) string {
	path := rt.Pattern
	switch rt.Kind {
	case policy.RouteTheme:
		file := "css/signin.css"
		if strings.Contains(path, "/common/") {
			file = "vendor/rfc4648/rfc4648.js"
		}
		return strings.Replace(strings.Replace(path, "{v}", testVersion, 1), "{file...}", file, 1)
	case policy.RouteSignin:
		return signinPrefix + "css/tokens.css"
	}
	q := url.Values{}
	switch rt.Kind {
	case policy.RouteAuth:
		return path + "?" + authQuery(doorClient(k), nil)
	case policy.RouteRegistrations:
		return path + "?" + authQuery(policy.ConsoleClient, map[string]string{"prompt": "create"})
	case policy.RouteToken:
		q.Set("client_id", doorClient(k))
		q.Set("grant_type", "authorization_code")
	case policy.RouteAuthenticate, policy.RouteRequiredAction:
		q.Set("client_id", doorClient(k))
	case policy.RouteResetCredential:
		q.Set("client_id", resetFor(k))
	case policy.RouteRegistration:
		q.Set("client_id", policy.ConsoleClient)
	case policy.RouteSAML:
		q.Set("SAMLRequest", "x")
	}
	if len(q) == 0 {
		return path
	}
	return path + "?" + q.Encode()
}

func resetFor(k Kind) string {
	if k == Home {
		return policy.ResetHomeClient
	}
	return policy.ResetAppClient
}

var allMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}

// TC-985-01: every allowlisted pattern is forwarded with each allowed method
// at each door; any other method gets the door page, never the mux's 405
// body, and nothing is forwarded.
func TestDoor_AllowlistPerDoor(t *testing.T) {
	f := newFixture(t)
	for _, k := range []Kind{Home, App} {
		for _, rt := range Routes(k) {
			target := validTarget(k, rt)
			for _, m := range allMethods {
				before := f.up.count()
				r := req{method: m, target: target}
				if m != http.MethodGet {
					r.form = url.Values{"username": {"someone"}}
				}
				w := f.do(k, r)
				what := k.String() + " " + m + " " + rt.Pattern
				switch {
				case !slices.Contains(rt.Methods, m):
					f.wantRefused(w, http.StatusMethodNotAllowed, before, what)
				case rt.Kind == policy.RouteSignin, rt.Kind == policy.RouteResetDone:
					if w.Code != http.StatusOK || f.up.count() != before {
						t.Errorf("%s: %d, forwarded %v; want 200 from the api", what, w.Code, f.up.count() != before)
					}
				default:
					f.wantForwarded(w, before, what)
				}
			}
		}
	}
}

// TC-985-02: the 404 surface. Every other path answers the 404 door page,
// the home door's naming the console, and reaches nothing.
func TestDoor_NotFoundSurface(t *testing.T) {
	f := newFixture(t)
	paths := []string{
		"/resources/" + testVersion + "/admin/x.js",
		"/resources/" + testVersion + "/account/x.js",
		"/resources/rasputin/login/en",
		"/resources/zzzzz/login/rasputin/css/signin.css",
		// The version segment matches exactly: no prefix, extension or case.
		"/resources/" + testVersion[:4] + "/login/rasputin/css/signin.css",
		"/resources/" + testVersion + "x/login/rasputin/css/signin.css",
		"/resources/" + strings.ToUpper(testVersion) + "/login/rasputin/css/signin.css",
		"/resources/" + testVersion + "/login/rasputin/css/notlisted.css",
		"/resources/" + testVersion + "/login/keycloak.v2/css/login.css",
		"/resources/" + testVersion + "/common/keycloak/vendor/notlisted.js",
		"/realms/master/protocol/openid-connect/auth",
		"/admin",
		"/admin/master/console",
		"/.well-known/openid-configuration",
		"/realms/rasputin/account",
		"/realms/rasputin/clients-registrations/openid-connect",
		"/realms/rasputin/broker/google/endpoint",
		"/realms/rasputin",
		"/",
	}
	for _, k := range []Kind{Home, App} {
		for _, p := range paths {
			before := f.up.count()
			w := f.do(k, req{target: p})
			f.wantRefused(w, http.StatusNotFound, before, k.String()+" "+p)
			names := strings.Contains(w.Body.String(), "https://ci.local")
			if names != (k == Home) {
				t.Errorf("%s %s: the 404 page names the console = %v, want %v", k, p, names, k == Home)
			}
		}
	}
}

// TC-985-03: registration only at the home door, SAML only at the app door.
func TestDoor_DoorOnlyRoutes(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct {
		k      Kind
		target string
	}{
		{App, oidc("registrations") + "?" + authQuery(policy.ConsoleClient, map[string]string{"prompt": "create"})},
		{App, actions("registration") + "?client_id=" + policy.ConsoleClient},
		{Home, realmPrefix + "protocol/saml?SAMLRequest=x"},
		{Home, realmPrefix + "protocol/saml/descriptor"},
	} {
		before := f.up.count()
		f.wantRefused(f.do(c.k, req{target: c.target}), http.StatusNotFound, before, c.k.String()+" "+c.target)
	}
}

// TC-985-04: /_signin/ is served from memory with the upstream stopped; an
// unlisted file is 404; nothing under it reaches upstream.
func TestDoor_SigninFiles(t *testing.T) {
	f := newFixture(t)
	f.up.srv.Close()
	for _, k := range []Kind{Home, App} {
		for _, file := range []string{"css/tokens.css", "css/signin.css", "css/fonts/JetBrainsMono.woff2", "img/brand.svg"} {
			w := f.do(k, req{target: signinPrefix + file})
			if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), testAssets[file].Data) {
				t.Errorf("%s %s: %d %q, want 200 with the file's bytes", k, file, w.Code, w.Body.String())
			}
		}
		for _, file := range []string{"js/rasputin-page.js", "css/missing.css", "index.html"} {
			if w := f.do(k, req{target: signinPrefix + file}); w.Code != http.StatusNotFound || !isDoorPage(w) {
				t.Errorf("%s %s: %d, want the 404 door page", k, file, w.Code)
			}
		}
	}
	if n := f.up.count(); n != 0 {
		t.Errorf("%d requests reached the upstream", n)
	}
}

// TC-985-05: the raw path's shape is refused with 400 and a sentence before
// anything is decoded or forwarded.
func TestDoor_PathShape(t *testing.T) {
	f := newFixture(t)
	auth := oidc("auth")
	for _, raw := range []string{
		realmPrefix + "protocol/openid-connect/%61uth",
		realmPrefix + "%2e%2e/master/protocol/openid-connect/auth",
		realmPrefix + "protocol%2Fopenid-connect/auth",
		auth + ";jsessionid=x",
		realmPrefix + "protocol\\openid-connect/auth",
		"/realms//rasputin/protocol/openid-connect/auth",
		"/realms/rasputin/./protocol/openid-connect/auth",
		"/realms/rasputin/../master/protocol/openid-connect/auth",
		auth + "/",
		"https://elsewhere.invalid" + auth,
		"*",
	} {
		for _, k := range []Kind{Home, App} {
			hr := httptest.NewRequest(http.MethodGet, "/", nil)
			hr.RequestURI = raw
			hr.RemoteAddr = peer
			w := httptest.NewRecorder()
			f.door(k).ServeHTTP(w, hr)
			if w.Code != http.StatusBadRequest || !isDoorPage(w) {
				t.Errorf("%s %q: %d, want 400 with the door page", k, raw, w.Code)
				continue
			}
			s := sentenceIn(t, w.Body.String())
			if s == "" || !isSentence(s) {
				t.Errorf("%s %q: the refusal %q is not a sentence", k, raw, s)
			}
		}
	}
	if n := f.up.count(); n != 0 {
		t.Errorf("%d requests reached the upstream", n)
	}
}

// sentenceIn is the door page's alert text.
func sentenceIn(t *testing.T, body string) string {
	t.Helper()
	const open = `<span class="rasp-alert-text">`
	i := strings.Index(body, open)
	if i < 0 {
		return ""
	}
	rest := body[i+len(open):]
	j := strings.Index(rest, "</span>")
	if j < 0 {
		return ""
	}
	return strings.NewReplacer("&#39;", "'", "&amp;", "&").Replace(rest[:j])
}

// isSentence: a capital first, a full stop last (ERR-MESSAGE).
func isSentence(s string) bool {
	return s != "" && s[0] >= 'A' && s[0] <= 'Z' && strings.HasSuffix(s, ".")
}

// TC-985-35: every route of both doors carries a reason, and its method list
// is not empty.
func TestRoutes_CarryReasons(t *testing.T) {
	for _, k := range []Kind{Home, App} {
		rs := Routes(k)
		if len(rs) < 15 {
			t.Fatalf("%s door: %d routes", k, len(rs))
		}
		for _, r := range rs {
			if strings.TrimSpace(r.Reason) == "" || len(r.Methods) == 0 || r.Kind == "" {
				t.Errorf("%s %s: reason %q, methods %v, kind %q", k, r.Pattern, r.Reason, r.Methods, r.Kind)
			}
		}
	}
}

// TC-992-16: the app door serves /api/auth/reset-done through ResetDone,
// with the query, and never relays it; the home door answers 404 for it.
// (door.New refusing a nil ResetDone is in TestNew_FailsClosed.)
func TestDoor_TC992_16_ResetDone(t *testing.T) {
	f := newFixture(t)
	before := f.up.count()
	w := f.do(App, req{target: "/api/auth/reset-done?code=c&iss=x"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), fakeResetSentence) || f.up.count() != before {
		t.Errorf("app door: %d, forwarded %v, body %s", w.Code, f.up.count() != before, w.Body.String())
	}
	if f.reset.count() != 1 || f.reset.queries[0].Get("code") != "c" {
		t.Errorf("ResetDone saw %v", f.reset.queries)
	}
	if w.Header().Get("Set-Cookie") != "" {
		t.Errorf("Set-Cookie %q", w.Header().Get("Set-Cookie"))
	}
	w = f.do(Home, req{target: "/api/auth/reset-done?code=c"})
	if w.Code != http.StatusNotFound || f.reset.count() != 1 || f.up.count() != before {
		t.Errorf("home door: %d, ResetDone calls %d", w.Code, f.reset.count())
	}
}
