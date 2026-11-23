package door

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-985-16: no client forwarding, client-certificate or Host value reaches
// upstream; the door writes exactly one of each forwarded header, for IPv4
// and IPv6 peers.
func TestDoor_ForwardedHeaders(t *testing.T) {
	f := newFixture(t)
	forged := http.Header{
		"Forwarded":               {"for=6.6.6.6;host=evil;proto=http"},
		"X-Forwarded-For":         {"6.6.6.6"},
		"X-Forwarded-Host":        {"evil.example"},
		"X-Forwarded-Proto":       {"http"},
		"X-Forwarded-Port":        {"8443"},
		"X-Forwarded-Prefix":      {"/evil"},
		"X-Forwarded-Server":      {"evil"},
		"X-Client-Cert":           {"forged"},
		"X-Ssl-Client-Cert":       {"forged"},
		"X-Forwarded-Client-Cert": {"forged"},
		"Ssl-Client-Cert":         {"forged"},
		"Client-Cert":             {"forged"},
		"Client-Cert-Chain":       {"forged"},
	}
	for _, k := range []Kind{Home, App} {
		for remote, want := range map[string]string{"192.0.2.1:4000": "192.0.2.1", "[2001:db8::7]:4000": "2001:db8::7", "[::ffff:192.0.2.9]:1": "192.0.2.9"} {
			w := f.do(k, req{target: realmPrefix + ".well-known/openid-configuration", header: forged, remote: remote})
			if w.Code != http.StatusOK {
				t.Fatalf("%s: %d", k, w.Code)
			}
			got := f.up.last(t)
			host := f.door(k).cfg.Door.Host
			if got.host != host {
				t.Errorf("%s: upstream Host %q, want %q", k, got.host, host)
			}
			for name, v := range map[string]string{"X-Forwarded-Host": host, "X-Forwarded-Proto": "https", "X-Forwarded-Port": "443", "X-Forwarded-For": want} {
				if vs := got.header.Values(name); len(vs) != 1 || vs[0] != v {
					t.Errorf("%s %s: upstream %s = %q, want exactly %q", k, remote, name, vs, v)
				}
			}
			for name := range got.header {
				if name == "Forwarded" || name == "X-Forwarded-Prefix" || name == "X-Forwarded-Server" || slices.Contains(clientCertHeaders, name) {
					t.Errorf("%s: the client's %s reached upstream", k, name)
				}
			}
			for _, vs := range got.header {
				for _, v := range vs {
					if strings.Contains(v, "evil") || strings.Contains(v, "6.6.6.6") || v == "forged" {
						t.Errorf("%s: a forged value %q reached upstream", k, v)
					}
				}
			}
		}
	}
}

// TC-985-17: every response class carries exactly the door's policy, one
// frame header, one nosniff, and no HSTS, Alt-Svc or Report-Only.
func TestDoor_ResponseHeaders(t *testing.T) {
	f := newFixture(t)
	classes := map[string]func(w http.ResponseWriter){
		"html": func(w http.ResponseWriter) { w.Header().Set("Content-Type", "text/html"); w.WriteHeader(200) },
		"302":  func(w http.ResponseWriter) { w.Header().Set("Location", "https://ci.local/cb"); w.WriteHeader(302) },
		"json": func(w http.ResponseWriter) { w.Header().Set("Content-Type", "application/json"); w.WriteHeader(200) },
		"css":  func(w http.ResponseWriter) { w.Header().Set("Content-Type", "text/css"); w.WriteHeader(200) },
		"bare": func(w http.ResponseWriter) { w.WriteHeader(204) },
	}
	for name, class := range classes {
		f.up.setHandler(func(w http.ResponseWriter, _ *http.Request) {
			h := w.Header()
			if name != "bare" {
				h.Set("Strict-Transport-Security", "max-age=31536000")
				h.Set("Alt-Svc", `h3=":443"`)
				h.Set("Content-Security-Policy", "frame-src 'self'")
				h.Set("Content-Security-Policy-Report-Only", "default-src 'none'")
				h.Set("X-Frame-Options", "ALLOW-FROM x")
				h.Add("X-Content-Type-Options", "nosniff")
				h.Add("X-Content-Type-Options", "nosniff")
			}
			class(w)
		})
		for _, k := range []Kind{Home, App} {
			target := realmPrefix + ".well-known/openid-configuration"
			if name == "css" {
				target = testLoginPath + "css/signin.css"
			}
			w := f.do(k, req{target: target})
			h := w.Header()
			want := policiesFor(k, f.door(k).cfg.Door.Host)
			if v := h.Values("Content-Security-Policy"); len(v) != 1 || v[0] != want.relayed(testVersion, true) || strings.Contains(v[0], "form-action") {
				t.Errorf("%s %s: CSP %q, want exactly %q", k, name, v, want.relayed(testVersion, true))
			}
			for _, gone := range []string{"Strict-Transport-Security", "Alt-Svc", "Content-Security-Policy-Report-Only"} {
				if h.Get(gone) != "" {
					t.Errorf("%s %s: %s present", k, name, gone)
				}
			}
			if v := h.Values("X-Frame-Options"); len(v) != 1 || v[0] != want.frame {
				t.Errorf("%s %s: XFO %q, want %q", k, name, v, want.frame)
			}
			if v := h.Values("X-Content-Type-Options"); len(v) != 1 || v[0] != "nosniff" {
				t.Errorf("%s %s: nosniff %q, want one", k, name, v)
			}
		}
	}
	// The exact policies (C32), and the door's own pages.
	if got := policiesFor(Home, "sso-ci.local").relayed(testVersion, true); got != "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" {
		t.Errorf("home policy %q", got)
	}
	if got := policiesFor(App, "signin.ci.internal").relayed(testVersion, true); got != "script-src https://signin.ci.internal/resources/ab12c/login/rasputin/ https://signin.ci.internal/resources/ab12c/common/keycloak/; object-src 'none'; base-uri 'none'; frame-ancestors 'self'" {
		t.Errorf("app policy %q", got)
	}
	for _, k := range []Kind{Home, App} {
		w := f.do(k, req{target: "/nothing"})
		if csp := w.Header().Get("Content-Security-Policy"); !strings.HasPrefix(csp, "script-src 'none';") {
			t.Errorf("%s door page CSP %q, want script-src 'none'", k, csp)
		}
		if w.Header().Get("Strict-Transport-Security") != "" {
			t.Errorf("%s door page carries HSTS", k)
		}
	}
}

func cookieNames(header string) []string {
	var names []string
	for _, c := range strings.Split(header, "; ") {
		if n, _, ok := strings.Cut(c, "="); ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

// TC-985-18: the inbound cookie rules.
func TestDoor_InboundCookies(t *testing.T) {
	f := newFixture(t)
	jar := []string{}
	for _, n := range keycloakCookies {
		jar = append(jar, n+"=plain")
	}
	for _, n := range renamedCookies {
		jar = append(jar, hostPrefix+n+"=host")
	}
	jar = append(jar, "rasputin-session=s", "__Host-rasputin-session=s", "__Secure-rasputin-x=s", "rasputin-repair=r",
		"unknown=u", "KC_RESTART=second")
	hdr := http.Header{"Cookie": {strings.Join(jar, "; ")}}
	for _, k := range []Kind{Home, App} {
		before := f.up.count()
		f.do(k, req{target: actions("restart"), header: hdr})
		if f.up.count() != before+1 {
			t.Fatalf("%s: a request with tossed cookies was not forwarded", k)
		}
		got := f.up.last(t).header.Get("Cookie")
		var want []string
		switch k {
		case App:
			// The five come from their __Host- names, renamed back; KC_RESTART
			// also arrived unprefixed twice, which is dropped, so one copy is
			// left.
			want = []string{"AUTH_SESSION_ID", "KC_AUTH_SESSION_HASH", "KC_RESTART", "KC_STATE_CHECKER", "KEYCLOAK_IDENTITY",
				"KEYCLOAK_LOCALE", "KEYCLOAK_REMEMBER_ME", "KEYCLOAK_SESSION"}
			for _, n := range renamedCookies {
				if !strings.Contains(got, n+"=host") {
					t.Errorf("app: %s is not the __Host- copy's value: %q", n, got)
				}
			}
		case Home:
			// KC_RESTART arrived twice: every copy is dropped.
			want = []string{"AUTH_SESSION_ID", "KC_AUTH_SESSION_HASH", "KC_STATE_CHECKER", "KEYCLOAK_LOCALE"}
		}
		if names := cookieNames(got); !slices.Equal(names, want) {
			t.Errorf("%s: upstream cookies %v, want %v", k, names, want)
		}
		if strings.Contains(got, "rasputin") || strings.Contains(got, "unknown") || strings.Contains(got, hostPrefix) {
			t.Errorf("%s: upstream Cookie %q", k, got)
		}
	}
}

// TC-985-19: the outbound cookie rules.
func TestDoor_OutboundCookies(t *testing.T) {
	f := newFixture(t)
	lines := []string{
		"KEYCLOAK_IDENTITY=id; Path=/realms/rasputin/; Secure; HttpOnly; SameSite=None",
		"AUTH_SESSION_ID=a; Path=/realms/rasputin/; Domain=signin.ci.internal; Secure; HttpOnly; SameSite=None",
		"KC_RESTART=r; Path=/realms/rasputin/; HttpOnly",
		"KEYCLOAK_REMEMBER_ME=; Path=/realms/rasputin/; Max-Age=0",
		"KEYCLOAK_LOCALE=en; Path=/realms/rasputin/; Secure",
		"__Host-rasputin-session=x; Path=/; Secure",
		"rasputin-session=x",
		"__Secure-rasputin-x=x; Secure",
		"KC_AUTH_SESSION_HASH=h; Path=/realms/rasputin/; Secure; SameSite=Strict",
	}
	f.up.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		for _, l := range lines {
			w.Header().Add("Set-Cookie", l)
		}
		w.WriteHeader(200)
	})
	for _, k := range []Kind{Home, App} {
		got := f.do(k, req{target: actions("restart")}).Header().Values("Set-Cookie")
		for _, l := range got {
			if strings.Contains(l, "rasputin-") {
				t.Errorf("%s: an own cookie passed: %q", k, l)
			}
		}
		if k == Home {
			if want := []string{lines[0], lines[1], lines[2], lines[3], lines[4], lines[8]}; !slices.Equal(got, want) {
				t.Errorf("home Set-Cookie %q, want the upstream's lines unchanged %q", got, want)
			}
			continue
		}
		byName := map[string]*http.Cookie{}
		for _, l := range got {
			c, err := http.ParseSetCookie(l)
			if err != nil {
				t.Fatalf("app: %q: %v", l, err)
			}
			byName[c.Name] = c
		}
		for _, n := range renamedCookies {
			c := byName[hostPrefix+n]
			if c == nil || c.Path != "/" || !c.Secure || c.Domain != "" {
				t.Errorf("app: %s became %+v, want __Host- with Path=/, Secure and no Domain", n, c)
			}
			if byName[n] != nil {
				t.Errorf("app: the unprefixed %s was sent too", n)
			}
		}
		if c := byName[hostPrefix+"KEYCLOAK_IDENTITY"]; c == nil || !c.HttpOnly || c.SameSite != http.SameSiteNoneMode || c.Value != "id" {
			t.Errorf("app: KEYCLOAK_IDENTITY's attributes were not kept: %+v", c)
		}
		if c := byName[hostPrefix+"KEYCLOAK_REMEMBER_ME"]; c == nil || c.MaxAge >= 0 {
			t.Errorf("app: the deletion was not kept: %+v", c)
		}
		if !slices.Contains(got, lines[8]) {
			t.Errorf("app: KC_AUTH_SESSION_HASH did not pass unchanged: %q", got)
		}
	}
}

// TC-985-21: every blocking state, features included, answers 503 with the
// not-ready sentence and TRY AGAIN and forwards nothing; history-behind and
// apps-paused do not block; a ctx error refuses; theme files, discovery,
// certs and userinfo are not gated (F-985-18).
func TestDoor_NotReady(t *testing.T) {
	f := newFixture(t)
	want := "Sign-in isn't available right now. Try again in a moment. If it stays like this, tell whoever runs Hoodoo Home."
	auth := req{target: oidc("auth") + "?" + authQuery(policy.ConsoleClient, nil)}
	for _, st := range []identitystate.State{identitystate.Starting, identitystate.Upgrading, identitystate.Paused,
		identitystate.DatabaseDown, identitystate.Held, identitystate.OutOfMemory, identitystate.Failed,
		identitystate.Unreachable, identitystate.Blank, identitystate.FeaturesMismatch, identitystate.FeaturesUnchecked,
		identitystate.AppsPaused, identitystate.HistoryBehind} {
		f.ready.err = readinessOf(st)
		for _, k := range []Kind{Home, App} {
			r := auth
			if k == App {
				r = req{target: oidc("auth") + "?" + authQuery("rasputin-account", nil)}
			}
			before := f.up.count()
			w := f.do(k, r)
			if !st.Blocks() {
				f.wantForwarded(w, before, string(st)+" at "+k.String())
				continue
			}
			f.wantRefused(w, http.StatusServiceUnavailable, before, string(st)+" at "+k.String())
			body := w.Body.String()
			if sentenceIn(t, body) != want || !strings.Contains(body, "TRY AGAIN") {
				t.Errorf("%s at %s: %q, want %q with TRY AGAIN", st, k, sentenceIn(t, body), want)
			}
		}
		if f.ready.err != nil {
			for _, p := range []string{testLoginPath + "css/signin.css", realmPrefix + ".well-known/openid-configuration", oidc("certs"), oidc("userinfo")} {
				f.wantPass(Home, req{target: p}, string(st)+": "+p+" is not gated on readiness")
			}
		}
	}
	f.ready.err = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.ready.err = ctx.Err()
	before := f.up.count()
	f.wantRefused(f.do(Home, auth), http.StatusServiceUnavailable, before, "a ctx error")
}

// readinessOf is Monitor.Ready's answer in state st.
func readinessOf(st identitystate.State) error {
	if st.Blocks() {
		return &identitystate.NotReadyError{State: st}
	}
	return nil
}

// TC-985-22: an upstream that refuses connections is the 502 door page, and
// the WARN record carries the error class and no URL.
func TestDoor_UpstreamFailure(t *testing.T) {
	f := newFixture(t)
	upURL := f.up.srv.URL
	f.up.srv.Close()
	for _, k := range []Kind{Home, App} {
		w := f.do(k, req{target: realmPrefix + ".well-known/openid-configuration"})
		if w.Code != http.StatusBadGateway || !isDoorPage(w) {
			t.Errorf("%s: %d, want the 502 door page", k, w.Code)
		}
	}
	warns := f.rec.Matching(slog.LevelWarn, "upstream failed")
	if len(warns) != 2 {
		t.Fatalf("%d upstream WARN records, want 2:\n%s", len(warns), f.rec.Text())
	}
	if c, _ := logkittest.Attr(warns[0], "error_class"); c != "connect" {
		t.Errorf("error_class %q, want connect", c)
	}
	host := strings.TrimPrefix(upURL, "https://")
	if text := f.rec.Text(); strings.Contains(text, host) || strings.Contains(text, "127.0.0.1") || strings.Contains(text, "dial tcp") {
		t.Errorf("a record names the URL or the error text:\n%s", text)
	}
	for _, c := range []struct {
		err  error
		want string
	}{{context.Canceled, "canceled"}, {context.DeadlineExceeded, "timeout"}, {errors.New("other"), "transport"}} {
		if got := errorClass(c.err); got != c.want {
			t.Errorf("errorClass(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

// TC-985-23: an empty or unreadable install name still reads as a sentence,
// and the page renders with the upstream down.
func TestDoor_InstallNameFallback(t *testing.T) {
	f := newFixture(t)
	f.up.srv.Close()
	f.ready.err = readinessOf(identitystate.Starting)
	want := "Sign-in isn't available right now. Try again in a moment. If it stays like this, tell whoever runs this cluster."
	for _, c := range []struct {
		name string
		err  error
	}{{"", nil}, {"  ", nil}, {"Hoodoo Home", errors.New("database is locked")}} {
		f.name, f.nameErr = c.name, c.err
		w := f.do(Home, req{target: oidc("auth") + "?" + authQuery(policy.ConsoleClient, nil)})
		if got := sentenceIn(t, w.Body.String()); got != want || w.Code != http.StatusServiceUnavailable {
			t.Errorf("name %q, err %v: %d %q, want 503 %q", c.name, c.err, w.Code, got, want)
		}
	}
}

// TC-985-24: one record per request with component, door, pattern, status
// and correlation id, at the plan's level; no URL, query, cookie value,
// address or user in any record.
func TestDoor_Logging(t *testing.T) {
	f := newFixture(t)
	const userNeedle, cookieNeedle, queryNeedle = "needle-user", "needle-cookie", "needle-query"
	hdr := http.Header{"Cookie": {"AUTH_SESSION_ID=" + cookieNeedle}}
	auth := oidc("auth") + "?" + authQuery(policy.ConsoleClient, map[string]string{"login_hint": userNeedle, "nonce": queryNeedle})
	cases := []struct {
		name  string
		do    func() int
		level slog.Level
	}{
		{"relayed", func() int { return f.do(Home, req{target: auth, header: hdr}).Code }, slog.LevelDebug},
		{"filter refusal", func() int {
			return f.do(Home, req{target: auth + "&prompt=none", header: hdr}).Code
		}, slog.LevelInfo},
		{"not found", func() int { return f.do(Home, req{target: "/admin?x=" + queryNeedle}).Code }, slog.LevelInfo},
		{"throttle refusal", func() int {
			for range 4 {
				failFrom(f, peer)
			}
			return f.do(Home, req{method: http.MethodPost, target: actions("authenticate") + "?client_id=" + policy.ConsoleClient,
				form: url.Values{"username": {userNeedle}, "password": {"pw"}}, header: hdr}).Code
		}, slog.LevelInfo},
		{"not ready", func() int {
			f.ready.err = readinessOf(identitystate.Starting)
			defer func() { f.ready.err = nil }()
			return f.do(Home, req{target: auth, header: hdr}).Code
		}, slog.LevelInfo},
		{"upstream failure", func() int {
			f.up.srv.Close()
			return f.do(Home, req{target: auth, header: hdr}).Code
		}, slog.LevelWarn},
	}
	for _, c := range cases {
		n := len(f.rec.Records())
		status := c.do()
		recs := f.rec.Records()[n:]
		var door []slog.Record
		for _, r := range recs {
			if comp, _ := logkittest.Attr(r, "component"); comp == "signin-door" {
				door = append(door, r)
			}
		}
		if len(door) != 1 {
			t.Errorf("%s: %d door records, want 1", c.name, len(door))
			continue
		}
		r := door[0]
		if r.Level != c.level {
			t.Errorf("%s: level %v, want %v", c.name, r.Level, c.level)
		}
		for _, key := range []string{"door", "pattern", "status", "correlation_id"} {
			if _, ok := logkittest.Attr(r, key); !ok {
				t.Errorf("%s: no %s field", c.name, key)
			}
		}
		if s, _ := logkittest.Attr(r, "status"); s != strconv.Itoa(status) {
			t.Errorf("%s: status field %s, answer %d", c.name, s, status)
		}
	}
	text := f.rec.Text()
	for _, needle := range []string{userNeedle, cookieNeedle, queryNeedle, "192.0.2.1", "client_id=", "?"} {
		if strings.Contains(text, needle) {
			t.Errorf("a record holds %q:\n%s", needle, text)
		}
	}
}
