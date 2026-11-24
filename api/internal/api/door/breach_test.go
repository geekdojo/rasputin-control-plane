package door

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/geekdojo/rasputin-control-plane/api/internal/api/door/policy"
	"github.com/geekdojo/rasputin-control-plane/api/internal/breachcheck"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// The breached-password warning's door cases (geekdojo/geekdojo-brain#1145,
// PR 2; TC-1145-29 to TC-1145-36). The password is the literal "password",
// whose SHA-1 is known, so no test here hashes anything.
const (
	pwHash   = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
	pwPrefix = "5BAA6"
	pwSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
)

// flowQuery is a login-actions step's query, as the identity service writes
// it into the form's action.
func flowQuery(client string) string {
	return "session_code=sc-1&execution=ex-1&client_id=" + client + "&tab_id=tab-1&client_data=cd-1"
}

// pwCase is one route that sets a new password.
type pwCase struct {
	name   string
	door   Kind
	target string
	field  string
}

func pwCases() []pwCase {
	return []pwCase{
		{"registration at the home door", Home, actions("registration") + "?" + flowQuery(policy.ConsoleClient), "password"},
		{"required-action at the home door", Home, actions("required-action") + "?" + flowQuery(policy.ConsoleClient), "password-new"},
		{"required-action at the app door", App, actions("required-action") + "?" + flowQuery(doorClient(App)), "password-new"},
	}
}

// formFor is a password post's form for c, with the password pw.
func formFor(c pwCase, pw string) url.Values {
	if c.field == "password" {
		return url.Values{"username": {"new"}, "email": {"new@x.invalid"}, "password": {pw}, "password-confirm": {pw}}
	}
	return url.Values{"password-new": {pw}, "password-confirm": {pw}}
}

// lastRecord is the request's one log record: the newest the door wrote.
func (f *fixture) lastRecord() slog.Record {
	f.t.Helper()
	recs := f.rec.Records()
	if len(recs) == 0 {
		f.t.Fatal("the door logged nothing")
	}
	return recs[len(recs)-1]
}

// wantRecord fails unless the last record has level, message (when not
// empty) and every field in want.
func (f *fixture) wantRecord(what string, level slog.Level, msg string, want map[string]string) {
	f.t.Helper()
	rec := f.lastRecord()
	if rec.Level != level || (msg != "" && rec.Message != msg) {
		f.t.Errorf("%s: the record is %s %q, want %s %q", what, rec.Level, rec.Message, level, msg)
	}
	for k, v := range want {
		if got, _ := logkittest.Attr(rec, k); got != v {
			f.t.Errorf("%s: the record's %s is %q, want %q", what, k, got, v)
		}
	}
}

// noBreachLeak is TC-1145-35: the captured log holds no password, hash,
// suffix or prefix, and no name of the service.
func (f *fixture) noBreachLeak(extra ...string) {
	f.t.Helper()
	text := f.rec.Text()
	for _, s := range append([]string{"password=", pwHash, strings.ToLower(pwHash), pwSuffix, strings.ToLower(pwSuffix),
		pwPrefix, strings.ToLower(pwPrefix), "pwnedpasswords"}, extra...) {
		if strings.Contains(text, s) {
			f.t.Errorf("the log holds %q:\n%s", s, text)
		}
	}
	// The literal password itself, as a value rather than a field name.
	for _, rec := range f.rec.Records() {
		rec.Attrs(func(a slog.Attr) bool {
			if strings.Contains(a.Value.String(), "password") && a.Key != "pattern" && a.Key != "msg" {
				f.t.Errorf("the log field %s holds %q", a.Key, a.Value.String())
			}
			return true
		})
	}
}

// warning is the parsed warning page.
type warning struct {
	action, method, choose string
	hidden                 [][2]string
}

func parseWarning(t *testing.T, body string) warning {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	attr := func(n *html.Node, k string) string {
		for _, a := range n.Attr {
			if a.Key == k {
				return a.Val
			}
		}
		return ""
	}
	var w warning
	var inForm func(*html.Node, bool)
	inForm = func(n *html.Node, form bool) {
		if n.Type == html.ElementNode {
			switch {
			case n.Data == "form" && attr(n, "id") == "rasputin-keep-form":
				w.action, w.method, form = attr(n, "action"), attr(n, "method"), true
			case n.Data == "input" && form && attr(n, "type") == "hidden":
				w.hidden = append(w.hidden, [2]string{attr(n, "name"), attr(n, "value")})
			case n.Data == "a" && attr(n, "id") == "rasputin-choose-another":
				w.choose = attr(n, "href")
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			inForm(c, form)
		}
	}
	inForm(doc, false)
	return w
}

// values is the Keep form re-encoded as a browser would post it.
func (w warning) values() url.Values {
	v := url.Values{}
	for _, h := range w.hidden {
		v.Add(h[0], h[1])
	}
	return v
}

// TC-1145-29: a listed password gets the warning page, and nothing is
// relayed.
func TestBreach_WarningPage(t *testing.T) {
	for _, c := range pwCases() {
		f := newFixture(t)
		f.breach.listed = true
		form := formFor(c, "password")
		form[c.field] = append(form[c.field], "second")
		w := f.do(c.door, req{method: http.MethodPost, target: c.target, form: form})
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `data-page-id="rasputin-door-warning"`) {
			t.Fatalf("%s: %d %.300q; want 200 with the warning page", c.name, w.Code, w.Body.String())
		}
		if !strings.Contains(html.UnescapeString(w.Body.String()), sentenceBreached) {
			t.Errorf("%s: the page does not say %q", c.name, sentenceBreached)
		}
		if n := f.up.count(); n != 0 {
			t.Errorf("%s: %d requests reached the upstream, want 0", c.name, n)
		}
		if got := f.breach.calls(); !slices.Equal(got, []string{"password"}) {
			t.Errorf("%s: Breach was asked %d times (first value checked: %v), want once with the first value", c.name, len(got), len(got) == 1 && got[0] == "password")
		}
		p := parseWarning(t, w.Body.String())
		if p.method != "post" || p.action != c.target {
			t.Errorf("%s: the Keep form is %s %q, want post to %q", c.name, p.method, p.action, c.target)
		}
		want := url.Values{}
		for k, vs := range form {
			want[k] = vs
		}
		want.Set(keepField, "keep")
		if got := p.values(); got.Encode() != want.Encode() {
			t.Errorf("%s: the Keep form's fields differ from the post's with the marker", c.name)
		}
		cu, err := url.Parse(p.choose)
		if err != nil {
			t.Fatal(err)
		}
		tu, _ := url.Parse(c.target)
		wantQ := tu.Query()
		wantQ.Del("session_code")
		if cu.Path != tu.Path || cu.Host != "" || cu.Query().Encode() != wantQ.Encode() || cu.Query().Has("session_code") {
			t.Errorf("%s: choose-another is %q, want the path with the query minus session_code", c.name, p.choose)
		}
		for _, k := range []string{"execution", "client_id", "tab_id", "client_data"} {
			if cu.Query().Get(k) == "" {
				t.Errorf("%s: choose-another dropped %s", c.name, k)
			}
		}
		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'none'") || strings.Contains(csp, "form-action") {
			t.Errorf("%s: the page's policy is %q, want script-src 'none' and no form-action", c.name, csp)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: Cache-Control %q, Referrer-Policy %q", c.name, w.Header().Get("Cache-Control"), w.Header().Get("Referrer-Policy"))
		}
		f.wantRecord(c.name, slog.LevelInfo, "sign-in door password warning shown", map[string]string{"breach_check": breachListed, "status": "200"})
		f.noBreachLeak()
	}
}

// TC-1145-30: the echoed fields round-trip byte for byte, a repeated field
// in its order.
func TestBreach_EchoRoundTrips(t *testing.T) {
	f := newFixture(t)
	f.breach.listed = true
	pw := `pa"ss<wo>rd&'é-xyz12`
	if n := len([]rune(pw)); n != 20 {
		t.Fatalf("given: the password is %d characters, want 20", n)
	}
	c := pwCases()[1]
	form := formFor(c, pw)
	form["extra"] = []string{"three", "one", "two"}
	w := f.do(c.door, req{method: http.MethodPost, target: c.target, form: form})
	p := parseWarning(t, w.Body.String())
	got := p.values()
	for k, vs := range form {
		if !slices.Equal(got[k], vs) {
			t.Errorf("the field %s came back as %d values, want %d in order, byte for byte", k, len(got[k]), len(vs))
		}
	}
	if strings.Contains(w.Body.String(), "[redacted]") {
		t.Error("the page echoes the redaction marker, not the value")
	}
	f.noBreachLeak(pw)
}

// TC-1145-31: a post carrying the keep marker is relayed unchanged with no
// check.
func TestBreach_KeepSkipsTheCheck(t *testing.T) {
	for _, c := range pwCases() {
		f := newFixture(t)
		f.breach.listed = true
		form := formFor(c, "password")
		form.Set(keepField, "keep")
		w := f.do(c.door, req{method: http.MethodPost, target: c.target, form: form})
		f.wantForwarded(w, 0, c.name)
		if n := len(f.breach.calls()); n != 0 {
			t.Errorf("%s: Breach was called %d times", c.name, n)
		}
		if got, _ := url.ParseQuery(f.up.last(t).body); got.Encode() != form.Encode() {
			t.Errorf("%s: the upstream received a different form", c.name)
		}
		f.wantRecord(c.name, slog.LevelInfo, "", map[string]string{"breach_check": breachKept})
		f.noBreachLeak()
	}
}

// TC-1145-32: a password that is not listed is relayed unchanged.
func TestBreach_NotListed(t *testing.T) {
	for _, c := range pwCases() {
		f := newFixture(t)
		form := formFor(c, "password")
		w := f.do(c.door, req{method: http.MethodPost, target: c.target, form: form})
		f.wantForwarded(w, 0, c.name)
		if got, _ := url.ParseQuery(f.up.last(t).body); got.Encode() != form.Encode() {
			t.Errorf("%s: the upstream received a different form", c.name)
		}
		if n := len(f.breach.calls()); n != 1 {
			t.Errorf("%s: Breach was called %d times, want 1", c.name, n)
		}
		f.wantRecord(c.name, slog.LevelDebug, "", map[string]string{"breach_check": breachNotListed})
		f.noBreachLeak()
	}
}

// TC-1145-33: a check that cannot finish relays the post (EX-1), with one
// WARN naming its class.
func TestBreach_FailOpenByClass(t *testing.T) {
	for class, err := range map[string]error{
		"timeout":   fmt.Errorf("range: %w", context.DeadlineExceeded),
		"canceled":  context.Canceled,
		"connect":   &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")},
		"tls":       &tls.CertificateVerificationError{Err: errors.New("unknown authority")},
		"transport": errors.New("unexpected EOF"),
		"answer":    fmt.Errorf("%w (status 503)", breachcheck.ErrUnexpectedAnswer),
	} {
		f := newFixture(t)
		f.breach.err = err
		c := pwCases()[1]
		form := formFor(c, "password")
		w := f.do(c.door, req{method: http.MethodPost, target: c.target, form: form})
		f.wantForwarded(w, 0, class)
		if isDoorPage(w) {
			t.Errorf("%s: a door page was shown", class)
		}
		if got, _ := url.ParseQuery(f.up.last(t).body); got.Encode() != form.Encode() {
			t.Errorf("%s: the upstream received a different form", class)
		}
		if n := len(f.rec.AtLevel(slog.LevelWarn)); n != 1 {
			t.Errorf("%s: %d WARN records, want 1", class, n)
		}
		f.wantRecord(class, slog.LevelWarn, "sign-in door relayed without the breach check",
			map[string]string{"breach_check": breachUnavailable, "breach_error_class": class})
		f.noBreachLeak()
	}
}

// TC-1145-34: the check never runs where no new password is set, and the
// request behaves as before.
func TestBreach_NeverChecked(t *testing.T) {
	f := newFixture(t)
	f.breach.listed = true
	ra := actions("required-action") + "?" + flowQuery(policy.ConsoleClient)
	reg := actions("registration") + "?" + flowQuery(policy.ConsoleClient)
	pass := []struct {
		what string
		r    req
	}{
		{"an authenticate POST with password", req{method: http.MethodPost, target: actions("authenticate") + "?" + flowQuery(policy.ConsoleClient),
			form: url.Values{"username": {"u"}, "password": {"password"}}}},
		{"a reset-credentials POST", req{method: http.MethodPost, target: actions("reset-credentials") + "?client_id=" + policy.ResetHomeClient,
			form: url.Values{"username": {"u"}}}},
		{"a GET of registration", req{target: reg}},
		{"a GET of required-action", req{target: ra}},
		{"password-new absent", req{method: http.MethodPost, target: ra, form: url.Values{"password-confirm": {"password"}}}},
		{"password-new empty", req{method: http.MethodPost, target: ra, form: url.Values{"password-new": {""}, "password-confirm": {"password"}}}},
	}
	for _, p := range pass {
		f.wantPass(Home, p.r, p.what)
		if _, ok := logkittest.Attr(f.lastRecord(), "breach_check"); ok {
			t.Errorf("%s: the record names a breach check", p.what)
		}
	}
	f.want400(Home, req{method: http.MethodPost, target: actions("registration") + "?" + flowQuery("rasputin-mesh"),
		form: url.Values{"username": {"new"}, "password": {"password"}}}, "a registration POST the policy refuses")
	if n := len(f.breach.calls()); n != 0 {
		t.Errorf("Breach was called %d times, want 0", n)
	}
	f.noBreachLeak()
}

// TC-1145-36: New refuses a missing Breach; Build gives both doors the one
// it is given.
func TestBreach_Wired(t *testing.T) {
	f := newFixture(t)
	s := f.shared(t)
	cfg := Config{Door: f.table.Home, Kind: Home, ConsoleOrigin: s.ConsoleOrigin, Policy: s.Policy, Throttle: s.Throttle,
		Transport: s.Transport, Upstream: s.Upstream, Theme: s.Theme, Assets: s.Assets, Version: s.Version, InstallName: s.InstallName,
		Dirty: s.Dirty, IDs: s.IDs, Log: s.Log}
	if _, err := New(cfg); err == nil || err.Error() != "door: Config.Breach is missing" {
		t.Errorf("New with no Breach = %v, want door: Config.Breach is missing", err)
	}
	f.breach.listed = true
	for i, c := range pwCases()[1:] {
		f.do(c.door, req{method: http.MethodPost, target: c.target, form: formFor(c, "password")})
		if n := len(f.breach.calls()); n != i+1 {
			t.Errorf("%s: the shared Breach has %d calls, want %d", c.name, n, i+1)
		}
	}
}

// The template never renders a field's value through secret.Value: a
// hidden field is a plain string (F-1145-28's trap).
func TestBreach_HiddenFieldIsAString(t *testing.T) {
	w := httptest.NewRecorder()
	f := newFixture(t)
	f.home.render(w, http.StatusOK, page{Kind: pageWarning, Keep: "/x", KeepField: keepField,
		Fields: []hiddenField{{Name: "password-new", Value: "v<1>"}}})
	if !strings.Contains(w.Body.String(), `name="password-new" value="v&lt;1&gt;"`) {
		t.Errorf("the hidden field renders as %q", w.Body.String())
	}
}
