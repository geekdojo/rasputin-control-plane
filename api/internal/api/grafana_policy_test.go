package api

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
)

// grafanaRootPath is what Grafana puts for $ROOT_PATH: root_url
// (http://localhost/observability/) without its scheme.
const grafanaRootPath = "localhost/observability/"

// grafanaNonceRE is Grafana's rendered $NONCE: 16 random bytes in unpadded
// base64, 22 characters.
var grafanaNonceRE = regexp.MustCompile(`'nonce-([A-Za-z0-9+/]{22})'`)

// grafanaPolicyRE matches exactly obs.GrafanaCSPTemplate as Grafana renders
// it behind the api's /observability/ proxy.
var grafanaPolicyRE = regexp.MustCompile("^" + strings.NewReplacer(
	regexp.QuoteMeta("$ROOT_PATH"), regexp.QuoteMeta(grafanaRootPath),
	regexp.QuoteMeta("$NONCE"), grafanaNonceRE.String(),
).Replace(regexp.QuoteMeta(obs.GrafanaCSPTemplate)) + "$")

// checkGrafanaPolicy passes only when one Content-Security-Policy value in h
// is Grafana's rendered template, with a nonce, and no value's script-src
// allows 'unsafe-inline'. The api's own frame-ancestors 'self'
// (sameOriginFraming) may sit beside it, and so may the "sandbox" Grafana
// adds to its datasource resource answers. It names what is wrong.
func checkGrafanaPolicy(h http.Header) error {
	values := h.Values("Content-Security-Policy")
	if len(values) == 0 {
		return errors.New("no Content-Security-Policy header")
	}
	var errs []error
	matched := 0
	for _, v := range values {
		if strings.Contains(" "+strings.Join(cspDirectives(v)["script-src"], " ")+" ", " 'unsafe-inline' ") {
			errs = append(errs, fmt.Errorf("script-src allows 'unsafe-inline': %q", v))
		}
		switch {
		case grafanaPolicyRE.MatchString(v):
			matched++
		case v == "frame-ancestors 'self'":
		case v == "sandbox":
			// Grafana's own extra policy on datasource resource answers; a
			// second policy only ever narrows the first.
		case strings.Contains(v, "'strict-dynamic'"):
			errs = append(errs, grafanaPolicyDiff(v))
		default:
			errs = append(errs, fmt.Errorf("unexpected policy %q", v))
		}
	}
	if matched != 1 {
		errs = append(errs, fmt.Errorf("%d values are Grafana's rendered policy, want exactly 1 (values: %q)", matched, values))
	}
	return errors.Join(errs...)
}

// grafanaPolicyDiff names each directive of v that differs from the rendered
// template.
func grafanaPolicyDiff(v string) error {
	want := cspDirectives(strings.ReplaceAll(obs.GrafanaCSPTemplate, "$ROOT_PATH", grafanaRootPath))
	got := cspDirectives(v)
	var errs []error
	for name, srcs := range got {
		w, ok := want[name]
		if !ok {
			errs = append(errs, fmt.Errorf("Grafana's policy carries an extra directive %s", name))
			continue
		}
		if name == "script-src" {
			nonces := grafanaNonceRE.FindAllString(strings.Join(srcs, " "), -1)
			if len(nonces) != 1 {
				errs = append(errs, fmt.Errorf("script-src carries %d nonces of 22 characters, want 1: %q", len(nonces), strings.Join(srcs, " ")))
			}
			srcs = withoutNonce(srcs)
			w = withoutNonce(w)
		}
		if strings.Join(srcs, " ") != strings.Join(w, " ") {
			errs = append(errs, fmt.Errorf("%s = %q, want %q", name, strings.Join(srcs, " "), strings.Join(w, " ")))
		}
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			errs = append(errs, fmt.Errorf("Grafana's policy lacks %s", name))
		}
	}
	return errors.Join(errs...)
}

func withoutNonce(srcs []string) []string {
	var out []string
	for _, s := range srcs {
		if s != "$NONCE" && !strings.HasPrefix(s, "'nonce-") {
			out = append(out, s)
		}
	}
	return out
}

// grafanaNonce returns the nonce in h's Grafana policy, or "".
func grafanaNonce(h http.Header) string {
	for _, v := range h.Values("Content-Security-Policy") {
		if grafanaPolicyRE.MatchString(v) {
			return grafanaNonceRE.FindStringSubmatch(v)[1]
		}
	}
	return ""
}

// TC-999-04: the header check passes Grafana's rendered policy beside the
// api's frame-ancestors, and fails, naming why, on a fixture without it, with
// no header, with no nonce, with 'unsafe-inline' and with grafana.com.
func TestCheckGrafanaPolicy(t *testing.T) {
	const nonce = "'nonce-aSO/7kakZgNW3la9FOJ9Gg'"
	rendered := strings.NewReplacer("$ROOT_PATH", grafanaRootPath, "$NONCE", nonce).Replace(obs.GrafanaCSPTemplate)
	header := func(values ...string) http.Header {
		h := http.Header{}
		for _, v := range values {
			h.Add("Content-Security-Policy", v)
		}
		return h
	}
	for _, c := range []struct {
		name    string
		h       http.Header
		wantErr []string // each must appear; none = must pass
	}{
		{"a: the api's frame-ancestors and Grafana's policy", header("frame-ancestors 'self'", rendered), nil},
		{"a: with Grafana's sandbox beside it", header("frame-ancestors 'self'", rendered, "sandbox"), nil},
		{"b: only the api's frame-ancestors", header("frame-ancestors 'self'"), []string{"0 values are Grafana's rendered policy"}},
		{"c: no header", header(), []string{"no Content-Security-Policy header"}},
		{"d: empty nonce", header(strings.Replace(rendered, nonce, "'nonce-'", 1)), []string{"script-src carries 0 nonces"}},
		{"d: no nonce", header(strings.Replace(rendered, " "+nonce, "", 1)), []string{"script-src carries 0 nonces"}},
		{"e: 'unsafe-inline' in script-src", header(strings.Replace(rendered, "'strict-dynamic'", "'strict-dynamic' 'unsafe-inline'", 1)),
			[]string{"script-src allows 'unsafe-inline'"}},
		{"f: grafana.com in connect-src", header(strings.Replace(rendered, "connect-src 'self'", "connect-src 'self' grafana.com", 1)),
			[]string{`connect-src = "'self' grafana.com wss://localhost/observability/"`}},
	} {
		err := checkGrafanaPolicy(c.h)
		if c.wantErr == nil {
			if err != nil {
				t.Errorf("%s: %v, want a pass", c.name, err)
			}
			if got := grafanaNonce(c.h); got != strings.TrimSuffix(strings.TrimPrefix(nonce, "'nonce-"), "'") {
				t.Errorf("%s: nonce = %q", c.name, got)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: passed, want a failure", c.name)
			continue
		}
		for _, w := range c.wantErr {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: error %q does not name %q", c.name, err, w)
			}
		}
		if grafanaNonce(c.h) != "" {
			t.Errorf("%s: a nonce was read from a policy that fails", c.name)
		}
	}
}

// cspViolation is one securitypolicyviolation a browser walk recorded: the
// directive it violated, what was blocked (a URL, "inline" or "eval"), and
// the whole event as text for the log.
type cspViolation struct {
	Directive string `json:"directive"`
	Blocked   string `json:"blocked"`
	Text      string `json:"text"`
}

// dashboardViolationProblems judges the violations one Grafana dashboard page
// load recorded. Grafana 13.3.1's bundled zod library probes eval once, in a
// try/catch, and falls back when the policy blocks it; that probe is allowed,
// at most once per page load, because the policy keeps 'unsafe-eval' out on
// purpose. It is matched by its directive and blocked value only, never by a
// bundle file or line, which change with every Grafana release. Any other
// violation, or a second eval probe, is a problem.
func dashboardViolationProblems(vs []cspViolation) []string {
	var problems []string
	evalProbes := 0
	for _, v := range vs {
		if v.Directive == "script-src" && v.Blocked == "eval" {
			evalProbes++
			if evalProbes == 1 {
				continue
			}
		}
		problems = append(problems, "violation: "+v.Text)
	}
	return problems
}

// TC-999-06: the dashboard walk allows exactly the one blocked eval probe per
// page load and fails on any other violation.
func TestDashboardViolationProblems(t *testing.T) {
	evalProbe := cspViolation{"script-src", "eval", "script-src eval at x.js:1:2"}
	for _, c := range []struct {
		name string
		vs   []cspViolation
		want int
	}{
		{"none", nil, 0},
		{"the one eval probe", []cspViolation{evalProbe}, 0},
		{"a second eval probe", []cspViolation{evalProbe, evalProbe}, 1},
		{"an inline script", []cspViolation{{"script-src-elem", "inline", "script-src-elem inline"}}, 1},
		{"eval under another directive", []cspViolation{{"style-src", "eval", "style-src eval"}}, 1},
		{"a blocked script URL beside the probe", []cspViolation{evalProbe, {"script-src", "https://evil.example/x.js", "script-src https://evil.example/x.js"}}, 1},
		{"a blocked connection", []cspViolation{{"connect-src", "wss://grafana.com/", "connect-src wss://grafana.com/"}}, 1},
	} {
		got := dashboardViolationProblems(c.vs)
		if len(got) != c.want {
			t.Errorf("%s: %d problems %q, want %d", c.name, len(got), got, c.want)
		}
		for _, p := range got {
			if strings.Contains(p, "eval at x.js") && c.name != "a second eval probe" {
				t.Errorf("%s: the allowed probe was reported: %q", c.name, p)
			}
		}
	}
}
