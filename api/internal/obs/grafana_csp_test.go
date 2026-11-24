package obs

import (
	"strconv"
	"strings"
	"testing"
)

// grafanaAdvisories are the two cross-site scripting advisories the 11.5.1
// pin sat inside (geekdojo/geekdojo-brain#999), with every release Grafana
// names as fixing them.
var grafanaAdvisories = []struct {
	id    string
	fixed []string
}{
	{"CVE-2025-4123", []string{"11.5.4+security-01", "12.0.0+security-01"}},
	// 12.1.2 fixes a bypass of the first fix.
	{"CVE-2025-6023", []string{"11.5.6+security-01", "12.0.2+security-01", "12.1.2"}},
}

// releaseAtOrPast reports whether release tag is at or past fixed. A fixed
// version with a +security suffix is past its own base, so tag must then be
// strictly newer than the base.
func releaseAtOrPast(t *testing.T, tag, fixed string) bool {
	t.Helper()
	base, suffix, _ := strings.Cut(fixed, "+")
	a, b := versionParts(t, tag), versionParts(t, base)
	for i := range 3 {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return suffix == ""
}

func versionParts(t *testing.T, v string) [3]int {
	t.Helper()
	var out [3]int
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		t.Fatalf("version %q is not major.minor.patch", v)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("version %q: %v", v, err)
		}
		out[i] = n
	}
	return out
}

// TC-999-01: the pinned Grafana is 13.3.1, at or past every release that fixes
// CVE-2025-4123 and CVE-2025-6023, the 12.1.2 bypass fix included.
func TestGrafanaPin_PastBothAdvisories(t *testing.T) {
	repoTag, _, ok := strings.Cut(defaultGrafanaImage, "@")
	if !ok {
		t.Fatalf("defaultGrafanaImage = %q carries no digest", defaultGrafanaImage)
	}
	_, tag, _ := strings.Cut(repoTag, ":")
	if tag != "13.3.1" {
		t.Fatalf("defaultGrafanaImage tag = %q, want 13.3.1", tag)
	}
	for _, adv := range grafanaAdvisories {
		for _, fixed := range adv.fixed {
			if !releaseAtOrPast(t, tag, fixed) {
				t.Errorf("Grafana %s is not past %s: it is fixed from %s", tag, adv.id, fixed)
			}
		}
		t.Logf("Grafana %s is past %s (fixed from %s)", tag, adv.id, strings.Join(adv.fixed, ", "))
	}
	// The comparison itself can fail: 11.5.1 is inside both advisories, and
	// 12.1.1 is inside the CVE-2025-6023 bypass.
	if releaseAtOrPast(t, "11.5.1", "11.5.4+security-01") || releaseAtOrPast(t, "12.1.1", "12.1.2") ||
		releaseAtOrPast(t, "11.5.4", "11.5.4+security-01") {
		t.Error("the version comparison passed a release inside an advisory")
	}
}

// issueGrafanaTemplate is the template geekdojo/geekdojo-brain#999 mandates,
// typed out here and not taken from GrafanaCSPTemplate, so the test compares
// the shipped constant with the issue's text. It carries base-uri 'self', not
// 'none', which blocks Grafana's own <base> (decision of 2026-11-23).
const issueGrafanaTemplate = "script-src 'strict-dynamic' $NONCE; object-src 'none'; base-uri 'self'; " +
	"frame-ancestors 'self'; form-action 'self'; connect-src 'self' wss://$ROOT_PATH; " +
	"img-src 'self' data: blob:; font-src 'self'; style-src 'self' 'unsafe-inline' blob:; " +
	"manifest-src 'self'; media-src 'none'"

// TC-999-02: grafana.ini turns Grafana's own script policy on with exactly
// the issue's template, in socket mode and in the developer TCP fallback, and
// keeps the [security] keys it already had.
func TestGrafanaIni_ScriptPolicy(t *testing.T) {
	for name, sup := range map[string]*DockerComposeSupervisor{
		"socket": socketSup(t, t.TempDir()),
		"tcp":    tcpSup(t, t.TempDir()),
	} {
		ini, err := sup.renderGrafanaIni()
		if err != nil {
			t.Fatalf("%s: render: %v", name, err)
		}
		_, security, ok := strings.Cut(ini, "\n[security]\n")
		if !ok {
			t.Fatalf("%s: grafana.ini has no [security] section\n---\n%s", name, ini)
		}
		security, _, _ = strings.Cut(security, "\n[")
		for _, want := range []string{
			"\ncontent_security_policy = true\n",
			"\ncontent_security_policy_template = \"\"\"" + issueGrafanaTemplate + "\"\"\"\n",
			"\ndisable_initial_admin_creation = true\n",
			"\nallow_embedding = true\n",
		} {
			if !strings.Contains("\n"+security, want) {
				t.Errorf("%s: [security] is missing %q\n---\n%s", name, strings.TrimSpace(want), security)
			}
		}
	}
}

// F-999-16: Grafana runs only the plugins bundled in the pinned image. From
// 13 its default downloads plugins from grafana.com on every start and swaps
// prometheus in over the bundled copy, which drops the VictoriaMetrics
// datasource while it swaps (measured on 13.3.1). Both modes turn that off.
func TestGrafanaIni_NoPluginPreinstall(t *testing.T) {
	for name, sup := range map[string]*DockerComposeSupervisor{
		"socket": socketSup(t, t.TempDir()),
		"tcp":    tcpSup(t, t.TempDir()),
	} {
		ini, err := sup.renderGrafanaIni()
		if err != nil {
			t.Fatalf("%s: render: %v", name, err)
		}
		_, plugins, ok := strings.Cut(ini, "\n[plugins]\n")
		if !ok {
			t.Fatalf("%s: grafana.ini has no [plugins] section\n---\n%s", name, ini)
		}
		plugins, _, _ = strings.Cut(plugins, "\n[")
		if !strings.Contains("\n"+plugins, "\npreinstall_disabled = true\n") {
			t.Errorf("%s: [plugins] does not set preinstall_disabled = true\n---\n%s", name, plugins)
		}
	}
}

// grafanaTemplateProblems names each way tmpl breaks the issue's acceptance
// criteria for Grafana's script policy. 'unsafe-inline' is refused in
// script-src only: the mandated template itself keeps it in style-src.
func grafanaTemplateProblems(tmpl string) []string {
	var problems []string
	directives := map[string][]string{}
	for _, d := range strings.Split(tmpl, ";") {
		f := strings.Fields(d)
		if len(f) == 0 {
			continue
		}
		directives[f[0]] = f[1:]
		for _, src := range f[1:] {
			switch {
			case src == "'unsafe-eval'":
				problems = append(problems, f[0]+" allows 'unsafe-eval'")
			case strings.Contains(src, "grafana.com"):
				problems = append(problems, f[0]+" names grafana.com")
			case strings.HasPrefix(src, "ws:"):
				problems = append(problems, f[0]+" names the plain ws: source "+src)
			}
		}
	}
	script := " " + strings.Join(directives["script-src"], " ") + " "
	if strings.Contains(script, " 'unsafe-inline' ") {
		problems = append(problems, "script-src allows 'unsafe-inline'")
	}
	for _, want := range []string{"'strict-dynamic'", "$NONCE"} {
		if !strings.Contains(script, " "+want+" ") {
			problems = append(problems, "script-src lacks "+want)
		}
	}
	for d, want := range map[string]string{"frame-ancestors": "'self'", "object-src": "'none'", "base-uri": "'self'"} {
		if got := strings.Join(directives[d], " "); got != want {
			problems = append(problems, d+" is "+strconv.Quote(got)+", want "+want)
		}
	}
	return problems
}

// grafanaDefaultTemplate is Grafana's own default template at v13.3.1
// (conf/defaults.ini:563), the negative control for TC-999-03.
const grafanaDefaultTemplate = "script-src 'self' 'unsafe-eval' 'unsafe-inline' 'strict-dynamic' $NONCE;object-src 'none';" +
	"font-src 'self';style-src 'self' 'unsafe-inline' blob:;img-src * data: blob:;base-uri 'self';" +
	"connect-src 'self' grafana.com *.cartocdn.com ws://$ROOT_PATH wss://$ROOT_PATH;manifest-src 'self';" +
	"media-src 'none';form-action 'self' $FORM_ACTION_ADDITIONAL_HOSTS;"

// TC-999-03: the rendered template carries no 'unsafe-inline' script source,
// no 'unsafe-eval', no grafana.com and no ws: source, and Grafana's default
// fails the same check on each of those.
func TestGrafanaCSPTemplate_RefusesUnsafeSources(t *testing.T) {
	ini, err := socketSup(t, t.TempDir()).renderGrafanaIni()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	_, rendered, _ := strings.Cut(ini, "content_security_policy_template = \"\"\"")
	rendered, _, ok := strings.Cut(rendered, "\"\"\"")
	if !ok {
		t.Fatalf("no template in grafana.ini\n---\n%s", ini)
	}
	if p := grafanaTemplateProblems(rendered); len(p) != 0 {
		t.Errorf("the rendered template fails the check: %v", p)
	}
	t.Logf("rendered template passes: %s", rendered)

	got := strings.Join(grafanaTemplateProblems(grafanaDefaultTemplate), "; ")
	for _, want := range []string{
		"script-src allows 'unsafe-inline'",
		"script-src allows 'unsafe-eval'",
		"connect-src names grafana.com",
		"connect-src names the plain ws: source ws://$ROOT_PATH",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Grafana's default template should fail with %q; the check said: %s", want, got)
		}
	}
	t.Logf("Grafana's default template fails: %s", got)
}
