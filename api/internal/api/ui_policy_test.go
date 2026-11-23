package api

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// policyFixturePage holds two inline scripts, the second with CRLF line
// endings, and one script loaded from /_next/.
const policyFixturePage = "<!DOCTYPE html><html><head>" +
	"<script src=\"/_next/static/x.js\" async></script>" +
	"<script>document.documentElement.dataset.a='1';</script>" +
	"</head><body><script>\r\nself.b=2;\r\nself.c=3;\r\n</script></body></html>"

// fixtureHashes are the hash sources of policyFixturePage's two inline
// scripts, computed here from their text with line endings normalised to LF,
// independently of the tokenizer pagePolicy uses.
func fixtureHashes() (string, string) {
	h := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	return h("document.documentElement.dataset.a='1';"), h("\nself.b=2;\nself.c=3;\n")
}

// assertOtherDirectivesAreBaseline checks every directive of policy but
// script-src against the baseline's.
func assertOtherDirectivesAreBaseline(t *testing.T, label, policy string) {
	t.Helper()
	got, want := cspDirectives(policy), cspDirectives(contentSecurityPolicy)
	if len(got) != len(want) {
		t.Errorf("%s: %d directives, want the baseline's %d: %s", label, len(got), len(want), policy)
	}
	for name, srcs := range want {
		if name == "script-src" {
			continue
		}
		if g := strings.Join(got[name], " "); g != strings.Join(srcs, " ") {
			t.Errorf("%s: %s = %q, want the baseline's %q", label, name, g, strings.Join(srcs, " "))
		}
	}
}

func assertNoUnsafeInlineOrSelfScript(t *testing.T, label, policy string) {
	t.Helper()
	for _, src := range cspDirectives(policy)["script-src"] {
		if src == "'unsafe-inline'" || src == "'self'" {
			t.Errorf("%s: script-src carries %s: %s", label, src, policy)
		}
	}
	if strings.Contains(policy, "'unsafe-inline'") && !strings.Contains(policy, "style-src 'self' 'unsafe-inline';") {
		t.Errorf("%s: 'unsafe-inline' outside style-src: %s", label, policy)
	}
}

// TC-999-08: over TLS at rasputin.local, the page policy's script-src is the
// page's own origin under /_next/, 'wasm-unsafe-eval' and exactly the hashes
// of its inline scripts; the src script is not hashed.
func TestPagePolicy_OverTLS(t *testing.T) {
	r := overTLS(httptest.NewRequest(http.MethodGet, "https://rasputin.local/", nil))
	got := pagePolicy(r, []byte(policyFixturePage))
	a, b := fixtureHashes()
	want := "https://rasputin.local/_next/ 'wasm-unsafe-eval' " + a + " " + b
	if src := strings.Join(cspDirectives(got)["script-src"], " "); src != want {
		t.Errorf("script-src = %q\nwant        %q", src, want)
	}
	assertNoUnsafeInlineOrSelfScript(t, "TLS page", got)
	assertOtherDirectivesAreBaseline(t, "TLS page", got)
}

// TC-999-09: over plain HTTP (the trust page) with a port in Host, the source
// is the http:// origin with that port.
func TestPagePolicy_PlainHTTPWithPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://192.168.1.10:8080/trust", nil)
	got := pagePolicy(r, []byte(policyFixturePage))
	a, b := fixtureHashes()
	src := strings.Join(cspDirectives(got)["script-src"], " ")
	if want := "http://192.168.1.10:8080/_next/ 'wasm-unsafe-eval' " + a + " " + b; src != want {
		t.Errorf("script-src = %q\nwant        %q", src, want)
	}
	assertNoUnsafeInlineOrSelfScript(t, "plain-HTTP page", got)
}

// readFailFS serves name to Stat and Open but fails ReadFile on it.
type readFailFS struct {
	fstest.MapFS
	name string
}

func (f readFailFS) ReadFile(name string) ([]byte, error) {
	if name == f.name {
		return nil, errors.New("read failed")
	}
	return f.MapFS.ReadFile(name)
}

// TC-999-10: a Host the policy cannot name, or a page that cannot be read,
// gets script-src 'none': no host source and no 'unsafe-inline'.
func TestPagePolicy_RefusedHostOrUnreadablePageGetsNoScript(t *testing.T) {
	for _, host := range []string{"", "[::1]", "evil;script-src *", "a b", "host:abc", "host:1:2", "rasputín.local"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = host
		got := pagePolicy(r, []byte(policyFixturePage))
		if src := strings.Join(cspDirectives(got)["script-src"], " "); src != "'none'" {
			t.Errorf("Host %q: script-src = %q, want 'none'", host, src)
		}
		if got != contentSecurityPolicy {
			t.Errorf("Host %q: policy = %q, want the baseline", host, got)
		}
	}

	h := uiHandler{fsys: readFailFS{MapFS: exportFS(), name: "login.html"}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login", nil))
	if got := w.Header().Get("Content-Security-Policy"); got != contentSecurityPolicy {
		t.Errorf("unreadable page: policy = %q, want the baseline's script-src 'none'", got)
	}
}

// writeExport writes a static export whose pages each hold an inline script
// of their own, so a page's policy can be told from another's.
func writeExport(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"index.html":                  "<html><script>self.page='index'</script></html>",
		"login.html":                  "<html><script>self.page='login'</script></html>",
		"trust.html":                  "<html><script>self.page='trust'</script></html>",
		"firewall/rules.html":         "<html><script>self.page='rules'</script></html>",
		"404.html":                    "<html><script>self.page='404'</script></html>",
		"index.txt":                   "rsc-payload",
		"_next/static/chunks/x.js":    "self.x=1",
		"_next/static/chunks/y.css":   "body{}",
		"_next/static/media/font.ttf": "font",
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TC-999-11: every page, the 404 page included, gets its own page policy on
// both listeners that serve the export; HEAD carries GET's headers; script
// and payload files get the baseline; the other security headers are
// unchanged.
func TestUIHandler_PagePolicyPerResponse(t *testing.T) {
	f := newAPIFixture(t)
	dir := writeExport(t)
	f.srv.SetUIDir(dir)
	pageScript := func(page string) string {
		sum := sha256.Sum256([]byte("self.page='" + page + "'"))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	for _, l := range []struct {
		name   string
		h      http.Handler
		tls    bool
		origin string
		pages  map[string]string // path → the page whose script it serves
		status map[string]int
		files  []string
	}{
		{
			name: "Handler", h: f.srv.Handler(), tls: true, origin: "https://example.com/_next/",
			pages:  map[string]string{"/": "index", "/login": "login", "/firewall/rules": "rules", "/no/such/page": "404"},
			status: map[string]int{"/no/such/page": http.StatusNotFound},
			files:  []string{"/_next/static/chunks/x.js", "/index.txt"},
		},
		{
			name: "BootstrapHandler", h: f.srv.BootstrapHandler(), origin: "http://example.com/_next/",
			pages:  map[string]string{"/trust": "trust", "/no-such-file.txt": "404"},
			status: map[string]int{"/no-such-file.txt": http.StatusNotFound},
			files:  []string{"/_next/static/chunks/x.js", "/index.txt"},
		},
	} {
		do := func(method, path string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(method, path, nil)
			if l.tls {
				r = overTLS(r)
			}
			w := httptest.NewRecorder()
			l.h.ServeHTTP(w, r)
			return w
		}
		for path, page := range l.pages {
			label := l.name + " " + path
			w := do(http.MethodGet, path)
			want := http.StatusOK
			if s, ok := l.status[path]; ok {
				want = s
			}
			if w.Code != want {
				t.Errorf("%s: status %d, want %d", label, w.Code, want)
			}
			policy := w.Header().Get("Content-Security-Policy")
			if src := strings.Join(cspDirectives(policy)["script-src"], " "); src != l.origin+" 'wasm-unsafe-eval' "+pageScript(page) {
				t.Errorf("%s: script-src = %q, want %s's own policy", label, src, page)
			}
			assertNoUnsafeInlineOrSelfScript(t, label, policy)
			assertOtherDirectivesAreBaseline(t, label, policy)
			assertHeaders(t, label, w.Header(), map[string]string{
				"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin",
			})
			head := do(http.MethodHead, path)
			for _, k := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Content-Type", "Cache-Control"} {
				if head.Header().Get(k) != w.Header().Get(k) {
					t.Errorf("%s: HEAD %s = %q, GET has %q", label, k, head.Header().Get(k), w.Header().Get(k))
				}
			}
		}
		for _, path := range l.files {
			label := l.name + " " + path
			w := do(http.MethodGet, path)
			if w.Code != http.StatusOK {
				t.Errorf("%s: status %d, want 200", label, w.Code)
			}
			assertHeaders(t, label, w.Header(), baselineHeaders)
		}
	}
}

// The 404 branch with no 404.html in the export is a plain 404 carrying no
// page policy of its own.
func TestUIHandler_NoNotFoundPageKeepsNoPolicy(t *testing.T) {
	fsys := exportFS()
	delete(fsys, "404.html")
	w := httptest.NewRecorder()
	uiHandler{fsys: fsys}.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if w.Code != http.StatusNotFound || w.Header().Get("Content-Security-Policy") != "" {
		t.Errorf("status %d policy %q, want a plain 404 with no page policy", w.Code, w.Header().Get("Content-Security-Policy"))
	}
}

// inlineScriptHashes hashes each distinct inline script once, skips src
// scripts in any letter case, and hashes an empty inline script's empty text.
func TestInlineScriptHashes(t *testing.T) {
	got, err := inlineScriptHashes([]byte(`<script>a</script><SCRIPT SRC="/_next/y.js"></SCRIPT><script>a</script><script></script><div>a</div>`))
	if err != nil {
		t.Fatal(err)
	}
	sum := func(s string) string {
		h := sha256.Sum256([]byte(s))
		return "sha256-" + base64.StdEncoding.EncodeToString(h[:])
	}
	want := []string{sum("a"), sum("")}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("hashes = %v, want %v", got, want)
	}
}

var _ fs.ReadFileFS = readFailFS{}
