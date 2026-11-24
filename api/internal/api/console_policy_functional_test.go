// Functional test: the console's own pages run under their page policy in a
// real browser (geekdojo/geekdojo-brain#999, CI UI-1's console part).
//
// The built static export (ui/out, from `npm ci && npm run build` in ui/) is
// served by the api's real Server.Handler() and BootstrapHandler(), and the
// pinned headless Chrome (scripts/install-identity.sh) visits every page. It
// proves that no page's policy allows 'unsafe-inline' or 'self' for scripts,
// that each page's /_next/ scripts load and its inline theme bootstrap runs,
// and that the browser reports no policy violation: over plain HTTP, over TLS
// at rasputin.local with no port in the origin (the path customers use), and
// on the plain-HTTP trust page. A negative control proves the violation
// recorder can fail.
//
// Run it:
//
//	RASPUTIN_CONSOLE_FUNCTIONAL=1 RASPUTIN_CONSOLE_UI_DIR=$PWD/ui/out \
//	RASPUTIN_IDENTITY_HOME=<install-identity.sh's home> \
//	go test ./api/internal/api -run '^TestConsolePagesPolicy' -v
//
// RASPUTIN_CONSOLE_FUNCTIONAL=required (what CI sets) turns a missing export
// or browser into a failure.

package api

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
)

const (
	consoleFuncEnv  = "RASPUTIN_CONSOLE_FUNCTIONAL"
	consoleUIDirEnv = "RASPUTIN_CONSOLE_UI_DIR"
	// consoleHost is the name the TLS walk visits, on port 443, as a
	// customer's browser does.
	consoleHost = "rasputin.local"
)

// themeSeedJS stores a theme choice before any page script runs, so the
// export's inline theme bootstrap (ui/lib/theme.tsx THEME_BOOTSTRAP) has
// something to apply: data-theme="cyberdeck" on <html> is its effect, and
// nothing else in the UI sets it without a click.
const themeSeedJS = `try { localStorage.setItem('rasputin.theme', 'cyberdeck'); } catch (e) {}`

// scriptSettleJS records, from before any page script runs, each script
// element's load or error event (a script the policy blocks fires error),
// and defines window.__rasputinSettled (see walkTab.visit): a promise that
// resolves once every script the document holds has fired one of them. It
// re-checks on each such event and on each DOM change, because Next.js
// inserts scripts after the load event: an unauthenticated page calls
// router.replace('/login') (ui/app/(authed)/layout.tsx), which inserts the
// login route's chunks. Reading at the load event raced those fetches
// (F-999-17). The scripts are judged at the moment that fact holds, in
// __rasputinScriptsAtSettle (src and outcome of each), so a script inserted
// after it does not race the read either. nomodule scripts are never
// fetched by a module-capable browser, so they are not waited for.
const scriptSettleJS = `(() => {
  const settled = new WeakMap();
  let wake = null;
  const record = (e) => {
    const s = e.target;
    if (s && s.tagName === 'SCRIPT' && s.src) {
      settled.set(s, e.type);
      if (wake) wake();
    }
  };
  document.addEventListener('load', record, true);
  document.addEventListener('error', record, true);
  const scripts = () => Array.from(document.querySelectorAll('script[src]')).filter((s) => !s.noModule);
  window.__rasputinSettled = () => new Promise((resolve) => {
    let watch = null;
    const check = () => {
      const now = scripts();
      if (now.every((s) => settled.has(s))) {
        window.__rasputinScriptsAtSettle = now.map((s) => [s.src, settled.get(s)]);
        wake = null;
        if (watch) watch.disconnect();
        resolve();
      }
    };
    watch = new MutationObserver(check);
    watch.observe(document, {childList: true, subtree: true});
    wake = check;
    check();
  });
})();
`

// pageProbes are read from every visited page, once scriptSettleJS's fact
// holds.
var pageProbes = map[string]string{
	// The inline theme bootstrap ran.
	"theme": `document.documentElement.getAttribute('data-theme')`,
	// Every script the page held when they had all settled loaded: none
	// failed (a script blocked by policy fires error).
	"missing": `window.__rasputinScriptsAtSettle.filter(([, how]) => how !== 'load').map(([src, how]) => src + ' ' + how)`,
	"scripts": `document.querySelectorAll('script[src^="/_next/"]').length`,
}

// consoleExport returns the export directory and its .html pages, as paths
// relative to it.
func consoleExport(t *testing.T) (string, []string) {
	t.Helper()
	if os.Getenv(consoleFuncEnv) == "" {
		t.Skip("set " + consoleFuncEnv + "=1 to run (needs the built export and the pinned browser)")
	}
	dir := os.Getenv(consoleUIDirEnv)
	if dir == "" {
		functest.SkipOrFail(t, consoleFuncEnv, "%s is not set, so there is no built export (npm run build in ui/)", consoleUIDirEnv)
		return "", nil
	}
	var pages []string
	err := fs.WalkDir(os.DirFS(dir), ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".html") {
			pages = append(pages, p)
		}
		return err
	})
	if err != nil || len(pages) == 0 {
		functest.SkipOrFail(t, consoleFuncEnv, "%s=%s holds no .html pages: %v", consoleUIDirEnv, dir, err)
		return "", nil
	}
	return dir, pages
}

// pageRoute is the path the console serves a page file at.
func pageRoute(p string) string {
	if p == "index.html" {
		return "/"
	}
	return "/" + strings.TrimSuffix(p, ".html")
}

// checkConsoleVisit asserts one walked page: a page policy whose script-src
// names wantOrigin and neither 'unsafe-inline' nor 'self', the inline theme
// bootstrap applied, every /_next/ script fetched, and no violation.
func checkConsoleVisit(t *testing.T, label, wantOrigin string, v pageVisit) {
	t.Helper()
	src := cspDirectives(v.policy)["script-src"]
	if len(src) == 0 || src[0] != wantOrigin {
		t.Errorf("%s: script-src = %q, want it to start with %s", label, strings.Join(src, " "), wantOrigin)
	}
	for _, s := range src {
		if s == "'unsafe-inline'" || s == "'self'" {
			t.Errorf("%s: script-src carries %s", label, s)
		}
	}
	if v.state["theme"] != "cyberdeck" {
		t.Errorf("%s: data-theme = %v; the inline theme bootstrap did not run", label, v.state["theme"])
	}
	if n, _ := v.state["scripts"].(float64); n == 0 {
		t.Errorf("%s: the page names no /_next/ script", label)
	}
	if m, ok := v.state["missing"].([]any); !ok || len(m) != 0 {
		t.Errorf("%s: /_next/ scripts not loaded: %v", label, v.state["missing"])
	}
	if len(v.violations) != 0 {
		t.Errorf("%s: %d violations: %v", label, len(v.violations), v.violations)
	}
	t.Logf("%s: %d violations; script-src %s", label, len(v.violations), strings.Join(src, " "))
}

var sha256SourceRE = regexp.MustCompile(` 'sha256-[A-Za-z0-9+/=]+'`)

// withoutHashes serves h with every hash source removed from the page
// policies it sets: the negative control's page.
func withoutHashes(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(&hashStripper{ResponseWriter: w}, r)
	})
}

type hashStripper struct {
	http.ResponseWriter
	wrote bool
}

func (s *hashStripper) WriteHeader(code int) {
	if !s.wrote {
		s.wrote = true
		hd := s.Header()
		hd.Set("Content-Security-Policy", sha256SourceRE.ReplaceAllString(hd.Get("Content-Security-Policy"), ""))
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *hashStripper) Write(b []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

func TestConsolePagesPolicy(t *testing.T) {
	dir, pages := consoleExport(t)
	f := newAPIFixture(t)
	f.srv.SetUIDir(dir)

	plain := httptest.NewServer(f.srv.Handler())
	t.Cleanup(plain.Close)
	tlsSrv := httptest.NewTLSServer(f.srv.Handler())
	t.Cleanup(tlsSrv.Close)
	boot := httptest.NewServer(f.srv.BootstrapHandler())
	t.Cleanup(boot.Close)
	stripped := httptest.NewServer(withoutHashes(f.srv.Handler()))
	t.Cleanup(stripped.Close)

	// Chrome reaches rasputin.local:443 at the TLS server and trusts its
	// certificate by key, so the origin is https://rasputin.local with no
	// port, as on a cluster.
	_, tlsPort, err := net.SplitHostPort(tlsSrv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	spki := sha256.Sum256(tlsSrv.Certificate().RawSubjectPublicKeyInfo)
	browserCtx := startWalkBrowser(t, consoleFuncEnv,
		chromedp.Flag("host-resolver-rules", "MAP "+consoleHost+":443 127.0.0.1:"+tlsPort),
		chromedp.Flag("ignore-certificate-errors-spki-list", base64.StdEncoding.EncodeToString(spki[:])),
	)

	// TC-999-13: every .html page of the export, served by Server.Handler()
	// over plain HTTP, runs with no violation.
	t.Run("TC-999-13 every page", func(t *testing.T) {
		tab := newWalkTab(t, browserCtx, themeSeedJS+scriptSettleJS)
		visited := 0
		for _, p := range pages {
			checkConsoleVisit(t, p, plain.URL+"/_next/", tab.visit(t, plain.URL+pageRoute(p), pageProbes))
			visited++
		}
		if visited != len(pages) || visited == 0 {
			t.Errorf("visited %d pages, the export holds %d", visited, len(pages))
		}
		t.Logf("visited %d of %d pages", visited, len(pages))
	})

	// TC-999-14: the same page with its hashes removed from the policy
	// records a script-src violation, and its inline script does not run.
	t.Run("TC-999-14 negative control", func(t *testing.T) {
		tab := newWalkTab(t, browserCtx, themeSeedJS+scriptSettleJS)
		v := tab.visit(t, stripped.URL+"/", pageProbes)
		if strings.Contains(v.policy, "'sha256-") {
			t.Fatalf("the control page still carries hashes: %s", v.policy)
		}
		scriptViolations := 0
		for _, s := range v.violations {
			if strings.HasPrefix(s, "script-src") {
				scriptViolations++
			}
		}
		if scriptViolations == 0 {
			t.Errorf("no script-src violation recorded without the hashes: %v", v.violations)
		}
		if v.state["theme"] == "cyberdeck" {
			t.Error("the inline theme bootstrap ran without its hash")
		}
		t.Logf("recorded without the hashes: %v", v.violations)
	})

	// TC-999-15: the production path, over TLS at rasputin.local with no
	// port in the origin, and the plain-HTTP trust page on the bootstrap
	// listener.
	t.Run("TC-999-15 TLS at rasputin.local and the trust page", func(t *testing.T) {
		tab := newWalkTab(t, browserCtx, themeSeedJS+scriptSettleJS)
		for _, route := range []string{"/", "/login", "/metrics"} {
			checkConsoleVisit(t, "https://"+consoleHost+route, "https://"+consoleHost+"/_next/",
				tab.visit(t, "https://"+consoleHost+route, pageProbes))
		}
		checkConsoleVisit(t, boot.URL+"/trust", boot.URL+"/_next/", tab.visit(t, boot.URL+"/trust", pageProbes))
	})
}
