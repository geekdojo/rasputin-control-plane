package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitytest"
)

// The browser walks in this package (the console's pages, Grafana's
// dashboards) run the pinned headless Chrome that scripts/install-identity.sh
// installs, found through identitytest's own layout. Test scaffolding only:
// the allocator options mirror identitytest's browser, whose are unexported.

// walkStepTimeout bounds one browser call (a navigation, an evaluation); it
// is far outside a page's normal load time and decides no outcome.
const walkStepTimeout = 90 * time.Second

// startWalkBrowser starts the pinned headless Chrome with extra flags and
// returns its context; t's cleanup stops it. A missing Chrome skips t, or
// fails it when switchEnv is required.
func startWalkBrowser(t *testing.T, switchEnv string, extra ...chromedp.ExecAllocatorOption) context.Context {
	t.Helper()
	cfg, err := identitytest.ConfigFromEnv()
	if err != nil {
		functest.SkipOrFail(t, switchEnv, "no pinned browser: %v", err)
		return nil
	}
	if _, err := os.Stat(cfg.ChromePath); err != nil {
		functest.SkipOrFail(t, switchEnv, "no pinned browser at %s (scripts/install-identity.sh): %v", cfg.ChromePath, err)
		return nil
	}
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(cfg.ChromePath),
		chromedp.UserDataDir(t.TempDir()),
		chromedp.Headless,
		chromedp.NoSandbox,
		chromedp.Flag("disable-breakpad", true),
		chromedp.Flag("disable-crash-reporter", true),
	)
	opts = append(opts, extra...)
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	t.Cleanup(func() {
		browserCancel()
		allocCancel()
	})
	if err := chromedp.Do(browserCtx); err != nil {
		t.Fatalf("start the pinned browser %s: %v", cfg.ChromePath, err)
	}
	return browserCtx
}

// violationSpyJS records every securitypolicyviolation in the page itself,
// before any page script runs, so the walk reads them with the page's other
// state: as text in __rasputinCSPV, and as its directive and blocked value in
// __rasputinCSPVRecords, for a walk that must tell one violation from another.
const violationSpyJS = `window.__rasputinCSPV = [];
window.__rasputinCSPVRecords = [];
document.addEventListener('securitypolicyviolation', (e) => {
  const text = e.violatedDirective + ' ' + (e.blockedURI || 'inline') +
    (e.sourceFile ? ' at ' + e.sourceFile + ':' + e.lineNumber + ':' + e.columnNumber : '') +
    (e.sample ? ' sample ' + JSON.stringify(e.sample) : '');
  window.__rasputinCSPV.push(text);
  window.__rasputinCSPVRecords.push({directive: e.violatedDirective, blocked: e.blockedURI || 'inline', text: text});
});
`

// walkTab is one browser tab, in a browser context of its own, that records
// the policy of each document it loads.
type walkTab struct {
	ctx context.Context

	mu        sync.Mutex
	docPolicy string // the last document response's Content-Security-Policy
	docs      int    // document responses seen
}

// newWalkTab opens a tab in browserCtx with the violation spy and initJS
// installed ahead of every document.
func newWalkTab(t *testing.T, browserCtx context.Context, initJS string) *walkTab {
	t.Helper()
	ctx, cancel := chromedp.NewContext(browserCtx, chromedp.WithNewBrowserContext())
	t.Cleanup(cancel)
	w := &walkTab{ctx: ctx}
	if err := chromedp.Do(ctx); err != nil {
		t.Fatalf("open a tab: %v", err)
	}
	if err := chromedp.Listen(ctx, func(ev any) {
		e, ok := ev.(*network.EventResponseReceived)
		if !ok || e.Type != network.ResourceTypeDocument {
			return
		}
		var csp []string
		for k, v := range e.Response.Headers {
			if strings.EqualFold(k, "Content-Security-Policy") {
				csp = append(csp, fmt.Sprint(v))
			}
		}
		w.mu.Lock()
		w.docPolicy = strings.Join(csp, "\n")
		w.docs++
		w.mu.Unlock()
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := chromedp.Call(ctx, network.Enable, network.EnableParams{}); err != nil {
		t.Fatalf("Network.enable: %v", err)
	}
	if _, err := chromedp.Call(ctx, page.AddScriptToEvaluateOnNewDocument,
		page.AddScriptToEvaluateOnNewDocumentParams{Source: violationSpyJS + initJS}); err != nil {
		t.Fatalf("install the violation spy: %v", err)
	}
	return w
}

// pageVisit is what a walk learns about one loaded page.
type pageVisit struct {
	policy     string   // the document response's Content-Security-Policy
	violations []string // each "<directive> <blocked URI or inline>"
	state      map[string]any
}

// visit navigates to url, which waits for the load event, and then reads the
// page's violations and the value of each probe expression. When the tab's
// init script defines window.__rasputinSettled, a function returning a
// promise, the read first waits for it: the fact the page must reach before
// it is judged (the console walk's: every script it holds has loaded or
// failed). The read is then queued behind the page's pending tasks (a
// zero-delay task), so violations the parser queued are dispatched before it.
func (w *walkTab) visit(t *testing.T, url string, probes map[string]string) pageVisit {
	t.Helper()
	w.mu.Lock()
	before := w.docs
	w.mu.Unlock()
	ctx, cancel := context.WithTimeout(w.ctx, walkStepTimeout)
	defer cancel()
	if err := chromedp.Do(ctx, chromedp.Navigate(url)); err != nil {
		t.Fatalf("open %s: %v", url, err)
	}
	var exprs []string
	for k, e := range probes {
		exprs = append(exprs, fmt.Sprintf("%q: (() => { try { return (%s); } catch (e) { return 'error: ' + e; } })()", k, e))
	}
	js := `Promise.resolve(typeof window.__rasputinSettled === 'function' ? window.__rasputinSettled() : null)
.then(() => new Promise((resolve) => setTimeout(() => resolve(JSON.stringify({
  violations: window.__rasputinCSPV || ['spy missing'],
  state: {` + strings.Join(exprs, ",\n") + `}
})), 0)))`
	raw, err := chromedp.Run(ctx, chromedp.Evaluate[string](js, chromedp.EvalAwaitPromise))
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	var out struct {
		Violations []string       `json:"violations"`
		State      map[string]any `json:"state"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("read %s: %v (%s)", url, err, raw)
	}
	w.mu.Lock()
	policy, docs := w.docPolicy, w.docs
	w.mu.Unlock()
	if docs == before {
		t.Fatalf("open %s: the browser reported no document response", url)
	}
	return pageVisit{policy: policy, violations: out.Violations, state: out.State}
}
