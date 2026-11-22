package identitytest

// The helpers of the sign-in theme walk (theme_walk_functional_test.go,
// geekdojo/geekdojo-brain#988): the forbidden-words matcher over
// ui/forbidden-words.json, the page table built from the theme's coverage
// record, the browser tab that records what each page loaded and logged, and
// the per-page checks of TC-988-18.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	_ "image/png"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/accessibility"
	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/input"
	cdplog "github.com/chromedp/cdproto/log"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// uiDir is ui/, from this package's directory.
var uiDir = filepath.Join("..", "..", "..", "ui")

// ---- forbidden words -------------------------------------------------------

// forbiddenWords is ui/forbidden-words.json. Its rule is ui/lib/forbidden-words.ts's:
// case-insensitive from a word start (not after a letter, digit or _), a
// multi-word entry across any white space. This is the Go copy, because the
// walk is Go; the exemptions cover console source files, which the walk never
// reads, so it applies none.
type forbiddenWords struct {
	Words []string `json:"words"`
	res   []*regexp.Regexp
}

func loadForbiddenWords(t *testing.T) forbiddenWords {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(uiDir, "forbidden-words.json"))
	if err != nil {
		t.Fatalf("read the forbidden-words list: %v", err)
	}
	var f forbiddenWords
	if err := json.Unmarshal(b, &f); err != nil || len(f.Words) == 0 {
		t.Fatalf("the forbidden-words list does not parse or holds no word: %v", err)
	}
	for _, w := range f.Words {
		parts := strings.Fields(w)
		for i, p := range parts {
			parts[i] = regexp.QuoteMeta(p)
		}
		f.res = append(f.res, regexp.MustCompile(`(?i)(?:^|[^\pL\pN_])(`+strings.Join(parts, `\s+`)+`)`))
	}
	return f
}

// hits names each forbidden word in text, as written.
func (f forbiddenWords) hits(text string) []string {
	var out []string
	for i, re := range f.res {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			out = append(out, fmt.Sprintf("%q (forbidden: %s)", m[1], f.Words[i]))
		}
	}
	return out
}

// ---- the page table (TC-988-19) -------------------------------------------

type pageStatus int

const (
	pageWalked pageStatus = iota + 1
	pageDeferred
	pageNever
)

// pageEntry is one page id's row: walked here, deferred to the issue that
// builds its flow, binding or door, or never rendered, with the reason.
type pageEntry struct {
	status pageStatus
	why    string
}

// walkedPages are the page ids the walk renders (TC-988-18, TC-988-21).
var walkedPages = []string{
	"login-login", "login-register", "login-login-reset-password", "login-login-update-password", "login-login-update-profile",
	"login-login-config-totp", "login-login-otp", "login-webauthn-register", "login-webauthn-error",
	"login-login-recovery-authn-code-config", "login-delete-credential", "login-error", "login-info",
	"login-login-page-expired", "login-logout-confirm", "login-frontchannel-logout", "login-saml-post-form",
}

// deferredPages are rendered only once a later item's flow, binding or door
// exists, each naming that item.
var deferredPages = map[string]string{
	"login-login-username":                          "Identity 4.5 (geekdojo/geekdojo-brain#987): the split sign-in flows",
	"login-login-password":                          "Identity 4.5 (geekdojo/geekdojo-brain#987): the split sign-in flows",
	"login-login-passkeys-conditional-authenticate": "Identity 4.5 (geekdojo/geekdojo-brain#987): the passkey-first flow",
	"login-webauthn-authenticate":                   "Identity 4.5 (geekdojo/geekdojo-brain#987): the passkey second step",
	"login-select-authenticator":                    "Identity 4.5 (geekdojo/geekdojo-brain#987): a second step with alternatives",
	"login-login-recovery-authn-code-input":         "Identity 4.5 (geekdojo/geekdojo-brain#987): the recovery-code second step",
	"login-login-reset-otp":                         "Identity 4.10 (geekdojo/geekdojo-brain#992): the reset flow",
}

// neverPages are never rendered for this realm, each with the reason.
var neverPages = map[string]string{
	"login-select-organization":                  "the organization feature is disabled",
	"login-login-oauth2-device-verify-user-code": "the device-flow feature is disabled",
	"login-update-email":                         "the update-email feature is disabled",
	"login-idp-review-user-profile":              "the realm has no identity provider",
	"login-link-idp-action":                      "the realm has no identity provider",
	"login-login-idp-link-confirm":               "the realm has no identity provider",
	"login-login-idp-link-confirm-override":      "the realm has no identity provider",
	"login-login-idp-link-email":                 "the realm has no identity provider",
	"login-login-x509-info":                      "no X.509 client-certificate authenticator",
	"login-login-verify-email":                   "D11: Rasputin sends no email",
	"login-terms":                                "the terms required action is disabled",
	"login-delete-account-confirm":               "the delete-account required action is disabled",
	"login-login-oauth-grant":                    "no client is consent-required",
	"login-code":                                 "no out-of-band redirect",
	"login-cli_splash":                           "no out-of-band redirect",
}

// notPages are base templates that are macros or fragments, never a page.
var notPages = map[string]bool{
	"footer.ftl": true, "password-commons.ftl": true, "register-commons.ftl": true, "theme-resources.ftl": true,
	"user-profile-commons.ftl": true, "template.ftl": true, "passkeys.ftl": true,
}

// pageID is the data-page-id Keycloak gives the page a template renders.
func pageID(template string) string { return "login-" + strings.TrimSuffix(template, ".ftl") }

// buildPageTable makes the table from the theme's coverage record: every
// base template is a page id with a row, or a fragment. It fails on a
// template with no row, and on a row no template has.
func buildPageTable(templates []string) (map[string]pageEntry, error) {
	table := map[string]pageEntry{}
	var problems []string
	for _, id := range walkedPages {
		table[id] = pageEntry{status: pageWalked}
	}
	for id, why := range deferredPages {
		table[id] = pageEntry{status: pageDeferred, why: why}
	}
	for id, why := range neverPages {
		table[id] = pageEntry{status: pageNever, why: why}
	}
	seen := map[string]bool{}
	for _, tpl := range templates {
		if notPages[tpl] {
			continue
		}
		id := pageID(tpl)
		seen[id] = true
		if _, ok := table[id]; !ok {
			problems = append(problems, fmt.Sprintf("the template %s renders %s, which the page table does not hold", tpl, id))
		}
	}
	for id := range table {
		if !seen[id] {
			problems = append(problems, fmt.Sprintf("the page table holds %s, which no base template renders", id))
		}
	}
	for id, e := range table {
		if e.status == pageDeferred && !strings.Contains(e.why, "geekdojo/geekdojo-brain#") {
			problems = append(problems, fmt.Sprintf("%s is deferred without naming the issue that builds it", id))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return table, nil
}

// classify is a rendered page id's row, or an error: a page the realm
// renders that the table does not hold fails the walk.
func classify(table map[string]pageEntry, id string) (pageEntry, error) {
	e, ok := table[id]
	if !ok {
		return e, fmt.Errorf("the realm rendered %s, which is not in the page table", id)
	}
	if e.status != pageWalked {
		return e, fmt.Errorf("the realm rendered %s, which the page table says is not walked (%s)", id, e.why)
	}
	return e, nil
}

// coverageTemplates are the base templates the theme's coverage record names.
func coverageTemplates(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(uiDir, "identity-theme", "coverage.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Overridden []struct {
			Template string `json:"template"`
		} `json:"overriddenTemplates"`
		Reviewed map[string]string `json:"reviewedTemplates"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, o := range c.Overridden {
		out = append(out, o.Template)
	}
	for k := range c.Reviewed {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- the resource allowlist ------------------------------------------------

type resourceAllowlist struct {
	Keycloak string   `json:"keycloak"`
	Login    []string `json:"login"`
	Common   []string `json:"common"`
}

var (
	loginResourceRE  = regexp.MustCompile(`^/resources/[^/]+/login/rasputin/(.+)$`)
	commonResourceRE = regexp.MustCompile(`^/resources/[^/]+/common/keycloak/(.+)$`)
)

// allows is whether the door proxy, reading the list, would serve path.
func (a resourceAllowlist) allows(path string) bool {
	if m := loginResourceRE.FindStringSubmatch(path); m != nil {
		return contains(a.Login, m[1])
	}
	if m := commonResourceRE.FindStringSubmatch(path); m != nil {
		return contains(a.Common, m[1])
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---- the tab ---------------------------------------------------------------

// request is one request the tab made, with its final answer.
type request struct {
	id       network.RequestID
	url      string
	method   string
	status   int64
	failed   string
	aborted  bool
	document bool
}

// tab is one browser tab in a browser context of its own, recording every
// request, console error, dialog, download and create() call, and answering
// the requests that leave Keycloak (the clients' callback and SAML endpoint)
// itself.
type tab struct {
	t     *testing.T
	ctx   context.Context
	front string

	mu        sync.Mutex
	requests  []*request
	byID      map[network.RequestID]*request
	errs      []string
	dialogs   int
	downloads []string
	acsPosts  []string
	held      map[string]string // URL substring -> body that answers it
}

// stubAnswers are what the tab answers for the addresses outside Keycloak.
const (
	callbackPath = "/rasputin-callback"
	acsPath      = "/rasputin-saml-acs"
	stubPage     = `<!doctype html><html lang="en"><head><title>Signed in</title></head><body data-page-id="rasputin-stub"><h1>Signed in</h1></body></html>`
)

func newTab(t *testing.T, browserCtx context.Context, front string) *tab {
	t.Helper()
	ctx, cancel := chromedp.NewContext(browserCtx, chromedp.WithNewBrowserContext())
	t.Cleanup(cancel)
	tb := &tab{t: t, ctx: ctx, front: front, byID: map[network.RequestID]*request{}, held: map[string]string{}}
	if err := chromedp.Do(ctx); err != nil {
		t.Fatalf("open a tab: %v", err)
	}
	paused := make(chan *fetch.EventRequestPaused, 64)
	dialogs := make(chan struct{}, 8)
	if err := chromedp.Listen(ctx, func(ev any) { tb.event(ev, paused, dialogs) }); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.ListenBrowser(ctx, func(ev any) {
		if e, ok := ev.(*browser.EventDownloadWillBegin); ok {
			tb.mu.Lock()
			tb.downloads = append(tb.downloads, e.SuggestedFilename)
			tb.mu.Unlock()
		}
	}); err != nil {
		t.Fatal(err)
	}
	// Answer the paused requests and close any dialog, off the event loop.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-paused:
				tb.answer(ev)
			case <-dialogs:
				_, _ = chromedp.Call(ctx, page.HandleJavaScriptDialog, page.HandleJavaScriptDialogParams{Accept: false})
			}
		}
	}()
	must := func(err error, what string) {
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	_, err := chromedp.Call(ctx, network.Enable, network.EnableParams{})
	must(err, "Network.enable")
	_, err = chromedp.Call(ctx, cdplog.Enable, cdp.Empty{})
	must(err, "Log.enable")
	tb.intercept()
	_, err = chromedp.CallBrowser(ctx, browser.SetDownloadBehavior, browser.SetDownloadBehaviorParams{
		Behavior: browser.SetDownloadBehaviorBehaviorAllowAndName, BrowserContextID: chromedp.FromContext(ctx).BrowserContextID,
		DownloadPath: t.TempDir(), EventsEnabled: new(true),
	})
	must(err, "Browser.setDownloadBehavior")
	return tb
}

// intercept pauses the requests the tab answers itself.
func (tb *tab) intercept() {
	tb.t.Helper()
	patterns := []*fetch.RequestPattern{
		{URLPattern: "*" + callbackPath + "*", RequestStage: fetch.RequestStageRequest},
		{URLPattern: "*" + acsPath + "*", RequestStage: fetch.RequestStageRequest},
	}
	tb.mu.Lock()
	for sub := range tb.held {
		patterns = append(patterns, &fetch.RequestPattern{URLPattern: "*" + sub + "*", RequestStage: fetch.RequestStageRequest})
	}
	tb.mu.Unlock()
	if _, err := chromedp.Call(tb.ctx, fetch.Enable, fetch.EnableParams{Patterns: patterns}); err != nil {
		tb.t.Fatalf("Fetch.enable: %v", err)
	}
}

// hold makes the tab answer requests whose URL holds sub with body (a
// JavaScript module), instead of letting them through.
func (tb *tab) hold(sub, body string) {
	tb.mu.Lock()
	tb.held[sub] = body
	tb.mu.Unlock()
	tb.intercept()
}

func (tb *tab) answer(ev *fetch.EventRequestPaused) {
	u := ev.Request.URL
	body, ctype := stubPage, "text/html; charset=utf-8"
	tb.mu.Lock()
	for sub, b := range tb.held {
		if strings.Contains(u, sub) {
			body, ctype = b, "text/javascript"
		}
	}
	if strings.Contains(u, acsPath) && ev.Request.Method == "POST" {
		var post bytes.Buffer
		for _, e := range ev.Request.PostDataEntries {
			post.Write(e.Bytes)
		}
		tb.acsPosts = append(tb.acsPosts, post.String())
	}
	tb.mu.Unlock()
	_, _ = chromedp.Call(tb.ctx, fetch.FulfillRequest, fetch.FulfillRequestParams{
		RequestID: ev.RequestID, ResponseCode: 200,
		ResponseHeaders: []*fetch.HeaderEntry{{Name: "Content-Type", Value: ctype}},
		Body:            []byte(body),
	})
}

// event records one event. It runs in the tab's read loop: no command here.
func (tb *tab) event(ev any, paused chan<- *fetch.EventRequestPaused, dialogs chan<- struct{}) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	switch e := ev.(type) {
	case *network.EventRequestWillBeSent:
		if prev := tb.byID[e.RequestID]; prev != nil && e.RedirectResponse != nil {
			prev.status = e.RedirectResponse.Status
		}
		r := &request{id: e.RequestID, url: e.Request.URL, method: e.Request.Method, document: e.Type == network.ResourceTypeDocument}
		tb.requests = append(tb.requests, r)
		tb.byID[e.RequestID] = r
	case *network.EventResponseReceived:
		if r := tb.byID[e.RequestID]; r != nil {
			r.status = e.Response.Status
		}
	case *network.EventLoadingFailed:
		if r := tb.byID[e.RequestID]; r != nil {
			if e.Canceled {
				r.aborted = true
			} else {
				r.failed = e.ErrorText + " " + string(e.BlockedReason)
			}
		}
	case *runtime.EventExceptionThrown:
		d := e.ExceptionDetails
		text := d.Text
		if d.Exception != nil && d.Exception.Description != "" {
			text += " " + d.Exception.Description
		}
		tb.errs = append(tb.errs, "exception: "+text+" at "+d.URL)
	case *runtime.EventConsoleAPICalled:
		if e.Type == runtime.ConsoleAPICalledTypeError {
			var parts []string
			for _, a := range e.Args {
				parts = append(parts, a.Description+string(a.Value))
			}
			tb.errs = append(tb.errs, "console.error: "+strings.Join(parts, " "))
		}
	case *cdplog.EventEntryAdded:
		if e.Entry.Level == cdplog.EntryLevelError {
			tb.errs = append(tb.errs, "log: "+e.Entry.Text+" "+e.Entry.URL)
		}
	case *page.EventJavascriptDialogOpening:
		tb.dialogs++
		select {
		case dialogs <- struct{}{}:
		default:
		}
	case *fetch.EventRequestPaused:
		select {
		case paused <- e:
		default:
			tb.errs = append(tb.errs, "the walk could not queue the paused request "+e.Request.URL)
		}
	}
}

// mark is where the next page's records start.
type mark struct{ requests, errs int }

func (tb *tab) mark() mark {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return mark{len(tb.requests), len(tb.errs)}
}

func (tb *tab) since(m mark) ([]request, []string) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	var rs []request
	for _, r := range tb.requests[m.requests:] {
		rs = append(rs, *r)
	}
	return rs, append([]string(nil), tb.errs[m.errs:]...)
}

// stepTimeout bounds one browser step: a navigation and its load, or one
// command. It is an I/O bound, never a wait for a state: each step waits on
// the page's own load event or the command's reply.
const stepTimeout = 90 * time.Second

func (tb *tab) step(a chromedp.Action[chromedp.Void], what string) {
	tb.t.Helper()
	ctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer cancel()
	if err := chromedp.Do(ctx, a); err != nil {
		tb.t.Fatalf("%s: %v", what, err)
	}
}

// navigate opens u and returns the page id it lands on.
func (tb *tab) navigate(u string) string {
	tb.t.Helper()
	tb.step(chromedp.Navigate(u), "open "+u)
	return tb.pageID()
}

// submit runs a that causes a navigation, waits for the new page's load and
// returns its page id.
func (tb *tab) submit(a chromedp.Action[chromedp.Void], what string) string {
	tb.t.Helper()
	ctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer cancel()
	if _, err := chromedp.Run(ctx, chromedp.WaitEvent(page.LoadEventFired, nil, a)); err != nil {
		tb.t.Fatalf("%s: %v", what, err)
	}
	return tb.pageID()
}

func (tb *tab) pageID() string {
	tb.t.Helper()
	return evalT[string](tb, `document.body ? (document.body.dataset.pageId || '') : ''`)
}

func evalT[T any](tb *tab, expr string) T {
	tb.t.Helper()
	ctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer cancel()
	v, err := chromedp.Run(ctx, chromedp.Evaluate[T](expr))
	if err != nil {
		tb.t.Fatalf("evaluate %.80s: %v", expr, err)
	}
	return v
}

// fillAndSubmit sets each field (by id) and submits by clicking the element
// the CSS selector button names.
func (tb *tab) fillAndSubmit(fields map[string]string, button string) string {
	tb.t.Helper()
	var steps []chromedp.Action[chromedp.Void]
	for id, v := range fields {
		steps = append(steps, chromedp.SetValue(chromedp.ID(id), v))
	}
	tb.step(chromedp.Steps(steps...), "fill the form")
	return tb.submit(chromedp.Click(chromedp.CSS(button)), "press "+button)
}

// ---- TC-988-18: the checks on every walked page -----------------------------

// pageFacts is what the page script reports about the page.
type pageFacts struct {
	Theme       string   `json:"theme"`
	PageID      string   `json:"pageId"`
	Text        string   `json:"text"`
	TextContent string   `json:"textContent"`
	Title       string   `json:"title"`
	Read        []string `json:"read"`
	Inline      int      `json:"inline"`
	Handlers    []string `json:"handlers"`
	H1          int      `json:"h1"`
	Small       []string `json:"small"`
	NotAlert    []string `json:"notAlert"`
	Focusable   int      `json:"focusable"`
	EmptyHrefs  int      `json:"emptyHrefs"`
}

const factsJS = `(() => {
  const b = document.body;
  const read = [];
  document.querySelectorAll('[title],[aria-label],[placeholder],[alt]').forEach((e) =>
    ['title', 'aria-label', 'placeholder', 'alt'].forEach((a) => { const v = e.getAttribute(a); if (v) read.push(a + ': ' + v); }));
  const handlers = [];
  document.querySelectorAll('*').forEach((e) => { for (const a of e.attributes) if (a.name.startsWith('on')) handlers.push(e.tagName + ' ' + a.name); });
  const small = [];
  document.querySelectorAll('input:not([type=hidden]),button,select,textarea').forEach((e) => {
    if (e.offsetParent === null) return;
    const px = parseFloat(getComputedStyle(e).fontSize);
    if (px < 16) small.push((e.id || e.name || e.tagName) + ' ' + px + 'px');
  });
  const notAlert = [];
  document.querySelectorAll('#kc-feedback,#kc-error-message').forEach((e) => { if (e.getAttribute('role') !== 'alert') notAlert.push(e.id); });
  const emptyHrefs = [...document.querySelectorAll('a')].filter((a) => { const h = a.getAttribute('href'); return h === null || h === '' || h === '#'; }).length;
  const focusable = [...document.querySelectorAll('a[href],button:not([disabled]),input:not([type=hidden]):not([disabled]),select,textarea')]
    .filter((e) => e.offsetParent !== null).length;
  return { theme: b.dataset.rasputinTheme || '', pageId: b.dataset.pageId || '', text: b.innerText, textContent: b.textContent,
    title: document.title, read, inline: document.querySelectorAll('script:not([src])').length, handlers,
    h1: document.querySelectorAll('h1').length, small, notAlert, focusable, emptyHrefs };
})()`

// accessibleRoles are the roles whose node needs an accessible name.
var accessibleRoles = map[string]bool{"button": true, "textbox": true, "checkbox": true, "radio": true, "combobox": true, "searchbox": true, "spinbutton": true}

// checkPage runs TC-988-18's checks on the page the tab shows, over what
// it loaded and logged since m, and records the page id as walked.
func (w *walk) checkPage(tb *tab, m mark, want string) {
	tb.t.Helper()
	t := tb.t
	f := evalT[pageFacts](tb, factsJS)
	if f.PageID != want {
		t.Fatalf("the walk expected %s and the page is %q, which reads: %.300s", want, f.PageID, strings.Join(strings.Fields(f.Text), " "))
	}
	if _, err := classify(w.table, f.PageID); err != nil {
		t.Error(err)
	}
	w.seen[f.PageID] = true
	where := f.PageID + ": "
	if f.Theme != "rasputin" {
		t.Errorf("%sdata-rasputin-theme = %q, want rasputin", where, f.Theme)
	}
	if !strings.Contains(f.TextContent, installName) {
		t.Errorf("%sthe page does not show the install name %q", where, installName)
	}
	for _, s := range append([]string{f.Text, "title: " + f.Title}, f.Read...) {
		for _, h := range w.words.hits(s) {
			t.Errorf("%sthe page reads %s in %.60q", where, h, s)
		}
	}
	if f.Inline != 0 || len(f.Handlers) != 0 {
		t.Errorf("%s%d inline scripts and the handlers %v, want none", where, f.Inline, f.Handlers)
	}
	if f.H1 != 1 {
		t.Errorf("%s%d h1 headings, want one", where, f.H1)
	}
	if len(f.Small) != 0 {
		t.Errorf("%sinputs and buttons under 16 px: %v", where, f.Small)
	}
	if len(f.NotAlert) != 0 {
		t.Errorf("%sthe message blocks %v have no alert role", where, f.NotAlert)
	}
	if f.EmptyHrefs != 0 {
		t.Errorf("%s%d anchors with an empty or # href", where, f.EmptyHrefs)
	}
	reqs, errs := tb.since(m)
	var errorDocs []string
	for _, r := range reqs {
		if strings.HasPrefix(r.url, "data:") || strings.HasPrefix(r.url, "blob:") {
			continue
		}
		u, err := url.Parse(r.url)
		if err != nil || u.Scheme+"://"+u.Host != tb.front {
			t.Errorf("%sa request to another origin: %s", where, r.url)
			continue
		}
		// The error page is Keycloak's answer to a refused request, which it
		// sends as a 4xx: that one document is the page under test.
		errorPage := f.PageID == "login-error" && r.document && r.status >= 400 && r.status < 500
		switch {
		case r.failed != "":
			t.Errorf("%s%s failed: %s", where, r.url, r.failed)
		case r.aborted || errorPage:
		case r.status == 0:
			// Still in flight when the page loaded (the favicon loads after
			// the load event); it has not answered anything yet.
		case r.status < 200 || r.status >= 400:
			t.Errorf("%s%s answered %d, want 2xx or 3xx", where, r.url, r.status)
		}
		if errorPage {
			errorDocs = append(errorDocs, r.url)
		}
		if strings.HasPrefix(u.Path, "/resources/") && !w.allow.allows(u.Path) {
			t.Errorf("%s%s is not in resource-allowlist.json", where, u.Path)
		}
	}
	for _, e := range errs {
		if slices.ContainsFunc(errorDocs, func(u string) bool { return strings.HasSuffix(e, " "+u) && strings.Contains(e, "status of 4") }) {
			continue // the browser's note of the error page's own 4xx
		}
		t.Errorf("%sthe console shows an error: %s", where, e)
	}
	// Every input and button has an accessible name.
	ctx, cancel := context.WithTimeout(tb.ctx, stepTimeout)
	defer cancel()
	tree, err := chromedp.Call(ctx, accessibility.GetFullAXTree, accessibility.GetFullAXTreeParams{})
	if err != nil {
		t.Fatalf("%sthe accessibility tree: %v", where, err)
	}
	for _, n := range tree.Nodes {
		if n.Ignored || n.Role == nil {
			continue
		}
		var role, name string
		_ = json.Unmarshal([]byte(n.Role.Value), &role)
		if n.Name != nil {
			_ = json.Unmarshal([]byte(n.Name.Value), &name)
		}
		if accessibleRoles[role] && strings.TrimSpace(name) == "" {
			t.Errorf("%sa %s with no accessible name (DOM node %d)", where, role, n.BackendDOMNodeID)
		}
	}
	// Tab moves a focus whose outline shows.
	if f.Focusable > 0 {
		for _, typ := range []input.DispatchKeyEventType{input.DispatchKeyEventTypeRawKeyDown, input.DispatchKeyEventTypeKeyUp} {
			if _, err := chromedp.Call(ctx, input.DispatchKeyEvent, input.DispatchKeyEventParams{
				Type: typ, Key: "Tab", Code: "Tab", WindowsVirtualKeyCode: 9, NativeVirtualKeyCode: 9,
			}); err != nil {
				t.Fatalf("%spress Tab: %v", where, err)
			}
		}
		outline := evalT[string](tb, `(() => { const a = document.activeElement; if (!a || a === document.body) return 'nothing focused'; return getComputedStyle(a).outlineStyle; })()`)
		if outline == "none" || outline == "nothing focused" {
			t.Errorf("%safter Tab: %s, want a focused element with an outline", where, outline)
		}
	}
	t.Logf("walked %s: %d requests, no failure above means every check held", f.PageID, len(reqs))
}

// ---- TOTP and the QR code (TC-988-22) ---------------------------------------

// totp is RFC 6238's code for secret (base32) at counter step, 6 digits,
// HMAC-SHA1: Keycloak's default policy.
func totp(secretB32 string, step int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secretB32, "=")))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	h := hmac.New(sha1.New, key)
	h.Write(msg[:])
	sum := h.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1000000), nil
}

// decodeQR reads the text of the QR code in a data:image/png;base64 URL.
func decodeQR(dataURL string) (string, error) {
	i := strings.Index(dataURL, ",")
	if i < 0 {
		return "", fmt.Errorf("not a data URL")
	}
	png, err := base64.StdEncoding.DecodeString(strings.TrimSpace(dataURL[i+1:]))
	if err != nil {
		return "", err
	}
	img, _, err := image.Decode(bytes.NewReader(png))
	if err != nil {
		return "", err
	}
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", err
	}
	res, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		return "", err
	}
	return res.GetText(), nil
}

// otpStep is the TOTP counter for now.
func otpStep(now time.Time) int64 { return now.Unix() / 30 }
