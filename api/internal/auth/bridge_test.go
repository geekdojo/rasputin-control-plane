package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth/passkeytest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The bridge (geekdojo/geekdojo-brain#1005) over a real auth.Store on
// SQLite, the real go-webauthn verifier and a soft P-256 authenticator.
// The moved accounts and the first-password job are doubles here; their
// own tests are in identity/move and accounts.

const (
	bridgeOrigin = "http://localhost:3000"
	bridgeRPID   = "localhost"
	subA         = "moved-sub-a"
	signInAt     = "https://sso-ci.local"
)

// fakeMoved is MovedAccounts over a map by handle.
type fakeMoved struct {
	mu       sync.Mutex
	accounts map[string]MovedAccount
	err      error
	offered  bool
	offerErr error
}

func (m *fakeMoved) Account(_ context.Context, handle []byte) (MovedAccount, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return MovedAccount{}, false, m.err
	}
	a, ok := m.accounts[string(handle)]
	return a, ok, nil
}

func (m *fakeMoved) Offered(context.Context) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.offered, m.offerErr
}

// fakeFirst is FirstPassword, recording what Set received.
type fakeFirst struct {
	mu                sync.Mutex
	has               bool
	hasErr            error
	hasCalls          int
	checkErr, setErr  error
	setCalls          int
	setBy             authz.Submitter
	setSub, pw, email string
}

func (f *fakeFirst) HasPassword(context.Context, string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hasCalls++
	return f.has, f.hasErr
}

func (f *fakeFirst) Check(context.Context, string, secret.Value, secret.Value) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checkErr
}

func (f *fakeFirst) Set(_ context.Context, by authz.Submitter, sub string, pw, email secret.Value) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setCalls++
	f.setBy, f.setSub, f.pw, f.email = by, sub, string(pw.Reveal()), string(email.Reveal())
	return f.setErr
}

func (f *fakeFirst) set(fn func(*fakeFirst)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeFirst) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.setCalls
}

type bridgeRig struct {
	f      *authFixture
	h      http.Handler
	moved  *fakeMoved
	first  *fakeFirst
	log    *logkittest.Recorder
	user   *User
	a      *passkeytest.Authenticator
	ids    int
	bridge *Bridge
}

// newBridgeRig is the bridge installed over a fixture holding one old user
// with a passkey, moved as subA ("b-1", from "b").
func newBridgeRig(t *testing.T) *bridgeRig {
	t.Helper()
	f := newAuthFixture(t)
	r := &bridgeRig{f: f, moved: &fakeMoved{accounts: map[string]MovedAccount{}, offered: true}, first: &fakeFirst{}}
	r.user = f.mintUser(t, "b")
	var err error
	if r.a, err = passkeytest.New([]byte("cred-b"), r.user.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateCredential(f.ctx, &Credential{ID: r.a.CredentialID, UserID: r.user.ID, PublicKey: r.a.COSE(),
		AttestationType: "none", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	r.moved.accounts[string(r.user.ID)] = MovedAccount{Sub: subA, Name: "b-1", OldName: "b", Designated: true, Roles: []string{"admin"}, NeedsPassword: true}
	log, rec := logkittest.New()
	r.log = rec
	if err := f.svc.InstallBridge(BridgeDeps{Accounts: r.moved, FirstPassword: r.first, SignInOrigin: signInAt,
		NewCorrelationID: r.nextID, Now: f.clock.Now, Rand: rand.Reader, Log: log}); err != nil {
		t.Fatal(err)
	}
	r.bridge = f.svc.bridgeOf()
	r.h = f.handler()
	return r
}

func (r *bridgeRig) nextID() string {
	r.ids++
	return "corr-" + string(rune('a'+r.ids))
}

func serveBridge(h http.Handler, method, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// cookieOf is the named cookie a response set, or nil.
func cookieOf(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// codeOf is a coded body's code, sentence and correlation id.
func codeOf(t *testing.T, w *httptest.ResponseRecorder) (code, sentence, id string) {
	t.Helper()
	var b bridgeError
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("body %s: %v", w.Body.String(), err)
	}
	return b.Code, b.Error, b.CorrelationID
}

// begin runs begin and returns its options and bridge cookie.
func (r *bridgeRig) begin(t *testing.T, cookies ...*http.Cookie) ([]byte, *http.Cookie) {
	t.Helper()
	w := serveBridge(r.h, http.MethodPost, "/api/auth/bridge/begin", "", cookies...)
	c := cookieOf(w, bridgeCookieName)
	if w.Code != http.StatusOK || c == nil {
		t.Fatalf("begin: %d %s", w.Code, w.Body.String())
	}
	return w.Body.Bytes(), c
}

// assertion is the authenticator's answer to options, edited by edit.
func (r *bridgeRig) assertion(t *testing.T, a *passkeytest.Authenticator, options []byte, edit func(*passkeytest.Request)) string {
	t.Helper()
	ch, err := passkeytest.ChallengeOf(options)
	if err != nil {
		t.Fatal(err)
	}
	req := passkeytest.Request{Challenge: ch, RPID: bridgeRPID, Origin: bridgeOrigin}
	if edit != nil {
		edit(&req)
	}
	body, err := a.Assert(req)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// finish runs a whole ceremony with r's authenticator.
func (r *bridgeRig) finish(t *testing.T, edit func(*passkeytest.Request)) *httptest.ResponseRecorder {
	t.Helper()
	opts, c := r.begin(t)
	return serveBridge(r.h, http.MethodPost, "/api/auth/bridge/finish", r.assertion(t, r.a, opts, edit), c)
}

// grant runs a ceremony to a live grant and returns its cookie.
func (r *bridgeRig) grant(t *testing.T) *http.Cookie {
	t.Helper()
	w := r.finish(t, nil)
	c := cookieOf(w, bridgeCookieName)
	if w.Code != http.StatusOK || c == nil || c.Value == "" {
		t.Fatalf("finish: %d %s", w.Code, w.Body.String())
	}
	return c
}

func (r *bridgeRig) password(body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	return serveBridge(r.h, http.MethodPost, "/api/auth/bridge/password", body, cookies...)
}

const goodBody = `{"password":"a long unlisted passphrase","email":"b@example.org"}`

// TC-1005-01: begin asks for user verification required with no
// allowCredentials, and sets the bridge's host-only cookie and no session
// cookie.
func TestBridge_TC1005_01_Begin(t *testing.T) {
	r := newBridgeRig(t)
	w := serveBridge(r.h, http.MethodPost, "/api/auth/bridge/begin", "")
	var o struct {
		PublicKey struct {
			Challenge        string            `json:"challenge"`
			UserVerification string            `json:"userVerification"`
			RPID             string            `json:"rpId"`
			Allow            []json.RawMessage `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &o); err != nil || w.Code != http.StatusOK {
		t.Fatalf("begin: %d %s", w.Code, w.Body.String())
	}
	if o.PublicKey.UserVerification != "required" || len(o.PublicKey.Allow) != 0 || o.PublicKey.Challenge == "" || o.PublicKey.RPID != bridgeRPID {
		t.Errorf("options %+v", o.PublicKey)
	}
	c := cookieOf(w, bridgeCookieName)
	if c == nil || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" ||
		c.MaxAge != int(bridgeLifetime/time.Second) || c.Value == "" {
		t.Errorf("bridge cookie %+v", c)
	}
	if cookieOf(w, SessionCookieName) != nil || cookieOf(w, legacySessionCookieName) != nil {
		t.Error("begin set a session cookie")
	}
}

// TC-1005-02: a valid assertion with UV yields a grant under a new cookie
// value, sets no session cookie, stores no session, and leaves the old
// tables byte-equal (sign_count unchanged).
func TestBridge_TC1005_02_GrantOpensNoSession(t *testing.T) {
	r := newBridgeRig(t)
	r.a.SignCount = 7
	before := map[string][]string{}
	for _, tb := range []string{"users", "credentials", "sessions"} {
		before[tb] = dump(t, r.f.store, tb)
	}
	opts, c := r.begin(t)
	w := serveBridge(r.h, http.MethodPost, "/api/auth/bridge/finish", r.assertion(t, r.a, opts, nil), c)
	next := cookieOf(w, bridgeCookieName)
	if w.Code != http.StatusOK || next == nil || next.Value == "" || next.Value == c.Value {
		t.Fatalf("finish: %d %s, cookie %+v", w.Code, w.Body.String(), next)
	}
	if cookieOf(w, SessionCookieName) != nil || cookieOf(w, legacySessionCookieName) != nil {
		t.Error("finish set a session cookie")
	}
	if r.f.countRows(t, "console_sessions") != 0 || r.f.countRows(t, "sessions") != 0 {
		t.Error("finish stored a session")
	}
	for tb, rows := range before {
		if got := dump(t, r.f.store, tb); strings.Join(got, "\n") != strings.Join(rows, "\n") {
			t.Errorf("%s changed:\n%v\nwas\n%v", tb, got, rows)
		}
	}
	if rec, ok := r.bridge.records.peek(next.Value); !ok || rec.grant == nil || rec.grant.sub != subA {
		t.Errorf("no live grant for %s", subA)
	}
	if len(r.log.Matching(slog.LevelInfo, "verified")) != 1 {
		t.Errorf("log %s", r.log.Text())
	}
}

// TC-1005-03: a ceremony finishes once; a grant submits once.
func TestBridge_TC1005_03_SingleUse(t *testing.T) {
	r := newBridgeRig(t)
	opts, c := r.begin(t)
	body := r.assertion(t, r.a, opts, nil)
	if w := serveBridge(r.h, http.MethodPost, "/api/auth/bridge/finish", body, c); w.Code != http.StatusOK {
		t.Fatalf("first finish %d", w.Code)
	}
	w := serveBridge(r.h, http.MethodPost, "/api/auth/bridge/finish", body, c)
	if code, sentence, _ := codeOf(t, w); w.Code != http.StatusUnauthorized || code != BridgeCodeExpired || sentence != sentenceBridgeExpired {
		t.Errorf("second finish: %d %s", w.Code, w.Body.String())
	}
	g := r.grant(t)
	if w := r.password(goodBody, g); w.Code != http.StatusOK {
		t.Fatalf("first password: %d %s", w.Code, w.Body.String())
	}
	w = r.password(goodBody, g)
	if code, sentence, _ := codeOf(t, w); w.Code != http.StatusConflict || code != BridgeCodeGrantUsed || sentence != sentenceGrantUsed {
		t.Errorf("second password: %d %s", w.Code, w.Body.String())
	}
	if n := r.first.calls(); n != 1 {
		t.Errorf("Set called %d times, want 1", n)
	}
}

// TC-1005-04: the grant is this browser's cookie, and submits only its own
// account.
func TestBridge_TC1005_04_BoundToBrowserAndAccount(t *testing.T) {
	r := newBridgeRig(t)
	g := r.grant(t)
	for name, cookies := range map[string][]*http.Cookie{
		"no cookie":    nil,
		"random value": {{Name: bridgeCookieName, Value: "not-a-grant"}},
	} {
		if w := r.password(goodBody, cookies...); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	w := r.password(goodBody, g, &http.Cookie{Name: bridgeCookieName, Value: "other"})
	if code, _, _ := codeOf(t, w); w.Code != http.StatusBadRequest || code != BridgeCodeDuplicateCookie {
		t.Errorf("two cookies: %d %s", w.Code, w.Body.String())
	}
	if w := r.password(`{"password":"a long unlisted passphrase","email":"b@example.org","sub":"someone-else","accountId":"x"}`, g); w.Code != http.StatusOK {
		t.Fatalf("password: %d %s", w.Code, w.Body.String())
	}
	if r.first.setBy != authz.BridgeGrant(subA) || r.first.setSub != subA {
		t.Errorf("Set ran as %+v for %q, want BridgeGrant(%s)", r.first.setBy, r.first.setSub, subA)
	}
	if r.first.pw != "a long unlisted passphrase" || r.first.email != "b@example.org" {
		t.Errorf("Set received the wrong values")
	}
	if r.first.calls() != 1 {
		t.Errorf("Set called %d times", r.first.calls())
	}
}

// TC-1005-05: each assertion refusal answers 401 passkey_refused, leaves no
// grant, and logs reason and kind but no handle, name or cookie.
func TestBridge_TC1005_05_AssertionRefusals(t *testing.T) {
	for _, name := range []string{"no UV flag", "bad signature", "wrong origin", "wrong challenge", "unknown credential", "unknown user"} {
		t.Run(name, func(t *testing.T) {
			r := newBridgeRig(t)
			a := r.a
			var edit func(*passkeytest.Request)
			var err error
			switch name {
			case "no UV flag":
				edit = func(q *passkeytest.Request) { q.NoUV = true }
			case "bad signature":
				edit = func(q *passkeytest.Request) { q.BadSignature = true }
			case "wrong origin":
				edit = func(q *passkeytest.Request) { q.Origin = "https://evil.example" }
			case "wrong challenge":
				edit = func(q *passkeytest.Request) { q.Challenge = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ" }
			case "unknown credential":
				a, err = passkeytest.New([]byte("cred-unknown"), r.user.ID)
			case "unknown user":
				a, err = passkeytest.New([]byte("cred-orphan"), bytes.Repeat([]byte{9}, 16))
			}
			if err != nil {
				t.Fatal(err)
			}
			opts, ck := r.begin(t)
			w := serveBridge(r.h, http.MethodPost, "/api/auth/bridge/finish", r.assertion(t, a, opts, edit), ck)
			code, sentence, id := codeOf(t, w)
			if w.Code != http.StatusUnauthorized || code != BridgeCodePasskeyRefused || sentence != sentencePasskeyRefused {
				t.Errorf("%d %s", w.Code, w.Body.String())
			}
			if n := r.bridge.records.size(); n != 0 {
				t.Errorf("%d records after a refusal", n)
			}
			recs := r.log.Matching(slog.LevelWarn, "refused")
			if len(recs) != 1 {
				t.Fatalf("log %s", r.log.Text())
			}
			if v, _ := logkittest.Attr(recs[0], "reason"); v != "assertion" {
				t.Errorf("reason %q", v)
			}
			if v, _ := logkittest.Attr(recs[0], "kind"); v == "" {
				t.Error("no kind")
			}
			if v, _ := logkittest.Attr(recs[0], "correlation_id"); v != id || id == "" {
				t.Errorf("correlation id %q in the log, %q in the body", v, id)
			}
			text := r.log.Text()
			for _, leak := range []string{"b-1", ck.Value, string(r.user.ID), "cred-"} {
				if strings.Contains(text, leak) {
					t.Errorf("the log carries %q: %s", leak, text)
				}
			}
		})
	}
}

// TC-1005-06: a credential whose saved clone_warning is 1 is admitted, as
// today's login admitted it (F-1005-01).
func TestBridge_TC1005_06_CloneWarningAdmitted(t *testing.T) {
	r := newBridgeRig(t)
	if _, err := r.f.store.db.Exec(`UPDATE credentials SET clone_warning = 1, sign_count = 5`); err != nil {
		t.Fatal(err)
	}
	w := r.finish(t, nil)
	c := cookieOf(w, bridgeCookieName)
	if w.Code != http.StatusOK || c == nil {
		t.Fatalf("finish: %d %s", w.Code, w.Body.String())
	}
	if rec, ok := r.bridge.records.peek(c.Value); !ok || rec.grant == nil {
		t.Error("no live grant")
	}
}

// TC-1005-07: an old user with no move row is refused not_moved; no grant.
func TestBridge_TC1005_07_NotMoved(t *testing.T) {
	r := newBridgeRig(t)
	delete(r.moved.accounts, string(r.user.ID))
	w := r.finish(t, nil)
	if code, sentence, _ := codeOf(t, w); w.Code != http.StatusConflict || code != BridgeCodeNotMoved || sentence != sentenceNotMoved {
		t.Errorf("%d %s", w.Code, w.Body.String())
	}
	if r.bridge.records.size() != 0 {
		t.Error("a grant exists")
	}
}

// TC-1005-08: an account that has a password is refused has_password at
// finish, with no grant; HasPassword (which records the fact) was read.
func TestBridge_TC1005_08_HasPassword(t *testing.T) {
	r := newBridgeRig(t)
	r.first.set(func(f *fakeFirst) { f.has = true })
	w := r.finish(t, nil)
	if code, sentence, _ := codeOf(t, w); w.Code != http.StatusConflict || code != BridgeCodeHasPassword || sentence != SentenceHasPassword {
		t.Errorf("%d %s", w.Code, w.Body.String())
	}
	if r.bridge.records.size() != 0 || r.first.hasCalls != 1 {
		t.Errorf("records %d, HasPassword calls %d", r.bridge.records.size(), r.first.hasCalls)
	}
	if recs := r.log.Matching(slog.LevelInfo, "refused"); len(recs) != 1 {
		t.Errorf("log %s", r.log.Text())
	}
}

// TC-1005-09: a dependency down at finish answers 503 bridge_unavailable,
// no grant, one ERROR record.
func TestBridge_TC1005_09_DependencyDown(t *testing.T) {
	for name, break_ := range map[string]func(r *bridgeRig){
		"identity credentials read": func(r *bridgeRig) { r.first.set(func(f *fakeFirst) { f.hasErr = errTest }) },
		"move row read":             func(r *bridgeRig) { r.moved.err = errTest },
		"old user read": func(r *bridgeRig) {
			if _, err := r.f.store.db.Exec(`ALTER TABLE credentials RENAME TO credentials_gone`); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newBridgeRig(t)
			opts, c := r.begin(t)
			body := r.assertion(t, r.a, opts, nil)
			break_(r)
			w := serveBridge(r.h, http.MethodPost, "/api/auth/bridge/finish", body, c)
			if code, sentence, _ := codeOf(t, w); w.Code != http.StatusServiceUnavailable || code != BridgeCodeUnavailable || sentence != sentenceBridgeUnavailable {
				t.Errorf("%d %s", w.Code, w.Body.String())
			}
			if r.bridge.records.size() != 0 {
				t.Error("a grant exists")
			}
			if recs := r.log.AtLevel(slog.LevelError); len(recs) != 1 {
				t.Errorf("log %s", r.log.Text())
			} else if ev, _ := logkittest.Attr(recs[0], "event"); ev != "bridge.unavailable" {
				t.Errorf("event %q", ev)
			}
		})
	}
}

// TC-1005-10: every refusal at the password step keeps the grant, carries
// the API's own sentence, and a following valid POST succeeds.
func TestBridge_TC1005_10_RefusalsKeepTheGrant(t *testing.T) {
	r := newBridgeRig(t)
	g := r.grant(t)
	listed := &BridgeRefusal{Code: BridgeCodeEmailListed, Sentence: "That email address belonged to a removed account and can't be used again."}
	taken := &BridgeRefusal{Code: BridgeCodeEmailTaken, Sentence: "Another account already uses that email address."}
	policy := &BridgeRefusal{Code: BridgeCodePasswordRefused, Sentence: "That password is too common. Choose another."}
	unreadable := &BridgeRefusal{Code: BridgeCodePasswordCheckUnavailable, Sentence: "Rasputin couldn't check the password. Try again shortly."}
	for _, c := range []struct {
		name, body string
		checkErr   error
		status     int
		code       string
		sentence   string
	}{
		{"empty email", `{"password":"a long unlisted passphrase","email":"  "}`, nil, 422, BridgeCodeEmailInvalid, sentenceEmailInvalid},
		{"unparsable email", `{"password":"a long unlisted passphrase","email":"Bob <b@example.org>"}`, nil, 422, BridgeCodeEmailInvalid, sentenceEmailInvalid},
		{"no at", `{"password":"a long unlisted passphrase","email":"not-an-address"}`, nil, 422, BridgeCodeEmailInvalid, sentenceEmailInvalid},
		{"removed-listed email", goodBody, listed, 422, listed.Code, listed.Sentence},
		{"email in use", goodBody, taken, 422, taken.Code, taken.Sentence},
		{"policy refusal", goodBody, policy, 422, policy.Code, policy.Sentence},
		{"deny list unreadable", goodBody, unreadable, 503, unreadable.Code, unreadable.Sentence},
		{"not JSON", `{"password":`, nil, 400, BridgeCodeInvalidRequest, sentenceBridgeBadRequest},
	} {
		r.first.set(func(f *fakeFirst) { f.checkErr = c.checkErr })
		w := r.password(c.body, g)
		if code, sentence, _ := codeOf(t, w); w.Code != c.status || code != c.code || sentence != c.sentence {
			t.Errorf("%s: %d %s", c.name, w.Code, w.Body.String())
		}
		if rec, ok := r.bridge.records.peek(g.Value); !ok || rec.grant.spent.Load() {
			t.Errorf("%s: the grant is gone or spent", c.name)
		}
	}
	if r.first.calls() != 0 {
		t.Error("Set ran on a refusal")
	}
	r.first.set(func(f *fakeFirst) { f.checkErr = nil })
	if w := r.password(` {"password":"a long unlisted passphrase","email":"  b@example.org "}`, g); w.Code != http.StatusOK {
		t.Errorf("the valid POST after the refusals: %d %s", w.Code, w.Body.String())
	}
	if r.first.email != "b@example.org" {
		t.Errorf("the email was not trimmed: %q", r.first.email)
	}
	if strings.Contains(r.log.Text(), "a long unlisted passphrase") || strings.Contains(r.log.Text(), "b@example.org") {
		t.Errorf("the log carries the password or the email: %s", r.log.Text())
	}
}

// TC-1005-12: a body over 8 KiB answers 413 and calls nothing; a valid
// POST answers 200 {next:"/api/auth/signin"} once Set returns; Set's
// refusal is its own code and sentence.
func TestBridge_TC1005_12_BoundsAndSuccess(t *testing.T) {
	r := newBridgeRig(t)
	g := r.grant(t)
	big := `{"password":"` + strings.Repeat("x", bridgeBodyLimit) + `","email":"b@example.org"}`
	if w := r.password(big, g); w.Code != http.StatusRequestEntityTooLarge || r.first.calls() != 0 {
		t.Errorf("a large body: %d, Set calls %d", w.Code, r.first.calls())
	}
	w := r.password(goodBody, g)
	var next map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &next); err != nil || w.Code != http.StatusOK || next["next"] != "/api/auth/signin" || len(next) != 1 {
		t.Errorf("success: %d %s", w.Code, w.Body.String())
	}

	r2 := newBridgeRig(t)
	g2 := r2.grant(t)
	r2.first.set(func(f *fakeFirst) {
		f.setErr = &BridgeRefusal{Code: BridgeCodeNotSet, Sentence: "The sign-in service couldn't set the password."}
	})
	w = r2.password(goodBody, g2)
	if code, sentence, _ := codeOf(t, w); w.Code != http.StatusConflict || code != BridgeCodeNotSet || sentence != "The sign-in service couldn't set the password." {
		t.Errorf("a job refusal: %d %s", w.Code, w.Body.String())
	}
	r3 := newBridgeRig(t)
	g3 := r3.grant(t)
	r3.first.set(func(f *fakeFirst) { f.setErr = errTest })
	if code, _, _ := codeOf(t, r3.password(goodBody, g3)); code != BridgeCodeUnavailable {
		t.Errorf("a submission error: %s", code)
	}
	r4 := newBridgeRig(t)
	g4 := r4.grant(t)
	r4.first.set(func(f *fakeFirst) { f.setErr = context.Canceled })
	if code, _, _ := codeOf(t, r4.password(goodBody, g4)); code != BridgeCodeNotSet {
		t.Errorf("a cancelled wait: %s", code)
	}
}

// TC-1005-13 (the bridge's half): at bridgeLifetime a grant answers
// bridge_expired; the janitor's sweep prunes expired bridge and pending
// records.
func TestBridge_TC1005_13_ExpiryAndSweep(t *testing.T) {
	r := newBridgeRig(t)
	g := r.grant(t)
	r.f.clock.Add(bridgeLifetime - time.Second)
	if rec, ok := r.bridge.records.peek(g.Value); !ok || rec.grant == nil {
		t.Fatal("the grant expired early")
	}
	r.f.clock.Add(time.Second)
	if code, _, _ := codeOf(t, r.password(goodBody, g)); code != BridgeCodeExpired {
		t.Errorf("at bridgeLifetime: %s", code)
	}
	r.begin(t)
	r.f.clock.Add(bridgeLifetime)
	if r.bridge.records.size() != 2 {
		t.Fatalf("%d records before the sweep", r.bridge.records.size())
	}
	r.f.svc.sweep(context.Background(), r.f.clock.Now())
	if n := r.bridge.records.size(); n != 0 {
		t.Errorf("%d bridge records after the sweep", n)
	}
	sr := newSigninRig(t)
	sr.begin(t)
	sr.f.clock.Add(signinPendingLifetime)
	sr.f.svc.sweep(context.Background(), sr.f.clock.Now())
	if n := sr.si.pending.size(); n != 0 {
		t.Errorf("%d pending sign-ins after the sweep", n)
	}
}

// GET /api/auth/bridge: offered alone, the grant's names and the home
// door's origin with a live grant, the previous name only when it changed,
// nothing once the grant is spent, and 500 with a WARN when the offer
// can't be read (TC-1005-23's route half).
func TestBridge_State(t *testing.T) {
	r := newBridgeRig(t)
	view := func(cookies ...*http.Cookie) (int, map[string]any) {
		w := serveBridge(r.h, http.MethodGet, "/api/auth/bridge", "", cookies...)
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m
	}
	if code, m := view(); code != 200 || m["offered"] != true || len(m) != 1 {
		t.Errorf("no grant: %d %v", code, m)
	}
	g := r.grant(t)
	if _, m := view(g); m["name"] != "b-1" || m["previousName"] != "b" || m["signInOrigin"] != signInAt {
		t.Errorf("with a grant: %v", m)
	}
	r.moved.accounts[string(r.user.ID)] = MovedAccount{Sub: subA, Name: "same", OldName: "same", Designated: true}
	g2 := r.grant(t)
	if _, m := view(g2); m["name"] != "same" || m["previousName"] != nil {
		t.Errorf("an unchanged name: %v", m)
	}
	if w := r.password(goodBody, g2); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	if _, m := view(g2); m["name"] != nil {
		t.Errorf("a spent grant still named: %v", m)
	}
	r.moved.offered = false
	if _, m := view(); m["offered"] != false {
		t.Errorf("not offered: %v", m)
	}
	r.moved.offerErr = errTest
	code, m := view()
	if code != http.StatusInternalServerError || m["correlationId"] == "" {
		t.Errorf("an unreadable offer: %d %v", code, m)
	}
	if recs := r.log.Matching(slog.LevelWarn, "offer"); len(recs) != 1 {
		t.Errorf("log %s", r.log.Text())
	}
}

// Begin replaces the ceremony or grant this browser holds, and refuses two
// bridge cookies.
func TestBridge_BeginReplaces(t *testing.T) {
	r := newBridgeRig(t)
	g := r.grant(t)
	r.begin(t, g)
	if _, ok := r.bridge.records.peek(g.Value); ok {
		t.Error("a newer ceremony left the grant live")
	}
	w := serveBridge(r.h, http.MethodPost, "/api/auth/bridge/begin", "", g, &http.Cookie{Name: bridgeCookieName, Value: "x"})
	if code, _, _ := codeOf(t, w); w.Code != http.StatusBadRequest || code != BridgeCodeDuplicateCookie {
		t.Errorf("two cookies: %d %s", w.Code, w.Body.String())
	}
	// A grant's cookie is not a ceremony.
	g = r.grant(t)
	if code, _, _ := codeOf(t, serveBridge(r.h, http.MethodPost, "/api/auth/bridge/finish", "{}", g)); code != BridgeCodeExpired {
		t.Errorf("finish with a grant's cookie: %s", code)
	}
	big := strings.Repeat("x", bridgeBodyLimit+1)
	_, c := r.begin(t)
	if w := serveBridge(r.h, http.MethodPost, "/api/auth/bridge/finish", big, c); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a large finish body: %d", w.Code)
	}
}

// TC-1005-24 (the auth half): InstallBridge refuses each nil collaborator;
// before it is installed the bridge routes answer 404 bridge_unavailable,
// no pre-update cookie resolves, and login/begin and /finish still 410.
func TestInstallBridge_TC1005_24(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/auth/bridge/begin"}, {http.MethodPost, "/api/auth/bridge/finish"},
		{http.MethodGet, "/api/auth/bridge"}, {http.MethodPost, "/api/auth/bridge/password"},
	} {
		w := serveBridge(h, c.method, c.path, "")
		if code, _, _ := codeOf(t, w); w.Code != http.StatusNotFound || code != BridgeCodeUnavailable {
			t.Errorf("%s %s before install: %d %s", c.method, c.path, w.Code, w.Body.String())
		}
	}
	u := f.mintUser(t, "old")
	if err := f.store.CreateSession(f.ctx, &Session{Token: "old-token", UserID: u.ID, CreatedAt: f.clock.Now(),
		ExpiresAt: f.clock.Now().Add(time.Hour), LastActiveAt: f.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	if w := get(h, "/api/auth/me", &http.Cookie{Name: legacySessionCookieName, Value: "old-token"}); w.Code != http.StatusUnauthorized {
		t.Errorf("an old cookie before install: %d", w.Code)
	}
	for _, p := range []string{"/api/auth/login/begin", "/api/auth/login/finish"} {
		if w := post(h, p, ""); w.Code != http.StatusGone {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	log, _ := logkittest.New()
	full := BridgeDeps{Accounts: &fakeMoved{}, FirstPassword: &fakeFirst{}, SignInOrigin: signInAt,
		NewCorrelationID: func() string { return "x" }, Now: time.Now, Rand: rand.Reader, Log: log}
	for name, edit := range map[string]func(*BridgeDeps){
		"Accounts":         func(d *BridgeDeps) { d.Accounts = nil },
		"FirstPassword":    func(d *BridgeDeps) { d.FirstPassword = nil },
		"SignInOrigin":     func(d *BridgeDeps) { d.SignInOrigin = "" },
		"NewCorrelationID": func(d *BridgeDeps) { d.NewCorrelationID = nil },
		"Now":              func(d *BridgeDeps) { d.Now = nil },
		"Rand":             func(d *BridgeDeps) { d.Rand = nil },
		"Log":              func(d *BridgeDeps) { d.Log = nil },
	} {
		d := full
		edit(&d)
		if err := f.svc.InstallBridge(d); err == nil {
			t.Errorf("InstallBridge accepted a nil %s", name)
		}
	}
	if f.svc.bridgeOf() != nil {
		t.Error("a refused install installed something")
	}
	if err := f.svc.InstallBridge(full); err != nil || f.svc.bridgeOf() == nil {
		t.Errorf("a full install: %v", err)
	}
}

// TC-1005-21 (the callback's half): a console sign-in that mints a session
// also clears the pre-update cookie.
func TestCallback_TC1005_21_ClearsPreUpdateCookie(t *testing.T) {
	r := newSigninRig(t)
	w := r.signIn(t, nil)
	if sessionFrom(w) == nil {
		t.Fatalf("no session minted: %d %s", w.Code, w.Header().Get("Location"))
	}
	if c := cookieOf(w, legacySessionCookieName); c == nil || c.MaxAge >= 0 {
		t.Errorf("the pre-update cookie was not cleared: %+v", c)
	}
}

// The parse at the endpoint: a bare address, trimmed; nothing else.
func TestParseEmail(t *testing.T) {
	for in, want := range map[string]string{
		" a@b.example ": "a@b.example", "a@b": "a@b", "": "", "A <a@b.example>": "", "<a@b.example>": "", "a b@c": "", "nope": "",
	} {
		got, ok := parseEmail(in)
		if got != want || ok != (want != "") {
			t.Errorf("parseEmail(%q) = %q %v", in, got, ok)
		}
	}
	if (&BridgeRefusal{Code: "x"}).Error() == "" || assertionKind(errors.New("plain")) != "other" {
		t.Error("the refusal's text or the assertion kind")
	}
}
