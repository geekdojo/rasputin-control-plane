package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth/idtoken"
	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// ---- the clock ---------------------------------------------------------------

// testClock is an injected clock a test moves by hand.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 11, 23, 12, 0, 0, 500_000_000, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ---- console sessions --------------------------------------------------------

// consoleCookie mints a console session for p straight through the store
// and returns its cookie.
func consoleCookie(t *testing.T, f *authFixture, p Principal) *http.Cookie {
	t.Helper()
	if p.Session.SID == "" {
		p.Session.SID = "sid-" + p.Sub
	}
	v, err := f.sessions.Create(f.ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Destroy)
	return &http.Cookie{Name: SessionCookieName, Value: string(v.Reveal())}
}

func (f *authFixture) countRows(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := f.store.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// ---- the issuer: a signing key and its key set ------------------------------

// testIssuer signs tokens as the home door's issuer and serves its key set
// on a plain test server, which keyClient reaches whatever host a URL names.
type testIssuer struct {
	mu   sync.Mutex
	keys []*rsa.PrivateKey
	kids []string
	srv  *httptest.Server
	hits atomic.Int64
	down atomic.Bool
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	is := &testIssuer{}
	is.rotate(t)
	is.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.hits.Add(1)
		if is.down.Load() || !strings.HasSuffix(r.URL.Path, "/protocol/openid-connect/certs") {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(is.jwks())
	}))
	t.Cleanup(is.srv.Close)
	return is
}

// rotate adds a new signing key, which signs from now on; the key set
// serves every key.
func (is *testIssuer) rotate(t *testing.T) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	is.mu.Lock()
	defer is.mu.Unlock()
	is.keys = append(is.keys, k)
	is.kids = append(is.kids, "kid-"+string(rune('a'+len(is.kids))))
}

func (is *testIssuer) jwks() []byte {
	is.mu.Lock()
	defer is.mu.Unlock()
	var keys []map[string]string
	for i, k := range is.keys {
		keys = append(keys, map[string]string{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": is.kids[i],
			"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		})
	}
	b, _ := json.Marshal(map[string]any{"keys": keys})
	return b
}

// sign is claims as an RS256 JWT under the newest key.
func (is *testIssuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	is.mu.Lock()
	k, kid := is.keys[len(is.keys)-1], is.kids[len(is.kids)-1]
	is.mu.Unlock()
	return signWith(t, k, kid, claims)
}

func signWith(t *testing.T, k *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// keyClient sends every request to the issuer's test server.
func (is *testIssuer) keyClient() *http.Client {
	target, _ := url.Parse(is.srv.URL)
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		out := r.Clone(r.Context())
		u := *r.URL
		u.Scheme, u.Host = target.Scheme, target.Host
		out.URL = &u
		out.Host = target.Host
		return http.DefaultTransport.RoundTrip(out)
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// ---- fakes -------------------------------------------------------------------

// fakeExchanger answers the exchange with token, or err.
type fakeExchanger struct {
	mu    sync.Mutex
	token string
	err   error
	calls int
	last  idclient.CodeExchange
	code  string
	verif string
}

func (x *fakeExchanger) ExchangeCode(_ context.Context, c idclient.CodeExchange) (secret.Value, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.calls++
	x.last = c
	x.code, x.verif = string(c.Code.Reveal()), string(c.Verifier.Reveal())
	if x.err != nil {
		return secret.Value{}, x.err
	}
	return secret.New([]byte(x.token)), nil
}

func (x *fakeExchanger) set(token string, err error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.token, x.err = token, err
}

// fakeEnder records each identity session it is asked to end.
type fakeEnder struct {
	mu   sync.Mutex
	sids []string
	err  error
}

func (e *fakeEnder) EndSession(_ context.Context, sid string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sids = append(e.sids, sid)
	return e.err
}

// fakeReady is the identity service's readiness.
type fakeReady struct{ err error }

func (r fakeReady) Ready(context.Context) error { return r.err }

// fakeAction counts its runs and the payloads it was given; err, when set,
// fails each run.
type fakeAction struct {
	mu       sync.Mutex
	runs     []Principal
	payloads []ActionPayload
	err      error
}

func (a *fakeAction) Run(_ context.Context, p Principal, payload ActionPayload) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.runs = append(a.runs, p)
	a.payloads = append(a.payloads, payload)
	if a.err != nil {
		return "", a.err
	}
	return "/settings?done=1", nil
}

// countingPayload counts its Destroy calls.
type countingPayload struct {
	mu        sync.Mutex
	destroyed int
}

func (c *countingPayload) Destroy() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.destroyed++
}

func (c *countingPayload) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.destroyed
}

func (a *fakeAction) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.runs)
}

// ---- the sign-in rig ---------------------------------------------------------

const (
	rigCID     = "ci"
	rigConsole = "ci.local"
	rigSub     = "0b6e2f4a-sub-alice"
	rigSID     = "sid-alice-1"
)

// signinRig is the auth service with a SignIn over the fakes, a real
// go-oidc verifier on the test issuer, and a recording logger.
type signinRig struct {
	f      *authFixture
	door   doors.Door
	app    doors.Door
	is     *testIssuer
	ex     *fakeExchanger
	ender  *fakeEnder
	action *fakeAction
	si     *SignIn
	log    *logkittest.Recorder
	h      http.Handler
	// first, claimer and observer are the first-run claim's fakes
	// (geekdojo/geekdojo-brain#990); first run is off unless a test turns
	// it on.
	first    *fakeFirstRun
	claimer  *fakeClaimer
	observer *fakeObserver
	// clock is the clock-sync fact (geekdojo/geekdojo-brain#1150); it holds
	// unless a test turns it off.
	clock *fakeClockFact
}

// fakeClockFact is the clock-sync fact, switchable, counting its reads.
type fakeClockFact struct {
	synced atomic.Bool
	reads  atomic.Int64
}

func newFakeClockFact(synced bool) *fakeClockFact {
	c := &fakeClockFact{}
	c.synced.Store(synced)
	return c
}

func (c *fakeClockFact) Synced(context.Context) bool {
	c.reads.Add(1)
	return c.synced.Load()
}

// fakeFirstRun answers first run.
type fakeFirstRun struct {
	mu    sync.Mutex
	first bool
	err   error
}

func (f *fakeFirstRun) set(first bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.first, f.err = first, err
}

func (f *fakeFirstRun) FirstRun(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.first, f.err
}

// fakeClaimer names sub, or fails with err.
type fakeClaimer struct {
	mu    sync.Mutex
	sub   string
	err   error
	calls int
}

func (c *fakeClaimer) Earliest(context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.sub, c.err
}

// fakeObserver records every sign-in it is told of.
type fakeObserver struct {
	mu   sync.Mutex
	subs []string
}

func (o *fakeObserver) SignedIn(_ context.Context, sub string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.subs = append(o.subs, sub)
}

func (o *fakeObserver) seen() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.subs...)
}

func newSigninRig(t *testing.T) *signinRig {
	t.Helper()
	f := newAuthFixture(t)
	table, err := doors.New(rigCID)
	if err != nil {
		t.Fatal(err)
	}
	is := newTestIssuer(t)
	v, err := idtoken.New(context.Background(), table.Home.Issuer, "rasputin-console", is.keyClient(), f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	log, rec := logkittest.New()
	r := &signinRig{f: f, door: table.Home, app: table.App, is: is, ex: &fakeExchanger{}, ender: &fakeEnder{}, action: &fakeAction{}, log: rec,
		first: &fakeFirstRun{}, claimer: &fakeClaimer{sub: "sub-earliest"}, observer: &fakeObserver{}, clock: newFakeClockFact(true)}
	r.si, err = NewSignIn(SignInDeps{
		Door: table.Home, ConsoleHost: rigConsole, ClientID: "rasputin-console", Realm: "rasputin",
		Exchanger: r.ex, Verifier: v, Ender: r.ender, Ready: fakeReady{}, Sessions: f.sessions,
		FirstRun: r.first, Claimer: r.claimer, Observer: r.observer,
		Actions: map[string]Action{"test-action": r.action}, Clock: r.clock, Now: f.clock.Now, Rand: rand.Reader, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.svc.SetSignIn(r.si)
	r.h = f.handler()
	return r
}

// prepare runs PrepareAction for sub's kind with payload, and returns the
// pending cookie it set.
func (r *signinRig) prepare(t *testing.T, sub, kind string, payload ActionPayload, cookies ...*http.Cookie) *http.Cookie {
	t.Helper()
	req := httptestRequest(rigConsole, "/api/accounts/x/reset-password")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req = req.WithContext(WithPrincipal(req.Context(), Principal{Sub: sub, Name: "alice"}))
	w := recorder()
	next, err := r.si.PrepareAction(w, req, kind, payload)
	if err != nil || next != "/api/auth/signin?action="+kind {
		t.Fatalf("PrepareAction = %q, %v", next, err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == pendingCookieName {
			return c
		}
	}
	t.Fatal("PrepareAction set no pending cookie")
	return nil
}

// get sends a GET to the console at host with cookies.
func (r *signinRig) get(path, host string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "https://"+host+path, nil)
	req.Host = host
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}

// begun is one Begin's answer: its pending cookie and the authorization
// request's query.
type begun struct {
	pending *http.Cookie
	q       url.Values
	loc     *url.URL
}

func (r *signinRig) begin(t *testing.T, cookies ...*http.Cookie) begun {
	t.Helper()
	return r.beginAt(t, "/api/auth/signin", cookies...)
}

// beginAt is begin through path: the sign-in, or the sign-up.
func (r *signinRig) beginAt(t *testing.T, path string, cookies ...*http.Cookie) begun {
	t.Helper()
	w := r.get(path, rigConsole, cookies...)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("signin: %d %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	b := begun{q: loc.Query(), loc: loc}
	for _, c := range w.Result().Cookies() {
		if c.Name == pendingCookieName {
			b.pending = c
		}
	}
	if b.pending == nil {
		t.Fatal("signin set no pending cookie")
	}
	return b
}

// idClaims are a valid ID token's claims for b's sign-in.
func (r *signinRig) idClaims(b begun) map[string]any {
	now := r.f.clock.Now()
	return map[string]any{
		"iss": r.door.Issuer, "sub": rigSub, "aud": "rasputin-console", "azp": "rasputin-console",
		"nonce": b.q.Get("nonce"), "sid": rigSID, "auth_time": now.Unix(), "iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "preferred_username": "alice", "rasputin_roles": []string{"admin"},
		"typ": "ID",
	}
}

// callbackQuery is the door's return for b with code.
func (r *signinRig) callbackQuery(b begun, code string) url.Values {
	return url.Values{"state": {b.q.Get("state")}, "code": {code}, "iss": {r.door.Issuer}, "session_state": {"ss-1"}}
}

// callback sends the door's return with q and the pending cookie.
func (r *signinRig) callback(q url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	return r.get("/api/auth/callback?"+q.Encode(), rigConsole, cookies...)
}

// signIn runs a whole sign-in with claims edited by edit, and returns the
// callback's answer.
func (r *signinRig) signIn(t *testing.T, edit func(map[string]any)) *httptest.ResponseRecorder {
	t.Helper()
	b := r.begin(t)
	c := r.idClaims(b)
	if edit != nil {
		edit(c)
	}
	r.ex.set(r.is.sign(t, c), nil)
	return r.callback(r.callbackQuery(b, "code-1"), b.pending)
}

// sessionFrom is the session cookie a response set, or nil.
func sessionFrom(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			return c
		}
	}
	return nil
}

// refusals are the signin.refused records' reasons.
func (r *signinRig) refusals() []string {
	var out []string
	for _, rec := range r.log.Records() {
		if ev, _ := logkittest.Attr(rec, "event"); ev == "signin.refused" && rec.Level == slog.LevelWarn {
			reason, _ := logkittest.Attr(rec, "reason")
			out = append(out, reason)
		}
	}
	return out
}

// events are the records whose event attribute is ev.
func (r *signinRig) events(ev string) []slog.Record {
	var out []slog.Record
	for _, rec := range r.log.Records() {
		if got, _ := logkittest.Attr(rec, "event"); got == ev {
			out = append(out, rec)
		}
	}
	return out
}

var errTest = errors.New("test failure")

// unreachable is an identity client error of kind ErrUnreachable.
func unreachable() error { return &idclient.Error{Op: "token", Kind: idclient.ErrUnreachable} }

// invalidGrant is the token endpoint refusing a spent code.
func invalidGrant() error {
	return &idclient.Error{Op: "token", Status: 400, Kind: idclient.ErrProtocol, OAuthError: "invalid_grant"}
}

// ---- small request helpers --------------------------------------------------

type httptestRecorder = httptest.ResponseRecorder

func recorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

func httptestRequest(host, path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://"+host+path, nil)
	r.Host = host
	return r
}

func serve(h http.Handler, host, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptestRequest(host, path)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func get(h http.Handler, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	return serve(h, rigConsole, path, cookies...)
}

// status is GET /api/auth/status's body.
func status(t *testing.T, h http.Handler, cookies ...*http.Cookie) map[string]any {
	t.Helper()
	w := get(h, "/api/auth/status", cookies...)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func hashOf(v string) string { return busauth.HashToken(v) }

// secretOf is a cookie's value as a secret.Value.
func secretOf(c *http.Cookie) secret.Value { return secret.New([]byte(c.Value)) }
