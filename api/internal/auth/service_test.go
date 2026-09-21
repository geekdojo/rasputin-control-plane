package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// makeUser / validUserName
// ============================================================================

func TestValidUserName(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"", false},
		{"a", true},
		{"alice", true},
		{"Alice", true},
		{"alice_99-x.y", true},
		{".dotleading", false},
		{"-dashleading", false},
		{"has space", false},
		{"has!bang", false},
		{strings.Repeat("a", 33), false},
		{strings.Repeat("a", 32), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validUserName(tc.name); got != tc.ok {
				t.Errorf("validUserName(%q) = %v, want %v", tc.name, got, tc.ok)
			}
		})
	}
}

func TestMakeUser_AssignsRandomID(t *testing.T) {
	a, err := makeUser("alice", "Alice")
	if err != nil {
		t.Fatalf("makeUser: %v", err)
	}
	if len(a.ID) != 16 {
		t.Errorf("want 16-byte id, got %d", len(a.ID))
	}
	b, err := makeUser("alice", "Alice")
	if err != nil {
		t.Fatalf("makeUser: %v", err)
	}
	if string(a.ID) == string(b.ID) {
		t.Error("makeUser produced duplicate ids")
	}
	if a.WebAuthnDisplayName() != "Alice" {
		t.Errorf("display name: got %q", a.WebAuthnDisplayName())
	}
}

func TestMakeUser_DefaultDisplayName(t *testing.T) {
	u, err := makeUser("alice", "")
	if err != nil {
		t.Fatalf("makeUser: %v", err)
	}
	if u.WebAuthnDisplayName() != "alice" {
		t.Errorf("display: want %q got %q", "alice", u.WebAuthnDisplayName())
	}
}

func TestMakeUser_InvalidName(t *testing.T) {
	if _, err := makeUser("has space", ""); err == nil {
		t.Error("want error for invalid user name")
	}
}

// ============================================================================
// User WebAuthn methods
// ============================================================================

func TestUser_WebAuthnAccessors(t *testing.T) {
	u := &User{ID: []byte("xyz"), Name: "alice", DisplayName: "Alice"}
	if string(u.WebAuthnID()) != "xyz" {
		t.Error("WebAuthnID mismatch")
	}
	if u.WebAuthnName() != "alice" {
		t.Error("WebAuthnName mismatch")
	}
	if u.WebAuthnDisplayName() != "Alice" {
		t.Error("WebAuthnDisplayName mismatch")
	}
	if got := u.WebAuthnCredentials(); got != nil {
		t.Errorf("WebAuthnCredentials default: want nil, got %v", got)
	}
}

// ============================================================================
// publicUser / bytesToHex
// ============================================================================

func TestPublicUser(t *testing.T) {
	now := time.Now().UTC()
	u := &User{
		ID: []byte{0x01, 0x02, 0xff}, Name: "alice", DisplayName: "Alice",
		CreatedAt: now,
	}
	pv := publicUser(u)
	if pv.ID != "0102ff" {
		t.Errorf("id hex: got %q", pv.ID)
	}
	if pv.Name != "alice" || pv.DisplayName != "Alice" {
		t.Errorf("public view fields wrong: %+v", pv)
	}
}

func TestBytesToHex(t *testing.T) {
	if got := bytesToHex([]byte{0, 0xff, 0x10}); got != "00ff10" {
		t.Errorf("bytesToHex: got %q", got)
	}
	if got := bytesToHex(nil); got != "" {
		t.Errorf("bytesToHex(nil): got %q", got)
	}
}

// ============================================================================
// randomToken
// ============================================================================

func TestRandomToken(t *testing.T) {
	a, err := randomToken(16)
	if err != nil {
		t.Fatalf("randomToken: %v", err)
	}
	b, err := randomToken(16)
	if err != nil {
		t.Fatalf("randomToken: %v", err)
	}
	if len(a) != 32 {
		t.Errorf("want 32 hex chars, got %d", len(a))
	}
	if a == b {
		t.Error("randomToken produced duplicates")
	}
}

// ============================================================================
// Pending store
// ============================================================================

func TestPending_StoreAndTake(t *testing.T) {
	f := newAuthFixture(t)
	tok, err := f.svc.storePending(&pendingAuth{kind: "register"})
	if err != nil {
		t.Fatalf("storePending: %v", err)
	}
	if len(tok) == 0 {
		t.Fatal("empty token")
	}
	got := f.svc.takePending(tok)
	if got == nil || got.kind != "register" {
		t.Fatalf("takePending: got %+v", got)
	}
	// Second take: should be gone (one-shot).
	if again := f.svc.takePending(tok); again != nil {
		t.Errorf("takePending second call: want nil, got %+v", again)
	}
}

func TestPending_ExpiredTakeReturnsNil(t *testing.T) {
	f := newAuthFixture(t)
	tok, err := f.svc.storePending(&pendingAuth{kind: "login"})
	if err != nil {
		t.Fatalf("storePending: %v", err)
	}
	// Reach inside and expire the entry.
	f.svc.mu.Lock()
	f.svc.pending[tok].expires = time.Now().Add(-time.Second)
	f.svc.mu.Unlock()
	if got := f.svc.takePending(tok); got != nil {
		t.Errorf("want nil for expired pending, got %+v", got)
	}
}

func TestPending_UnknownTokenReturnsNil(t *testing.T) {
	f := newAuthFixture(t)
	if got := f.svc.takePending("unknown-token"); got != nil {
		t.Errorf("want nil, got %+v", got)
	}
}

func TestService_CleanupPending(t *testing.T) {
	f := newAuthFixture(t)
	tok, _ := f.svc.storePending(&pendingAuth{kind: "register"})
	// Force the expiry into the past.
	f.svc.mu.Lock()
	f.svc.pending[tok].expires = time.Now().Add(-time.Minute)
	f.svc.mu.Unlock()
	f.svc.cleanupPending(time.Now())
	f.svc.mu.Lock()
	_, ok := f.svc.pending[tok]
	f.svc.mu.Unlock()
	if ok {
		t.Error("expected expired pending to be cleaned")
	}
}

// ============================================================================
// createSession
// ============================================================================

func TestCreateSession_PersistsAndReturnsToken(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	sess, err := f.svc.createSession(f.ctx, u.ID)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	if len(sess.Token) != 64 {
		t.Errorf("token len: want 64 hex, got %d", len(sess.Token))
	}
	got, err := f.store.GetSession(f.ctx, sess.Token)
	if err != nil || got == nil {
		t.Fatalf("session not persisted: err=%v got=%+v", err, got)
	}
	if sess.ExpiresAt.Sub(sess.CreatedAt) != sessionLifetime {
		t.Errorf("expiry: want %v, got %v", sessionLifetime, sess.ExpiresAt.Sub(sess.CreatedAt))
	}
}

// ============================================================================
// Cookie helpers
// ============================================================================

// Every cookie this service emits must honour SecureCookies — all four, not
// just the session one. The pending cookie carries the in-flight WebAuthn
// ceremony, so it leaking over plaintext is not meaningfully better.
//
// Guards the regression in geekdojo/geekdojo-brain#143: SecureCookies came
// from an opt-in env var that defaulted off and was set in no deployment, so
// appliances served the 7-day passkey session cookie without Secure.
func TestCookiesHonourSecureFlag(t *testing.T) {
	for _, secure := range []bool{true, false} {
		t.Run(map[bool]string{true: "secure", false: "insecure"}[secure], func(t *testing.T) {
			f := newAuthFixture(t)
			f.svc.cfg.SecureCookies = secure

			emit := map[string]func(w *httptest.ResponseRecorder){
				"setSessionCookie":   func(w *httptest.ResponseRecorder) { f.svc.setSessionCookie(w, "tok", time.Now().Add(time.Hour)) },
				"clearSessionCookie": func(w *httptest.ResponseRecorder) { f.svc.clearSessionCookie(w) },
				"setPendingCookie":   func(w *httptest.ResponseRecorder) { f.svc.setPendingCookie(w, "tok") },
				"clearPendingCookie": func(w *httptest.ResponseRecorder) { f.svc.clearPendingCookie(w) },
			}
			for name, fn := range emit {
				w := httptest.NewRecorder()
				fn(w)
				got := w.Result().Cookies()
				if len(got) != 1 {
					t.Fatalf("%s: want 1 cookie, got %d", name, len(got))
				}
				if got[0].Secure != secure {
					t.Errorf("%s: Secure = %v, want %v", name, got[0].Secure, secure)
				}
				// HttpOnly is unconditional and must not regress alongside.
				if !got[0].HttpOnly {
					t.Errorf("%s: cookie should always be HttpOnly", name)
				}
			}
		})
	}
}

func TestSetClearSessionCookie(t *testing.T) {
	f := newAuthFixture(t)
	w := httptest.NewRecorder()
	f.svc.setSessionCookie(w, "tok123", time.Now().Add(time.Hour))
	got := w.Result().Cookies()
	if len(got) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(got))
	}
	if got[0].Name != sessionCookie || got[0].Value != "tok123" {
		t.Errorf("unexpected cookie: %+v", got[0])
	}
	if !got[0].HttpOnly {
		t.Error("session cookie should be HttpOnly")
	}

	// Clear: yields a cookie with MaxAge<0.
	w2 := httptest.NewRecorder()
	f.svc.clearSessionCookie(w2)
	clr := w2.Result().Cookies()
	if len(clr) != 1 || clr[0].MaxAge >= 0 {
		t.Errorf("clear cookie: %+v", clr)
	}
}

func TestSetClearPendingCookie(t *testing.T) {
	f := newAuthFixture(t)
	w := httptest.NewRecorder()
	f.svc.setPendingCookie(w, "ptok")
	got := w.Result().Cookies()
	if len(got) != 1 || got[0].Name != pendingCookie {
		t.Fatalf("setPendingCookie: %+v", got)
	}
	if got[0].MaxAge != int(pendingLifetime.Seconds()) {
		t.Errorf("MaxAge: want %d got %d", int(pendingLifetime.Seconds()), got[0].MaxAge)
	}

	w2 := httptest.NewRecorder()
	f.svc.clearPendingCookie(w2)
	clr := w2.Result().Cookies()
	if len(clr) != 1 || clr[0].MaxAge >= 0 {
		t.Errorf("clearPendingCookie: %+v", clr)
	}
}

// ============================================================================
// resolveSession / RequireSession / RequireSessionFunc
// ============================================================================

func freshSession(t *testing.T, f *authFixture, u *User) *Session {
	t.Helper()
	sess, err := f.svc.createSession(f.ctx, u.ID)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	return sess
}

func TestResolveSession_NoCookieReturnsNothing(t *testing.T) {
	f := newAuthFixture(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, user, err := f.svc.resolveSession(r)
	if err != nil {
		t.Fatalf("resolveSession: %v", err)
	}
	if sess != nil || user != nil {
		t.Errorf("want nil session/user, got %+v/%+v", sess, user)
	}
}

func TestResolveSession_ValidCookie(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	sess := freshSession(t, f, u)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess.Token})

	gotSess, gotUser, err := f.svc.resolveSession(r)
	if err != nil {
		t.Fatalf("resolveSession: %v", err)
	}
	if gotSess == nil || gotSess.Token != sess.Token {
		t.Errorf("want session %q, got %+v", sess.Token, gotSess)
	}
	if gotUser == nil || gotUser.Name != "alice" {
		t.Errorf("want alice, got %+v", gotUser)
	}
}

func TestResolveSession_ExpiredCookieIsCleanedUp(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")

	// Insert an already-expired session row directly.
	now := time.Now().UTC()
	expired := &Session{
		Token:        "expired-tok",
		UserID:       u.ID,
		CreatedAt:    now.Add(-2 * time.Hour),
		ExpiresAt:    now.Add(-time.Hour),
		LastActiveAt: now.Add(-time.Hour),
	}
	if err := f.store.CreateSession(f.ctx, expired); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "expired-tok"})

	sess, user, err := f.svc.resolveSession(r)
	if err != nil {
		t.Fatalf("resolveSession: %v", err)
	}
	if sess != nil || user != nil {
		t.Errorf("expired session resolved as live: %+v / %+v", sess, user)
	}
	// And the expired row should have been deleted.
	if got, _ := f.store.GetSession(f.ctx, "expired-tok"); got != nil {
		t.Error("expired session row was not cleaned up")
	}
}

func TestRequireSession_MissingCookieReturns401(t *testing.T) {
	f := newAuthFixture(t)
	handler := f.svc.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestRequireSession_ValidCookiePasses(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	sess := freshSession(t, f, u)

	var gotName string
	handler := f.svc.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := UserFromContext(r.Context())
		if ok {
			gotName = got.Name
		}
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess.Token})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
	if gotName != "alice" {
		t.Errorf("expected user in context, got %q", gotName)
	}
}

func TestRequireSession_ExpiredCookieReturns401(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	expired := &Session{
		Token:        "x",
		UserID:       u.ID,
		CreatedAt:    time.Now().Add(-2 * time.Hour),
		ExpiresAt:    time.Now().Add(-time.Hour),
		LastActiveAt: time.Now().Add(-time.Hour),
	}
	if err := f.store.CreateSession(f.ctx, expired); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	handler := f.svc.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downstream handler should not run")
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "x"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestRequireSessionFunc_DelegatesToRequireSession(t *testing.T) {
	f := newAuthFixture(t)
	called := false
	wrapped := f.svc.RequireSessionFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	// No cookie → 401, downstream not called.
	w := httptest.NewRecorder()
	wrapped(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
	if called {
		t.Error("wrapped handler should not have been invoked")
	}
}

// ============================================================================
// UserFromContext
// ============================================================================

func TestUserFromContext_NoValue(t *testing.T) {
	if _, ok := UserFromContext(context.Background()); ok {
		t.Error("want ok=false on empty ctx")
	}
}

func TestUserFromContext_HasValue(t *testing.T) {
	u := &User{Name: "alice"}
	ctx := context.WithValue(context.Background(), ctxUser, u)
	got, ok := UserFromContext(ctx)
	if !ok || got.Name != "alice" {
		t.Errorf("UserFromContext: ok=%v user=%+v", ok, got)
	}
}

// ============================================================================
// Handlers: status / me / logout
// ============================================================================

func TestHandleStatus_EmptyDB(t *testing.T) {
	f := newAuthFixture(t)
	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	r := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp["hasUsers"] != false {
		t.Errorf("hasUsers: want false, got %v", resp["hasUsers"])
	}
	if resp["userCount"].(float64) != 0 {
		t.Errorf("userCount: want 0, got %v", resp["userCount"])
	}
}

func TestHandleStatus_WithUsersAndSession(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	sess := freshSession(t, f, u)

	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)

	r := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess.Token})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp["hasUsers"] != true {
		t.Errorf("hasUsers: want true, got %v", resp["hasUsers"])
	}
	if resp["user"] == nil {
		t.Error("expected user in response")
	}
}

func TestHandleMe_Unauthenticated(t *testing.T) {
	f := newAuthFixture(t)
	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	r := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestHandleMe_Authenticated(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	sess := freshSession(t, f, u)

	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	r := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess.Token})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp publicUserView
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json: %v", err)
	}
	if resp.Name != "alice" {
		t.Errorf("name: want alice, got %q", resp.Name)
	}
}

func TestHandleLogout_DeletesSessionAndClearsCookie(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	sess := freshSession(t, f, u)

	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	r := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess.Token})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
	// Cookie cleared in response.
	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("expected cleared session cookie")
	}
	// Session row gone.
	if got, _ := f.store.GetSession(f.ctx, sess.Token); got != nil {
		t.Error("session row not deleted on logout")
	}
}

func TestHandleLogout_NoCookieStillOK(t *testing.T) {
	f := newAuthFixture(t)
	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	r := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("want 200 even without session, got %d", w.Code)
	}
}

// ============================================================================
// Handler bad-input cases (don't need full WebAuthn)
// ============================================================================

func TestHandleRegisterBegin_BadJSON(t *testing.T) {
	f := newAuthFixture(t)
	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	r := httptest.NewRequest(http.MethodPost, "/api/auth/register/begin", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleRegisterBegin_RequiresAuthOnceUsersExist(t *testing.T) {
	f := newAuthFixture(t)
	f.mintUser(t, "alice")
	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	body := `{"name":"bob","displayName":"Bob"}`
	r := httptest.NewRequest(http.MethodPost, "/api/auth/register/begin", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestHandleRegisterBegin_FirstUserAllowed(t *testing.T) {
	f := newAuthFixture(t)
	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	body := `{"name":"alice","displayName":"Alice"}`
	r := httptest.NewRequest(http.MethodPost, "/api/auth/register/begin", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	// Should succeed because the DB is empty (first-run). The body is
	// CredentialCreation options issued by webauthn.
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	// Pending cookie was set.
	gotPending := false
	for _, c := range w.Result().Cookies() {
		if c.Name == pendingCookie {
			gotPending = true
		}
	}
	if !gotPending {
		t.Error("expected pending cookie on register/begin success")
	}
}

// Guards the registration/login contract at the wire, not at the config
// struct: login is BeginDiscoverableLogin (empty allowCredentials), so
// registration must ask for a discoverable credential or a security key
// registers fine and can then never sign in. Asserting the emitted JSON is
// deliberate — this is exactly the field the browser acts on, and a test that
// only inspected our Config would still pass if the option stopped reaching
// the response.
func TestHandleRegisterBegin_RequiresDiscoverableCredential(t *testing.T) {
	f := newAuthFixture(t)
	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	body := `{"name":"alice","displayName":"Alice"}`
	r := httptest.NewRequest(http.MethodPost, "/api/auth/register/begin", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}

	var got struct {
		PublicKey struct {
			AuthenticatorSelection struct {
				ResidentKey        string `json:"residentKey"`
				RequireResidentKey *bool  `json:"requireResidentKey"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode options: %v body=%s", err, w.Body.String())
	}

	sel := got.PublicKey.AuthenticatorSelection
	if sel.ResidentKey != "required" {
		t.Errorf("residentKey = %q, want \"required\" — discoverable login cannot find a non-discoverable credential", sel.ResidentKey)
	}
	// Legacy flag older authenticators still read; must agree with residentKey.
	if sel.RequireResidentKey == nil {
		t.Error("requireResidentKey absent, want true")
	} else if !*sel.RequireResidentKey {
		t.Error("requireResidentKey = false, want true")
	}
}

// ============================================================================
// The authenticator choice on the wire (geekdojo/geekdojo-brain#586)
// ============================================================================

// creationOptionsJSON is the slice of the emitted creation options these tests
// read: the fields a browser acts on when deciding which authenticators to
// offer. Asserted as JSON for the same reason the discoverable-credential test
// is — this is what the browser sees, and an option that stopped reaching the
// response would still leave our own structs looking right.
type creationOptionsJSON struct {
	PublicKey struct {
		AuthenticatorSelection struct {
			AuthenticatorAttachment string `json:"authenticatorAttachment"`
			ResidentKey             string `json:"residentKey"`
			RequireResidentKey      *bool  `json:"requireResidentKey"`
			UserVerification        string `json:"userVerification"`
		} `json:"authenticatorSelection"`
		Hints []string `json:"hints"`
	} `json:"publicKey"`
}

func decodeCreationOptions(t *testing.T, body []byte) creationOptionsJSON {
	t.Helper()
	var got creationOptionsJSON
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode creation options: %v body=%s", err, body)
	}
	return got
}

// A choice narrows the ceremony to the authenticator the operator picked, and
// says so twice: the hint for a browser that implements WebAuthn Level 3, the
// matching authenticatorAttachment for one that predates hints. Whatever the
// choice, the credential stays discoverable and user verification stays
// required — WithAuthenticatorSelection replaces that whole struct, so this is
// the assertion that catches it being dropped.
func TestHandleRegisterBegin_AuthenticatorChoice(t *testing.T) {
	cases := []struct {
		choice     authenticatorChoice
		attachment string
		hint       string
	}{
		{authenticatorPlatform, "platform", "client-device"},
		{authenticatorHybrid, "cross-platform", "hybrid"},
		{authenticatorSecurityKey, "cross-platform", "security-key"},
	}
	for _, tc := range cases {
		t.Run(string(tc.choice), func(t *testing.T) {
			f := newAuthFixture(t)
			mux := http.NewServeMux()
			f.svc.RegisterRoutes(mux)
			body := `{"name":"alice","displayName":"Alice","authenticator":"` + string(tc.choice) + `"}`
			r := httptest.NewRequest(http.MethodPost, "/api/auth/register/begin", strings.NewReader(body))
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
			}

			got := decodeCreationOptions(t, w.Body.Bytes())
			sel := got.PublicKey.AuthenticatorSelection
			if sel.AuthenticatorAttachment != tc.attachment {
				t.Errorf("authenticatorAttachment = %q, want %q", sel.AuthenticatorAttachment, tc.attachment)
			}
			if len(got.PublicKey.Hints) != 1 || got.PublicKey.Hints[0] != tc.hint {
				t.Errorf("hints = %v, want [%q]", got.PublicKey.Hints, tc.hint)
			}
			if sel.UserVerification != "required" {
				t.Errorf("userVerification = %q, want \"required\" — the choice must not relax decision #561", sel.UserVerification)
			}
			if sel.ResidentKey != "required" || sel.RequireResidentKey == nil || !*sel.RequireResidentKey {
				t.Errorf("residentKey = %q requireResidentKey = %v, want required/true", sel.ResidentKey, sel.RequireResidentKey)
			}
		})
	}
}

// No choice is not a fourth choice: it emits neither field, so the browser
// offers everything it can. This is the first-run wizard's request, which the
// #586 work must leave exactly as it was.
func TestHandleRegisterBegin_NoAuthenticatorChoiceNarrowsNothing(t *testing.T) {
	for _, body := range []string{
		`{"name":"alice","displayName":"Alice"}`,
		`{"name":"alice","displayName":"Alice","authenticator":""}`,
	} {
		f := newAuthFixture(t)
		mux := http.NewServeMux()
		f.svc.RegisterRoutes(mux)
		r := httptest.NewRequest(http.MethodPost, "/api/auth/register/begin", strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d body=%s", body, w.Code, w.Body.String())
		}
		// The keys are omitempty, so their absence is visible in the raw JSON
		// — a decoded zero value would not tell them apart from "sent empty".
		for _, key := range []string{"authenticatorAttachment", "hints"} {
			if strings.Contains(w.Body.String(), key) {
				t.Errorf("%s: creation options carry %q: %s", body, key, w.Body.String())
			}
		}
		got := decodeCreationOptions(t, w.Body.Bytes())
		if got.PublicKey.AuthenticatorSelection.UserVerification != "required" {
			t.Errorf("%s: userVerification = %q, want \"required\"", body, got.PublicKey.AuthenticatorSelection.UserVerification)
		}
	}
}

// An authenticator value this api does not model is a 400, not a silent
// widening back to "whatever the browser offers" — that is the dead end the
// choice exists to avoid, and a UI sending it has a bug worth seeing.
func TestHandleRegisterBegin_UnknownAuthenticatorRefused(t *testing.T) {
	for _, v := range []string{"cross-platform", "client-device", "PLATFORM", "usb", "none", " platform"} {
		f := newAuthFixture(t)
		mux := http.NewServeMux()
		f.svc.RegisterRoutes(mux)
		body := `{"name":"alice","displayName":"Alice","authenticator":"` + v + `"}`
		r := httptest.NewRequest(http.MethodPost, "/api/auth/register/begin", strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("authenticator %q: want 400, got %d %s", v, w.Code, w.Body.String())
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == pendingCookie {
				t.Errorf("authenticator %q: a refused begin started a ceremony", v)
			}
		}
		if f.countUsers(t) != 0 {
			t.Errorf("authenticator %q: a refused begin created a user", v)
		}
	}
}

func TestHandleRegisterBegin_InvalidName(t *testing.T) {
	f := newAuthFixture(t)
	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	body := `{"name":"has space","displayName":""}`
	r := httptest.NewRequest(http.MethodPost, "/api/auth/register/begin", strings.NewReader(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleRegisterFinish_MissingPendingCookie(t *testing.T) {
	f := newAuthFixture(t)
	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	r := httptest.NewRequest(http.MethodPost, "/api/auth/register/finish", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleLoginFinish_MissingPendingCookie(t *testing.T) {
	f := newAuthFixture(t)
	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login/finish", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleLoginBegin_PendingCookieSet(t *testing.T) {
	f := newAuthFixture(t)
	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login/begin", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
	gotPending := false
	for _, c := range w.Result().Cookies() {
		if c.Name == pendingCookie {
			gotPending = true
		}
	}
	if !gotPending {
		t.Error("expected pending cookie")
	}
}

// ============================================================================
// NewService default-config behavior
// ============================================================================

func TestNewService_DefaultsAreApplied(t *testing.T) {
	f := newAuthFixture(t)
	// Re-create with empty config.
	svc, err := NewService(f.store, Config{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if svc.cfg.RPDisplayName == "" {
		t.Error("RPDisplayName default not applied")
	}
	if svc.cfg.RPID == "" {
		t.Error("RPID default not applied")
	}
	if len(svc.cfg.RPOrigins) == 0 {
		t.Error("RPOrigins default not applied")
	}
}

// ============================================================================
// Start / Stop lifecycle (basic — no jitter)
// ============================================================================

func TestStart_Stop_NoPanic(t *testing.T) {
	f := newAuthFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.svc.Start(ctx)
	f.svc.Stop()
}

// ============================================================================
// httpError
// ============================================================================

func TestHTTPError_ErrorString(t *testing.T) {
	if got := httpError("boom").Error(); got != "boom" {
		t.Errorf("want %q, got %q", "boom", got)
	}
}

// ============================================================================
// LoginHook
// ============================================================================

func TestSetLoginHook_NoHookIsNoop(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	// Should not panic, should not block; with no hook installed there's
	// no observable effect, so the test asserts the negative (returns).
	f.svc.runLoginHook(context.Background(), u)
}

func TestSetLoginHook_FiresWithUserAndContext(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")

	type call struct {
		user *User
		ctx  context.Context
	}
	got := make(chan call, 1)
	f.svc.SetLoginHook(func(ctx context.Context, u *User) error {
		got <- call{user: u, ctx: ctx}
		return nil
	})

	// Use a distinctive ctx key so we can confirm the hook receives the
	// caller's context (not a fresh background one).
	type k int
	ctx := context.WithValue(context.Background(), k(0), "marker")
	f.svc.runLoginHook(ctx, u)

	select {
	case c := <-got:
		if c.user != u {
			t.Errorf("hook user: got %p want %p", c.user, u)
		}
		if c.ctx.Value(k(0)) != "marker" {
			t.Errorf("hook did not receive caller context value")
		}
	case <-time.After(time.Second):
		t.Fatal("hook never fired")
	}
}

func TestSetLoginHook_ErrorDoesNotPropagate(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	f.svc.SetLoginHook(func(ctx context.Context, u *User) error {
		return httpError("downstream-down")
	})
	// runLoginHook returns nothing; the panic that this guards against is
	// the most important assertion. We also rely on it logging — covered
	// by manual inspection rather than capturing stderr (brittle).
	f.svc.runLoginHook(context.Background(), u)
}

func TestSetLoginHook_Replaceable(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")

	var aCount, bCount int
	f.svc.SetLoginHook(func(ctx context.Context, u *User) error { aCount++; return nil })
	f.svc.SetLoginHook(func(ctx context.Context, u *User) error { bCount++; return nil })
	f.svc.runLoginHook(context.Background(), u)
	if aCount != 0 {
		t.Errorf("replaced hook should not fire; aCount=%d", aCount)
	}
	if bCount != 1 {
		t.Errorf("replacement hook should fire exactly once; bCount=%d", bCount)
	}
}

func TestSetLoginHook_NilUninstalls(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	var fired bool
	f.svc.SetLoginHook(func(ctx context.Context, u *User) error { fired = true; return nil })
	f.svc.SetLoginHook(nil)
	f.svc.runLoginHook(context.Background(), u)
	if fired {
		t.Error("nil SetLoginHook did not uninstall")
	}
}

// Login + register handlers must call runLoginHook so a downstream
// EnsureUser side-effect is observable when the response returns. We
// can't exercise the full WebAuthn flow in a unit test (real attestation
// data), but we CAN assert the source contains both call sites — a
// regression where someone deletes one of those calls would silently
// break per-IAM-user Headscale provisioning. This catches that.
func TestLoginHook_HandlerCallSitesIntact(t *testing.T) {
	src, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatalf("read handlers.go: %v", err)
	}
	body := string(src)
	if !strings.Contains(body, "s.runLoginHook(r.Context(), p.user)") {
		t.Error("handleRegisterFinish missing runLoginHook call")
	}
	if !strings.Contains(body, "s.runLoginHook(ctx, user)") {
		t.Error("handleLoginFinish missing runLoginHook call")
	}
}
