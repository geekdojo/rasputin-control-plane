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

func TestHandleRegisterBegin_ConflictExistingUser(t *testing.T) {
	f := newAuthFixture(t)
	// Existing user → next register requires auth.
	u := f.mintUser(t, "alice")
	sess := freshSession(t, f, u)

	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	body := `{"name":"alice","displayName":"Alice"}`
	r := httptest.NewRequest(http.MethodPost, "/api/auth/register/begin", strings.NewReader(body))
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess.Token})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusConflict {
		t.Errorf("want 409, got %d body=%s", w.Code, w.Body.String())
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
