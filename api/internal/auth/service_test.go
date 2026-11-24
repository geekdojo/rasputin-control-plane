package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
	tok, err := f.svc.storePending(&pendingAuth{kind: "register"})
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
// RequireSession / RequireSessionFunc
// ============================================================================

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
		if c.Name == ceremonyCookieName {
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
			if c.Name == ceremonyCookieName {
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
// LoginHook
// ============================================================================

func TestSetLoginHook_NoHookIsNoop(t *testing.T) {
	f := newAuthFixture(t)
	// Should not panic, should not block; with no hook installed there's
	// no observable effect, so the test asserts the negative (returns).
	f.svc.runLoginHook(context.Background(), "alice")
}

func TestSetLoginHook_FiresWithUserAndContext(t *testing.T) {
	f := newAuthFixture(t)
	type call struct {
		name string
		ctx  context.Context
	}
	got := make(chan call, 1)
	f.svc.SetLoginHook(func(ctx context.Context, name string) error {
		got <- call{name: name, ctx: ctx}
		return nil
	})

	// Use a distinctive ctx key so we can confirm the hook receives the
	// caller's context (not a fresh background one).
	type k int
	ctx := context.WithValue(context.Background(), k(0), "marker")
	f.svc.runLoginHook(ctx, "alice")

	select {
	case c := <-got:
		if c.name != "alice" {
			t.Errorf("hook name: got %q want alice", c.name)
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
	f.svc.SetLoginHook(func(ctx context.Context, _ string) error {
		return errors.New("downstream-down")
	})
	// runLoginHook returns nothing; the panic that this guards against is
	// the most important assertion.
	f.svc.runLoginHook(context.Background(), "alice")
}

func TestSetLoginHook_Replaceable(t *testing.T) {
	f := newAuthFixture(t)
	var aCount, bCount int
	f.svc.SetLoginHook(func(ctx context.Context, _ string) error { aCount++; return nil })
	f.svc.SetLoginHook(func(ctx context.Context, _ string) error { bCount++; return nil })
	f.svc.runLoginHook(context.Background(), "alice")
	if aCount != 0 {
		t.Errorf("replaced hook should not fire; aCount=%d", aCount)
	}
	if bCount != 1 {
		t.Errorf("replacement hook should fire exactly once; bCount=%d", bCount)
	}
}

func TestSetLoginHook_NilUninstalls(t *testing.T) {
	f := newAuthFixture(t)
	var fired bool
	f.svc.SetLoginHook(func(ctx context.Context, _ string) error { fired = true; return nil })
	f.svc.SetLoginHook(nil)
	f.svc.runLoginHook(context.Background(), "alice")
	if fired {
		t.Error("nil SetLoginHook did not uninstall")
	}
}
