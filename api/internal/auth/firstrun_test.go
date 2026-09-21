package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// ============================================================================
// A software authenticator, so the tests below drive register/finish through
// the real go-webauthn verification rather than stopping at a 400 on a
// malformed attestation. It answers a creation request with "none"
// attestation over a fresh P-256 key.
// ============================================================================

type softAuthenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
	origin string
	rpID   string
	count  uint32
	// noUV makes the authenticator skip user verification (UV flag clear).
	noUV bool
}

func newSoftAuthenticator(t *testing.T) *softAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &softAuthenticator{key: key, credID: id, origin: "http://localhost:3000", rpID: "localhost"}
}

// attest turns register/begin's options JSON into register/finish's body.
func (a *softAuthenticator) attest(t *testing.T, optionsJSON []byte) string {
	t.Helper()
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(optionsJSON, &opts); err != nil || opts.PublicKey.Challenge == "" {
		t.Fatalf("creation options: %v %s", err, optionsJSON)
	}
	clientData, _ := json.Marshal(map[string]any{
		"type": "webauthn.create", "challenge": opts.PublicKey.Challenge, "origin": a.origin,
	})
	pub, err := a.key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	raw := pub.Bytes() // 0x04 || X || Y
	cose, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:65]})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte(a.rpID))
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, a.flags(0x40))       // UP | UV | AT
	authData = append(authData, 0, 0, 0, 0)          // sign count
	authData = append(authData, make([]byte, 16)...) // AAGUID
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(a.credID)))
	authData = append(authData, a.credID...)
	authData = append(authData, cose...)
	attObj, err := webauthncbor.Marshal(map[string]any{
		"fmt": "none", "attStmt": map[string]any{}, "authData": authData,
	})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	body, _ := json.Marshal(map[string]any{
		"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64(clientData),
			"attestationObject": b64(attObj),
		},
	})
	return string(body)
}

// flags is UP | UV plus extra, without UV when the authenticator skips it.
func (a *softAuthenticator) flags(extra byte) byte {
	f := byte(0x05) | extra
	if a.noUV {
		f &^= 0x04
	}
	return f
}

// assert answers an assertion request (options JSON, bare or wrapped in
// "stepUp") as userID's passkey, returning the body the api expects.
func (a *softAuthenticator) assert(t *testing.T, optionsJSON []byte, userID []byte) string {
	t.Helper()
	var wrapped struct {
		StepUp    json.RawMessage `json:"stepUp"`
		PublicKey json.RawMessage `json:"publicKey"`
	}
	if err := json.Unmarshal(optionsJSON, &wrapped); err != nil {
		t.Fatalf("assertion options: %v", err)
	}
	if wrapped.StepUp != nil {
		optionsJSON = wrapped.StepUp
	}
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(optionsJSON, &opts); err != nil || opts.PublicKey.Challenge == "" {
		t.Fatalf("assertion options: %v %s", err, optionsJSON)
	}
	clientData, _ := json.Marshal(map[string]any{
		"type": "webauthn.get", "challenge": opts.PublicKey.Challenge, "origin": a.origin,
	})
	rpHash := sha256.Sum256([]byte(a.rpID))
	a.count++
	authData := append([]byte{}, rpHash[:]...)
	authData = append(authData, a.flags(0)) // UP | UV
	authData = binary.BigEndian.AppendUint32(authData, a.count)
	cdHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	body, _ := json.Marshal(map[string]any{
		"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    b64(clientData),
			"authenticatorData": b64(authData),
			"signature":         b64(sig),
			"userHandle":        b64(userID),
		},
	})
	return string(body)
}

// ceremony is one begun registration: the pending cookie and the finish body.
type ceremony struct {
	pending *http.Cookie
	body    string
	auth    *softAuthenticator
}

func registerBegin(t *testing.T, h http.Handler, name string, session *http.Cookie) (*httptest.ResponseRecorder, *ceremony) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/register/begin",
		strings.NewReader(`{"name":"`+name+`","displayName":"`+name+`"}`))
	if session != nil {
		r.AddCookie(session)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		return w, nil
	}
	a := newSoftAuthenticator(t)
	c := &ceremony{body: a.attest(t, w.Body.Bytes()), auth: a}
	for _, ck := range w.Result().Cookies() {
		if ck.Name == pendingCookie {
			c.pending = ck
		}
	}
	if c.pending == nil {
		t.Fatal("register/begin set no pending cookie")
	}
	return w, c
}

func registerFinish(h http.Handler, c *ceremony, session *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/auth/register/finish", strings.NewReader(c.body))
	r.AddCookie(c.pending)
	if session != nil {
		r.AddCookie(session)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func (f *authFixture) handler() http.Handler {
	mux := http.NewServeMux()
	f.svc.RegisterRoutes(mux)
	return mux
}

func (f *authFixture) countCredentials(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.store.db.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM credentials`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *authFixture) countUsers(t *testing.T) int {
	t.Helper()
	n, err := f.store.CountUsers(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// ============================================================================
// FirstRun
// ============================================================================

func TestFirstRun_TrueOnEmptyFalseOnceAUserExists(t *testing.T) {
	f := newAuthFixture(t)
	if first, err := f.svc.FirstRun(f.ctx); err != nil || !first {
		t.Fatalf("empty db: first=%v err=%v", first, err)
	}
	f.mintUser(t, "alice")
	if first, err := f.svc.FirstRun(f.ctx); err != nil || first {
		t.Fatalf("with a user: first=%v err=%v", first, err)
	}
}

// An unreadable users table is "not first run", never "first run".
func TestFirstRun_FailsClosedOnDBError(t *testing.T) {
	f := newAuthFixture(t)
	_ = f.store.Close()
	first, err := f.svc.FirstRun(f.ctx)
	if err == nil {
		t.Fatal("want an error from a closed store")
	}
	if first {
		t.Fatal("a DB error read as first run")
	}
}

// ============================================================================
// Registration: the recorded basis and the conditional insert
// ============================================================================

func TestRegister_FirstRunCeremonyCompletes(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	_, c := registerBegin(t, h, "alice", nil)
	if c == nil {
		t.Fatal("register/begin refused on a fresh box")
	}
	w := registerFinish(h, c, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("finish: %d %s", w.Code, w.Body.String())
	}
	if f.countUsers(t) != 1 || f.countCredentials(t) != 1 {
		t.Fatalf("users=%d credentials=%d, want 1/1", f.countUsers(t), f.countCredentials(t))
	}
}

// A ceremony begun during first run cannot finish once another registration
// has created the first operator.
func TestRegisterFinish_StaleFirstRunCeremonyRefused(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	_, first := registerBegin(t, h, "alice", nil)
	_, stale := registerBegin(t, h, "mallory", nil)
	if first == nil || stale == nil {
		t.Fatal("both ceremonies should begin during first run")
	}
	if w := registerFinish(h, first, nil); w.Code != http.StatusOK {
		t.Fatalf("first finish: %d %s", w.Code, w.Body.String())
	}
	w := registerFinish(h, stale, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("stale finish: want 403, got %d %s", w.Code, w.Body.String())
	}
	for _, ck := range w.Result().Cookies() {
		if ck.Name == sessionCookie && ck.Value != "" {
			t.Fatal("a refused registration set a session cookie")
		}
	}
	if u, _ := f.store.GetUserByName(f.ctx, "mallory"); u != nil {
		t.Fatal("the stale ceremony created a user")
	}
	if f.countUsers(t) != 1 || f.countCredentials(t) != 1 {
		t.Fatalf("users=%d credentials=%d, want 1/1", f.countUsers(t), f.countCredentials(t))
	}
}

// Many first-run ceremonies finishing at once create exactly one operator,
// and no refused one leaves a user or credential row behind.
func TestRegisterFinish_ConcurrentFirstRunRace(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	const n = 16
	cs := make([]*ceremony, n)
	for i := range cs {
		_, c := registerBegin(t, h, "user"+string(rune('a'+i)), nil)
		if c == nil {
			t.Fatalf("ceremony %d did not begin", i)
		}
		cs[i] = c
	}
	codes := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range cs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i] = registerFinish(h, cs[i], nil).Code
		}(i)
	}
	close(start)
	wg.Wait()
	ok, refused := 0, 0
	for i, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusForbidden:
			refused++
		default:
			t.Errorf("ceremony %d: unexpected status %d", i, c)
		}
	}
	if ok != 1 || refused != n-1 {
		t.Fatalf("ok=%d refused=%d, want 1/%d", ok, refused, n-1)
	}
	if f.countUsers(t) != 1 || f.countCredentials(t) != 1 {
		t.Fatalf("users=%d credentials=%d, want 1/1", f.countUsers(t), f.countCredentials(t))
	}
}

func TestRegisterBegin_SecondBeginWithoutSessionRefused(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	_, c := registerBegin(t, h, "alice", nil)
	if w := registerFinish(h, c, nil); w.Code != http.StatusOK {
		t.Fatalf("first registration: %d", w.Code)
	}
	w, c2 := registerBegin(t, h, "bob", nil)
	if c2 != nil || w.Code != http.StatusUnauthorized {
		t.Fatalf("second begin: want 401, got %d", w.Code)
	}
}

// ============================================================================
// DB errors fail closed at every auth caller
// ============================================================================

func TestFirstRunCallers_FailClosedOnDBError(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		f := newAuthFixture(t)
		_ = f.store.Close()
		w := httptest.NewRecorder()
		f.handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/auth/status", nil))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("want 500, got %d %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "hasUsers") {
			t.Fatalf("status reported hasUsers on a DB error: %s", w.Body.String())
		}
	})
	t.Run("register/begin", func(t *testing.T) {
		f := newAuthFixture(t)
		_ = f.store.Close()
		w, c := registerBegin(t, f.handler(), "alice", nil)
		if c != nil || w.Code != http.StatusInternalServerError {
			t.Fatalf("want 500 and no ceremony, got %d", w.Code)
		}
		if len(f.svc.pending) != 0 {
			t.Fatal("a ceremony was stored on a DB error")
		}
	})
	t.Run("register/finish", func(t *testing.T) {
		f := newAuthFixture(t)
		h := f.handler()
		_, c := registerBegin(t, h, "alice", nil)
		_ = f.store.Close()
		if w := registerFinish(h, c, nil); w.Code != http.StatusInternalServerError {
			t.Fatalf("want 500, got %d %s", w.Code, w.Body.String())
		}
	})
}

// ============================================================================
// Store: the conditional insert
// ============================================================================

func TestCreateFirstUser_RefusesWhenAUserExists(t *testing.T) {
	f := newAuthFixture(t)
	f.mintUser(t, "alice")
	u, err := makeUser("bob", "")
	if err != nil {
		t.Fatal(err)
	}
	cred := &Credential{ID: []byte("cred-bob"), UserID: u.ID, PublicKey: []byte{1}, CreatedAt: time.Now()}
	if err := f.store.CreateFirstUser(f.ctx, u, cred); !errors.Is(err, ErrNotFirstRun) {
		t.Fatalf("want ErrNotFirstRun, got %v", err)
	}
	if f.countUsers(t) != 1 || f.countCredentials(t) != 0 {
		t.Fatalf("users=%d credentials=%d, want 1/0", f.countUsers(t), f.countCredentials(t))
	}
}

// A credential that cannot be written rolls the user back with it.
func TestCreateFirstUser_RollsBackTheUserOnCredentialFailure(t *testing.T) {
	f := newAuthFixture(t)
	u, _ := makeUser("alice", "")
	// public_key is NOT NULL: the credential insert fails.
	err := f.store.CreateFirstUser(f.ctx, u, &Credential{ID: []byte("c"), UserID: u.ID, CreatedAt: time.Now()})
	if err == nil {
		t.Fatal("want a credential insert error")
	}
	if got, _ := f.store.GetUserByName(context.Background(), "alice"); got != nil {
		t.Fatal("the user outlived its failed credential")
	}
	if first, err := f.store.FirstRun(f.ctx); err != nil || !first {
		t.Fatalf("installation should still be at first run: first=%v err=%v", first, err)
	}
}

// ============================================================================
// Pending ceremony map cap
// ============================================================================

func TestStorePending_CapEvictsExpiredFirstThenOldest(t *testing.T) {
	f := newAuthFixture(t)
	expired, _ := f.svc.storePending(&pendingAuth{kind: "login"})
	f.svc.mu.Lock()
	f.svc.pending[expired].expires = time.Now().Add(-time.Second)
	f.svc.mu.Unlock()
	oldest, _ := f.svc.storePending(&pendingAuth{kind: "login"})
	// Live, but closest to expiry, whatever the clock's resolution.
	f.svc.mu.Lock()
	f.svc.pending[oldest].expires = time.Now().Add(time.Minute)
	f.svc.mu.Unlock()
	for len(f.svc.pending) < maxPending {
		if _, err := f.svc.storePending(&pendingAuth{kind: "login"}); err != nil {
			t.Fatal(err)
		}
	}
	// Full: the next store prunes the expired entry, not a live one.
	if _, err := f.svc.storePending(&pendingAuth{kind: "login"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.svc.pending[expired]; ok {
		t.Fatal("the expired entry survived a full map")
	}
	if _, ok := f.svc.pending[oldest]; !ok {
		t.Fatal("a live entry was evicted while an expired one could go")
	}
	// Full again with nothing expired: the entry closest to expiry goes.
	if _, err := f.svc.storePending(&pendingAuth{kind: "login"}); err != nil {
		t.Fatal(err)
	}
	if len(f.svc.pending) != maxPending {
		t.Fatalf("map size %d, want the cap %d", len(f.svc.pending), maxPending)
	}
	if _, ok := f.svc.pending[oldest]; ok {
		t.Fatal("the oldest entry survived eviction")
	}
}

// ============================================================================
// Signed-in registration: step-up with an existing passkey
// ============================================================================

// operator is a user registered through the real first-run ceremony: its
// passkey (the software authenticator) and a live session cookie.
type operator struct {
	user    *User
	auth    *softAuthenticator
	session *http.Cookie
}

func firstOperator(t *testing.T, f *authFixture, h http.Handler, name string) *operator {
	t.Helper()
	_, c := registerBegin(t, h, name, nil)
	if c == nil {
		t.Fatal("first-run begin refused")
	}
	w := registerFinish(h, c, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("first-run finish: %d %s", w.Code, w.Body.String())
	}
	op := &operator{auth: c.auth}
	for _, ck := range w.Result().Cookies() {
		if ck.Name == sessionCookie {
			op.session = ck
		}
	}
	op.user, _ = f.store.GetUserByName(f.ctx, name)
	if op.session == nil || op.user == nil {
		t.Fatal("first operator has no session or user row")
	}
	return op
}

// enrol gives u a passkey held by a new software authenticator, written
// straight to the store.
func (f *authFixture) enrol(t *testing.T, u *User) *softAuthenticator {
	t.Helper()
	a := newSoftAuthenticator(t)
	pub, err := a.key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	raw := pub.Bytes()
	cose, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: raw[1:33], -3: raw[33:65]})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateCredential(f.ctx, &Credential{
		ID: a.credID, UserID: u.ID, PublicKey: cose, AttestationType: "none", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	return a
}

func post(h http.Handler, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func pendingFrom(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, ck := range w.Result().Cookies() {
		if ck.Name == pendingCookie {
			return ck
		}
	}
	t.Fatalf("no pending cookie: %d %s", w.Code, w.Body.String())
	return nil
}

// signedInBegin starts a signed-in registration (empty name: add a passkey to
// the caller's own account) with no authenticator choice, and returns the
// pending cookie and step-up options.
func signedInBegin(t *testing.T, h http.Handler, session *http.Cookie, name string) (*http.Cookie, []byte) {
	t.Helper()
	return signedInBeginAs(t, h, session, name, authenticatorAny)
}

// signedInBeginAs is signedInBegin with the authenticator kind the operator
// picked in the UI on the body.
func signedInBeginAs(t *testing.T, h http.Handler, session *http.Cookie, name string, choice authenticatorChoice) (*http.Cookie, []byte) {
	t.Helper()
	body := `{"name":"` + name + `","authenticator":"` + string(choice) + `"}`
	w := post(h, "/api/auth/register/begin", body, session)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"stepUp"`) {
		t.Fatalf("signed-in begin: %d %s", w.Code, w.Body.String())
	}
	return pendingFrom(t, w), w.Body.Bytes()
}

func TestAddPasskey_StepUpThenCreateEndToEnd(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	alice := firstOperator(t, f, h, "alice")

	pending, stepUpOpts := signedInBegin(t, h, alice.session, "")
	w := post(h, "/api/auth/register/step-up", alice.auth.assert(t, stepUpOpts, alice.user.ID), pending, alice.session)
	if w.Code != http.StatusOK {
		t.Fatalf("step-up: %d %s", w.Code, w.Body.String())
	}
	// The creation options exclude the passkey alice already has.
	if !strings.Contains(w.Body.String(), base64.RawURLEncoding.EncodeToString(alice.auth.credID)) {
		t.Fatalf("creation options do not exclude the existing passkey: %s", w.Body.String())
	}
	second := newSoftAuthenticator(t)
	w = post(h, "/api/auth/register/finish", second.attest(t, w.Body.Bytes()), pending, alice.session)
	if w.Code != http.StatusOK {
		t.Fatalf("finish: %d %s", w.Code, w.Body.String())
	}
	for _, ck := range w.Result().Cookies() {
		if ck.Name == sessionCookie {
			t.Fatal("adding a passkey replaced the session")
		}
	}
	if f.countUsers(t) != 1 || f.countCredentials(t) != 2 {
		t.Fatalf("users=%d credentials=%d, want 1/2", f.countUsers(t), f.countCredentials(t))
	}
	u, _ := f.store.GetUserByID(f.ctx, alice.user.ID)
	if len(u.WebAuthnCredentials()) != 2 {
		t.Fatalf("alice has %d passkeys, want 2", len(u.WebAuthnCredentials()))
	}
}

// The authenticator the operator picked at register/begin has to survive the
// step-up, because that is where the creation options are minted — a signed-in
// ceremony issues them at the END of step 1, and step 2 only replays them.
// This is the whole point of #586: on a machine whose built-in authenticator
// already holds a passkey for the account, exclusion refuses it and the
// operator needs the ceremony pointed at their phone or their key instead.
func TestAddPasskey_ChoiceRidesTheCeremony(t *testing.T) {
	cases := []struct {
		name       string
		choice     authenticatorChoice
		attachment string
		hint       string
	}{
		{"no choice", authenticatorAny, "", ""},
		{"this device", authenticatorPlatform, "platform", "client-device"},
		{"phone or tablet", authenticatorHybrid, "cross-platform", "hybrid"},
		{"security key", authenticatorSecurityKey, "cross-platform", "security-key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuthFixture(t)
			h := f.handler()
			alice := firstOperator(t, f, h, "alice")

			pending, stepUpOpts := signedInBeginAs(t, h, alice.session, "", tc.choice)
			w := post(h, "/api/auth/register/step-up", alice.auth.assert(t, stepUpOpts, alice.user.ID), pending, alice.session)
			if w.Code != http.StatusOK {
				t.Fatalf("step-up: %d %s", w.Code, w.Body.String())
			}
			got := decodeCreationOptions(t, w.Body.Bytes())
			sel := got.PublicKey.AuthenticatorSelection
			if sel.AuthenticatorAttachment != tc.attachment {
				t.Errorf("authenticatorAttachment = %q, want %q", sel.AuthenticatorAttachment, tc.attachment)
			}
			if tc.hint == "" {
				if len(got.PublicKey.Hints) != 0 {
					t.Errorf("hints = %v, want none", got.PublicKey.Hints)
				}
			} else if len(got.PublicKey.Hints) != 1 || got.PublicKey.Hints[0] != tc.hint {
				t.Errorf("hints = %v, want [%q]", got.PublicKey.Hints, tc.hint)
			}
			// Narrowing the ceremony never widens anything else: the passkey
			// alice already has stays excluded, and both the discoverable and
			// the user-verification requirements survive.
			if !strings.Contains(w.Body.String(), base64.RawURLEncoding.EncodeToString(alice.auth.credID)) {
				t.Errorf("creation options do not exclude the existing passkey: %s", w.Body.String())
			}
			if sel.UserVerification != "required" || sel.ResidentKey != "required" {
				t.Errorf("userVerification = %q residentKey = %q, want both required", sel.UserVerification, sel.ResidentKey)
			}

			// And the passkey is still created: a narrowed ceremony finishes.
			second := newSoftAuthenticator(t)
			if w = post(h, "/api/auth/register/finish", second.attest(t, w.Body.Bytes()), pending, alice.session); w.Code != http.StatusOK {
				t.Fatalf("finish: %d %s", w.Code, w.Body.String())
			}
			if f.countCredentials(t) != 2 {
				t.Fatalf("credentials=%d, want 2", f.countCredentials(t))
			}
		})
	}
}

// A signed-in begin validates the choice the same way first-run does, before
// it starts a ceremony.
func TestAddPasskey_UnknownAuthenticatorRefused(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	alice := firstOperator(t, f, h, "alice")
	w := post(h, "/api/auth/register/begin", `{"name":"","authenticator":"usb"}`, alice.session)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d %s", w.Code, w.Body.String())
	}
	for _, ck := range w.Result().Cookies() {
		if ck.Name == pendingCookie {
			t.Fatal("a refused begin started a ceremony")
		}
	}
}

func TestAddPasskey_FinishWithoutStepUpRefused(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	alice := firstOperator(t, f, h, "alice")
	pending, stepUpOpts := signedInBegin(t, h, alice.session, "")
	// Skip step-up: answer the step-up challenge with an attestation.
	var wrapped struct {
		StepUp json.RawMessage `json:"stepUp"`
	}
	_ = json.Unmarshal(stepUpOpts, &wrapped)
	w := post(h, "/api/auth/register/finish", newSoftAuthenticator(t).attest(t, wrapped.StepUp), pending, alice.session)
	if w.Code != http.StatusForbidden {
		t.Fatalf("finish without step-up: want 403, got %d %s", w.Code, w.Body.String())
	}
	if f.countCredentials(t) != 1 {
		t.Fatalf("credentials=%d, want 1", f.countCredentials(t))
	}
}

func TestAddPasskey_StepUpByAnotherUsersPasskeyRefused(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	alice := firstOperator(t, f, h, "alice")

	// bob is another user with a passkey of his own.
	bob := f.mintUser(t, "bob")
	bobAuth := f.enrol(t, bob)
	var pending *http.Cookie
	var opts []byte
	var w *httptest.ResponseRecorder

	// alice's add-passkey ceremony answered by bob's passkey, under either
	// user handle.
	for _, handle := range [][]byte{bob.ID, alice.user.ID} {
		pending, opts = signedInBegin(t, h, alice.session, "")
		w = post(h, "/api/auth/register/step-up", bobAuth.assert(t, opts, handle), pending, alice.session)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("step-up by bob's passkey: want 401, got %d %s", w.Code, w.Body.String())
		}
		// The ceremony is gone: the right passkey cannot rescue it.
		if w = post(h, "/api/auth/register/step-up", alice.auth.assert(t, opts, alice.user.ID), pending, alice.session); w.Code != http.StatusBadRequest {
			t.Fatalf("retry after a failed step-up: want 400, got %d", w.Code)
		}
	}
	if u, _ := f.store.GetUserByID(f.ctx, alice.user.ID); len(u.WebAuthnCredentials()) != 1 {
		t.Fatal("alice gained a passkey")
	}
}

func TestAddPasskey_StepUpAssertionCannotBeReplayed(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	alice := firstOperator(t, f, h, "alice")

	p1, opts1 := signedInBegin(t, h, alice.session, "")
	a1 := alice.auth.assert(t, opts1, alice.user.ID)
	if w := post(h, "/api/auth/register/step-up", a1, p1, alice.session); w.Code != http.StatusOK {
		t.Fatalf("step-up 1: %d %s", w.Code, w.Body.String())
	}
	// The same ceremony's challenge is spent.
	if w := post(h, "/api/auth/register/step-up", a1, p1, alice.session); w.Code != http.StatusBadRequest {
		t.Fatalf("second step-up on the same ceremony: want 400, got %d", w.Code)
	}
	// Another ceremony has its own challenge; the old assertion does not answer it.
	p2, _ := signedInBegin(t, h, alice.session, "")
	if w := post(h, "/api/auth/register/step-up", a1, p2, alice.session); w.Code != http.StatusUnauthorized {
		t.Fatalf("replayed assertion on a second ceremony: want 401, got %d %s", w.Code, w.Body.String())
	}
	if w := post(h, "/api/auth/register/finish", `{}`, p2, alice.session); w.Code == http.StatusOK {
		t.Fatal("the second ceremony finished")
	}
}

func TestAddPasskey_SessionEndedAfterStepUpRefused(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	alice := firstOperator(t, f, h, "alice")
	pending, opts := signedInBegin(t, h, alice.session, "")
	w := post(h, "/api/auth/register/step-up", alice.auth.assert(t, opts, alice.user.ID), pending, alice.session)
	if w.Code != http.StatusOK {
		t.Fatalf("step-up: %d", w.Code)
	}
	if err := f.store.DeleteSession(f.ctx, alice.session.Value); err != nil {
		t.Fatal(err)
	}
	if w = post(h, "/api/auth/register/finish", newSoftAuthenticator(t).attest(t, w.Body.Bytes()), pending, alice.session); w.Code != http.StatusUnauthorized {
		t.Fatalf("finish after sign-out: want 401, got %d %s", w.Code, w.Body.String())
	}
	if f.countCredentials(t) != 1 {
		t.Fatalf("credentials=%d, want 1", f.countCredentials(t))
	}
}

func TestAddPasskey_StepUpUnderAnotherSessionRefused(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	alice := firstOperator(t, f, h, "alice")
	other := f.mintUser(t, "carol")
	carolSess := &http.Cookie{Name: sessionCookie, Value: freshSession(t, f, other).Token}
	pending, opts := signedInBegin(t, h, alice.session, "")
	if w := post(h, "/api/auth/register/step-up", alice.auth.assert(t, opts, alice.user.ID), pending, carolSess); w.Code != http.StatusUnauthorized {
		t.Fatalf("step-up under another user's session: want 401, got %d", w.Code)
	}
}

func TestRegisterBegin_SignedInWithoutAPasskeyRefused(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "alice")
	w := post(f.handler(), "/api/auth/register/begin", `{}`, &http.Cookie{Name: sessionCookie, Value: freshSession(t, f, u).Token})
	if w.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d %s", w.Code, w.Body.String())
	}
}

// Signed in, registration only adds a passkey to the caller's own account.
// Any other name is an attempt to create another user and is refused.
func TestRegisterBegin_SignedInCannotCreateAnotherUser(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	alice := firstOperator(t, f, h, "alice")
	for _, name := range []string{"bob", "Alice", "alice2"} {
		w := post(h, "/api/auth/register/begin", `{"name":"`+name+`","displayName":"X"}`, alice.session)
		if w.Code != http.StatusForbidden {
			t.Fatalf("name %q: want 403, got %d %s", name, w.Code, w.Body.String())
		}
		for _, ck := range w.Result().Cookies() {
			if ck.Name == pendingCookie {
				t.Fatalf("name %q: a refused begin started a ceremony", name)
			}
		}
	}
	// The caller's own name is the same as no name: a passkey for alice.
	pending, opts := signedInBegin(t, h, alice.session, "alice")
	w := post(h, "/api/auth/register/step-up", alice.auth.assert(t, opts, alice.user.ID), pending, alice.session)
	if w.Code != http.StatusOK {
		t.Fatalf("step-up: %d %s", w.Code, w.Body.String())
	}
	if w = post(h, "/api/auth/register/finish", newSoftAuthenticator(t).attest(t, w.Body.Bytes()), pending, alice.session); w.Code != http.StatusOK {
		t.Fatalf("finish: %d %s", w.Code, w.Body.String())
	}
	if f.countUsers(t) != 1 || f.countCredentials(t) != 2 {
		t.Fatalf("users=%d credentials=%d, want 1/2", f.countUsers(t), f.countCredentials(t))
	}
}

// ============================================================================
// User verification is required (decision #561)
// ============================================================================

func TestUserVerificationRequired(t *testing.T) {
	t.Run("options ask for it", func(t *testing.T) {
		f := newAuthFixture(t)
		w, _ := registerBegin(t, f.handler(), "alice", nil)
		if !strings.Contains(w.Body.String(), `"userVerification":"required"`) {
			t.Fatalf("creation options: %s", w.Body.String())
		}
		w = post(f.handler(), "/api/auth/login/begin", "")
		if !strings.Contains(w.Body.String(), `"userVerification":"required"`) {
			t.Fatalf("login options: %s", w.Body.String())
		}
	})
	t.Run("registration without UV refused", func(t *testing.T) {
		f := newAuthFixture(t)
		h := f.handler()
		w := post(h, "/api/auth/register/begin", `{"name":"alice"}`)
		a := newSoftAuthenticator(t)
		a.noUV = true
		w = post(h, "/api/auth/register/finish", a.attest(t, w.Body.Bytes()), pendingFrom(t, w))
		if w.Code != http.StatusBadRequest || f.countUsers(t) != 0 {
			t.Fatalf("want 400 and no user, got %d users=%d", w.Code, f.countUsers(t))
		}
	})
	t.Run("sign-in without UV refused", func(t *testing.T) {
		f := newAuthFixture(t)
		h := f.handler()
		alice := firstOperator(t, f, h, "alice")
		alice.auth.noUV = true
		w := post(h, "/api/auth/login/begin", "")
		w = post(h, "/api/auth/login/finish", alice.auth.assert(t, w.Body.Bytes(), alice.user.ID), pendingFrom(t, w))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d %s", w.Code, w.Body.String())
		}
		alice.auth.noUV = false
		w = post(h, "/api/auth/login/begin", "")
		if w = post(h, "/api/auth/login/finish", alice.auth.assert(t, w.Body.Bytes(), alice.user.ID), pendingFrom(t, w)); w.Code != http.StatusOK {
			t.Fatalf("sign-in with UV: %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("step-up without UV refused", func(t *testing.T) {
		f := newAuthFixture(t)
		h := f.handler()
		alice := firstOperator(t, f, h, "alice")
		alice.auth.noUV = true
		pending, opts := signedInBegin(t, h, alice.session, "")
		if w := post(h, "/api/auth/register/step-up", alice.auth.assert(t, opts, alice.user.ID), pending, alice.session); w.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d %s", w.Code, w.Body.String())
		}
	})
	// Picking an authenticator (#586) sets AuthenticatorSelection through a
	// library option that REPLACES the struct the relying-party config seeded
	// — including this requirement. Every choice, on both paths that mint
	// creation options, is asserted here rather than trusted to a reading of
	// the option's source.
	t.Run("every authenticator choice still asks for it", func(t *testing.T) {
		for _, choice := range []authenticatorChoice{
			authenticatorAny, authenticatorPlatform, authenticatorHybrid, authenticatorSecurityKey,
		} {
			f := newAuthFixture(t)
			h := f.handler()
			w := post(h, "/api/auth/register/begin", `{"name":"alice","authenticator":"`+string(choice)+`"}`)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"userVerification":"required"`) {
				t.Fatalf("first-run options for %q: %d %s", choice, w.Code, w.Body.String())
			}

			f = newAuthFixture(t)
			h = f.handler()
			alice := firstOperator(t, f, h, "alice")
			pending, opts := signedInBeginAs(t, h, alice.session, "", choice)
			w = post(h, "/api/auth/register/step-up", alice.auth.assert(t, opts, alice.user.ID), pending, alice.session)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"userVerification":"required"`) {
				t.Fatalf("add-passkey options for %q: %d %s", choice, w.Code, w.Body.String())
			}
		}
	})
	// The whole point of requiring it: an authenticator that skips user
	// verification is refused even on a narrowed ceremony.
	t.Run("registration without UV refused for every choice", func(t *testing.T) {
		for _, choice := range []authenticatorChoice{
			authenticatorPlatform, authenticatorHybrid, authenticatorSecurityKey,
		} {
			f := newAuthFixture(t)
			h := f.handler()
			w := post(h, "/api/auth/register/begin", `{"name":"alice","authenticator":"`+string(choice)+`"}`)
			a := newSoftAuthenticator(t)
			a.noUV = true
			w = post(h, "/api/auth/register/finish", a.attest(t, w.Body.Bytes()), pendingFrom(t, w))
			if w.Code != http.StatusBadRequest || f.countUsers(t) != 0 {
				t.Fatalf("choice %q: want 400 and no user, got %d users=%d", choice, w.Code, f.countUsers(t))
			}
		}
	})
}
