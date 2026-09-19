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
	authData = append(authData, 0x45)                // UP | UV | AT
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

// ceremony is one begun registration: the pending cookie and the finish body.
type ceremony struct {
	pending *http.Cookie
	body    string
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
	c := &ceremony{body: newSoftAuthenticator(t).attest(t, w.Body.Bytes())}
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

// A ceremony a signed-in user began commits while that session is live, and
// is refused once it is gone.
func TestRegisterFinish_SessionBasisNeedsTheSameLiveSession(t *testing.T) {
	f := newAuthFixture(t)
	h := f.handler()
	alice := f.mintUser(t, "alice")
	sess := freshSession(t, f, alice)
	cookie := &http.Cookie{Name: sessionCookie, Value: sess.Token}

	_, bob := registerBegin(t, h, "bob", cookie)
	if bob == nil {
		t.Fatal("a signed-in user could not begin a registration")
	}
	if w := registerFinish(h, bob, cookie); w.Code != http.StatusOK {
		t.Fatalf("finish with the session: %d %s", w.Code, w.Body.String())
	}

	_, carol := registerBegin(t, h, "carol", cookie)
	if carol == nil {
		t.Fatal("second begin refused")
	}
	if err := f.store.DeleteSession(f.ctx, sess.Token); err != nil {
		t.Fatal(err)
	}
	if w := registerFinish(h, carol, cookie); w.Code != http.StatusUnauthorized {
		t.Fatalf("finish after sign-out: want 401, got %d %s", w.Code, w.Body.String())
	}
	if u, _ := f.store.GetUserByName(f.ctx, "carol"); u != nil {
		t.Fatal("a ceremony whose session ended created a user")
	}

	// Another user's session is not the session that began the ceremony.
	_, dave := registerBegin(t, h, "dave", &http.Cookie{Name: sessionCookie, Value: freshSession(t, f, alice).Token})
	if dave == nil {
		t.Fatal("begin refused")
	}
	bobUser, _ := f.store.GetUserByName(f.ctx, "bob")
	bobSess := freshSession(t, f, bobUser)
	if w := registerFinish(h, dave, &http.Cookie{Name: sessionCookie, Value: bobSess.Token}); w.Code != http.StatusUnauthorized {
		t.Fatalf("finish under another user's session: want 401, got %d", w.Code)
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

func TestCreateUserWithCredential_FirstRunOnlyRefusesWhenAUserExists(t *testing.T) {
	f := newAuthFixture(t)
	f.mintUser(t, "alice")
	u, err := makeUser("bob", "")
	if err != nil {
		t.Fatal(err)
	}
	cred := &Credential{ID: []byte("cred-bob"), UserID: u.ID, PublicKey: []byte{1}, CreatedAt: time.Now()}
	err = f.store.CreateUserWithCredential(f.ctx, u, cred, true)
	if !errors.Is(err, ErrNotFirstRun) {
		t.Fatalf("want ErrNotFirstRun, got %v", err)
	}
	if f.countUsers(t) != 1 || f.countCredentials(t) != 0 {
		t.Fatalf("users=%d credentials=%d, want 1/0", f.countUsers(t), f.countCredentials(t))
	}
	// Without the first-run restriction (a session-authorized registration)
	// the same insert commits both rows.
	if err := f.store.CreateUserWithCredential(f.ctx, u, cred, false); err != nil {
		t.Fatal(err)
	}
	if f.countUsers(t) != 2 || f.countCredentials(t) != 1 {
		t.Fatalf("users=%d credentials=%d, want 2/1", f.countUsers(t), f.countCredentials(t))
	}
}

// A credential that cannot be written rolls the user back with it.
func TestCreateUserWithCredential_RollsBackTheUserOnCredentialFailure(t *testing.T) {
	f := newAuthFixture(t)
	alice := f.mintUser(t, "alice")
	dup := &Credential{ID: []byte("dup"), UserID: alice.ID, PublicKey: []byte{1}, CreatedAt: time.Now()}
	if err := f.store.CreateCredential(f.ctx, dup); err != nil {
		t.Fatal(err)
	}
	u, _ := makeUser("bob", "")
	err := f.store.CreateUserWithCredential(f.ctx, u, &Credential{ID: []byte("dup"), UserID: u.ID, PublicKey: []byte{1}, CreatedAt: time.Now()}, false)
	if err == nil {
		t.Fatal("want a duplicate-credential error")
	}
	if got, _ := f.store.GetUserByName(context.Background(), "bob"); got != nil {
		t.Fatal("the user outlived its failed credential")
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
