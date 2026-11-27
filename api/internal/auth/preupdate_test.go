package auth_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/move"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The pre-update session (geekdojo/geekdojo-brain#1005; register row E3)
// over a real rasputin.db: the auth store's old tables, the move's record
// and the real Designations, read through move.Accounts, as main wires
// them. TC-1005-17 to -22.

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// noFirst is the bridge's first-password service, unused here.
type noFirst struct{}

func (noFirst) HasPassword(context.Context, string) (bool, error) { return false, nil }
func (noFirst) Check(context.Context, string, secret.Value, secret.Value) error {
	return nil
}
func (noFirst) Set(context.Context, authz.Submitter, string, secret.Value, secret.Value) error {
	return nil
}

// noPersons and noRemoved are the move state's realm reads, which Pending
// does not make.
type noPersons struct{}

func (noPersons) People(context.Context) ([]accounts.Account, error) { return nil, nil }
func (noPersons) Read(context.Context, string) (accounts.Person, error) {
	return accounts.Person{}, nil
}

type noRemoved struct{}

func (noRemoved) Removed(context.Context, string, string) (bool, error) { return false, nil }

type preRig struct {
	clock    *clock
	store    *auth.Store
	moves    *move.Store
	des      *accounts.Designations
	sessions *auth.ConsoleSessions
	svc      *auth.Service
	h        http.Handler
	handle   []byte
	sub      string
}

const oldToken = "old-session-token"

// newPreRig is one pre-update operator "b", moved to "b-1", with an old
// session begun an hour ago that expires in a day. The account holds no
// designation until a test gives it one.
func newPreRig(t *testing.T) *preRig {
	t.Helper()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "rasputin.db")
	r := &preRig{clock: &clock{t: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)}}
	var err error
	if r.store, err = auth.OpenStore(ctx, path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.store.Close() })
	if r.moves, err = move.OpenStore(ctx, path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.moves.Close() })
	if r.des, err = accounts.OpenDesignations(ctx, path, r.clock.Now); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.des.Close() })
	if r.sessions, err = auth.NewConsoleSessions(r.store, r.clock.Now, rand.Reader, r.des); err != nil {
		t.Fatal(err)
	}
	if r.svc, err = auth.NewService(r.store, auth.Config{RPID: "ci.local", RPOrigins: []string{"https://ci.local"}, Sessions: r.sessions}); err != nil {
		t.Fatal(err)
	}
	r.handle = []byte("0123456789abcdef")
	r.sub = auth.MovedAccountID(r.handle)
	begun := r.clock.Now().Add(-time.Hour)
	if err := r.store.CreateUser(ctx, &auth.User{ID: r.handle, Name: "b", DisplayName: "B", CreatedAt: begun}); err != nil {
		t.Fatal(err)
	}
	r.oldSession(t, oldToken, begun, begun.Add(24*time.Hour))
	if err := r.moves.Record(ctx, []move.Row{{Handle: r.handle, AccountID: r.sub, OldName: "b", NewName: "b-1", MovedAt: r.clock.Now()}}); err != nil {
		t.Fatal(err)
	}
	state, err := move.NewState(r.store, r.moves, noPersons{}, noRemoved{})
	if err != nil {
		t.Fatal(err)
	}
	ma, err := move.NewAccounts(r.moves, state, r.store, r.des)
	if err != nil {
		t.Fatal(err)
	}
	log, _ := logkittest.New()
	if err := r.svc.InstallBridge(auth.BridgeDeps{Accounts: ma, FirstPassword: noFirst{}, SignInOrigin: "https://sso-ci.local",
		NewCorrelationID: func() string { return "id" }, Now: r.clock.Now, Rand: rand.Reader, Log: log}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	r.svc.RegisterRoutes(mux)
	// An admin-gated route: it answers 403 to a principal without IAM.
	mux.Handle("GET /admin-only", r.svc.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		p, _ := auth.PrincipalFrom(req.Context())
		if !p.Capabilities().Has(authz.IAM) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	})))
	r.h = mux
	return r
}

func (r *preRig) oldSession(t *testing.T, token string, created, expires time.Time) {
	t.Helper()
	if err := r.store.CreateSession(t.Context(), &auth.Session{Token: token, UserID: r.handle, CreatedAt: created,
		ExpiresAt: expires, LastActiveAt: created}); err != nil {
		t.Fatal(err)
	}
}

func old(token string) *http.Cookie { return &http.Cookie{Name: "rasputin-session", Value: token} }

func (r *preRig) do(method, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://ci.local"+path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}

type meBody struct {
	Sub       string   `json:"sub"`
	Name      string   `json:"name"`
	Roles     []string `json:"roles"`
	PreUpdate *struct {
		NeedsPassword bool `json:"needsPassword"`
	} `json:"preUpdate"`
}

func (r *preRig) me(t *testing.T, cookies ...*http.Cookie) (int, meBody) {
	t.Helper()
	w := r.do(http.MethodGet, "/api/auth/me", cookies...)
	var m meBody
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code, m
}

// console mints a console session for sub and returns its cookie.
func (r *preRig) console(t *testing.T, sub string) *http.Cookie {
	t.Helper()
	v, err := r.sessions.Create(t.Context(), auth.Principal{Sub: sub, Name: "new", Roles: []string{"viewer"}, Session: auth.SessionRef{SID: "sid-" + sub}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Destroy)
	return &http.Cookie{Name: auth.SessionCookieName, Value: string(v.Reveal())}
}

// TC-1005-17 (issue TC-05, unit): the moved administrator's old session
// is an administrator session that needs a password, and is never touched.
func TestPreUpdate_TC1005_17_AdminSession(t *testing.T) {
	r := newPreRig(t)
	if err := r.des.DesignateMoved(t.Context(), r.sub); err != nil {
		t.Fatal(err)
	}
	code, m := r.me(t, old(oldToken))
	if code != http.StatusOK || m.Sub != r.sub || m.Name != "b-1" || !slices.Equal(m.Roles, []string{"admin"}) || m.PreUpdate == nil || !m.PreUpdate.NeedsPassword {
		t.Errorf("me: %d %+v", code, m)
	}
	if w := r.do(http.MethodGet, "/admin-only", old(oldToken)); w.Code != http.StatusOK {
		t.Errorf("an admin-gated route: %d", w.Code)
	}
	s, err := r.store.GetSession(t.Context(), oldToken)
	if err != nil || s == nil || !s.LastActiveAt.Equal(r.clock.Now().Add(-time.Hour)) {
		t.Errorf("last_active_at changed: %+v %v", s, err)
	}
	if err := r.moves.RecordPasswordSet(t.Context(), r.sub); err != nil {
		t.Fatal(err)
	}
	if _, m := r.me(t, old(oldToken)); m.PreUpdate == nil || m.PreUpdate.NeedsPassword {
		t.Errorf("needsPassword once the password is set: %+v", m.PreUpdate)
	}
}

// TC-1005-18 (issue TC-06, unit): a waiting account's old session carries
// no console role and needs a password; with no designation (the walk
// finished) the old cookie answers 401 (F-1005-06).
func TestPreUpdate_TC1005_18_Waiting(t *testing.T) {
	r := newPreRig(t)
	if err := r.des.DesignateMoved(t.Context(), r.sub); err != nil {
		t.Fatal(err)
	}
	if err := r.des.Wait(t.Context(), r.sub); err != nil {
		t.Fatal(err)
	}
	code, m := r.me(t, old(oldToken))
	if code != http.StatusOK || m.Roles == nil || len(m.Roles) != 0 || m.PreUpdate == nil || !m.PreUpdate.NeedsPassword {
		t.Errorf("waiting: %d %+v", code, m)
	}
	if w := r.do(http.MethodGet, "/admin-only", old(oldToken)); w.Code != http.StatusForbidden {
		t.Errorf("an admin-gated route: %d", w.Code)
	}
	if err := r.des.Clear(t.Context(), r.sub); err != nil {
		t.Fatal(err)
	}
	if code, _ := r.me(t, old(oldToken)); code != http.StatusUnauthorized {
		t.Errorf("no designation: %d", code)
	}
}

// TC-1005-19: no move row, a passed expires_at, a passed created_at plus
// seven days, each answer 401; a read error answers 500.
func TestPreUpdate_TC1005_19_WhichRowsCount(t *testing.T) {
	r := newPreRig(t)
	if err := r.des.DesignateMoved(t.Context(), r.sub); err != nil {
		t.Fatal(err)
	}
	// created_at + 7 days passes before expires_at.
	r.oldSession(t, "long", r.clock.Now().Add(-auth.SessionLifetime+time.Minute), r.clock.Now().Add(30*24*time.Hour))
	if code, _ := r.me(t, old("long")); code != http.StatusOK {
		t.Fatalf("a session within its seven days: %d", code)
	}
	r.clock.add(time.Minute)
	if code, _ := r.me(t, old("long")); code != http.StatusUnauthorized {
		t.Errorf("at created_at + 7 days: %d", code)
	}
	r.oldSession(t, "short", r.clock.Now().Add(-time.Minute), r.clock.Now().Add(time.Minute))
	r.clock.add(time.Minute)
	if code, _ := r.me(t, old("short")); code != http.StatusUnauthorized {
		t.Errorf("at expires_at: %d", code)
	}
	if code, _ := r.me(t, old("no-such-token")); code != http.StatusUnauthorized {
		t.Errorf("an unknown token: %d", code)
	}

	pre := newPreRig(t)
	other := []byte("fedcba9876543210")
	if err := pre.store.CreateUser(t.Context(), &auth.User{ID: other, Name: "pre", DisplayName: "P", CreatedAt: pre.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := pre.store.CreateSession(t.Context(), &auth.Session{Token: "pre-move", UserID: other, CreatedAt: pre.clock.Now(),
		ExpiresAt: pre.clock.Now().Add(time.Hour), LastActiveAt: pre.clock.Now()}); err != nil {
		t.Fatal(err)
	}
	if code, _ := pre.me(t, old("pre-move")); code != http.StatusUnauthorized {
		t.Errorf("no move row: %d", code)
	}
	if err := pre.des.Close(); err != nil {
		t.Fatal(err)
	}
	if code, _ := pre.me(t, old(oldToken)); code != http.StatusInternalServerError {
		t.Errorf("a read error: %d", code)
	}
	if w := pre.do(http.MethodGet, "/admin-only", old(oldToken)); w.Code != http.StatusInternalServerError {
		t.Errorf("a read error behind RequireSession: %d", w.Code)
	}
}

// TC-1005-20: the console cookie wins over the old one; an invalid console
// cookie never falls back; two old cookies answer 400.
func TestPreUpdate_TC1005_20_Precedence(t *testing.T) {
	r := newPreRig(t)
	if err := r.des.DesignateMoved(t.Context(), r.sub); err != nil {
		t.Fatal(err)
	}
	c := r.console(t, "sub-new")
	if code, m := r.me(t, c, old(oldToken)); code != http.StatusOK || m.Sub != "sub-new" || m.PreUpdate != nil {
		t.Errorf("both valid: %d %+v", code, m)
	}
	bad := &http.Cookie{Name: auth.SessionCookieName, Value: "not-a-session"}
	if code, _ := r.me(t, bad, old(oldToken)); code != http.StatusUnauthorized {
		t.Errorf("an invalid console cookie with a valid old one: %d", code)
	}
	if code, _ := r.me(t, old(oldToken), old("again")); code != http.StatusBadRequest {
		t.Errorf("two old cookies: %d", code)
	}
	if w := r.do(http.MethodGet, "/admin-only", old(oldToken), old("again")); w.Code != http.StatusBadRequest {
		t.Errorf("two old cookies behind RequireSession: %d", w.Code)
	}
}

// cleared reports whether w cleared the cookie named name.
func cleared(w *httptest.ResponseRecorder, name string) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

// TC-1005-21 (F-1005-05): sign-out ends and clears the old session, and
// both when both are present; a following /me answers 401. (The callback's
// clearing is TestCallback_TC1005_21_ClearsPreUpdateCookie.)
func TestPreUpdate_TC1005_21_SignOut(t *testing.T) {
	r := newPreRig(t)
	if err := r.des.DesignateMoved(t.Context(), r.sub); err != nil {
		t.Fatal(err)
	}
	w := r.do(http.MethodPost, "/api/auth/logout", old(oldToken))
	if w.Code != http.StatusOK || !cleared(w, "rasputin-session") {
		t.Errorf("logout with the old cookie: %d, cleared %v", w.Code, cleared(w, "rasputin-session"))
	}
	if s, err := r.store.GetSession(t.Context(), oldToken); s != nil || err != nil {
		t.Errorf("the old session row survived: %+v %v", s, err)
	}
	if code, _ := r.me(t, old(oldToken)); code != http.StatusUnauthorized {
		t.Errorf("me after logout: %d", code)
	}

	r.oldSession(t, "second", r.clock.Now(), r.clock.Now().Add(time.Hour))
	c := r.console(t, "sub-new")
	w = r.do(http.MethodPost, "/api/auth/logout", c, old("second"))
	if w.Code != http.StatusOK || !cleared(w, "rasputin-session") || !cleared(w, auth.SessionCookieName) {
		t.Errorf("logout with both: %d", w.Code)
	}
	if code, _ := r.me(t, c); code != http.StatusUnauthorized {
		t.Errorf("the console session survived: %d", code)
	}
	if code, _ := r.me(t, old("second")); code != http.StatusUnauthorized {
		t.Errorf("the old session survived: %d", code)
	}
}

// TC-1005-22: C15's deletion of a moved person's old rows ends the old
// session.
func TestPreUpdate_TC1005_22_RemovalEndsIt(t *testing.T) {
	r := newPreRig(t)
	if err := r.des.DesignateMoved(t.Context(), r.sub); err != nil {
		t.Fatal(err)
	}
	if code, _ := r.me(t, old(oldToken)); code != http.StatusOK {
		t.Fatalf("before: %d", code)
	}
	if _, _, err := r.store.RemoveMovedRows(t.Context(), r.sub); err != nil {
		t.Fatal(err)
	}
	if code, _ := r.me(t, old(oldToken)); code != http.StatusUnauthorized {
		t.Errorf("after the removal: %d", code)
	}
}
