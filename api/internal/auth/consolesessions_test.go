package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-989-17 (issue TC-03, unit part): after a sign-in through the store the
// database file holds no JWT, no cookie value and no token bytes; a row
// resolves before 7 days and is refused and deleted at created_at + 7d;
// EndBySID and EndBySub remove exactly their rows.
func TestConsoleSessions_HashOnlyExpiryAndEnds(t *testing.T) {
	r := newSigninRig(t)
	b := r.begin(t)
	tok := r.is.sign(t, r.idClaims(b))
	r.ex.set(tok, nil)
	w := r.callback(r.callbackQuery(b, "code-scan-1"), b.pending)
	c := sessionFrom(w)
	if c == nil {
		t.Fatal("no session")
	}
	if _, err := r.f.store.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, suffix := range []string{"", "-wal", "-shm"} {
		files = append(files, filepath.Join(r.f.dir, "auth.db"+suffix))
	}
	scanned := 0
	for _, p := range files {
		raw, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for _, needle := range []string{"eyJ", c.Value, tok, "code-scan-1"} {
			if bytes.Contains(raw, []byte(needle)) {
				t.Errorf("%s holds %q", filepath.Base(p), needle[:min(len(needle), 12)])
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no database file was scanned")
	}

	f := newAuthFixture(t)
	a := consoleCookie(t, f, Principal{Sub: "a", Session: SessionRef{SID: "s1"}})
	a2 := consoleCookie(t, f, Principal{Sub: "a", Session: SessionRef{SID: "s2"}})
	bb := consoleCookie(t, f, Principal{Sub: "b", Session: SessionRef{SID: "s1"}})
	cc := consoleCookie(t, f, Principal{Sub: "c", Session: SessionRef{SID: "s3"}})
	resolves := func(ck *http.Cookie) bool {
		v := secretOf(ck)
		defer v.Destroy()
		_, ok, err := f.sessions.Resolve(f.ctx, v)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if n, err := f.sessions.EndBySID(f.ctx, "s1"); err != nil || n != 2 {
		t.Fatalf("EndBySID = %d, %v; want 2", n, err)
	}
	if resolves(a) || resolves(bb) || !resolves(a2) || !resolves(cc) {
		t.Error("EndBySID ended the wrong rows")
	}
	if n, err := f.sessions.EndBySub(f.ctx, "a"); err != nil || n != 1 {
		t.Fatalf("EndBySub = %d, %v; want 1", n, err)
	}
	if resolves(a2) || !resolves(cc) {
		t.Error("EndBySub ended the wrong rows")
	}
	f.clock.Add(sessionLifetime - time.Nanosecond)
	if !resolves(cc) {
		t.Fatal("a session died before 7 days")
	}
	f.clock.Add(time.Nanosecond)
	if resolves(cc) {
		t.Fatal("a session resolved at created_at + 7d")
	}
	if n := f.countRows(t, "console_sessions"); n != 0 {
		t.Errorf("%d rows left; the expired row was not deleted", n)
	}
	if _, err := f.sessions.EndBySub(f.ctx, ""); err == nil {
		t.Error("EndBySub accepted an empty subject")
	}
	if _, err := NewConsoleSessions(nil, time.Now, rand.Reader, f.des); err == nil {
		t.Error("NewConsoleSessions accepted a nil store")
	}
	// TC-990-28: a nil designator is refused (F-990-01).
	if _, err := NewConsoleSessions(f.store, time.Now, rand.Reader, nil); err == nil {
		t.Error("NewConsoleSessions accepted a nil designator")
	}
}

// F-989-17 (verifier r1): one janitor sweep, with one session at
// sessionLifetime and one younger, deletes the expired row and keeps the
// live one. Read straight from the table: Resolve deletes an expired row on
// its own, so it would hide a sweep that deleted nothing, and it would not
// show a sweep that deleted every row until the live one was presented.
func TestConsoleSessions_SweepKeepsLiveRows(t *testing.T) {
	f := newAuthFixture(t)
	consoleCookie(t, f, Principal{Sub: "expired"})
	f.clock.Add(2 * 24 * time.Hour)
	consoleCookie(t, f, Principal{Sub: "live"})
	f.clock.Add(sessionLifetime - 2*24*time.Hour)

	f.svc.sweep(f.ctx, f.clock.Now())

	subs := map[string]bool{}
	rows, err := f.store.db.QueryContext(f.ctx, `SELECT sub FROM console_sessions`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var sub string
		if err := rows.Scan(&sub); err != nil {
			t.Fatal(err)
		}
		subs[sub] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !subs["live"] {
		t.Error("the sweep deleted a session younger than sessionLifetime")
	}
	if subs["expired"] {
		t.Error("the sweep kept a session at sessionLifetime")
	}
	if len(subs) != 1 {
		t.Errorf("rows after the sweep = %v, want only the live one", subs)
	}
}

// TC-989-18: a database from the previous release opens with
// console_sessions added and its users and legacy sessions untouched; the
// legacy cookie gets 401; a console session puts the Principal in the
// handler's context; the control lock still answers 423; the janitor still
// deletes expired legacy rows.
func TestUpgradeFromPreviousRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.db")
	prev, err := dbutil.Open(context.Background(), path, schema, "auth-prev")
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateSessionHash(context.Background(), prev); err != nil {
		t.Fatal(err)
	}
	old := &Store{db: prev}
	u := &User{ID: []byte("0123456789abcdef"), Name: "bryce", DisplayName: "B", CreatedAt: time.Now().UTC()}
	if err := old.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for tok, exp := range map[string]time.Time{"legacy-live": now.Add(time.Hour), "legacy-expired": now.Add(-time.Hour)} {
		if err := old.CreateSession(context.Background(), &Session{Token: tok, UserID: u.ID, CreatedAt: now, ExpiresAt: exp, LastActiveAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if err := prev.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := OpenStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	f := &authFixture{ctx: context.Background(), store: store, clock: newTestClock()}
	f.des = newTxDesignator(t, store)
	if f.sessions, err = NewConsoleSessions(store, f.clock.Now, rand.Reader, f.des); err != nil {
		t.Fatal(err)
	}
	if f.svc, err = NewService(store, Config{RPID: "localhost", RPOrigins: []string{"http://localhost:3000"}, Sessions: f.sessions}); err != nil {
		t.Fatal(err)
	}
	if f.countRows(t, "console_sessions") != 0 || f.countRows(t, "users") != 1 || f.countRows(t, "sessions") != 2 {
		t.Fatalf("after the upgrade: console %d users %d sessions %d", f.countRows(t, "console_sessions"), f.countRows(t, "users"), f.countRows(t, "sessions"))
	}

	var got []Principal
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r.Context())
		got = append(got, p)
		w.WriteHeader(http.StatusOK)
	})
	mux := http.NewServeMux()
	mux.Handle("GET /api/nodes", f.svc.RequireSession(ok))
	mux.Handle("POST /api/nodes/{id}/reboot", f.svc.RequireSession(ok))
	if w := serve(mux, rigConsole, "/api/nodes", &http.Cookie{Name: "rasputin-session", Value: "legacy-live"}); w.Code != http.StatusUnauthorized {
		t.Errorf("the legacy cookie: %d, want 401", w.Code)
	}
	want := Principal{Sub: "sub-b", Name: "bryce", Roles: []string{"admin", "viewer"}, Session: SessionRef{SID: "sid-b"}}
	ck := consoleCookie(t, f, want)
	if w := serve(mux, rigConsole, "/api/nodes", ck); w.Code != http.StatusOK || len(got) != 1 {
		t.Fatalf("a console session: %d", w.Code)
	}
	p := got[0]
	if p.Sub != want.Sub || p.Name != want.Name || !slices.Equal(p.Roles, want.Roles) || p.Session.SID != "sid-b" ||
		!p.Session.CreatedAt.Equal(f.clock.Now().Truncate(time.Millisecond)) {
		t.Errorf("Principal = %+v", p)
	}
	log, _ := logkittest.New()
	f.svc.SetControlGate(func(context.Context) error { return errors.New("differs") }, log)
	r := httptestRequest(rigConsole, "/api/nodes/n1/reboot")
	r.Method = http.MethodPost
	r.AddCookie(ck)
	w := recorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusLocked {
		t.Errorf("a control route under the lock: %d, want 423", w.Code)
	}
	f.svc.sweep(context.Background(), time.Now())
	if n := f.countRows(t, "sessions"); n != 1 {
		t.Errorf("legacy rows after a sweep: %d, want the live one only", n)
	}
}
