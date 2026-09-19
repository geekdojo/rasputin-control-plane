package auth

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
)

// preHashSchema is the users + sessions DDL exactly as the api shipped it
// before sessions.token_hash existed. It stands in for the previous api in the
// other RAUC slot, and for a DB restored from an older identity archive.
const preHashSchema = `
CREATE TABLE IF NOT EXISTS users (
    id            BLOB PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
    token          TEXT PRIMARY KEY,
    user_id        BLOB NOT NULL,
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    last_active_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
`

// oldAPI drives a DB with the previous api's exact session SQL: plaintext
// token only, no knowledge of token_hash.
type oldAPI struct{ db *sql.DB }

func openOldAPI(t *testing.T, path string) *oldAPI {
	t.Helper()
	db, err := dbutil.Open(context.Background(), path, preHashSchema, "auth-old")
	if err != nil {
		t.Fatalf("open as old api: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &oldAPI{db: db}
}

func (o *oldAPI) createUser(t *testing.T, id []byte, name string) {
	t.Helper()
	if _, err := o.db.Exec(`INSERT INTO users (id, name, display_name, created_at) VALUES (?, ?, ?, ?)`,
		id, name, name, ms(time.Now())); err != nil {
		t.Fatalf("old api create user: %v", err)
	}
}

func (o *oldAPI) createSession(t *testing.T, token string, userID []byte) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := o.db.Exec(`
        INSERT INTO sessions (token, user_id, created_at, expires_at, last_active_at)
        VALUES (?, ?, ?, ?, ?)`,
		token, userID, ms(now), ms(now.Add(time.Hour)), ms(now)); err != nil {
		t.Fatalf("old api create session: %v", err)
	}
}

// getSession is the previous api's GetSession query, verbatim.
func (o *oldAPI) getSession(t *testing.T, token string) (userID []byte, found bool) {
	t.Helper()
	var (
		tok                   string
		created, exp, lastAct int64
	)
	err := o.db.QueryRow(`
        SELECT token, user_id, created_at, expires_at, last_active_at
        FROM sessions WHERE token = ?`, token).Scan(&tok, &userID, &created, &exp, &lastAct)
	if err == sql.ErrNoRows {
		return nil, false
	}
	if err != nil {
		t.Fatalf("old api get session: %v", err)
	}
	return userID, true
}

func (o *oldAPI) close(t *testing.T) {
	t.Helper()
	if err := o.db.Close(); err != nil {
		t.Fatalf("close old api db: %v", err)
	}
}

func openNewStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := OpenStore(context.Background(), path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// sessionRow is the raw at-rest state of one session row.
type sessionRow struct {
	token string
	hash  sql.NullString
}

func readSessionRows(t *testing.T, db *sql.DB) map[string]sessionRow {
	t.Helper()
	rows, err := db.Query(`SELECT token, token_hash FROM sessions`)
	if err != nil {
		t.Fatalf("read sessions: %v", err)
	}
	defer rows.Close()
	out := map[string]sessionRow{}
	for rows.Next() {
		var r sessionRow
		if err := rows.Scan(&r.token, &r.hash); err != nil {
			t.Fatalf("scan session: %v", err)
		}
		out[r.token] = r
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate sessions: %v", err)
	}
	return out
}

func TestSessionHash_MigratesPreHashDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rasputin.db")
	uid := []byte("0123456789abcdef")

	old := openOldAPI(t, path)
	old.createUser(t, uid, "bryce")
	old.createSession(t, "tok-old-1", uid)
	old.createSession(t, "tok-old-2", uid)
	old.close(t)

	s := openNewStore(t, path)
	rows := readSessionRows(t, s.db)
	if len(rows) != 2 {
		t.Fatalf("migration changed the row count: got %d rows, want 2", len(rows))
	}
	for tok, r := range rows {
		if !r.hash.Valid || r.hash.String != busauth.HashToken(tok) {
			t.Errorf("row %q: token_hash = %+v, want %s", tok, r.hash, busauth.HashToken(tok))
		}
	}
	got, err := s.GetSession(context.Background(), "tok-old-1")
	if err != nil || got == nil {
		t.Fatalf("GetSession after migration: sess=%v err=%v", got, err)
	}
	if string(got.UserID) != string(uid) || got.Token != "tok-old-1" {
		t.Errorf("GetSession = %+v", got)
	}
}

func TestSessionHash_BackfillIsIdempotentAndRunsOnEveryOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rasputin.db")
	ctx := context.Background()

	s1, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatalf("OpenStore 1: %v", err)
	}
	u, _ := makeUser("bryce", "Bryce")
	if err := s1.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	now := time.Now().UTC()
	if err := s1.CreateSession(ctx, &Session{Token: "tok-new", UserID: u.ID,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastActiveAt: now}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	before := readSessionRows(t, s1.db)
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// A second open with nothing to do changes nothing.
	s2, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatalf("OpenStore 2: %v", err)
	}
	after := readSessionRows(t, s2.db)
	if len(after) != len(before) || after["tok-new"] != before["tok-new"] {
		t.Fatalf("second open changed rows: before=%+v after=%+v", before, after)
	}
	if err := s2.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The previous api (a rollback) or an older archive's restore brings a
	// plaintext-only row back; the NEXT open backfills it.
	old := openOldAPI(t, path)
	old.createSession(t, "tok-plain", u.ID)
	old.close(t)

	s3 := openNewStore(t, path)
	rows := readSessionRows(t, s3.db)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if r := rows["tok-plain"]; !r.hash.Valid || r.hash.String != busauth.HashToken("tok-plain") {
		t.Errorf("plaintext-only row not backfilled: %+v", r)
	}
	if rows["tok-new"] != before["tok-new"] {
		t.Errorf("existing hashed row changed: %+v", rows["tok-new"])
	}
}

func TestSessionHash_BackfillSkipsAHashAnotherRowCarries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rasputin.db")
	s := openNewStore(t, path)
	f := &authFixture{ctx: context.Background(), store: s}
	u := f.mintUser(t, "bryce")
	now := time.Now().UTC()
	// Row "x" already carries the hash that row "t" would backfill to.
	if _, err := s.db.Exec(`INSERT INTO sessions (token, token_hash, user_id, created_at, expires_at, last_active_at)
        VALUES ('x', ?, ?, ?, ?, ?)`, busauth.HashToken("t"), u.ID, ms(now), ms(now.Add(time.Hour)), ms(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO sessions (token, user_id, created_at, expires_at, last_active_at)
        VALUES ('t', ?, ?, ?, ?)`, u.ID, ms(now), ms(now.Add(time.Hour)), ms(now)); err != nil {
		t.Fatal(err)
	}
	if err := migrateSessionHash(context.Background(), s.db); err != nil {
		t.Fatalf("migrate must not fail on a hash collision: %v", err)
	}
	rows := readSessionRows(t, s.db)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (never delete)", len(rows))
	}
	if rows["t"].hash.Valid {
		t.Errorf("colliding row was given a duplicate hash: %+v", rows["t"])
	}
}

func TestSessionHash_LookupPrefersHashThenPlaintext(t *testing.T) {
	ctx := context.Background()
	f := newAuthFixture(t)
	byHash := f.mintUser(t, "hashed")
	byPlain := f.mintUser(t, "plain")
	now := time.Now().UTC()

	// Row A carries hash(k) under an unrelated plaintext; row B carries k
	// in plaintext only. Presenting k must resolve through the hash to A.
	if _, err := f.store.db.Exec(`INSERT INTO sessions (token, token_hash, user_id, created_at, expires_at, last_active_at)
        VALUES ('a-plain', ?, ?, ?, ?, ?)`, busauth.HashToken("k"), byHash.ID, ms(now), ms(now.Add(time.Hour)), ms(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`INSERT INTO sessions (token, user_id, created_at, expires_at, last_active_at)
        VALUES ('k', ?, ?, ?, ?)`, byPlain.ID, ms(now), ms(now.Add(time.Hour)), ms(now)); err != nil {
		t.Fatal(err)
	}
	got, err := f.store.GetSession(ctx, "k")
	if err != nil || got == nil {
		t.Fatalf("GetSession(k): sess=%v err=%v", got, err)
	}
	if string(got.UserID) != string(byHash.ID) {
		t.Errorf("GetSession(k) resolved by plaintext, want the hash match first")
	}
	if got.Token != "k" {
		t.Errorf("returned Token = %q, want the presented token", got.Token)
	}

	// A plaintext-only row that no hash matches is still found.
	if _, err := f.store.db.Exec(`INSERT INTO sessions (token, user_id, created_at, expires_at, last_active_at)
        VALUES ('only-plain', ?, ?, ?, ?)`, byPlain.ID, ms(now), ms(now.Add(time.Hour)), ms(now)); err != nil {
		t.Fatal(err)
	}
	got, err = f.store.GetSession(ctx, "only-plain")
	if err != nil || got == nil || string(got.UserID) != string(byPlain.ID) {
		t.Fatalf("plaintext fallback: sess=%v err=%v", got, err)
	}

	// Touch and Delete reach a plaintext-only row too.
	later := now.Add(time.Minute).Truncate(time.Millisecond)
	if err := f.store.TouchSession(ctx, "only-plain", later); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	got, _ = f.store.GetSession(ctx, "only-plain")
	if got == nil || !got.LastActiveAt.Equal(later) {
		t.Errorf("TouchSession on plaintext-only row: %+v", got)
	}
	if err := f.store.DeleteSession(ctx, "only-plain"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if got, _ := f.store.GetSession(ctx, "only-plain"); got != nil {
		t.Errorf("DeleteSession left the plaintext-only row")
	}

	// An empty cookie value matches nothing.
	if got, err := f.store.GetSession(ctx, ""); got != nil || err != nil {
		t.Errorf("GetSession(\"\") = %v, %v; want nil, nil", got, err)
	}
}

func TestSessionHash_CreateWritesBothForms(t *testing.T) {
	f := newAuthFixture(t)
	u := f.mintUser(t, "bryce")
	now := time.Now().UTC()
	if err := f.store.CreateSession(f.ctx, &Session{Token: "tok-both", UserID: u.ID,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastActiveAt: now}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	r := readSessionRows(t, f.store.db)["tok-both"]
	if r.token != "tok-both" {
		t.Errorf("plaintext not written (expand release keeps it): %+v", r)
	}
	if !r.hash.Valid || r.hash.String != busauth.HashToken("tok-both") {
		t.Errorf("hash not written: %+v", r)
	}
}

// TestSessionHash_RollbackToPreviousAPI: a DB the new api wrote is opened by
// the previous api (A/B rollback). Its schema DDL is a no-op, it finds the
// session by plaintext, and the sessions it writes (no hash) are backfilled
// and resolvable once the new api opens the DB again.
func TestSessionHash_RollbackToPreviousAPI(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "rasputin.db")

	s, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	u, _ := makeUser("bryce", "Bryce")
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	now := time.Now().UTC()
	if err := s.CreateSession(ctx, &Session{Token: "tok-from-new", UserID: u.ID,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastActiveAt: now}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Roll back.
	old := openOldAPI(t, path)
	uid, found := old.getSession(t, "tok-from-new")
	if !found || string(uid) != string(u.ID) {
		t.Fatalf("previous api cannot find a session the new api wrote")
	}
	old.createSession(t, "tok-from-old", u.ID)
	if _, err := old.db.Exec(`UPDATE sessions SET last_active_at = ? WHERE token = ?`, ms(now), "tok-from-new"); err != nil {
		t.Fatalf("previous api touch: %v", err)
	}
	old.close(t)

	// Roll forward again.
	s2 := openNewStore(t, path)
	for _, tok := range []string{"tok-from-new", "tok-from-old"} {
		got, err := s2.GetSession(ctx, tok)
		if err != nil || got == nil {
			t.Fatalf("after roll-forward GetSession(%q): sess=%v err=%v", tok, got, err)
		}
	}
	if r := readSessionRows(t, s2.db)["tok-from-old"]; !r.hash.Valid {
		t.Errorf("session the previous api wrote was not backfilled: %+v", r)
	}
}
