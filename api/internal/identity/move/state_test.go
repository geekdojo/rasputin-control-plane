package move

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	_ "modernc.org/sqlite"
)

// prevSchema is v2026.11.3's old tables, as that release created them
// (git show v2026.11.3:api/internal/auth/schema.go): users, credentials and
// sessions, and no identity_move and no first_admin.
const prevSchema = `
CREATE TABLE users (id BLOB PRIMARY KEY, name TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, created_at INTEGER NOT NULL, last_login_at INTEGER);
CREATE TABLE credentials (id BLOB PRIMARY KEY, user_id BLOB NOT NULL, public_key BLOB NOT NULL, attestation TEXT NOT NULL DEFAULT '',
  transports TEXT NOT NULL DEFAULT '[]', aaguid BLOB, sign_count INTEGER NOT NULL DEFAULT 0, clone_warning INTEGER NOT NULL DEFAULT 0,
  backup_eligible INTEGER NOT NULL DEFAULT 0, backup_state INTEGER NOT NULL DEFAULT 0, nickname TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL, last_used_at INTEGER, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE sessions (token TEXT PRIMARY KEY, token_hash TEXT, user_id BLOB NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, last_active_at INTEGER NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
INSERT INTO users (id, name, display_name, created_at) VALUES (x'00000000000000000000000000000001', 'Bryce', 'Bryce', 1);
`

// TC-1004-09: #1008's interface, move.State.Pending, over a real
// rasputin.db from the previous release's schema. The Store opens it and
// creates its table; Pending is true with old users and no rows, false
// with none, false after Record; an error, never false, when CountUsers or
// Recorded fails; and still true with no row after a move that failed at
// import, read-back or record.
func TestPending_TC1004_09(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "rasputin.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, prevSchema); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	store, err := OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var n int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='identity_move'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("identity_move in sqlite_master: %d %v", n, err)
	}
	if rec, err := store.Recorded(ctx); rec || err != nil {
		t.Errorf("Recorded on a fresh table: %v %v", rec, err)
	}
	old, err := auth.OpenStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = old.Close() })
	w := &world{fail: map[string]error{}, realm: map[string]accounts.Account{}, removed: map[string]bool{}}
	st, err := NewState(failingOld{w: w, inner: old}, failingRecords{w: w, inner: store}, fPersons{w}, fRemoved{w})
	if err != nil {
		t.Fatal(err)
	}
	if p, err := st.Pending(ctx); !p || err != nil {
		t.Errorf("old users, no rows: %v %v, want true", p, err)
	}
	for _, f := range []string{"count", "recorded"} {
		w.fail = map[string]error{f: errDown}
		if p, err := st.Pending(ctx); err == nil || p {
			t.Errorf("%s fails: %v %v, want an error and false", f, p, err)
		}
	}
	w.fail = map[string]error{}
	if err := store.Record(ctx, []Row{{Handle: []byte{1}, AccountID: "a", OldName: "Bryce", NewName: "bryce", MovedAt: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	if p, err := st.Pending(ctx); p || err != nil {
		t.Errorf("after Record: %v %v, want false", p, err)
	}

	empty := newWorld(t)
	if p, err := empty.state(t).Pending(ctx); p || err != nil {
		t.Errorf("no old users: %v %v, want false", p, err)
	}

	for _, c := range []struct {
		name string
		set  func(w *world)
	}{
		{"import", func(w *world) { w.fail["import"] = errDown }},
		{"read-back", func(w *world) { w.readName = "someone-else" }},
		{"record", func(w *world) { w.fail["record"] = errDown }},
	} {
		w := newWorld(t)
		w.addOld(t, 1, "op", 1)
		c.set(w)
		if _, err := w.run(t, Spec{}); err == nil {
			t.Errorf("%s: the move succeeded", c.name)
		}
		if n := w.rowCount(t); n != 0 {
			t.Errorf("%s: %d rows after a failed move, want 0", c.name, n)
		}
		if p, err := w.state(t).Pending(ctx); !p || err != nil {
			t.Errorf("%s: Pending %v %v after a failed move, want true", c.name, p, err)
		}
	}
}

// TC-1004-18: C9's state and its token. Holds only when the realm has no
// person, old users exist, a move is recorded and one account is not
// removed; each failing alone is false. Accounts leaves removed names out.
// The token is the same in any read order and changes when a person is
// removed or the old users change. Each read error is returned.
func TestRepair_TC1004_18(t *testing.T) {
	ctx := t.Context()
	w := newWorld(t)
	w.addOld(t, 1, "alice", 1)
	w.addOld(t, 2, "bob", 2)
	if err := w.store.Record(ctx, []Row{{Handle: []byte{9}, AccountID: "x", OldName: "alice", NewName: "alice", MovedAt: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	st := w.state(t)
	r, err := st.Repair(ctx)
	if err != nil || !r.Holds || r.Accounts != 2 || r.Token == "" {
		t.Fatalf("the state: %+v %v, want holding with 2", r, err)
	}
	tok, holds, err := st.RepairToken(ctx)
	if err != nil || !holds || tok != r.Token {
		t.Errorf("RepairToken: %q %v %v", tok, holds, err)
	}
	// A person in the realm: not holding.
	w.realm["p"] = accounts.Account{ID: "p", Username: "door"}
	if r2, _ := st.Repair(ctx); r2.Holds {
		t.Error("holds with a person in the realm")
	}
	delete(w.realm, "p")
	// Every account removed: not holding.
	w.removed = map[string]bool{"alice": true, "bob": true}
	if r2, _ := st.Repair(ctx); r2.Holds || r2.Accounts != 0 {
		t.Errorf("every account removed: %+v", r2)
	}
	// One removed: Accounts leaves it out and the token changes.
	w.removed = map[string]bool{"alice": true}
	r3, err := st.Repair(ctx)
	if err != nil || !r3.Holds || r3.Accounts != 1 || r3.Token == r.Token {
		t.Errorf("one removed: %+v %v, want 1 and a new token", r3, err)
	}
	w.removed = map[string]bool{}
	// Same state, same token (the realm read in another order is the same
	// set; the token is over sorted ids).
	if again, _ := st.Repair(ctx); again.Token != r.Token {
		t.Error("the same state gave another token")
	}
	// The old users change: the token changes.
	w.addOld(t, 3, "carol", 3)
	if r4, _ := st.Repair(ctx); r4.Token == r.Token || r4.Accounts != 3 {
		t.Errorf("a new old user: %+v, want a new token", r4)
	}
	// No move recorded: not holding. No old users: not holding.
	fresh := newWorld(t)
	fresh.addOld(t, 1, "alice", 1)
	if r5, _ := fresh.state(t).Repair(ctx); r5.Holds {
		t.Error("holds with no move recorded")
	}
	none := newWorld(t)
	if err := none.store.Record(ctx, []Row{{Handle: []byte{9}, AccountID: "x", OldName: "a", NewName: "a", MovedAt: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	if r6, _ := none.state(t).Repair(ctx); r6.Holds {
		t.Error("holds with no old users")
	}
	for _, f := range []string{"count", "recorded", "people", "removed", "list", "rows"} {
		w.fail = map[string]error{f: errDown}
		if _, err := st.Repair(ctx); !errors.Is(err, errDown) {
			t.Errorf("%s fails: %v, want the error", f, err)
		}
		if _, _, err := st.RepairToken(ctx); err == nil {
			t.Errorf("%s fails: RepairToken has no error", f)
		}
	}
	if _, err := NewState(nil, w.records, fPersons{w}, fRemoved{w}); err == nil {
		t.Error("NewState(nil) succeeded")
	}
}
