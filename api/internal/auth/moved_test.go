package auth

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TC-991-22: MovedAccountID is a UUID v5 over the handle under the fixed
// namespace, equal to vectors computed outside the code (Python's hashlib
// over the namespace's bytes and the handle, RFC 9562 §5.5).
func TestMovedAccountID_Pinned(t *testing.T) {
	for _, c := range []struct {
		handle []byte
		want   string
	}{
		{[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, "91e750d1-e628-576b-a59a-ab6d21a1364c"},
		{bytes.Repeat([]byte{0xaa}, 16), "aae49de5-def0-5f46-864e-0b5dc588a328"},
	} {
		if got, again := MovedAccountID(c.handle), MovedAccountID(c.handle); got != c.want || again != got {
			t.Errorf("MovedAccountID(%x) = %s then %s, want %s", c.handle, got, again, c.want)
		}
	}
}

var (
	movedHandle = bytes.Repeat([]byte{0x11}, 16)
	otherHandle = bytes.Repeat([]byte{0x22}, 16)
)

// movedFixture is an auth store holding two pre-update users, each with a
// credential and a session.
func movedFixture(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(t.Context(), filepath.Join(t.TempDir(), "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for i, h := range [][]byte{movedHandle, otherHandle} {
		stmts := []struct {
			q    string
			args []any
		}{
			{`INSERT INTO users (id, name, display_name, created_at) VALUES (?, ?, ?, 1)`, []any{h, fmt.Sprint("user", i), "User"}},
			{`INSERT INTO credentials (id, user_id, public_key, created_at) VALUES (?, ?, x'01', 1)`, []any{[]byte{byte(i), 9}, h}},
			{`INSERT INTO sessions (token, token_hash, user_id, created_at, expires_at, last_active_at) VALUES (?, ?, ?, 1, 2, 1)`,
				[]any{fmt.Sprint("tok", i), fmt.Sprint("hash", i), h}},
		}
		for _, st := range stmts {
			if _, err := s.db.ExecContext(t.Context(), st.q, st.args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	return s
}

// dump is a table's rows, each rendered, in order.
func dump(t *testing.T, s *Store, table string) []string {
	t.Helper()
	rows, err := s.db.QueryContext(context.Background(), `SELECT * FROM `+table+` ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	cols, _ := rows.Columns()
	var out []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%x", vals))
	}
	return out
}

// TC-991-20: only the moved handle's credentials and sessions rows go; both
// users rows and the other user's rows stay byte-equal. No match deletes
// nothing, and a sqlite error is returned wrapped.
func TestRemoveMovedRows(t *testing.T) {
	s := movedFixture(t)
	users := dump(t, s, "users")
	creds, sess := dump(t, s, "credentials"), dump(t, s, "sessions")

	nc, ns, err := s.RemoveMovedRows(t.Context(), MovedAccountID(movedHandle))
	if err != nil || nc != 1 || ns != 1 {
		t.Fatalf("RemoveMovedRows = %d, %d, %v; want 1, 1, nil", nc, ns, err)
	}
	if got := dump(t, s, "users"); !slices.Equal(got, users) {
		t.Errorf("users changed:\n%v\n%v", users, got)
	}
	if got := dump(t, s, "credentials"); !slices.Equal(got, creds[1:]) {
		t.Errorf("credentials = %v, want only the other user's %v", got, creds[1:])
	}
	if got := dump(t, s, "sessions"); !slices.Equal(got, sess[1:]) {
		t.Errorf("sessions = %v, want only the other user's %v", got, sess[1:])
	}

	if nc, ns, err := s.RemoveMovedRows(t.Context(), "00000000-0000-5000-8000-000000000000"); err != nil || nc != 0 || ns != 0 {
		t.Errorf("no match: %d, %d, %v", nc, ns, err)
	}

	if _, err := s.db.ExecContext(t.Context(), `DROP TABLE credentials`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RemoveMovedRows(t.Context(), MovedAccountID(otherHandle)); err == nil ||
		!strings.Contains(err.Error(), "auth: remove moved rows") {
		t.Errorf("a sqlite error: %v, want it wrapped", err)
	}
}
