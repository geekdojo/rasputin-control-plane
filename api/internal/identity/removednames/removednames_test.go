package removednames

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

func key(t *testing.T) *credmac.Key {
	t.Helper()
	k, err := credmac.New(secret.New(bytes.Repeat([]byte{0x5a}, credmac.MinKeyLen)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func open(t *testing.T, dbPath string) (*Store, *logkittest.Recorder) {
	t.Helper()
	log, rec := logkittest.New()
	s, err := OpenStore(t.Context(), dbPath, key(t), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, rec
}

func rawDB(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TC-991-11: Removed answers true for a recorded name alone, its email
// alone, and both, and false for an unrelated name and email.
func TestRemoved_NameEmailBoth(t *testing.T) {
	s, _ := open(t, filepath.Join(t.TempDir(), "rasputin.db"))
	ctx := t.Context()
	if err := s.Record(ctx, "Alice", " alice@example.invalid "); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, email string
		want        bool
	}{
		{"alice", "", true}, {"", "ALICE@example.invalid", true}, {"alice", "alice@example.invalid", true},
		{"bob", "", false}, {"", "bob@example.invalid", false}, {"bob", "bob@example.invalid", false}, {"", "", false},
	} {
		got, err := s.Removed(ctx, c.name, c.email)
		if err != nil || got != c.want {
			t.Errorf("Removed(%q, %q) = %v, %v; want %v", c.name, c.email, got, err, c.want)
		}
	}
	// A name recorded with no email matches by name only.
	if err := s.Record(ctx, "carol", ""); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Removed(ctx, "Carol", ""); err != nil || !got {
		t.Errorf("a name with no email: %v, %v", got, err)
	}
}

// TC-991-13 (the store's part): every unreadable case returns an error
// wrapping ErrUnreadable and raises the one warning; one WARN record per run
// of failures names the error's class; after the repair the next read admits
// and the alert is gone.
func TestRemoved_FailsClosed(t *testing.T) {
	cases := []struct {
		name, class string
		breakIt     func(db *sql.DB) error
		repair      func(db *sql.DB) error
	}{
		{"the table missing", "missing_table",
			func(db *sql.DB) error { _, err := db.Exec(`DROP TABLE removed_names`); return err },
			func(db *sql.DB) error { _, err := db.Exec(schema); return err }},
		{"an empty hash cell", "malformed_row",
			func(db *sql.DB) error { _, err := db.Exec(`INSERT INTO removed_names VALUES ('', NULL)`); return err },
			func(db *sql.DB) error { _, err := db.Exec(`DELETE FROM removed_names WHERE name_mac = ''`); return err }},
		{"an empty email cell", "malformed_row",
			func(db *sql.DB) error {
				_, err := db.Exec(`INSERT INTO removed_names VALUES ('k1-` + strings.Repeat("a", 64) + `', '')`)
				return err
			},
			func(db *sql.DB) error {
				_, err := db.Exec(`DELETE FROM removed_names WHERE email_mac = ''`)
				return err
			}},
		{"a hash of the wrong length", "malformed_row",
			func(db *sql.DB) error {
				_, err := db.Exec(`INSERT INTO removed_names VALUES ('k1-abcd', NULL)`)
				return err
			},
			func(db *sql.DB) error {
				_, err := db.Exec(`DELETE FROM removed_names WHERE name_mac = 'k1-abcd'`)
				return err
			}},
		{"an unkeyed hash", "malformed_row",
			func(db *sql.DB) error {
				_, err := db.Exec(`INSERT INTO removed_names VALUES ('` + strings.Repeat("a", 67) + `', NULL)`)
				return err
			},
			func(db *sql.DB) error {
				_, err := db.Exec(`DELETE FROM removed_names WHERE name_mac NOT LIKE 'k1-%'`)
				return err
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "rasputin.db")
			s, rec := open(t, dbPath)
			db := rawDB(t, dbPath)
			if err := s.Record(t.Context(), "alice", "alice@example.invalid"); err != nil {
				t.Fatal(err)
			}
			if err := c.breakIt(db); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if _, err := s.Removed(t.Context(), "alice", ""); !errors.Is(err, ErrUnreadable) {
					t.Fatalf("Removed = %v, want ErrUnreadable", err)
				}
			}
			if a := s.Alerts(t.Context(), time.Now()); len(a) != 1 || a[0].ID != AlertID || a[0].Title != SentencePaused {
				t.Errorf("alerts while unreadable: %+v", a)
			}
			warns := rec.Matching(slog.LevelWarn, "")
			if len(warns) != 1 {
				t.Fatalf("%d WARN records for one run of failures:\n%s", len(warns), rec.Text())
			}
			if cl, _ := logkittest.Attr(warns[0], "class"); cl != c.class {
				t.Errorf("class = %q, want %q", cl, c.class)
			}
			if err := c.repair(db); err != nil {
				t.Fatal(err)
			}
			if got, err := s.Removed(t.Context(), "bob", ""); err != nil || got {
				t.Errorf("after the repair: %v, %v", got, err)
			}
			if a := s.Alerts(t.Context(), time.Now()); len(a) != 0 {
				t.Errorf("alerts after the repair: %+v", a)
			}
		})
	}
	t.Run("a closed database", func(t *testing.T) {
		s, rec := open(t, filepath.Join(t.TempDir(), "rasputin.db"))
		_ = s.Close()
		if _, err := s.Removed(t.Context(), "", ""); !errors.Is(err, ErrUnreadable) {
			t.Errorf("Removed = %v", err)
		}
		if err := s.Record(t.Context(), "x", ""); !errors.Is(err, ErrUnreadable) {
			t.Errorf("Record = %v", err)
		}
		if w := rec.Matching(slog.LevelWarn, ""); len(w) != 1 {
			t.Fatalf("WARN records:\n%s", rec.Text())
		} else if cl, _ := logkittest.Attr(w[0], "class"); cl != "closed" {
			t.Errorf("class %q", cl)
		}
	})
	t.Run("the key unavailable or of the wrong length", func(t *testing.T) {
		_, keyErr := credmac.New(secret.New([]byte("short")))
		if keyErr == nil {
			t.Fatal("a short key was accepted")
		}
		u := Unavailable{Err: keyErr}
		if _, err := u.Removed(t.Context(), "alice", ""); !errors.Is(err, ErrUnreadable) {
			t.Errorf("Removed = %v", err)
		}
		if err := u.Record(t.Context(), "alice", ""); !errors.Is(err, ErrUnreadable) {
			t.Errorf("Record = %v", err)
		}
		if a := u.Alerts(t.Context(), time.Now()); len(a) != 1 || a[0].ID != AlertID {
			t.Errorf("alerts %+v", a)
		}
		if _, err := u.Facts().Held(t.Context(), "sub"); err == nil {
			t.Error("Held with no store succeeded")
		}
		if err := u.Facts().Record(t.Context(), "sub"); err == nil {
			t.Error("Record fact with no store succeeded")
		}
		if _, err := OpenStore(t.Context(), filepath.Join(t.TempDir(), "x.db"), nil, slog.Default()); err == nil {
			t.Error("OpenStore with no key succeeded")
		}
	})
}

// TC-991-15: a recorded name stays refused after the store is closed and
// opened again with the same key source, and the database holds no key: its
// only tables are the list and the fact.
func TestRemoved_SurvivesReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rasputin.db")
	s, _ := open(t, dbPath)
	if err := s.Record(t.Context(), "alice", ""); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	again, _ := open(t, dbPath)
	if got, err := again.Removed(t.Context(), "alice", ""); err != nil || !got {
		t.Errorf("after the reopen: %v, %v", got, err)
	}
	rows, err := rawDB(t, dbPath).Query(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var tables []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		tables = append(tables, n)
	}
	if !slices.Equal(tables, []string{"app_access_facts", "removed_names"}) {
		t.Errorf("tables %v", tables)
	}
}

// TC-991-16: a previous release's rasputin.db, with the api's tables and
// none of these, opens with the tables created, no pause and no alert.
func TestRemoved_UpgradeFromPreviousRelease(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rasputin.db")
	old, err := auth.OpenStore(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = old.Close()
	s, rec := open(t, dbPath)
	if got, err := s.Removed(t.Context(), "alice", "alice@example.invalid"); err != nil || got {
		t.Errorf("Removed = %v, %v", got, err)
	}
	if a := s.Alerts(t.Context(), time.Now()); len(a) != 0 {
		t.Errorf("alerts %+v", a)
	}
	if held, err := s.Facts().Held(t.Context(), "sub-1"); err != nil || held {
		t.Errorf("Held = %v, %v", held, err)
	}
	if len(rec.Records()) != 0 {
		t.Errorf("records:\n%s", rec.Text())
	}
}

// The app-access fact: recorded once, held after, idempotent.
func TestAccessFacts(t *testing.T) {
	s, _ := open(t, filepath.Join(t.TempDir(), "rasputin.db"))
	f := s.Facts()
	for range 2 {
		if err := f.Record(t.Context(), "sub-1"); err != nil {
			t.Fatal(err)
		}
	}
	if held, err := f.Held(t.Context(), "sub-1"); err != nil || !held {
		t.Errorf("Held = %v, %v", held, err)
	}
	if err := f.Record(t.Context(), ""); err == nil {
		t.Error("an empty sub was recorded")
	}
	if err := s.Record(t.Context(), " ", "x@example.invalid"); !errors.Is(err, ErrUnreadable) {
		t.Errorf("Record with no name = %v", err)
	}
}
