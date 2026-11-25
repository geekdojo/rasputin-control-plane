// Package removednames is the removed-name list and the app-access fact
// (geekdojo/geekdojo-brain#991, Identity 4.9; app-sso.md §8), in
// rasputin.db.
//
// Deleting an account that ever held app access puts keyed hashes of its
// sign-in name and its email on the list, so a newcomer can't take the name
// and inherit what apps still hold under it. The hashes are the api's
// fingerprint key's (credmac.Key, derived from the app-secret seed on every
// start), under purposes of their own, so the list holds no name and no
// email and has no key of its own to lose.
//
// The list fails closed: a read that can't check every row returns
// ErrUnreadable, which pauses sign-up, and Alerts raises a warning until a
// read succeeds again. An empty list admits.
package removednames

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/credmac"
	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The purposes the two hashes are taken under.
const (
	purposeName  = "removed-name.name"
	purposeEmail = "removed-name.email"
)

// AlertID is the warning raised while the list can't be read.
const AlertID = "identity:removed-names-unreadable"

// SentencePaused is what a person and the alert read while the list can't
// be read.
const SentencePaused = "Sign-up is paused: Rasputin can't check removed names right now."

// ErrUnreadable is every failure to read or write the list: a missing
// table, an empty or malformed cell, a database error, or no store at all.
var ErrUnreadable = errors.New("removednames: the removed-name list can't be read")

// errMalformed is a row whose cell is empty or not a keyed hash.
var errMalformed = errors.New("a row is malformed")

// MAC is the keyed hash (*credmac.Key).
type MAC interface {
	Sum(purpose string, parts ...[]byte) string
}

const schema = `
CREATE TABLE IF NOT EXISTS removed_names (
    name_mac  TEXT NOT NULL,
    email_mac TEXT
);
CREATE TABLE IF NOT EXISTS app_access_facts (
    sub TEXT PRIMARY KEY
);
`

// Store is the list and the app-access fact over rasputin.db.
type Store struct {
	db  *sql.DB
	mac MAC
	log *slog.Logger

	mu   sync.Mutex
	down bool
}

// OpenStore opens dbPath and creates the two tables when they are missing.
func OpenStore(ctx context.Context, dbPath string, mac MAC, log *slog.Logger) (*Store, error) {
	switch {
	case mac == nil:
		return nil, errors.New("removednames: OpenStore: mac is nil")
	case log == nil:
		return nil, errors.New("removednames: OpenStore: log is nil")
	}
	db, err := dbutil.Open(ctx, dbPath, schema, "removednames")
	if err != nil {
		return nil, err
	}
	return &Store{db: db, mac: mac, log: log.With("component", "accounts")}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Normal is the one form a sign-in name or an email is compared in: trimmed
// and lower-cased. The list hashes it, and the in-use email check
// (accounts.Users.EmailInUse) queries it, so the two agree on what "the same
// address" is (F-990-08).
func Normal(v string) string { return strings.ToLower(strings.TrimSpace(v)) }

// normal is Normal as the bytes the list hashes.
func normal(v string) []byte { return []byte(Normal(v)) }

// Record puts the hashes of name and email on the list. An empty email
// leaves its hash empty (NULL).
func (s *Store) Record(ctx context.Context, name, email string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: record: no name", ErrUnreadable)
	}
	var emailMAC any
	if strings.TrimSpace(email) != "" {
		emailMAC = s.mac.Sum(purposeEmail, normal(email))
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO removed_names (name_mac, email_mac) VALUES (?, ?)`,
		s.mac.Sum(purposeName, normal(name)), emailMAC); err != nil {
		return fmt.Errorf("%w: record: %w", ErrUnreadable, err)
	}
	return nil
}

// Removed reports whether name or email is on the list. Every call reads
// and checks every row, so an empty argument is skipped in the comparison
// but the list is still read: an unreadable list returns ErrUnreadable
// whatever was asked.
func (s *Store) Removed(ctx context.Context, name, email string) (bool, error) {
	found, err := s.removed(ctx, name, email)
	s.outage(ctx, err)
	if err != nil {
		return false, err
	}
	return found, nil
}

func (s *Store) removed(ctx context.Context, name, email string) (bool, error) {
	var nameMAC, emailMAC string
	if strings.TrimSpace(name) != "" {
		nameMAC = s.mac.Sum(purposeName, normal(name))
	}
	if strings.TrimSpace(email) != "" {
		emailMAC = s.mac.Sum(purposeEmail, normal(email))
	}
	rows, err := s.db.QueryContext(ctx, `SELECT name_mac, email_mac FROM removed_names`)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	defer func() { _ = rows.Close() }()
	found := false
	for rows.Next() {
		var n string
		var e sql.NullString
		if err := rows.Scan(&n, &e); err != nil {
			return false, fmt.Errorf("%w: %w", ErrUnreadable, err)
		}
		if !wellFormed(n) || (e.Valid && !wellFormed(e.String)) {
			return false, fmt.Errorf("%w: %w", ErrUnreadable, errMalformed)
		}
		if nameMAC != "" && hmac.Equal([]byte(n), []byte(nameMAC)) {
			found = true
		}
		if emailMAC != "" && e.Valid && hmac.Equal([]byte(e.String), []byte(emailMAC)) {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	return found, nil
}

// wellFormed reports whether h is a keyed hash as credmac.Key.Sum writes
// it: the prefix and 64 lowercase hex characters.
func wellFormed(h string) bool {
	rest, ok := strings.CutPrefix(h, "k1-")
	if !ok || !credmac.IsKeyed(h) || len(rest) != 64 {
		return false
	}
	for _, c := range rest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// outage logs a read failure at WARN once per run of failures, with the
// error's class only, and clears the run on a good read.
func (s *Store) outage(ctx context.Context, err error) {
	s.mu.Lock()
	first := err != nil && !s.down
	s.down = err != nil
	s.mu.Unlock()
	if first {
		s.log.LogAttrs(ctx, slog.LevelWarn, "The removed-name list can't be read, so sign-up is paused.",
			slog.String("event", "accounts.removed_names.unreadable"), slog.String("class", errorClass(err)))
	}
}

// errorClass names what kind of failure err is, never its text.
func errorClass(err error) string {
	switch {
	case errors.Is(err, errMalformed):
		return "malformed_row"
	case errors.Is(err, sql.ErrConnDone), strings.Contains(err.Error(), "database is closed"):
		return "closed"
	case strings.Contains(err.Error(), "no such table"):
		return "missing_table"
	}
	return "database"
}

// Alerts reads the list and returns one warning while it can't be read,
// and nothing once it can. now is the alert's Since only.
func (s *Store) Alerts(ctx context.Context, now time.Time) []proto.Alert {
	if _, err := s.Removed(ctx, "", ""); err != nil {
		return []proto.Alert{pausedAlert(now)}
	}
	return nil
}

func pausedAlert(now time.Time) proto.Alert {
	return proto.Alert{ID: AlertID, Severity: proto.AlertWarn, Source: proto.AlertSourceSecurity,
		Title: SentencePaused, Detail: SentencePaused, Since: now, RelatedKind: "accounts"}
}

// AccessFacts is the app-access fact: the accounts that were ever given
// app access, whose deletion puts their name on the list.
type AccessFacts struct{ s *Store }

// Facts is the store's app-access fact.
func (s *Store) Facts() AccessFacts { return AccessFacts{s: s} }

// Record records that sub was given app access.
func (f AccessFacts) Record(ctx context.Context, sub string) error {
	if sub == "" {
		return errors.New("removednames: record the app-access fact: no account id")
	}
	if _, err := f.s.db.ExecContext(ctx, `INSERT OR IGNORE INTO app_access_facts (sub) VALUES (?)`, sub); err != nil {
		return fmt.Errorf("removednames: record the app-access fact: %w", err)
	}
	return nil
}

// Held reports whether sub was ever given app access.
func (f AccessFacts) Held(ctx context.Context, sub string) (bool, error) {
	var n int
	if err := f.s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_access_facts WHERE sub = ?`, sub).Scan(&n); err != nil {
		return false, fmt.Errorf("removednames: read the app-access fact: %w", err)
	}
	return n > 0, nil
}

// Unavailable is what the composition root wires when OpenStore fails:
// every read and write returns ErrUnreadable wrapped around Err, and Alerts
// returns the warning. Sign-up pauses and a held-access delete fails before
// it deletes anything.
type Unavailable struct{ Err error }

func (u Unavailable) err() error { return fmt.Errorf("%w: %w", ErrUnreadable, u.Err) }

// Removed returns ErrUnreadable.
func (u Unavailable) Removed(context.Context, string, string) (bool, error) { return false, u.err() }

// Record returns ErrUnreadable.
func (u Unavailable) Record(context.Context, string, string) error { return u.err() }

// Alerts returns the warning.
func (u Unavailable) Alerts(_ context.Context, now time.Time) []proto.Alert {
	return []proto.Alert{pausedAlert(now)}
}

// Facts is the app-access fact with no store: it can't be kept or read.
func (u Unavailable) Facts() UnavailableFacts { return UnavailableFacts(u) }

// UnavailableFacts is the app-access fact with no store.
type UnavailableFacts struct{ Err error }

// Record returns an error wrapping Err.
func (u UnavailableFacts) Record(context.Context, string) error {
	return fmt.Errorf("removednames: record the app-access fact: %w", u.Err)
}

// Held returns an error wrapping Err.
func (u UnavailableFacts) Held(context.Context, string) (bool, error) {
	return false, fmt.Errorf("removednames: read the app-access fact: %w", u.Err)
}
