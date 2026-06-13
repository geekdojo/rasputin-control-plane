package busauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Tokens are high-entropy random strings; only their sha256 is stored, so a
// read of the DB doesn't leak usable credentials. The plaintext is returned
// to the operator exactly once at mint time (same one-shot model as mesh
// preauth keys).
const schema = `
CREATE TABLE IF NOT EXISTS bus_tokens (
    token_hash   TEXT PRIMARY KEY,   -- sha256(plaintext) hex; the id
    label        TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at   INTEGER
);`

// Store is the SQLite-backed bus join-token ledger.
type Store struct {
	db *sql.DB
}

// TokenInfo is the non-secret view of a token row (no plaintext, ever).
type TokenInfo struct {
	ID         string     `json:"id"` // token_hash — stable handle for revoke
	Label      string     `json:"label"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("busauth: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("busauth: apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64     { return t.UnixMilli() }
func fromMs(v int64) time.Time { return time.UnixMilli(v).UTC() }

func hashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// Mint generates a fresh token, stores its hash, and returns the plaintext
// ONCE along with its id (the hash). The plaintext is unrecoverable after this.
func (s *Store) Mint(ctx context.Context, label string) (plaintext, id string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("busauth: rand: %w", err)
	}
	plaintext = hex.EncodeToString(raw)
	id = hashToken(plaintext)
	if _, err := s.db.ExecContext(ctx, `
        INSERT INTO bus_tokens (token_hash, label, created_at) VALUES (?, ?, ?)`,
		id, label, ms(time.Now().UTC())); err != nil {
		return "", "", fmt.Errorf("busauth: insert token: %w", err)
	}
	return plaintext, id, nil
}

// Validate reports whether plaintext matches a live (non-revoked) token, and
// best-effort touches last_used_at. Constant work regardless of match isn't
// attempted — tokens are 256-bit random, so timing oracles on the indexed
// lookup don't help an attacker.
func (s *Store) Validate(ctx context.Context, plaintext string) (bool, error) {
	if plaintext == "" {
		return false, nil
	}
	id := hashToken(plaintext)
	var revoked sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT revoked_at FROM bus_tokens WHERE token_hash = ?`, id).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("busauth: validate: %w", err)
	}
	if revoked.Valid {
		return false, nil
	}
	_, _ = s.db.ExecContext(ctx,
		`UPDATE bus_tokens SET last_used_at = ? WHERE token_hash = ?`, ms(time.Now().UTC()), id)
	return true, nil
}

// Revoke marks a token revoked by its id (token_hash). Returns sql.ErrNoRows
// if no such live token existed.
func (s *Store) Revoke(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE bus_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL`,
		ms(time.Now().UTC()), id)
	if err != nil {
		return fmt.Errorf("busauth: revoke: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// List returns all tokens (secret-free), newest first.
func (s *Store) List(ctx context.Context) ([]TokenInfo, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT token_hash, label, created_at, last_used_at, revoked_at
        FROM bus_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("busauth: list: %w", err)
	}
	defer rows.Close()
	var out []TokenInfo
	for rows.Next() {
		var (
			t                 TokenInfo
			createdAt         int64
			lastUsed, revoked sql.NullInt64
		)
		if err := rows.Scan(&t.ID, &t.Label, &createdAt, &lastUsed, &revoked); err != nil {
			return nil, err
		}
		t.CreatedAt = fromMs(createdAt)
		if lastUsed.Valid {
			lu := fromMs(lastUsed.Int64)
			t.LastUsedAt = &lu
		}
		if revoked.Valid {
			rv := fromMs(revoked.Int64)
			t.RevokedAt = &rv
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
