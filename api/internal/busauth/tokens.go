package busauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Tokens are high-entropy random strings; only their sha256 is stored, so a
// read of the DB doesn't leak usable credentials. The plaintext is returned
// to the operator exactly once at mint time (same one-shot model as mesh
// preauth keys).
//
// node_id binds a token to a single node id (the NATS username it will present):
// a bound token only authenticates as that node, so a token lifted from one
// node's seed is useless presented as any other. NULL = unbound (legal for the
// interactive / pairing-beacon path, where the id isn't known at mint time).
// See design/os-images/token-provisioning-pipeline.md §3.
const schema = `
CREATE TABLE IF NOT EXISTS bus_tokens (
    token_hash   TEXT PRIMARY KEY,   -- sha256(plaintext) hex; the id
    label        TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at   INTEGER,
    node_id      TEXT                -- bound node id, or NULL when unbound
);`

// Store is the SQLite-backed bus join-token ledger.
type Store struct {
	db *sql.DB
}

// TokenInfo is the non-secret view of a token row (no plaintext, ever).
type TokenInfo struct {
	ID         string     `json:"id"` // token_hash — stable handle for revoke
	Label      string     `json:"label"`
	NodeID     *string    `json:"nodeId,omitempty"` // bound node id, omitted when unbound
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

// PreseedToken is a hash-only token record for preloading the store from a
// provisioning manifest. The controlplane never holds a plaintext token — only
// the sha256 verifier and the node id the token is bound to. Emitted by the
// rasputin-provision CLI, ingested via PreloadHashes.
type PreseedToken struct {
	Hash   string `json:"hash"`
	NodeID string `json:"nodeId"`
	Label  string `json:"label"`
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
	// Additive migration for DBs created before node binding. SQLite has no
	// "ADD COLUMN IF NOT EXISTS"; on a fresh DB the column already exists (the
	// CREATE TABLE above has it) so this is a no-op we swallow.
	if _, err := db.ExecContext(ctx, `ALTER TABLE bus_tokens ADD COLUMN node_id TEXT`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		_ = db.Close()
		return nil, fmt.Errorf("busauth: migrate node_id: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64     { return t.UnixMilli() }
func fromMs(v int64) time.Time { return time.UnixMilli(v).UTC() }

// HashToken returns the sha256-hex of a token plaintext — the stored id. Shared
// with the offline provisioning CLI so the validator and the minter can never
// disagree on the hashing scheme.
func HashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// GenerateToken returns a fresh high-entropy token and its hash (the id). Used
// by Mint and by the offline rasputin-provision CLI. The plaintext is
// unrecoverable from the hash.
func GenerateToken() (plaintext, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("busauth: rand: %w", err)
	}
	plaintext = hex.EncodeToString(raw)
	return plaintext, HashToken(plaintext), nil
}

// Mint generates a fresh UNBOUND token (any node id may present it), stores its
// hash, and returns the plaintext ONCE along with its id (the hash). The
// plaintext is unrecoverable after this.
func (s *Store) Mint(ctx context.Context, label string) (plaintext, id string, err error) {
	return s.mint(ctx, label, nil)
}

// MintBound is Mint but binds the token to nodeID: only a connection presenting
// that node id as its NATS username can authenticate with it.
func (s *Store) MintBound(ctx context.Context, label, nodeID string) (plaintext, id string, err error) {
	return s.mint(ctx, label, &nodeID)
}

func (s *Store) mint(ctx context.Context, label string, nodeID *string) (plaintext, id string, err error) {
	plaintext, id, err = GenerateToken()
	if err != nil {
		return "", "", err
	}
	if _, err := s.db.ExecContext(ctx, `
        INSERT INTO bus_tokens (token_hash, label, created_at, node_id) VALUES (?, ?, ?, ?)`,
		id, label, ms(time.Now().UTC()), nodeID); err != nil {
		return "", "", fmt.Errorf("busauth: insert token: %w", err)
	}
	return plaintext, id, nil
}

// PreloadHashes idempotently inserts preseeded (hash, node-id) bindings — the
// controlplane half of a provisioning matched set. Re-running is a no-op
// (INSERT OR IGNORE on the hash PK), so it's safe to call on every boot, matching
// firstboot's derived-state contract. It inserts hashes directly and never sees
// a plaintext token. Returns the count of newly-inserted rows.
func (s *Store) PreloadHashes(ctx context.Context, toks []PreseedToken) (int, error) {
	now := ms(time.Now().UTC())
	inserted := 0
	for _, tk := range toks {
		if tk.Hash == "" {
			continue
		}
		var nodeID *string
		if tk.NodeID != "" {
			nodeID = &tk.NodeID
		}
		res, err := s.db.ExecContext(ctx, `
            INSERT OR IGNORE INTO bus_tokens (token_hash, label, created_at, node_id) VALUES (?, ?, ?, ?)`,
			tk.Hash, tk.Label, now, nodeID)
		if err != nil {
			return inserted, fmt.Errorf("busauth: preload: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			inserted++
		}
	}
	return inserted, nil
}

// Validate reports whether plaintext matches a live (non-revoked) token that is
// also permitted for presentedNodeID — a bound token only validates for its
// bound node; an unbound token (node_id NULL) validates for any node. It
// best-effort touches last_used_at. Constant work regardless of match isn't
// attempted — tokens are 256-bit random, so timing oracles on the indexed
// lookup don't help an attacker.
func (s *Store) Validate(ctx context.Context, plaintext, presentedNodeID string) (bool, error) {
	if plaintext == "" {
		return false, nil
	}
	id := HashToken(plaintext)
	var (
		revoked   sql.NullInt64
		boundNode sql.NullString
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT revoked_at, node_id FROM bus_tokens WHERE token_hash = ?`, id).Scan(&revoked, &boundNode)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("busauth: validate: %w", err)
	}
	if revoked.Valid {
		return false, nil
	}
	// A bound token only authenticates as the node it was provisioned for.
	if boundNode.Valid && boundNode.String != presentedNodeID {
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
        SELECT token_hash, label, node_id, created_at, last_used_at, revoked_at
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
			nodeID            sql.NullString
			lastUsed, revoked sql.NullInt64
		)
		if err := rows.Scan(&t.ID, &t.Label, &nodeID, &createdAt, &lastUsed, &revoked); err != nil {
			return nil, err
		}
		t.CreatedAt = fromMs(createdAt)
		if nodeID.Valid {
			n := nodeID.String
			t.NodeID = &n
		}
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
