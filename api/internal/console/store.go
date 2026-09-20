package console

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

const schema = `
CREATE TABLE IF NOT EXISTS console_root_secret (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    hash    TEXT    NOT NULL,
    hash_id TEXT    NOT NULL,
    set_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS console_root_nodes (
    node_id    TEXT PRIMARY KEY,
    hash_id    TEXT    NOT NULL DEFAULT '',
    status     TEXT    NOT NULL,
    detail     TEXT    NOT NULL DEFAULT '',
    job_id     TEXT    NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
);
`

// NodeStatus is what a node's console root password is known to be.
type NodeStatus string

const (
	// NodeApplied: the node acknowledged the hash it now holds.
	NodeApplied NodeStatus = "applied"
	// NodeFailed: the node did not take it. Detail says why.
	NodeFailed NodeStatus = "failed"
	// NodePending: a push has been submitted for the node and has not
	// answered yet.
	NodePending NodeStatus = "pending"
)

// NodeState is one node's row.
type NodeState struct {
	NodeID string     `json:"nodeId"`
	Status NodeStatus `json:"status"`
	// HashID names the password the node holds ("" when it holds none the
	// api knows about). Never a hash.
	HashID    string    `json:"hashId,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	JobID     string    `json:"jobId,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
	// Current is true when HashID is the id of the password currently
	// stored. Derived by Status, not stored.
	Current bool `json:"current"`
}

// Status is the reader-facing view of the console root password. It carries
// no hash and cannot be made to: the hash column is read by exactly one
// method, HashForDispatch, which the push step is the only caller of.
type Status struct {
	// Set reports whether a password has been chosen.
	Set bool `json:"set"`
	// HashID names the current password; "" when none is set.
	HashID string     `json:"hashId,omitempty"`
	SetAt  *time.Time `json:"setAt,omitempty"`
	// Nodes is every node the api has a delivery record for, node-id order.
	Nodes []NodeState `json:"nodes"`
}

// Store is the console root password's slice of rasputin.db.
type Store struct {
	db *sql.DB
}

// OpenStore opens (and migrates) the console tables in the database at path.
// dbutil pre-creates and tightens the file to 0600 — that is where the "at
// rest 0600" rule for the hash is met.
func OpenStore(ctx context.Context, path string) (*Store, error) {
	db, err := dbutil.Open(ctx, path, schema, "console")
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// NewStoreForDB wraps an already-open handle. For tests.
func NewStoreForDB(ctx context.Context, db *sql.DB) (*Store, error) {
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return nil, fmt.Errorf("console: apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// SetPassword validates password, hashes it, and replaces the stored hash.
// It returns the id of the new password — never the hash.
//
// Every node's delivery record is reset to pending in the same
// transaction: the moment the password changes, what each node holds is
// out of date, and a Settings page that still said "applied" for the old
// one would be lying until the push finished.
func (s *Store) SetPassword(ctx context.Context, password string) (hashID string, err error) {
	hash, hashID, err := HashPassword(password)
	if err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO console_root_secret (id, hash, hash_id, set_at) VALUES (1, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET hash = excluded.hash, hash_id = excluded.hash_id, set_at = excluded.set_at`,
		hash, hashID, now.UnixMilli()); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `
        UPDATE console_root_nodes SET status = ?, detail = '', updated_at = ?`,
		string(NodePending), now.UnixMilli()); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return hashID, nil
}

// HashForDispatch returns the stored hash and its id.
//
// THE ONLY READER OF THE HASH. Its result goes into the bus command and
// nowhere else — not into a job spec, a step result, an event or a log
// line. ErrNoPassword when none is set; an empty hash is never returned
// alongside a nil error, because dispatching one would either lock or open
// every root account in the fleet.
func (s *Store) HashForDispatch(ctx context.Context) (hash, hashID string, err error) {
	row := s.db.QueryRowContext(ctx, `SELECT hash, hash_id FROM console_root_secret WHERE id = 1`)
	if err := row.Scan(&hash, &hashID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", ErrNoPassword
		}
		return "", "", err
	}
	if hash == "" {
		return "", "", ErrNoPassword
	}
	if err := proto.ValidConsoleRootHash(hash); err != nil {
		return "", "", fmt.Errorf("console: stored hash is unusable: %w", err)
	}
	return hash, hashID, nil
}

// CurrentHashID returns the id of the stored password, or "" when none is
// set. Safe for any reader.
func (s *Store) CurrentHashID(ctx context.Context) (string, error) {
	row := s.db.QueryRowContext(ctx, `SELECT hash_id FROM console_root_secret WHERE id = 1`)
	var id string
	if err := row.Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return id, nil
}

// RecordNode upserts one node's delivery outcome.
func (s *Store) RecordNode(ctx context.Context, st NodeState) error {
	if st.UpdatedAt.IsZero() {
		st.UpdatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO console_root_nodes (node_id, hash_id, status, detail, job_id, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(node_id) DO UPDATE SET
            hash_id    = excluded.hash_id,
            status     = excluded.status,
            detail     = excluded.detail,
            job_id     = excluded.job_id,
            updated_at = excluded.updated_at`,
		st.NodeID, st.HashID, string(st.Status), st.Detail, st.JobID, st.UpdatedAt.UnixMilli())
	return err
}

// ForgetNode drops a node's record. Called when a node leaves inventory so
// a removed node stops being reported as a fleet failure for ever.
func (s *Store) ForgetNode(ctx context.Context, nodeID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM console_root_nodes WHERE node_id = ?`, nodeID)
	return err
}

// Status reads the whole reader-facing view.
func (s *Store) Status(ctx context.Context) (*Status, error) {
	out := &Status{Nodes: []NodeState{}}
	row := s.db.QueryRowContext(ctx, `SELECT hash_id, set_at FROM console_root_secret WHERE id = 1`)
	var hashID string
	var setAt int64
	switch err := row.Scan(&hashID, &setAt); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return nil, err
	default:
		t := time.UnixMilli(setAt).UTC()
		out.Set, out.HashID, out.SetAt = true, hashID, &t
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT node_id, hash_id, status, detail, job_id, updated_at FROM console_root_nodes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var st NodeState
		var status string
		var updated int64
		if err := rows.Scan(&st.NodeID, &st.HashID, &status, &st.Detail, &st.JobID, &updated); err != nil {
			return nil, err
		}
		st.Status = NodeStatus(status)
		st.UpdatedAt = time.UnixMilli(updated).UTC()
		st.Current = out.Set && st.Status == NodeApplied && st.HashID == out.HashID
		out.Nodes = append(out.Nodes, st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].NodeID < out.Nodes[j].NodeID })
	return out, nil
}
