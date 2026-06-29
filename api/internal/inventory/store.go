package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed ledger of known nodes.
type Store struct {
	db *sql.DB
}

// OpenStore opens (and migrates) the SQLite database at path. Safe to point
// at the same file the jobs store uses; tables don't overlap.
func OpenStore(ctx context.Context, path string) (*Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("inventory: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("inventory: apply schema: %w", err)
	}
	applyMigrations(ctx, db)
	return &Store{db: db}, nil
}

// applyMigrations runs forward-only DDL that may not be expressible as
// CREATE TABLE IF NOT EXISTS (e.g. adding a column to a pre-existing table).
// Failures matching "duplicate column" / "already exists" are expected for
// fresh installs where the CREATE TABLE already covered the change.
func applyMigrations(ctx context.Context, db *sql.DB) {
	for _, stmt := range migrations {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			msg := err.Error()
			if strings.Contains(msg, "duplicate column name") ||
				strings.Contains(msg, "already exists") {
				continue
			}
			log.Printf("inventory: migration %q: %v", stmt, err)
		}
	}
}

func (s *Store) Close() error { return s.db.Close() }

func tsMillis(t time.Time) int64    { return t.UnixMilli() }
func fromMillis(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

// Insert persists a brand-new node. Returns an error if a row with the same
// id already exists.
func (s *Store) Insert(ctx context.Context, n *proto.Node) error {
	caps, _ := json.Marshal(n.Capabilities)
	meta, _ := json.Marshal(n.Metadata)
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO nodes (id, role, hostname, agent_version, image_version, architecture, capabilities, metadata, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		n.ID, string(n.Role), n.Hostname, n.AgentVersion, n.ImageVersion, n.Architecture,
		string(caps), string(meta),
		tsMillis(n.FirstSeen), tsMillis(n.LastSeen))
	return err
}

// Update overwrites the mutable fields of an existing node. first_seen is
// preserved.
func (s *Store) Update(ctx context.Context, n *proto.Node) error {
	caps, _ := json.Marshal(n.Capabilities)
	meta, _ := json.Marshal(n.Metadata)
	_, err := s.db.ExecContext(ctx, `
        UPDATE nodes
        SET role=?, hostname=?, agent_version=?, image_version=?, architecture=?, capabilities=?, metadata=?, last_seen=?
        WHERE id=?`,
		string(n.Role), n.Hostname, n.AgentVersion, n.ImageVersion, n.Architecture,
		string(caps), string(meta),
		tsMillis(n.LastSeen), n.ID)
	return err
}

// TouchLastSeen updates only the last_seen column. Cheap, used on every
// heartbeat.
func (s *Store) TouchLastSeen(ctx context.Context, id string, ts time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE nodes SET last_seen=? WHERE id=?`, tsMillis(ts), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Delete removes the node row. Returns sql.ErrNoRows if no row matched.
// Callers that need to also clear in-memory status and emit events should
// use Service.Remove instead of calling this directly.
func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Get returns the node with the given id, or (nil, nil) if not found.
func (s *Store) Get(ctx context.Context, id string) (*proto.Node, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, role, hostname, agent_version, image_version, architecture, capabilities, metadata, first_seen, last_seen
        FROM nodes WHERE id=?`, id)
	return scanNode(row.Scan)
}

// List returns every known node.
// ListByRole returns every known node with the given role, ordered by
// first_seen. Used by subsystems that target a particular role
// (e.g. firewall workflows need the firewall node).
func (s *Store) ListByRole(ctx context.Context, role proto.NodeRole) ([]*proto.Node, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, role, hostname, agent_version, image_version, architecture, capabilities, metadata, first_seen, last_seen
        FROM nodes WHERE role = ? ORDER BY first_seen ASC`, string(role))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*proto.Node
	for rows.Next() {
		n, err := scanNode(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) List(ctx context.Context) ([]*proto.Node, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, role, hostname, agent_version, image_version, architecture, capabilities, metadata, first_seen, last_seen
        FROM nodes ORDER BY first_seen ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*proto.Node
	for rows.Next() {
		n, err := scanNode(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func scanNode(scan func(...any) error) (*proto.Node, error) {
	var (
		n               proto.Node
		role, caps, met string
		firstSeen       int64
		lastSeen        int64
	)
	if err := scan(&n.ID, &role, &n.Hostname, &n.AgentVersion, &n.ImageVersion, &n.Architecture,
		&caps, &met, &firstSeen, &lastSeen); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	n.Role = proto.NodeRole(role)
	_ = json.Unmarshal([]byte(caps), &n.Capabilities)
	_ = json.Unmarshal([]byte(met), &n.Metadata)
	n.FirstSeen = fromMillis(firstSeen)
	n.LastSeen = fromMillis(lastSeen)
	return &n, nil
}
