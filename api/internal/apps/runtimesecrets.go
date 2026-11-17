package apps

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// The runtime indexes: the names of the entries a granted app has written
// itself through its relay socket, under apps/<id>/_runtime/
// (geekdojo/geekdojo-brain#1081), and of the Transit keys it has created,
// app-<id>-<name> (#1084). The store's policies grant the api no list, so
// these tables are how app delete and node removal find every entry and key
// to destroy.
//
// Order is the reverse of S15's, because nothing resolves through these rows:
// the row is recorded BEFORE its entry or key is created and forgotten AFTER
// it is deleted. A failure between the two leaves a row naming something that
// reads NotFound, which every delete treats as done; the opposite order could
// leave an entry or key no delete can ever find.

// indexTable is one runtime index table: its rows' name for errors and its
// three statements, each a constant, so no SQL is built at run time.
type indexTable struct {
	what, insert, remove, list string
}

var (
	runtimeIndexTable = indexTable{
		what:   "runtime secret",
		insert: `INSERT OR IGNORE INTO app_runtime_secrets (app_id, name) VALUES (?, ?)`,
		remove: `DELETE FROM app_runtime_secrets WHERE app_id = ? AND name = ?`,
		list:   `SELECT name FROM app_runtime_secrets WHERE app_id = ? ORDER BY name`,
	}
	keyIndexTable = indexTable{
		what:   "transit key",
		insert: `INSERT OR IGNORE INTO app_transit_keys (app_id, name) VALUES (?, ?)`,
		remove: `DELETE FROM app_transit_keys WHERE app_id = ? AND name = ?`,
		list:   `SELECT name FROM app_transit_keys WHERE app_id = ? ORDER BY name`,
	}
)

// record records name for appID in t. It is idempotent; a missing app fails
// on the foreign key.
func (s *Store) record(ctx context.Context, t indexTable, appID, name string) error {
	if _, err := s.db.ExecContext(ctx, t.insert, appID, name); err != nil {
		return fmt.Errorf("apps: record %s %s/%s: %w", t.what, appID, name, err)
	}
	return nil
}

// forget removes appID's row for name in t. A row that is absent is success.
func (s *Store) forget(ctx context.Context, t indexTable, appID, name string) error {
	if _, err := s.db.ExecContext(ctx, t.remove, appID, name); err != nil {
		return fmt.Errorf("apps: forget %s %s/%s: %w", t.what, appID, name, err)
	}
	return nil
}

// RecordRuntimeSecret records that app appID may hold the runtime entry name.
// It is idempotent. A missing app fails (the foreign key), so no row can name
// an app that is gone.
func (s *Store) RecordRuntimeSecret(ctx context.Context, appID, name string) error {
	return s.record(ctx, runtimeIndexTable, appID, name)
}

// ForgetRuntimeSecret removes app appID's row for name. A row that is absent
// is success.
func (s *Store) ForgetRuntimeSecret(ctx context.Context, appID, name string) error {
	return s.forget(ctx, runtimeIndexTable, appID, name)
}

// RuntimeSecretNames returns the runtime entry names app appID's rows record,
// sorted.
func (s *Store) RuntimeSecretNames(ctx context.Context, appID string) ([]string, error) {
	return indexNames(ctx, s.db, runtimeIndexTable, appID)
}

// RecordTransitKey records that app appID may hold the Transit key name
// (geekdojo/geekdojo-brain#1084). It is idempotent. A missing app fails (the
// foreign key).
func (s *Store) RecordTransitKey(ctx context.Context, appID, name string) error {
	return s.record(ctx, keyIndexTable, appID, name)
}

// ForgetTransitKey removes app appID's row for key name. A row that is absent
// is success.
func (s *Store) ForgetTransitKey(ctx context.Context, appID, name string) error {
	return s.forget(ctx, keyIndexTable, appID, name)
}

// HasTransitKey reports whether app appID's rows record key name.
func (s *Store) HasTransitKey(ctx context.Context, appID, name string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM app_transit_keys WHERE app_id = ? AND name = ?`, appID, name).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("apps: transit key %s/%s: %w", appID, name, err)
	}
	return true, nil
}

// TransitKeyNames returns the key names app appID's rows record, sorted.
func (s *Store) TransitKeyNames(ctx context.Context, appID string) ([]string, error) {
	return indexNames(ctx, s.db, keyIndexTable, appID)
}

// indexNames returns the names appID's rows in t record, sorted.
func indexNames(ctx context.Context, q queryer, t indexTable, appID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, t.list, appID)
	if err != nil {
		return nil, fmt.Errorf("apps: %ss of %s: %w", t.what, appID, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("apps: %ss of %s: %w", t.what, appID, err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("apps: %ss of %s: %w", t.what, appID, err)
	}
	return out, nil
}
