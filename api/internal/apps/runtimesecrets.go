package apps

import (
	"context"
	"fmt"
)

// The runtime secret index (geekdojo/geekdojo-brain#1081): the names of the
// entries a granted app has written itself through its relay socket, under
// apps/<id>/_runtime/. The store's policy grants the api no list, so this
// table is how app delete and node removal find every entry to destroy.
//
// Order is the reverse of S15's, because nothing resolves through these rows:
// the row is recorded BEFORE its entry is created and forgotten AFTER its
// entry is deleted. A failure between the two leaves a row naming an entry
// that reads NotFound, which every delete treats as done; the opposite order
// could leave an entry no delete can ever find.

// RecordRuntimeSecret records that app appID may hold the runtime entry name.
// It is idempotent. A missing app fails (the foreign key), so no row can name
// an app that is gone.
func (s *Store) RecordRuntimeSecret(ctx context.Context, appID, name string) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO app_runtime_secrets (app_id, name) VALUES (?, ?)`, appID, name); err != nil {
		return fmt.Errorf("apps: record runtime secret %s/%s: %w", appID, name, err)
	}
	return nil
}

// ForgetRuntimeSecret removes app appID's row for name. A row that is absent
// is success.
func (s *Store) ForgetRuntimeSecret(ctx context.Context, appID, name string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM app_runtime_secrets WHERE app_id = ? AND name = ?`, appID, name); err != nil {
		return fmt.Errorf("apps: forget runtime secret %s/%s: %w", appID, name, err)
	}
	return nil
}

// RuntimeSecretNames returns the runtime entry names app appID's rows record,
// sorted.
func (s *Store) RuntimeSecretNames(ctx context.Context, appID string) ([]string, error) {
	return runtimeSecretNames(ctx, s.db, appID)
}

func runtimeSecretNames(ctx context.Context, q queryer, appID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT name FROM app_runtime_secrets WHERE app_id = ? ORDER BY name`, appID)
	if err != nil {
		return nil, fmt.Errorf("apps: runtime secrets of %s: %w", appID, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("apps: runtime secrets of %s: %w", appID, err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("apps: runtime secrets of %s: %w", appID, err)
	}
	return out, nil
}
