package apps

import (
	"context"
	"fmt"
)

// SecretRef is one recorded secret store entry: app AppID's ${secret:Name}
// (geekdojo/geekdojo-brain#800).
type SecretRef struct {
	AppID string
	Name  string
}

// RecordSecretRef records that the store holds app appID's secret name. It
// is idempotent: recording a reference already recorded changes nothing. The
// caller records only an entry it has confirmed in the store, after the
// entry was written (S15 write order).
func (s *Store) RecordSecretRef(ctx context.Context, appID, name string) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO app_secret_refs (app_id, name) VALUES (?, ?)`, appID, name); err != nil {
		return fmt.Errorf("apps: record secret ref %s/%s: %w", appID, name, err)
	}
	return nil
}

// ListSecretRefs returns every recorded reference, ordered by app and name.
func (s *Store) ListSecretRefs(ctx context.Context) ([]SecretRef, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT app_id, name FROM app_secret_refs ORDER BY app_id, name`)
	if err != nil {
		return nil, fmt.Errorf("apps: list secret refs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []SecretRef
	for rows.Next() {
		var r SecretRef
		if err := rows.Scan(&r.AppID, &r.Name); err != nil {
			return nil, fmt.Errorf("apps: list secret refs: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("apps: list secret refs: %w", err)
	}
	return out, nil
}
