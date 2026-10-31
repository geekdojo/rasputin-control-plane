package apps

import (
	"context"
	"database/sql"
	"fmt"
	"slices"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// secretNames is every secret name an app may have in the store: the names
// its app_secret_refs rows record, and every ${secret:} name in its compose
// and its previous compose (geekdojo/geekdojo-brain#783). The scanned names
// cover an app last deployed on v2026.10.2, which created store entries but
// recorded no references. Sorted, without duplicates. A compose the one token
// scanner refuses is an error: the set would be incomplete.
func secretNames(refs []string, composes ...string) ([]string, error) {
	names := slices.Clone(refs)
	for _, c := range composes {
		tokens, err := tileschema.ScanSecretTokens(c)
		if err != nil {
			return nil, fmt.Errorf("scanning the compose for secrets: %w", err)
		}
		for _, tok := range tokens {
			names = append(names, tok.Name)
		}
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

// queryer is what SecretRefNames reads through: the store's database or a
// transaction.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// SecretRefNames returns the names app appID's app_secret_refs rows record,
// sorted.
func (s *Store) SecretRefNames(ctx context.Context, appID string) ([]string, error) {
	return secretRefNames(ctx, s.db, appID)
}

func secretRefNames(ctx context.Context, q queryer, appID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT name FROM app_secret_refs WHERE app_id = ? ORDER BY name`, appID)
	if err != nil {
		return nil, fmt.Errorf("apps: secret refs of %s: %w", appID, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("apps: secret refs of %s: %w", appID, err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("apps: secret refs of %s: %w", appID, err)
	}
	return out, nil
}

// DeleteWithSecretNames deletes app id's row, and with it its app_secret_refs
// rows, and returns the secret names it had (secretNames over the recorded
// references and both composes). The names are read in the same transaction
// as the delete, because the references cascade with the row. A compose the
// scanner refuses rolls back and the row stays. A missing row is
// sql.ErrNoRows.
func (s *Store) DeleteWithSecretNames(ctx context.Context, id string) (names []string, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	var compose, previous string
	if err := tx.QueryRowContext(ctx, `SELECT compose_yaml, previous_compose_yaml FROM apps WHERE id = ?`, id).Scan(&compose, &previous); err != nil {
		return nil, err
	}
	refs, err := secretRefNames(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	names, err = secretNames(refs, compose, previous)
	if err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM apps WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return names, nil
}
