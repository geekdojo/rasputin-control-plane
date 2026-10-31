package apps

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// inUseSecretNames is the one secret token scanner's answer to "which
// ${secret:} names do these composes use" (geekdojo/geekdojo-brain#783,
// F-783-24): the names in each compose the scanner accepts. A compose the
// scanner refuses names no secret. That is exact, not an omission: the
// resolver scans before it makes any store call and refuses the deploy on a
// scan error, so such a compose has never read or created an entry. Sorted,
// without duplicates.
func inUseSecretNames(composes ...string) []string {
	var names []string
	for _, c := range composes {
		tokens, err := tileschema.ScanSecretTokens(c)
		if err != nil {
			continue
		}
		for _, tok := range tokens {
			names = append(names, tok.Name)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// secretNames is every secret name an app may have in the store: the names
// its app_secret_refs rows record, and every name inUseSecretNames finds in
// its compose and its previous compose. The scanned names cover an app last
// deployed on v2026.10.2, which created store entries but recorded no
// references. Sorted, without duplicates.
func secretNames(refs []string, composes ...string) []string {
	names := append(slices.Clone(refs), inUseSecretNames(composes...)...)
	slices.Sort(names)
	return slices.Compact(names)
}

// queryer is what the secret name reads go through: the store's database or
// a transaction.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
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
// as the delete, because the references cascade with the row. A missing row
// is sql.ErrNoRows.
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
	names = secretNames(refs, compose, previous)
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

// UnusedSecretRefs returns the names app appID's app_secret_refs rows record
// that neither its compose nor its previous compose uses, and that neither
// its operator-secret declarations nor the previous ones declare
// (geekdojo/geekdojo-brain#783, F-783-19, F-783-29). The previous compose and
// declarations count, so the rollback target keeps its secrets. It writes nothing. A missing row is
// sql.ErrNoRows.
func (s *Store) UnusedSecretRefs(ctx context.Context, appID string) ([]string, error) {
	return unusedSecretRefs(ctx, s.db, appID)
}

func unusedSecretRefs(ctx context.Context, q queryer, appID string) ([]string, error) {
	var compose, previous, declared, previousDeclared string
	if err := q.QueryRowContext(ctx, `SELECT compose_yaml, previous_compose_yaml, operator_secrets, previous_operator_secrets FROM apps WHERE id = ?`, appID).
		Scan(&compose, &previous, &declared, &previousDeclared); err != nil {
		return nil, fmt.Errorf("apps: composes of %s: %w", appID, err)
	}
	refs, err := secretRefNames(ctx, q, appID)
	if err != nil {
		return nil, err
	}
	inUse := inUseSecretNames(compose, previous)
	// An operator secret either manifest declares is in use whether or not a
	// compose places it (F-783-29): the declaration is the durable statement
	// that the app still wants the value its owner typed in. A column that
	// does not decode fails the read, and nothing is released (ERR-CLOSED).
	for _, col := range []struct{ name, raw string }{{"operator_secrets", declared}, {"previous_operator_secrets", previousDeclared}} {
		decls, err := decodeOperatorSecrets(appID, col.name, col.raw)
		if err != nil {
			return nil, err
		}
		for _, d := range decls {
			inUse = append(inUse, d.Name)
		}
	}
	slices.Sort(inUse)
	inUse = slices.Compact(inUse)
	var unused []string
	for _, r := range refs {
		if _, found := slices.BinarySearch(inUse, r); !found {
			unused = append(unused, r)
		}
	}
	return unused, nil
}

// DropUnusedSecretRefs deletes, in one transaction, the app_secret_refs rows
// of app appID that UnusedSecretRefs names as it reads them inside that
// transaction, and returns their names. A name a compose change put back in
// use since an earlier read is kept. The ref row goes before the store entry,
// as S15 orders it. A missing row is sql.ErrNoRows, and nothing is deleted.
func (s *Store) DropUnusedSecretRefs(ctx context.Context, appID string) (dropped []string, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("apps: drop unused secret refs of %s: %w", appID, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	unused, err := unusedSecretRefs(ctx, tx, appID)
	if err != nil {
		return nil, err
	}
	for _, name := range unused {
		if _, err := tx.ExecContext(ctx, `DELETE FROM app_secret_refs WHERE app_id = ? AND name = ?`, appID, name); err != nil {
			return nil, fmt.Errorf("apps: drop secret ref %s/%s: %w", appID, name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("apps: drop unused secret refs of %s: %w", appID, err)
	}
	return unused, nil
}

// AppSecretNames is one app's secret names, as node removal reads them: every
// name the app may have in the store (secretNames), and how many of them its
// app_secret_refs rows record.
type AppSecretNames struct {
	AppID        string
	Names        []string
	RecordedRefs int
}

// SecretNamesByTargetNode reads AppSecretNames for every app whose
// target_node is nodeID, ordered by app id. It writes nothing.
func (s *Store) SecretNamesByTargetNode(ctx context.Context, nodeID string) ([]AppSecretNames, error) {
	return secretNamesByTargetNode(ctx, s.db, nodeID)
}

func secretNamesByTargetNode(ctx context.Context, q queryer, nodeID string) ([]AppSecretNames, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, compose_yaml, previous_compose_yaml FROM apps WHERE target_node = ? ORDER BY id`, nodeID)
	if err != nil {
		return nil, fmt.Errorf("apps: apps of node %s: %w", nodeID, err)
	}
	type row struct{ id, compose, previous string }
	var read []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.compose, &r.previous); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("apps: apps of node %s: %w", nodeID, err)
		}
		read = append(read, r)
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return nil, fmt.Errorf("apps: apps of node %s: %w", nodeID, err)
	}
	out := make([]AppSecretNames, 0, len(read))
	for _, r := range read {
		refs, err := secretRefNames(ctx, q, r.id)
		if err != nil {
			return nil, err
		}
		out = append(out, AppSecretNames{AppID: r.id, Names: secretNames(refs, r.compose, r.previous), RecordedRefs: len(refs)})
	}
	return out, nil
}

// DeleteByTargetNodeWithSecretNames removes every apps row whose target_node
// is nodeID, and with them their app_secret_refs rows, and returns each
// app's AppSecretNames read in the same transaction, because the references
// cascade with the rows. A node with no apps returns an empty result and
// writes nothing.
//
// Contract: this removes *deployments* targeting the node — never a shared
// catalog entry. In today's schema each apps row IS both the catalog
// definition and the deployment (target_node is on the same row, name is
// UNIQUE), so deleting by target_node and "removing the deployment" are
// the same operation.
func (s *Store) DeleteByTargetNodeWithSecretNames(ctx context.Context, nodeID string) (removed []AppSecretNames, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("apps: delete apps of node %s: %w", nodeID, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	removed, err = secretNamesByTargetNode(ctx, tx, nodeID)
	if err != nil {
		return nil, err
	}
	if len(removed) == 0 {
		return removed, tx.Rollback()
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM apps WHERE target_node = ?`, nodeID); err != nil {
		return nil, fmt.Errorf("apps: delete apps of node %s: %w", nodeID, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("apps: delete apps of node %s: %w", nodeID, err)
	}
	return removed, nil
}
