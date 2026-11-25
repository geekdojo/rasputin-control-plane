package auth

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// movedNamespace is the fixed namespace a moved account's id is named
// under. It never changes: a moved account's id is derived from it.
var movedNamespace = uuid.MustParse("7589372d-61ac-4162-9efa-0eaa139cb8d0")

// MovedAccountID is the identity service's account id a pre-update user
// with the 16-byte handle is moved to (lifecycle.md §3): a name-based UUID
// (version 5) over the handle under a fixed namespace, so the move is
// idempotent. identity.move (geekdojo/geekdojo-brain#1004) uses it.
func MovedAccountID(handle []byte) string {
	return uuid.NewSHA1(movedNamespace, handle).String()
}

// RemoveMovedRows deletes the pre-update credentials and sessions rows of
// the old user moved to the account sub (C15), in one transaction. It never
// deletes the users row. With no old user moved to sub it deletes nothing
// and returns 0 and 0.
func (s *Store) RemoveMovedRows(ctx context.Context, sub string) (creds, sessions int64, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("auth: remove moved rows: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM users`)
	if err != nil {
		return 0, 0, fmt.Errorf("auth: remove moved rows: read users: %w", err)
	}
	var handle []byte
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, 0, fmt.Errorf("auth: remove moved rows: read users: %w", err)
		}
		if handle == nil && MovedAccountID(id) == sub {
			handle = id
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, 0, fmt.Errorf("auth: remove moved rows: read users: %w", err)
	}
	_ = rows.Close()
	if handle == nil {
		return 0, 0, nil
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM credentials WHERE user_id = ?`, handle)
	if err != nil {
		return 0, 0, fmt.Errorf("auth: remove moved rows: credentials: %w", err)
	}
	creds, _ = res.RowsAffected()
	res, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, handle)
	if err != nil {
		return 0, 0, fmt.Errorf("auth: remove moved rows: sessions: %w", err)
	}
	sessions, _ = res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("auth: remove moved rows: commit: %w", err)
	}
	return creds, sessions, nil
}
