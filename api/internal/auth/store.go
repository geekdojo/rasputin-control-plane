package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Store is the SQLite-backed user/credential/session ledger.
type Store struct {
	db *sql.DB
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	db, err := dbutil.Open(ctx, path, schema, "auth")
	if err != nil {
		return nil, err
	}
	applyMigrations(ctx, db)
	if err := migrateSessionHash(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
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
			log.Printf("auth: migration %q: %v", stmt, err)
		}
	}
}

func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64     { return t.UnixMilli() }
func fromMs(v int64) time.Time { return time.UnixMilli(v).UTC() }

// ----- Users --------------------------------------------------------------

// CountUsers returns the number of registered users. Used by the api's
// /api/auth/status endpoint to decide whether to show first-run setup.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) CreateUser(ctx context.Context, u *User) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO users (id, name, display_name, created_at)
        VALUES (?, ?, ?, ?)`,
		u.ID, u.Name, u.DisplayName, ms(u.CreatedAt))
	return err
}

func (s *Store) GetUserByID(ctx context.Context, id []byte) (*User, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, name, display_name, created_at, last_login_at
        FROM users WHERE id = ?`, id)
	u, err := scanUserRow(row.Scan)
	if err != nil || u == nil {
		return u, err
	}
	if err := s.loadCredentials(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) GetUserByName(ctx context.Context, name string) (*User, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, name, display_name, created_at, last_login_at
        FROM users WHERE name = ?`, name)
	u, err := scanUserRow(row.Scan)
	if err != nil || u == nil {
		return u, err
	}
	if err := s.loadCredentials(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// ListUsers returns all users with their credentials. The user rows are read
// into memory and the rows iterator is closed BEFORE credentials are fetched,
// because db.SetMaxOpenConns(1) makes a per-row credential query while the
// outer rows still hold the connection a hard deadlock.
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, name, display_name, created_at, last_login_at
        FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	var out []*User
	for rows.Next() {
		u, err := scanUserRow(rows.Scan)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for _, u := range out {
		if err := s.loadCredentials(ctx, u); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) UpdateLastLogin(ctx context.Context, id []byte, ts time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET last_login_at = ? WHERE id = ?`, ms(ts), id)
	return err
}

// scanUserRow decodes a single users-row into a User WITHOUT touching the
// credentials table. Callers must invoke loadCredentials separately once the
// originating rows iterator (if any) has been closed.
func scanUserRow(scan func(...any) error) (*User, error) {
	var (
		u           User
		createdAt   int64
		lastLoginAt sql.NullInt64
	)
	if err := scan(&u.ID, &u.Name, &u.DisplayName, &createdAt, &lastLoginAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	u.CreatedAt = fromMs(createdAt)
	if lastLoginAt.Valid {
		t := fromMs(lastLoginAt.Int64)
		u.LastLoginAt = &t
	}
	return &u, nil
}

func (s *Store) loadCredentials(ctx context.Context, u *User) error {
	creds, err := s.listCredentialsForUser(ctx, u.ID)
	if err != nil {
		return err
	}
	u.credentials = make([]webauthn.Credential, 0, len(creds))
	for _, c := range creds {
		u.credentials = append(u.credentials, c.toWebAuthn())
	}
	return nil
}

// ----- Credentials --------------------------------------------------------

func (s *Store) CreateCredential(ctx context.Context, c *Credential) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO credentials (id, user_id, public_key, attestation, transports,
                                 aaguid, sign_count, clone_warning,
                                 backup_eligible, backup_state, nickname,
                                 created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.UserID, c.PublicKey, c.AttestationType,
		encodeTransports(c.Transports), c.AAGUID,
		c.SignCount, boolToInt(c.CloneWarning),
		boolToInt(c.BackupEligible), boolToInt(c.BackupState),
		c.Nickname, ms(c.CreatedAt))
	return err
}

// UpdateCredentialAfterLogin refreshes sign_count, clone_warning, and
// backup_state (BS can legitimately change). BackupEligible (BE) is set at
// registration and must NEVER change — the WebAuthn library aborts login if
// it does, so we deliberately don't update it here.
func (s *Store) UpdateCredentialAfterLogin(ctx context.Context, c *webauthn.Credential, lastUsed time.Time) error {
	_, err := s.db.ExecContext(ctx, `
        UPDATE credentials
        SET sign_count = ?, clone_warning = ?, backup_state = ?, last_used_at = ?
        WHERE id = ?`,
		c.Authenticator.SignCount, boolToInt(c.Authenticator.CloneWarning),
		boolToInt(c.Flags.BackupState), ms(lastUsed), c.ID)
	return err
}

func (s *Store) listCredentialsForUser(ctx context.Context, userID []byte) ([]*Credential, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, user_id, public_key, attestation, transports, aaguid,
               sign_count, clone_warning, backup_eligible, backup_state,
               nickname, created_at, last_used_at
        FROM credentials WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Credential
	for rows.Next() {
		var (
			c              Credential
			transports     string
			cloneWarning   int
			backupEligible int
			backupState    int
			createdAt      int64
			lastUsedAt     sql.NullInt64
			aaguid         sql.RawBytes
		)
		if err := rows.Scan(&c.ID, &c.UserID, &c.PublicKey, &c.AttestationType,
			&transports, &aaguid, &c.SignCount, &cloneWarning,
			&backupEligible, &backupState,
			&c.Nickname, &createdAt, &lastUsedAt); err != nil {
			return nil, err
		}
		c.Transports = decodeTransports(transports)
		if len(aaguid) > 0 {
			c.AAGUID = append([]byte(nil), aaguid...)
		}
		c.CloneWarning = cloneWarning != 0
		c.BackupEligible = backupEligible != 0
		c.BackupState = backupState != 0
		c.CreatedAt = fromMs(createdAt)
		if lastUsedAt.Valid {
			t := fromMs(lastUsedAt.Int64)
			c.LastUsedAt = &t
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// UserHandleForCredential returns the user-handle (== users.id) that owns the
// given credential id. Used by the discoverable-login finish step.
func (s *Store) UserHandleForCredential(ctx context.Context, credID []byte) ([]byte, error) {
	var userID []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id FROM credentials WHERE id = ?`, credID).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return userID, err
}

// ----- Sessions -----------------------------------------------------------
//
// Session tokens are stored hashed (token_hash = busauth.HashToken(token)),
// rolled out as expand/contract because an A/B rollback boots the previous
// api against this same database, and that api reads only the plaintext
// token column. A session it cannot find is an operator locked out of an
// appliance that has no account recovery.
//
// This is the EXPAND release:
//   - CreateSession writes both the plaintext token and its hash;
//   - lookups try the hash first and fall back to the plaintext column;
//   - every OpenStore backfills token_hash for rows that lack it, because an
//     identity-archive restore (or a rollback to an api that predates the
//     column) brings plaintext-only rows back;
//   - no row is ever deleted by the migration.
//
// CONTRACT (a later release, NOT this one): stop writing the plaintext token
// and clear it from existing rows. Its trigger is a checkable fact, not a
// date: it ships only once the api in the OTHER RAUC slot is at least this
// expand release, so a rollback always lands on an api that can look a
// session up by its hash. Until then the plaintext column must keep being
// written. Rows are never deleted by either step.

// migrateSessionHash adds the token_hash column and its unique index to a DB
// that predates them, then backfills the hash for every row that has a
// plaintext token and no hash. Idempotent: it runs on every open, and a second
// run finds nothing to do.
func migrateSessionHash(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `ALTER TABLE sessions ADD COLUMN token_hash TEXT`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("auth: migrate sessions.token_hash: %w", err)
	}
	// NULLs are distinct in a SQLite UNIQUE index, so rows written by an
	// older api (no hash yet) never conflict with each other here.
	if _, err := db.ExecContext(ctx,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash)`); err != nil {
		return fmt.Errorf("auth: index sessions.token_hash: %w", err)
	}
	if err := backfillSessionHashes(ctx, db); err != nil {
		return fmt.Errorf("auth: backfill sessions.token_hash: %w", err)
	}
	return nil
}

// backfillSessionHashes sets token_hash on every row that has a plaintext
// token and no hash. Rows are only updated, never deleted. A row whose hash
// another row already carries is left alone rather than failing the open.
func backfillSessionHashes(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Read every candidate before writing: the DB is capped at one
	// connection, so the rows iterator must be closed before the updates.
	rows, err := tx.QueryContext(ctx, `
        SELECT token FROM sessions
        WHERE token_hash IS NULL AND token IS NOT NULL AND token <> ''`)
	if err != nil {
		return err
	}
	var tokens []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			_ = rows.Close()
			return err
		}
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, t := range tokens {
		h := busauth.HashToken(t)
		if _, err := tx.ExecContext(ctx, `
            UPDATE sessions SET token_hash = ?
            WHERE token = ? AND token_hash IS NULL
              AND NOT EXISTS (SELECT 1 FROM sessions WHERE token_hash = ?)`,
			h, t, h); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CreateSession stores the session with BOTH its plaintext token and the
// token's hash (expand release; see the Sessions section comment).
func (s *Store) CreateSession(ctx context.Context, sess *Session) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO sessions (token, token_hash, user_id, created_at, expires_at, last_active_at)
        VALUES (?, ?, ?, ?, ?, ?)`,
		sess.Token, busauth.HashToken(sess.Token), sess.UserID,
		ms(sess.CreatedAt), ms(sess.ExpiresAt), ms(sess.LastActiveAt))
	return err
}

// GetSession returns the session the presented token names, or nil. It looks
// the token up by its hash first and falls back to the plaintext column, which
// only rows written by an older api (or restored from an older archive, before
// the next open backfills them) still need. The returned Session carries the
// presented token, so TouchSession/DeleteSession can be called with it.
func (s *Store) GetSession(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		return nil, nil
	}
	sess, err := s.getSession(ctx, sessionByHash, busauth.HashToken(token))
	if err != nil || sess != nil {
		if sess != nil {
			sess.Token = token
		}
		return sess, err
	}
	sess, err = s.getSession(ctx, sessionByPlaintext, token)
	if sess != nil {
		sess.Token = token
	}
	return sess, err
}

const (
	sessionByHash = `
        SELECT user_id, created_at, expires_at, last_active_at
        FROM sessions WHERE token_hash = ?`
	sessionByPlaintext = `
        SELECT user_id, created_at, expires_at, last_active_at
        FROM sessions WHERE token = ?`
)

// getSession reads the one session row query (sessionByHash or
// sessionByPlaintext) matches for arg, or nil.
func (s *Store) getSession(ctx context.Context, query, arg string) (*Session, error) {
	row := s.db.QueryRowContext(ctx, query, arg)
	var (
		sess         Session
		createdAt    int64
		expiresAt    int64
		lastActiveAt int64
	)
	if err := row.Scan(&sess.UserID, &createdAt, &expiresAt, &lastActiveAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	sess.CreatedAt = fromMs(createdAt)
	sess.ExpiresAt = fromMs(expiresAt)
	sess.LastActiveAt = fromMs(lastActiveAt)
	return &sess, nil
}

// TouchSession and DeleteSession match the row by hash or by plaintext, so a
// row written before the hash column existed is still reachable.
func (s *Store) TouchSession(ctx context.Context, token string, ts time.Time) error {
	if token == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET last_active_at = ? WHERE token_hash = ? OR token = ?`,
		ms(ts), busauth.HashToken(token), token)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE token_hash = ? OR token = ?`,
		busauth.HashToken(token), token)
	return err
}

func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, ms(now))
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
