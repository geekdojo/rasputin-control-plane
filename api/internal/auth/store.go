package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	_ "modernc.org/sqlite"
)

// Store is the SQLite-backed user/credential/session ledger.
type Store struct {
	db *sql.DB
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("auth: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("auth: apply schema: %w", err)
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
			log.Printf("auth: migration %q: %v", stmt, err)
		}
	}
}

func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64 { return t.UnixMilli() }
func msPtr(t time.Time) any { return t.UnixMilli() }
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
	return s.scanUser(ctx, row.Scan)
}

func (s *Store) GetUserByName(ctx context.Context, name string) (*User, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, name, display_name, created_at, last_login_at
        FROM users WHERE name = ?`, name)
	return s.scanUser(ctx, row.Scan)
}

func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, name, display_name, created_at, last_login_at
        FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := s.scanUser(ctx, rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) UpdateLastLogin(ctx context.Context, id []byte, ts time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET last_login_at = ? WHERE id = ?`, ms(ts), id)
	return err
}

func (s *Store) scanUser(ctx context.Context, scan func(...any) error) (*User, error) {
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
	creds, err := s.listCredentialsForUser(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	u.credentials = make([]webauthn.Credential, 0, len(creds))
	for _, c := range creds {
		u.credentials = append(u.credentials, c.toWebAuthn())
	}
	return &u, nil
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

func (s *Store) CreateSession(ctx context.Context, sess *Session) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO sessions (token, user_id, created_at, expires_at, last_active_at)
        VALUES (?, ?, ?, ?, ?)`,
		sess.Token, sess.UserID,
		ms(sess.CreatedAt), ms(sess.ExpiresAt), ms(sess.LastActiveAt))
	return err
}

func (s *Store) GetSession(ctx context.Context, token string) (*Session, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT token, user_id, created_at, expires_at, last_active_at
        FROM sessions WHERE token = ?`, token)
	var (
		sess         Session
		createdAt    int64
		expiresAt    int64
		lastActiveAt int64
	)
	if err := row.Scan(&sess.Token, &sess.UserID, &createdAt, &expiresAt, &lastActiveAt); err != nil {
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

func (s *Store) TouchSession(ctx context.Context, token string, ts time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET last_active_at = ? WHERE token = ?`, ms(ts), token)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token)
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
