package auth

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// ConsoleSessions is the console's session store in rasputin.db
// (geekdojo/geekdojo-brain#989, register row C72): one row per signed-in
// browser, keyed by the hash of its cookie. The cookie is 32 random bytes;
// only busauth.HashToken of it is stored, so the database holds nothing a
// request could present. No token the identity service issued is ever
// stored: the session names the account (sub), its identity session (sid)
// and its console roles at sign-in.
//
// A session ends on sign-out (Delete), a back-channel logout of its sid
// (EndBySID), a change to the account's roles (EndBySub), and at
// sessionLifetime after it began, which Resolve enforces and DeleteExpired
// tidies.
//
// The first sign-in of first run also claims the first administrator, in
// the same transaction as its session (CreateWithClaim,
// geekdojo/geekdojo-brain#990).
type ConsoleSessions struct {
	db         *sql.DB
	now        func() time.Time
	rand       io.Reader
	designator Designator
}

// Designator records the claimed account's designation inside the claim's
// own transaction (*accounts.Designations): its console role admin and app
// access admin, reason first_admin, which accounts.grant_designated_role
// grants once the account holds a second step and recovery codes (C29).
type Designator interface {
	DesignateFirstAdmin(ctx context.Context, tx *sql.Tx, sub string) error
}

// Claim is a first-run claim CreateWithClaim tries to commit: the account
// the identity service created first.
type Claim struct{ Sub string }

// consoleSessionsSchema is created by OpenStore with the rest of the schema.
const consoleSessionsSchema = `
CREATE TABLE IF NOT EXISTS console_sessions (
    token_hash     TEXT PRIMARY KEY,       -- busauth.HashToken of the cookie; the cookie itself is never stored
    sub            TEXT NOT NULL,          -- the identity service's subject
    sid            TEXT NOT NULL,          -- the identity service's session id
    roles          TEXT NOT NULL,          -- JSON list of console roles at sign-in
    name           TEXT NOT NULL,          -- preferred_username, display only
    created_at     INTEGER NOT NULL,
    last_active_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_console_sessions_sub ON console_sessions(sub);
CREATE INDEX IF NOT EXISTS idx_console_sessions_sid ON console_sessions(sid);
`

// sessionCookieBytes is the cookie's length in random bytes.
const sessionCookieBytes = 32

// NewConsoleSessions is the store over store's database, with the clock,
// the randomness the cookies are made from, and the designator a first-run
// claim records its designation through. It refuses a missing one.
func NewConsoleSessions(store *Store, now func() time.Time, rand io.Reader, designator Designator) (*ConsoleSessions, error) {
	switch {
	case store == nil:
		return nil, errors.New("auth: NewConsoleSessions: store is nil")
	case now == nil:
		return nil, errors.New("auth: NewConsoleSessions: now is nil")
	case rand == nil:
		return nil, errors.New("auth: NewConsoleSessions: rand is nil")
	case designator == nil:
		return nil, errors.New("auth: NewConsoleSessions: designator is nil")
	}
	return &ConsoleSessions{db: store.db, now: now, rand: rand, designator: designator}, nil
}

// Create stores a session for p and returns its cookie value.
func (c *ConsoleSessions) Create(ctx context.Context, p Principal) (secret.Value, error) {
	cookie, _, err := c.CreateWithClaim(ctx, p, nil)
	return cookie, err
}

// CreateWithClaim stores a session for p and, when claim is set, commits the
// first-run claim in the same transaction: a first_admin row naming
// claim.Sub, inserted only while neither first_admin nor users holds a row,
// checked in the same statement, and on that insert the claimed account's
// designation (Designator). claimed reports that this call made the claim.
//
// Write transactions begin IMMEDIATE on a one-connection pool (dbutil.Open),
// so two callbacks serialize, and the second sees the first one's row and
// claims nothing. Any error rolls everything back: no claim, no
// designation and no session, and a users or first_admin table that can't
// be read is such an error (C03, ERR-CLOSED).
func (c *ConsoleSessions) CreateWithClaim(ctx context.Context, p Principal, claim *Claim) (secret.Value, bool, error) {
	if p.Sub == "" || p.Session.SID == "" {
		return secret.Value{}, false, errors.New("auth: a console session needs a subject and a session id")
	}
	if claim != nil && claim.Sub == "" {
		return secret.Value{}, false, errors.New("auth: a first-run claim needs a subject")
	}
	raw := make([]byte, sessionCookieBytes)
	if _, err := io.ReadFull(c.rand, raw); err != nil {
		return secret.Value{}, false, fmt.Errorf("auth: console session cookie: %w", err)
	}
	text := []byte(hex.EncodeToString(raw))
	clear(raw)
	cookie := secret.New(text)
	clear(text)
	claimed, err := c.store(ctx, p, claim, cookie)
	if err != nil {
		cookie.Destroy()
		return secret.Value{}, false, err
	}
	return cookie, claimed, nil
}

// store is CreateWithClaim's transaction.
func (c *ConsoleSessions) store(ctx context.Context, p Principal, claim *Claim, cookie secret.Value) (bool, error) {
	roles, err := json.Marshal(nonNil(p.Roles))
	if err != nil {
		return false, fmt.Errorf("auth: console session roles: %w", err)
	}
	now := c.now().UTC()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("auth: store console session: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	claimed := false
	if claim != nil {
		res, err := tx.ExecContext(ctx, `
            INSERT INTO first_admin (id, sub, claimed_at)
            SELECT 1, ?, ?
            WHERE NOT EXISTS (SELECT 1 FROM first_admin) AND NOT EXISTS (SELECT 1 FROM users)`,
			claim.Sub, ms(now))
		if err != nil {
			return false, fmt.Errorf("auth: first-run claim: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return false, fmt.Errorf("auth: first-run claim: %w", err)
		}
		if n == 1 {
			if err := c.designator.DesignateFirstAdmin(ctx, tx, claim.Sub); err != nil {
				return false, fmt.Errorf("auth: first-run claim: designate: %w", err)
			}
			claimed = true
		}
	}
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO console_sessions (token_hash, sub, sid, roles, name, created_at, last_active_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		hashCookie(cookie), p.Sub, p.Session.SID, string(roles), p.Name, ms(now), ms(now)); err != nil {
		return false, fmt.Errorf("auth: store console session: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("auth: store console session: %w", err)
	}
	return claimed, nil
}

// Resolve returns the Principal of the session cookie names, and false when
// there is none or it has reached sessionLifetime, in which case the row is
// deleted.
func (c *ConsoleSessions) Resolve(ctx context.Context, cookie secret.Value) (Principal, bool, error) {
	if cookie.Len() == 0 {
		return Principal{}, false, nil
	}
	h := hashCookie(cookie)
	var (
		p                    Principal
		roles                string
		createdAt, lastTouch int64
	)
	err := c.db.QueryRowContext(ctx, `
        SELECT sub, sid, roles, name, created_at, last_active_at
        FROM console_sessions WHERE token_hash = ?`, h).
		Scan(&p.Sub, &p.Session.SID, &roles, &p.Name, &createdAt, &lastTouch)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, false, nil
	}
	if err != nil {
		return Principal{}, false, fmt.Errorf("auth: read console session: %w", err)
	}
	p.Session.CreatedAt = fromMs(createdAt)
	if !c.now().UTC().Before(p.Session.CreatedAt.Add(sessionLifetime)) {
		if _, err := c.db.ExecContext(ctx, `DELETE FROM console_sessions WHERE token_hash = ?`, h); err != nil {
			return Principal{}, false, fmt.Errorf("auth: delete expired console session: %w", err)
		}
		return Principal{}, false, nil
	}
	if err := json.Unmarshal([]byte(roles), &p.Roles); err != nil {
		return Principal{}, false, fmt.Errorf("auth: console session roles: %w", err)
	}
	return p, true, nil
}

// Touch records that the session cookie names was used now.
func (c *ConsoleSessions) Touch(ctx context.Context, cookie secret.Value) error {
	_, err := c.db.ExecContext(ctx, `UPDATE console_sessions SET last_active_at = ? WHERE token_hash = ?`,
		ms(c.now().UTC()), hashCookie(cookie))
	return err
}

// Delete ends the session cookie names and returns its sid, "" when there
// was none.
func (c *ConsoleSessions) Delete(ctx context.Context, cookie secret.Value) (string, error) {
	h := hashCookie(cookie)
	var sid string
	err := c.db.QueryRowContext(ctx, `DELETE FROM console_sessions WHERE token_hash = ? RETURNING sid`, h).Scan(&sid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("auth: delete console session: %w", err)
	}
	return sid, nil
}

// EndBySID ends every session signed in under the identity session sid (a
// back-channel logout) and returns how many it ended.
func (c *ConsoleSessions) EndBySID(ctx context.Context, sid string) (int64, error) {
	return c.end(ctx, `DELETE FROM console_sessions WHERE sid = ?`, sid)
}

// EndBySub ends every session of the account sub (a role change; Identity
// 4.9 and 4.12's account changes) and returns how many it ended.
func (c *ConsoleSessions) EndBySub(ctx context.Context, sub string) (int64, error) {
	return c.end(ctx, `DELETE FROM console_sessions WHERE sub = ?`, sub)
}

func (c *ConsoleSessions) end(ctx context.Context, query, key string) (int64, error) {
	if key == "" {
		return 0, errors.New("auth: ending console sessions needs a key")
	}
	res, err := c.db.ExecContext(ctx, query, key)
	if err != nil {
		return 0, fmt.Errorf("auth: end console sessions: %w", err)
	}
	return res.RowsAffected()
}

// DeleteExpired removes every session that has reached sessionLifetime.
func (c *ConsoleSessions) DeleteExpired(ctx context.Context) error {
	_, err := c.db.ExecContext(ctx, `DELETE FROM console_sessions WHERE created_at <= ?`,
		ms(c.now().UTC().Add(-sessionLifetime)))
	return err
}

// hashCookie is the stored form of a cookie value.
func hashCookie(cookie secret.Value) string {
	return busauth.HashToken(string(cookie.Reveal()))
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
