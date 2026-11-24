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
type ConsoleSessions struct {
	db   *sql.DB
	now  func() time.Time
	rand io.Reader
}

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

// NewConsoleSessions is the store over store's database, with the clock and
// the randomness the cookies are made from.
func NewConsoleSessions(store *Store, now func() time.Time, rand io.Reader) (*ConsoleSessions, error) {
	switch {
	case store == nil:
		return nil, errors.New("auth: NewConsoleSessions: store is nil")
	case now == nil:
		return nil, errors.New("auth: NewConsoleSessions: now is nil")
	case rand == nil:
		return nil, errors.New("auth: NewConsoleSessions: rand is nil")
	}
	return &ConsoleSessions{db: store.db, now: now, rand: rand}, nil
}

// Create stores a session for p and returns its cookie value.
func (c *ConsoleSessions) Create(ctx context.Context, p Principal) (secret.Value, error) {
	if p.Sub == "" || p.Session.SID == "" {
		return secret.Value{}, errors.New("auth: a console session needs a subject and a session id")
	}
	raw := make([]byte, sessionCookieBytes)
	if _, err := io.ReadFull(c.rand, raw); err != nil {
		return secret.Value{}, fmt.Errorf("auth: console session cookie: %w", err)
	}
	text := []byte(hex.EncodeToString(raw))
	clear(raw)
	cookie := secret.New(text)
	clear(text)
	roles, err := json.Marshal(nonNil(p.Roles))
	if err != nil {
		cookie.Destroy()
		return secret.Value{}, fmt.Errorf("auth: console session roles: %w", err)
	}
	now := c.now().UTC()
	if _, err := c.db.ExecContext(ctx, `
        INSERT INTO console_sessions (token_hash, sub, sid, roles, name, created_at, last_active_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		hashCookie(cookie), p.Sub, p.Session.SID, string(roles), p.Name, ms(now), ms(now)); err != nil {
		cookie.Destroy()
		return secret.Value{}, fmt.Errorf("auth: store console session: %w", err)
	}
	return cookie, nil
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
