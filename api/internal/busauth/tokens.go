package busauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Tokens are high-entropy random strings; only their sha256 is stored, so a
// read of the DB doesn't leak usable credentials. The plaintext is returned
// to the operator exactly once at mint time (same one-shot model as mesh
// preauth keys).
//
// node_id binds a token to a single node id (the NATS username it will present):
// a token only authenticates as that node, so a token lifted from one node's
// seed is useless presented as any other. See
// design/os-images/token-provisioning-pipeline.md §3.
//
// Every token is bound (geekdojo-brain#423, decided 2026-09-16). The column
// stays nullable only because databases minted before that decision may hold
// UNBOUND rows (node_id NULL), which used to validate for any node id the
// connection chose. Nothing creates one any more — MintBound and PreloadHashes
// both refuse — and Validate refuses the ones that exist, so a legacy unbound
// token authenticates nothing. CountActiveUnbound finds them for the operator,
// who revokes them (DELETE /api/bus/tokens/{id}) and mints bound replacements.
//
// Every token also carries the ROLE of the node it was minted for (role.go).
// The same shape applies: the column is nullable only for rows written before
// it existed, OpenStore fills it wherever the row says what the role is, and
// Validate refuses a token whose row still names no role.
const schema = `
CREATE TABLE IF NOT EXISTS bus_tokens (
    token_hash   TEXT PRIMARY KEY,   -- sha256(plaintext) hex; the id
    label        TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at   INTEGER,
    node_id      TEXT,               -- bound node id; NULL only on a legacy unbound row
    self_agent   INTEGER NOT NULL DEFAULT 0, -- 1 on the token the api minted for this controlplane's own agent
    role         TEXT                -- the node role the token was minted for; NULL only on a legacy row (role.go)
);`

// Store is the SQLite-backed bus join-token ledger.
type Store struct {
	db *sql.DB

	// sess records the connections each token authenticated so a revoke can
	// close them (sessions.go). Empty until TrackSessions is called.
	sess sessions

	// selfMu guards selfNodeID, which EnsureAgentToken sets at api start and
	// the revoke paths read while serving.
	selfMu sync.RWMutex
	// selfNodeID is THIS controlplane's own node id — the id its co-located
	// agent authenticates as. Empty until EnsureAgentToken is called, which a
	// dev api with no RASPUTIN_SELF_NODE_ID never does; nothing is protected
	// then, because there is no api-minted agent token to protect.
	selfNodeID string
}

// TokenInfo is the non-secret view of a token row (no plaintext, ever).
type TokenInfo struct {
	ID     string  `json:"id"` // token_hash — stable handle for revoke
	Label  string  `json:"label"`
	NodeID *string `json:"nodeId,omitempty"` // bound node id, omitted when unbound
	// Role is the node role the token was minted for. Omitted on a legacy row
	// that names none, which the bus refuses (role.go).
	Role       proto.NodeRole `json:"role,omitempty"`
	CreatedAt  time.Time      `json:"createdAt"`
	LastUsedAt *time.Time     `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time     `json:"revokedAt,omitempty"`
	// SelfAgent marks the one token this api minted for its own controlplane's
	// agent: live, bound to this controlplane's node id, and carrying the
	// marker EnsureAgentToken sets. It is the token the revoke paths refuse
	// (ErrSelfAgentToken), so the UI must not offer the action for it.
	SelfAgent bool `json:"selfAgent,omitempty"`
}

// PreseedToken is a hash-only token record for preloading the store from a
// provisioning manifest. The controlplane never holds a plaintext token — only
// the sha256 verifier and the node id the token is bound to. Emitted by the
// rasputin-provision CLI, ingested via PreloadHashes.
type PreseedToken struct {
	Hash   string `json:"hash"`
	NodeID string `json:"nodeId"`
	Label  string `json:"label"`
	// Role is the node role the token is for. rasputin-provision writes it;
	// a manifest from before it did carries the role as the label, which
	// PreloadHashes reads instead (ResolveRole).
	Role proto.NodeRole `json:"role,omitempty"`
}

func OpenStore(ctx context.Context, path string) (*Store, error) {
	db, err := dbutil.Open(ctx, path, schema, "busauth")
	if err != nil {
		return nil, err
	}
	// Additive migration for DBs created before node binding. SQLite has no
	// "ADD COLUMN IF NOT EXISTS"; on a fresh DB the column already exists (the
	// CREATE TABLE above has it) so this is a no-op we swallow.
	if _, err := db.ExecContext(ctx, `ALTER TABLE bus_tokens ADD COLUMN node_id TEXT`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		_ = db.Close()
		return nil, fmt.Errorf("busauth: migrate node_id: %w", err)
	}
	// Same additive migration for the self_agent marker (agenttoken.go). Rows
	// written before it existed read as 0 — unmarked, and so revocable — until
	// EnsureAgentToken adopts the one the agent token file actually names at
	// the next start.
	if _, err := db.ExecContext(ctx, `ALTER TABLE bus_tokens ADD COLUMN self_agent INTEGER NOT NULL DEFAULT 0`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		_ = db.Close()
		return nil, fmt.Errorf("busauth: migrate self_agent: %w", err)
	}
	// The role column (role.go), and its backfill. The backfill runs on EVERY
	// open, not once: restoring an identity archive taken before this column
	// existed brings role-less rows back, and it is idempotent (it only fills
	// rows that have no role).
	if _, err := db.ExecContext(ctx, `ALTER TABLE bus_tokens ADD COLUMN role TEXT`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		_ = db.Close()
		return nil, fmt.Errorf("busauth: migrate role: %w", err)
	}
	if err := backfillRoles(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64     { return t.UnixMilli() }
func fromMs(v int64) time.Time { return time.UnixMilli(v).UTC() }

// HashToken returns the sha256-hex of a token plaintext — the stored id. Shared
// with the offline provisioning CLI so the validator and the minter can never
// disagree on the hashing scheme.
//
// CodeQL flags this as go/weak-sensitive-data-hashing (HIGH) — "insecure for
// password hashing, since it is not a computationally expensive hash function".
// False positive: this is not password hashing. Every verifier the store holds
// is the sha256 of a token GenerateToken produced — 32 bytes from crypto/rand,
// 256 bits of entropy, hex-encoded — whether it was minted here (mint) or
// offline by rasputin-provision and loaded as a preseed hash (PreloadHashes).
// The flow CodeQL reports is Validate hashing the join token a connecting
// client presents as its NATS password (callout.go): network input, but only
// ever looked up against those verifiers, so what an attacker has to guess is a
// 256-bit random value.
//
// Slow KDFs (bcrypt, scrypt, argon2) exist to make brute-force expensive
// against LOW-entropy, human-chosen secrets, where the keyspace is small enough
// that hash speed is the only thing standing between an attacker and the
// plaintext. A 256-bit random token has no such keyspace to search, so a slow
// KDF would buy nothing and would add its cost to every bus authentication.
//
// TRIP-WIRE: this rests entirely on every stored verifier being derived from a
// generated token, never a chosen one. If a verifier is ever stored for an
// operator-typed secret — a password, a passphrase, a PSK someone picks —
// whether through HashToken, PreloadHashes or anything else, this verdict is
// void and the finding becomes real. Today HashToken's callers are
// GenerateToken (used by MintBound and by rasputin-provision) and Validate (hashing
// a presented token for lookup), and PreloadHashes stores only the hashes
// rasputin-provision got from GenerateToken. The passkey session store
// (api/internal/auth/store.go) also uses it as its at-rest verifier for session
// cookies; those tokens are 32 bytes from crypto/rand (auth.randomToken), the
// same premise.
func HashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// GenerateToken returns a fresh high-entropy token and its hash (the id). Used
// by MintBound and by the offline rasputin-provision CLI. The plaintext is
// unrecoverable from the hash.
func GenerateToken() (plaintext, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("busauth: rand: %w", err)
	}
	plaintext = hex.EncodeToString(raw)
	return plaintext, HashToken(plaintext), nil
}

// ErrUnboundToken is returned (wrapped) wherever a token that names no node id
// is refused. Every token is bound to one node (geekdojo-brain#423).
var ErrUnboundToken = errors.New("unbound join token: every token must be bound to a node id")

// MintBound generates a fresh token bound to nodeID and role, stores its
// hash, and returns the plaintext ONCE along with its id (the hash); the
// plaintext is unrecoverable after this. Only a connection presenting nodeID
// as its NATS username can authenticate with the token.
//
// It is the only way to mint: there is no unbound mint (geekdojo-brain#423). An
// empty nodeID is refused with ErrUnboundToken, and any other id that fails
// ValidNodeID with ErrInvalidNodeID — the callout would never accept it as a
// username, so the token could never authenticate. A role that is not one of
// proto.AllRoles is refused with ErrNoRole, for the same reason: Validate
// refuses a token with no role.
func (s *Store) MintBound(ctx context.Context, label, nodeID string, role proto.NodeRole) (plaintext, id string, err error) {
	if nodeID == "" {
		return "", "", ErrUnboundToken
	}
	if err := checkNodeID(nodeID); err != nil {
		return "", "", err
	}
	if err := checkRole(role); err != nil {
		return "", "", err
	}
	plaintext, id, err = GenerateToken()
	if err != nil {
		return "", "", err
	}
	if _, err := s.db.ExecContext(ctx, `
        INSERT INTO bus_tokens (token_hash, label, created_at, node_id, role) VALUES (?, ?, ?, ?, ?)`,
		id, label, ms(time.Now().UTC()), nodeID, string(role)); err != nil {
		return "", "", fmt.Errorf("busauth: insert token: %w", err)
	}
	return plaintext, id, nil
}

// PreloadHashes idempotently inserts preseeded (hash, node-id) bindings — the
// controlplane half of a provisioning matched set. Re-running is a no-op
// (INSERT OR IGNORE on the hash PK), so it's safe to call on every boot, matching
// firstboot's derived-state contract. It inserts hashes directly and never sees
// a plaintext token. Returns the count of newly-inserted rows.
//
// Every entry's node id is checked BEFORE anything is inserted, and one bad
// entry fails the whole load with nothing stored: an entry naming no node id
// (ErrUnboundToken — every token is bound, geekdojo-brain#423) or an invalid
// one (ErrInvalidNodeID), the error naming the entry. Neither could ever
// authenticate, and rasputin-provision never emits either, so a manifest
// carrying one was hand-edited or corrupted — the same treatment an
// unparseable manifest already gets. The same goes for an entry whose role
// cannot be resolved (ErrNoRole): rasputin-provision has always written the
// node's role, as the label and now also as role. An entry with no hash
// carries nothing to store and is skipped.
func (s *Store) PreloadHashes(ctx context.Context, toks []PreseedToken) (int, error) {
	roles := make([]proto.NodeRole, len(toks))
	for i, tk := range toks {
		if tk.Hash == "" {
			continue
		}
		if tk.NodeID == "" {
			return 0, fmt.Errorf("busauth: preload entry %d: %w", i, ErrUnboundToken)
		}
		if err := checkNodeID(tk.NodeID); err != nil {
			return 0, fmt.Errorf("busauth: preload entry %d: %w", i, err)
		}
		role, err := ResolveRole(tk.Role, tk.Label)
		if err != nil {
			return 0, fmt.Errorf("busauth: preload entry %d (node %q): %w", i, tk.NodeID, err)
		}
		roles[i] = role
	}
	now := ms(time.Now().UTC())
	inserted := 0
	for i, tk := range toks {
		if tk.Hash == "" {
			continue
		}
		res, err := s.db.ExecContext(ctx, `
            INSERT OR IGNORE INTO bus_tokens (token_hash, label, created_at, node_id, role) VALUES (?, ?, ?, ?, ?)`,
			tk.Hash, tk.Label, now, tk.NodeID, string(roles[i]))
		if err != nil {
			return inserted, fmt.Errorf("busauth: preload: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			inserted++
		}
	}
	return inserted, nil
}

// Validate reports whether plaintext matches a live (non-revoked) token bound to
// presentedNodeID. A legacy UNBOUND token (node_id NULL, minted before
// geekdojo-brain#423) never validates, whatever id it is presented under, and
// the refusal is logged with the token's id so a node stranded by it can be
// found and re-provisioned. A legacy token whose row names no role (role.go)
// is refused the same way. It best-effort touches last_used_at. Constant work regardless of match isn't
// attempted — tokens are 256-bit random, so timing oracles on the indexed
// lookup don't help an attacker.
func (s *Store) Validate(ctx context.Context, plaintext, presentedNodeID string) (bool, error) {
	if plaintext == "" {
		return false, nil
	}
	id := HashToken(plaintext)
	var (
		revoked   sql.NullInt64
		boundNode sql.NullString
		role      sql.NullString
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT revoked_at, node_id, role FROM bus_tokens WHERE token_hash = ?`, id).Scan(&revoked, &boundNode, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("busauth: validate: %w", err)
	}
	if revoked.Valid {
		return false, nil
	}
	// Every token must be bound; a legacy unbound row authenticates nothing.
	if !boundNode.Valid || boundNode.String == "" {
		log.Printf("busauth: refused unbound join token id=%q presented as node=%q: every token must be bound to a node id (revoke it and mint one bound to the node)", id, presentedNodeID)
		return false, nil
	}
	// A token only authenticates as the node it was provisioned for.
	if boundNode.String != presentedNodeID {
		return false, nil
	}
	// Every token must name the role it was minted for; a legacy row that
	// names none authenticates nothing (geekdojo-brain#423 precedent).
	if !role.Valid || !proto.ValidRole(proto.NodeRole(role.String)) {
		log.Printf("busauth: refused join token id=%q for node=%q: %s", id, presentedNodeID, noRoleRemedy)
		return false, nil
	}
	_, _ = s.db.ExecContext(ctx,
		`UPDATE bus_tokens SET last_used_at = ? WHERE token_hash = ?`, ms(time.Now().UTC()), id)
	return true, nil
}

// Revoke marks a token revoked by its id (token_hash) and closes every live
// bus connection that authenticated with it, returning how many it closed.
// Returns sql.ErrNoRows if no such live token existed.
//
// It refuses THIS controlplane's own agent token with ErrSelfAgentToken: that
// revoke is a one-click self-inflicted outage with no way back from the UI
// (geekdojo-brain#140, decided 2026-09-17). See ErrSelfAgentToken.
//
// The closed count is exact for connections this process admitted: a revoked
// token's connections are all closed before Revoke returns (sessions.go). The
// agent's reconnect is then refused by the callout, because the row is revoked.
func (s *Store) Revoke(ctx context.Context, id string) (disconnected int, err error) {
	protected, err := s.isSelfAgentToken(ctx, id)
	if err != nil {
		return 0, err
	}
	if protected {
		return 0, ErrSelfAgentToken
	}
	return s.revoke(ctx, id)
}

// revoke is Revoke without the self-agent guard — the statement the api's own
// re-mint uses to retire a token it has just replaced (EnsureAgentToken). No
// request-driven path may call it: an operator revoke goes through Revoke.
func (s *Store) revoke(ctx context.Context, id string) (disconnected int, err error) {
	s.sess.mu.Lock()
	res, err := s.db.ExecContext(ctx,
		`UPDATE bus_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL`,
		ms(time.Now().UTC()), id)
	if err != nil {
		s.sess.mu.Unlock()
		return 0, fmt.Errorf("busauth: revoke: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		s.sess.mu.Unlock()
		return 0, sql.ErrNoRows
	}
	taken := s.takeLocked(func(g grant) bool { return g.tokenID == id })
	d := s.sess.disc
	s.sess.mu.Unlock()
	return s.disconnect(d, taken), nil
}

// RevokeByNodeID revokes every still-active token bound to nodeID and closes
// every live bus connection that authenticated as nodeID with a token,
// returning both counts. The node-removal cascade calls it so a removed node
// leaves no dangling enrollment token — which would otherwise resurface as a
// ghost "pending" bay on the node grid — and no live session. Idempotent:
// revoking zero tokens is not an error.
//
// It closes by node id rather than by the tokens it revoked: removal evicts
// the node, whichever token its session used. Every session Admit records was
// authenticated by a token bound to the node it presented, so a node's
// sessions and its tokens are the same set; a legacy unbound token cannot
// reconnect either, because Validate refuses it (geekdojo-brain#423).
//
// It refuses the controlplane's own node id with ErrSelfAgentToken and revokes
// nothing, for the same reason Revoke does. Its one caller — node removal —
// already refuses the controlplane node ahead of this (409, "the controlplane
// node cannot be removed"), so this is the backstop for a future caller, not a
// reachable path today.
func (s *Store) RevokeByNodeID(ctx context.Context, nodeID string) (revoked, disconnected int, err error) {
	protected, err := s.nodeHasSelfAgentToken(ctx, nodeID)
	if err != nil {
		return 0, 0, err
	}
	if protected {
		return 0, 0, ErrSelfAgentToken
	}
	s.sess.mu.Lock()
	res, err := s.db.ExecContext(ctx,
		`UPDATE bus_tokens SET revoked_at = ? WHERE node_id = ? AND revoked_at IS NULL`,
		ms(time.Now().UTC()), nodeID)
	if err != nil {
		s.sess.mu.Unlock()
		return 0, 0, fmt.Errorf("busauth: revoke by node: %w", err)
	}
	n, _ := res.RowsAffected()
	taken := s.takeLocked(func(g grant) bool { return g.nodeID == nodeID })
	d := s.sess.disc
	s.sess.mu.Unlock()
	return int(n), s.disconnect(d, taken), nil
}

// NodeHasLiveToken reports whether nodeID holds at least one token the bus
// would admit it with: unrevoked, bound to nodeID, and naming a valid role.
// It is how the node's other credentials follow its token: the collector
// ingress admits a node only while this holds, so revoking a node's token
// (or removing the node, which revokes them all) cuts its HTTPS pushes too.
func (s *Store) NodeHasLiveToken(ctx context.Context, nodeID string) (bool, error) {
	if nodeID == "" {
		return false, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT role FROM bus_tokens WHERE node_id = ? AND revoked_at IS NULL`, nodeID)
	if err != nil {
		return false, fmt.Errorf("busauth: live token for %q: %w", nodeID, err)
	}
	defer rows.Close()
	for rows.Next() {
		var role sql.NullString
		if err := rows.Scan(&role); err != nil {
			return false, fmt.Errorf("busauth: live token for %q: %w", nodeID, err)
		}
		if role.Valid && proto.ValidRole(proto.NodeRole(role.String)) {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("busauth: live token for %q: %w", nodeID, err)
	}
	return false, nil
}

// CountActiveUnbound returns how many live (unrevoked) legacy unbound tokens
// the store holds. Validate refuses every one of them, so a nonzero count
// means a node seeded with one cannot join; the api logs it at startup, and
// the tokens are listed by GET /api/bus/tokens with no nodeId.
func (s *Store) CountActiveUnbound(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `
        SELECT COUNT(*) FROM bus_tokens
        WHERE (node_id IS NULL OR node_id = '') AND revoked_at IS NULL`).Scan(&n); err != nil {
		return 0, fmt.Errorf("busauth: count unbound: %w", err)
	}
	return n, nil
}

// List returns all tokens (secret-free), newest first. SelfAgent is set on the
// one this controlplane's own agent holds, so a client can tell the token it
// must not offer to revoke from a node's enrollment token.
func (s *Store) List(ctx context.Context) ([]TokenInfo, error) {
	self := s.SelfNodeID()
	rows, err := s.db.QueryContext(ctx, `
        SELECT token_hash, label, node_id, created_at, last_used_at, revoked_at, self_agent, role
        FROM bus_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("busauth: list: %w", err)
	}
	defer rows.Close()
	var out []TokenInfo
	for rows.Next() {
		var (
			t                 TokenInfo
			createdAt         int64
			nodeID            sql.NullString
			lastUsed, revoked sql.NullInt64
			selfAgent         int
			role              sql.NullString
		)
		if err := rows.Scan(&t.ID, &t.Label, &nodeID, &createdAt, &lastUsed, &revoked, &selfAgent, &role); err != nil {
			return nil, err
		}
		if role.Valid && proto.ValidRole(proto.NodeRole(role.String)) {
			t.Role = proto.NodeRole(role.String)
		}
		// Exactly the predicate the revoke paths refuse on, so the UI never
		// offers an action the api would answer 409 to.
		t.SelfAgent = selfAgent == 1 && self != "" && nodeID.Valid && nodeID.String == self && !revoked.Valid
		t.CreatedAt = fromMs(createdAt)
		if nodeID.Valid {
			n := nodeID.String
			t.NodeID = &n
		}
		if lastUsed.Valid {
			lu := fromMs(lastUsed.Int64)
			t.LastUsedAt = &lu
		}
		if revoked.Valid {
			rv := fromMs(revoked.Int64)
			t.RevokedAt = &rv
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
