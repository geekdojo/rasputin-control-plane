package backupxfer

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The upload credential — §4.1's "scoped, short-lived upload credential",
// defined rather than hand-waved.
//
// # Shape
//
// A Grant, JSON-encoded, signed with HMAC-SHA-256 under a key the api holds
// only in memory:
//
//	rbx1.<base64url(grant JSON)>.<base64url(hmac)>
//
// The api verifies it STATELESSLY: parse, recompute the MAC, compare in
// constant time, check the clock. There is no token table, no lookup, and
// nothing to leak from a database read — the token never touches disk on
// either side.
//
// # Why a signed grant and not a stored random token
//
// A stored token needs a row per volume per run, a sweep for the expired
// ones, and a read on every upload; a signed grant needs a key. The key is
// minted at api start from crypto/rand and lives only in the process, which
// is exactly the lifetime a credential should have: a backup run does not
// survive an api restart (saga policy is abort, not resume — architecture.md
// §13 decision 12), so a credential that dies with the process loses nothing
// and gains that nothing at rest can mint one. Refusing reuse after a member
// lands is still stateless — the member EXISTS, and the endpoint never
// overwrites — and refusing a credential after its run ends is one field:
// the grant names the job, and Ingest checks it against the generation that
// is open.
//
// # Scope, in one sentence
//
// One destination (the endpoint that holds the key), one generation, one
// member, one node, one run, until ExpiresAt. Every field is checked against
// the request AND against what the endpoint has open; a grant that matches
// the request but names a closed run is refused.

// tokenPrefix names the format. A token that does not start with it is not
// ours and is refused before anything is decoded.
const tokenPrefix = "rbx1"

// CredentialTTL is how long a freshly minted credential is honoured: the
// agent's transfer budget plus the api's round-trip slack, and nothing more.
// The api mints the credential immediately before it sends the transfer verb,
// so this is the whole window in which the member can be uploaded — a leaked
// credential is dead within it whether or not anything else happens.
const CredentialTTL = proto.BackupTransferWork + 5*time.Minute

// clockSkew is how far into the future a grant's IssuedAt may sit before it is
// refused as not-yet-valid. Both ends are on one LAN with one NTP source; a
// minute is generous.
const clockSkew = time.Minute

// Grant is what a credential authorises. Every field is scope: a request that
// does not match all of them is refused.
type Grant struct {
	// Generation and Member name the ONE file this credential may create.
	Generation string `json:"gen"`
	Member     string `json:"mem"`
	// NodeID is the node the credential was issued to. Logged on every
	// upload so the ledger says which node landed which member.
	NodeID string `json:"node"`
	// JobID is the backup.run this credential belongs to. The endpoint refuses
	// a credential whose run is not the one with a generation open.
	JobID string `json:"job"`
	// IssuedAt and ExpiresAt bound the credential's life, Unix seconds.
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
	// Nonce makes two grants for the same member distinguishable in a log
	// (a retry after a stalled upload mints a fresh one).
	Nonce string `json:"n"`
}

// ID is a short, publishable name for the grant — the nonce. Safe in a log
// line or a ledger row; it is not the credential and cannot be turned into one.
func (g Grant) ID() string { return g.Nonce }

// The refusals, as sentinel errors so the endpoint maps them to codes rather
// than matching on text.
var (
	ErrCredentialMalformed = errors.New("backupxfer: credential is not a token this endpoint issues")
	ErrCredentialSignature = errors.New("backupxfer: credential signature does not verify")
	ErrCredentialExpired   = errors.New("backupxfer: credential has expired")
	ErrCredentialNotYet    = errors.New("backupxfer: credential is not valid yet")
	ErrGrantShape          = errors.New("backupxfer: grant names a generation or member of the wrong shape")
)

// Authority mints and verifies credentials under one in-memory key.
type Authority struct {
	key []byte
	now func() time.Time
}

// NewAuthority mints a fresh 256-bit key from crypto/rand. One per api
// process; there is deliberately no way to load a key from disk.
func NewAuthority() (*Authority, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("backupxfer: authority key: %w", err)
	}
	return &Authority{key: key, now: time.Now}, nil
}

// withClock replaces the clock. Tests only.
func (a *Authority) withClock(now func() time.Time) *Authority {
	a.now = now
	return a
}

// Mint issues a credential for g, valid for ttl from now. IssuedAt, ExpiresAt
// and Nonce are filled in here; a caller cannot back-date or extend a grant.
func (a *Authority) Mint(g Grant, ttl time.Duration) (string, error) {
	if a == nil || len(a.key) == 0 {
		return "", errors.New("backupxfer: no authority key")
	}
	if !proto.BackupValidGenerationID(g.Generation) || !proto.BackupValidMemberPath(g.Member) {
		return "", ErrGrantShape
	}
	if strings.TrimSpace(g.NodeID) == "" || strings.TrimSpace(g.JobID) == "" {
		return "", errors.New("backupxfer: a grant names its node and its run")
	}
	if ttl <= 0 || ttl > CredentialTTL {
		return "", fmt.Errorf("backupxfer: credential ttl %s is outside (0, %s]", ttl, CredentialTTL)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	now := a.now().UTC()
	g.IssuedAt = now.Unix()
	g.ExpiresAt = now.Add(ttl).Unix()
	g.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	body, err := json.Marshal(g)
	if err != nil {
		return "", err
	}
	payload := tokenPrefix + "." + base64.RawURLEncoding.EncodeToString(body)
	return payload + "." + base64.RawURLEncoding.EncodeToString(a.mac(payload)), nil
}

// Verify parses and checks a credential, returning its grant. It checks the
// signature BEFORE it decodes the grant, the clock after, and the grant's
// shape last — so a forged token is refused without any of its content being
// interpreted.
func (a *Authority) Verify(token string) (Grant, error) {
	var g Grant
	if a == nil || len(a.key) == 0 {
		return g, errors.New("backupxfer: no authority key")
	}
	token = strings.TrimSpace(token)
	if len(token) > 4096 {
		return g, ErrCredentialMalformed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != tokenPrefix {
		return g, ErrCredentialMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return g, ErrCredentialMalformed
	}
	payload := parts[0] + "." + parts[1]
	if !hmac.Equal(sig, a.mac(payload)) {
		return g, ErrCredentialSignature
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return g, ErrCredentialMalformed
	}
	if err := json.Unmarshal(body, &g); err != nil {
		return g, ErrCredentialMalformed
	}
	now := a.now().UTC().Unix()
	if g.ExpiresAt <= now {
		return g, ErrCredentialExpired
	}
	if g.IssuedAt > now+int64(clockSkew.Seconds()) {
		return g, ErrCredentialNotYet
	}
	if !proto.BackupValidGenerationID(g.Generation) || !proto.BackupValidMemberPath(g.Member) ||
		strings.TrimSpace(g.NodeID) == "" || strings.TrimSpace(g.JobID) == "" {
		return g, ErrGrantShape
	}
	return g, nil
}

func (a *Authority) mac(payload string) []byte {
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(payload))
	return m.Sum(nil)
}
