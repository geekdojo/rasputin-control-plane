package busauth

import (
	"context"
	"sync"
)

// Revoke = force-disconnect (certificates.md §4.2(1), decided 2026-07-03 and
// made the ONLY stolen-token control on 2026-09-16, when expiry and rotation
// were ruled out): revoking a token must also close every live bus connection
// that authenticated with it, not merely refuse the next reconnect. Without
// this a connected compromised node keeps its session for the minted JWT's
// whole 24h lifetime.
//
// # Mechanism
//
// The auth callout reports the id of the server asking and the
// server-assigned connection id (CID) of the connection it is authenticating.
// Admit records (server id, CID) → (token, node id) for every token it
// accepts; Revoke and RevokeByNodeID close exactly the recorded connections
// through the embedded server (bus.Server.DisconnectClient).
//
// The server id is part of the key because a CID is unique within one server
// only. The api replaces its embedded server in-process when the bus switches
// to TLS-only (bus.Server.SetAllowNonTLS, geekdojo/geekdojo-brain#448), and
// the new server numbers connections from the start again. A record from the
// old server — including one an auth request queued before the switch writes
// after it — must never close a connection on the new one: the Disconnector
// answers false for any server id but the running server's, and prune drops
// such records.
//
// Rejected alternatives:
//
//   - Scan the server's live connections (Connz) for the node's username. The
//     name a callout user is registered under is only set once the server has
//     processed the callout's reply, so a connection whose callout is still in
//     flight is invisible to the scan — exactly the race below — and a scan
//     cannot tell which TOKEN a connection used, which revoking one of a
//     node's tokens (a re-mint leaves it holding two) needs.
//   - JWT user revocation on the account. The callout mints a fresh user nkey
//     per connection, so there is no stable key to revoke, and account
//     revocations are an operator-mode (JWT account) feature the non-operator
//     embedded server does not run.
//   - Short JWT TTLs. The TTL is the backstop, not the control: it bounds how
//     long a kick can be missed, and shortening it churns every healthy node.
//
// # Concurrency
//
// A revoke racing a reconnect must not leave a session alive. Admit validates
// and records under mu; Revoke writes revoked_at and snapshots the records
// under the same mu. So either Admit's validation ran after the revoke
// committed (and refused the token), or its record exists when Revoke
// snapshots (and the CID is closed). The close itself happens outside the lock
// and is safe at any point in the connection's life: a CID is registered with
// the server before its CONNECT is processed, so a kick that lands while the
// callout reply is still in flight makes the server refuse the authentication.
//
// Every connection passes through Admit, the controlplane's own agent's
// included: the bus trusts no connection for coming from loopback
// (geekdojo/geekdojo-brain#140). Revoking the token the api minted for that
// agent disconnects it like any other node, and the api mints it a new one at
// its next start (Store.EnsureAgentToken).

// Disconnector closes client connections on the embedded bus.
// *bus.Server implements it. A connection is named by the id of the server it
// is on and its connection id on that server; a server id other than the
// running server's names no open connection.
type Disconnector interface {
	// ClientOpen reports whether the connection is still registered.
	ClientOpen(serverID string, cid uint64) bool
	// DisconnectClient closes the connection; false if it was already gone.
	DisconnectClient(serverID string, cid uint64) bool
}

// Conn names the connection being authenticated: the server asking, its id
// for the connection, and the host the server saw the connection come from.
// The auth callout fills it from the authorization request
// (jwt.ClientInformation).
type Conn struct {
	ServerID string
	CID      uint64
	// Host is the client's address as the server saw it. It is not an
	// identity and nothing is authorized by it — it only tells one presenter
	// of a token from another when a session is taken over (takeover.go).
	Host string
}

// session names one connection: the server it is on and its id there.
type session struct {
	serverID string
	cid      uint64
}

// grant is one connection a join token authenticated.
type grant struct {
	tokenID string // token_hash
	nodeID  string // the node id the connection presented
	host    string // the host that presented it; see Conn.Host
}

// heldSession is a recorded session together with what it was granted.
type heldSession struct {
	session
	grant
}

// sessions is the Store's record of token-authenticated connections.
type sessions struct {
	mu     sync.Mutex
	disc   Disconnector
	grants map[session]grant

	// afterValidate, when set, runs inside Admit after the token has validated
	// and before the grant is recorded, with mu held. Tests only: it opens the
	// exact window a revoke would have to race into.
	afterValidate func()
}

// TrackSessions makes the store record every connection Admit accepts and
// close those connections when their token is revoked. Call it once, before
// the auth-callout responder starts; with no Disconnector (bus auth off) the
// store records nothing and revocation only refuses future connections —
// which, on an unauthenticated bus, is all a token ever gated.
func (s *Store) TrackSessions(d Disconnector) {
	s.sess.mu.Lock()
	defer s.sess.mu.Unlock()
	s.sess.disc = d
	if s.sess.grants == nil {
		s.sess.grants = make(map[session]grant)
	}
}

// Admit is the auth callout's token check for the connection conn names:
// Validate, plus — when sessions are tracked — a record of the grant so a
// later revoke can close that connection, and the eviction of whatever session
// the same token already held (takeover.go: a token holds ONE live session,
// and the newest wins). See the concurrency note above for why validating and
// recording happen under one lock.
//
// The eviction happens after the lock is released, like revoke's: closing a
// connection reaches into the server, and nothing here needs it to have
// finished. The new session is recorded before the old one is closed, so a
// revoke that arrives in between still finds — and closes — the new one.
func (s *Store) Admit(ctx context.Context, conn Conn, plaintext, presentedNodeID string) (bool, error) {
	s.sess.mu.Lock()
	ok, err := s.Validate(ctx, plaintext, presentedNodeID)
	if err != nil || !ok {
		s.sess.mu.Unlock()
		return false, err
	}
	if s.sess.disc == nil {
		s.sess.mu.Unlock()
		return true, nil
	}
	if s.sess.afterValidate != nil {
		s.sess.afterValidate()
	}
	// Prune first: a session the node has already dropped is not a second
	// presenter, so an ordinary agent reconnect evicts nothing and is not
	// recorded as a takeover.
	s.pruneLocked()
	id := HashToken(plaintext)
	superseded := s.takeHeldLocked(func(g grant) bool { return g.tokenID == id })
	s.sess.grants[session{serverID: conn.ServerID, cid: conn.CID}] = grant{tokenID: id, nodeID: presentedNodeID, host: conn.Host}
	d := s.sess.disc
	s.sess.mu.Unlock()

	s.evictSuperseded(d, conn, id, presentedNodeID, superseded)
	return true, nil
}

// pruneLocked drops records for connections that have since closed, so the
// table tracks live sessions rather than every connection ever made. It runs
// on each grant, which bounds the table by the live connections plus those
// closed since the previous grant — no timer involved. CIDs are never reused
// within a server's lifetime, and a server that was replaced never comes back,
// so a closed session cannot reopen.
func (s *Store) pruneLocked() {
	for k := range s.sess.grants {
		if !s.sess.disc.ClientOpen(k.serverID, k.cid) {
			delete(s.sess.grants, k)
		}
	}
}

// takeLocked removes and returns every recorded session match selects.
func (s *Store) takeLocked(match func(grant) bool) []session {
	held := s.takeHeldLocked(match)
	out := make([]session, 0, len(held))
	for _, h := range held {
		out = append(out, h.session)
	}
	return out
}

// takeHeldLocked is takeLocked with the grant each session held — what a
// takeover needs to name the presenter it evicted.
func (s *Store) takeHeldLocked(match func(grant) bool) []heldSession {
	var out []heldSession
	for k, g := range s.sess.grants {
		if match(g) {
			out = append(out, heldSession{session: k, grant: g})
			delete(s.sess.grants, k)
		}
	}
	return out
}

// disconnect closes sessions and returns how many were still open.
func (s *Store) disconnect(d Disconnector, sessions []session) int {
	n := 0
	for _, k := range sessions {
		if d.DisconnectClient(k.serverID, k.cid) {
			n++
		}
	}
	return n
}
