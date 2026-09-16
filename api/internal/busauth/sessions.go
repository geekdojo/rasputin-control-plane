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
// The auth callout reports the server-assigned connection id (CID) of the
// connection it is authenticating. Admit records CID → (token, node id) for
// every token it accepts; Revoke and RevokeByNodeID close exactly the recorded
// CIDs through the embedded server (bus.Server.DisconnectClient).
//
// Rejected alternatives:
//
//   - Scan the server's live connections (Connz) for the node's username. The
//     name a callout user is registered under is only set once the server has
//     processed the callout's reply, so a connection whose callout is still in
//     flight is invisible to the scan — exactly the race below — and a scan
//     cannot tell which TOKEN a connection used, which revoking one unbound
//     token (valid for any node id) needs.
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
// Loopback connections (the controlplane's own tokenless agent) never pass
// through Admit, so no revoke disconnects them: they present no token, and
// the controlplane node cannot be removed.

// Disconnector closes client connections on the embedded bus.
// *bus.Server implements it.
type Disconnector interface {
	// ClientOpen reports whether the connection is still registered.
	ClientOpen(cid uint64) bool
	// DisconnectClient closes the connection; false if it was already gone.
	DisconnectClient(cid uint64) bool
}

// grant is one connection a join token authenticated.
type grant struct {
	tokenID string // token_hash
	nodeID  string // the node id the connection presented
}

// sessions is the Store's record of token-authenticated connections.
type sessions struct {
	mu     sync.Mutex
	disc   Disconnector
	grants map[uint64]grant

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
		s.sess.grants = make(map[uint64]grant)
	}
}

// Admit is the auth callout's token check for the connection with server id
// cid: Validate, plus — when sessions are tracked — a record of the grant so a
// later revoke can close that connection. See the concurrency note above for
// why both happen under one lock.
func (s *Store) Admit(ctx context.Context, cid uint64, plaintext, presentedNodeID string) (bool, error) {
	s.sess.mu.Lock()
	defer s.sess.mu.Unlock()
	ok, err := s.Validate(ctx, plaintext, presentedNodeID)
	if err != nil || !ok {
		return false, err
	}
	if s.sess.disc == nil {
		return true, nil
	}
	if s.sess.afterValidate != nil {
		s.sess.afterValidate()
	}
	s.pruneLocked()
	s.sess.grants[cid] = grant{tokenID: HashToken(plaintext), nodeID: presentedNodeID}
	return true, nil
}

// pruneLocked drops records for connections that have since closed, so the
// table tracks live sessions rather than every connection ever made. It runs
// on each grant, which bounds the table by the live connections plus those
// closed since the previous grant — no timer involved. CIDs are never reused
// within a server's lifetime, so a closed CID cannot come back.
func (s *Store) pruneLocked() {
	for cid := range s.sess.grants {
		if !s.sess.disc.ClientOpen(cid) {
			delete(s.sess.grants, cid)
		}
	}
}

// takeLocked removes and returns the CIDs of every record match selects.
func (s *Store) takeLocked(match func(grant) bool) []uint64 {
	var cids []uint64
	for cid, g := range s.sess.grants {
		if match(g) {
			cids = append(cids, cid)
			delete(s.sess.grants, cid)
		}
	}
	return cids
}

// disconnect closes cids and returns how many were still open.
func (s *Store) disconnect(d Disconnector, cids []uint64) int {
	n := 0
	for _, cid := range cids {
		if d.DisconnectClient(cid) {
			n++
		}
	}
	return n
}
