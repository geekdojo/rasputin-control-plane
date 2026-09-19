package busauth

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The controlplane's own agent holds a join token like every other node
// (geekdojo/geekdojo-brain#140): the bus trusts no connection for coming from
// loopback. The api mints that token itself, so first boot needs no step from
// anyone — see proto.BusAgentTokenFileName for the file contract.

// AgentTokenLabel labels the token the api mints for its own agent, so an
// operator listing tokens can tell it from a provisioned one. It is display
// text only: nothing keys a decision off it, because an operator can mint a
// token with any label they like. The self_agent column is what the revoke
// paths read (see isSelfAgentToken).
const AgentTokenLabel = "controlplane agent (minted by the api at start)"

// ErrSelfAgentToken is returned wherever a revoke would take THIS
// controlplane's own agent off the bus (geekdojo-brain#140, decided
// 2026-09-17).
//
// The api mints and re-mints that token only at start (EnsureAgentToken), so a
// revoke is a one-click self-inflicted outage: the controlplane's agent is
// refused at its next connect, every verb that rides its own agent stops, and
// nothing in the UI mints a replacement — recovery is a shell on the
// controlplane and an api restart.
//
// Refusing costs nothing, because a revoke of this token contains no
// compromise: the plaintext lives only in <dataDir>/bus/agent.token, 0600
// root-owned, and anyone who can read it is already root on the controlplane —
// where the bus signing key and the token database itself are.
//
// The remedy it names is the one that works: EnsureAgentToken re-mints only
// when the token file is missing or unusable, so a bare restart keeps the same
// token. Removing the file first is what makes the next start mint a fresh
// token and revoke this one.
var ErrSelfAgentToken = errors.New("the controlplane's own bus agent token cannot be revoked: the api minted it for this controlplane's agent, and revoking it would take that agent off the bus with no way back from the UI — to rotate it, delete bus/" + proto.BusAgentTokenFileName + " in the api's data directory (/var/lib/rasputin on an appliance) and restart the api, which then mints a fresh token and revokes this one")

// SelfNodeID returns the node id of the controlplane this api runs on — the id
// its co-located agent authenticates as — or "" when there is none. It is set
// by EnsureAgentToken, so an api that never calls it (a dev api with no
// RASPUTIN_SELF_NODE_ID) protects nothing, which is right: it minted no agent
// token.
func (s *Store) SelfNodeID() string {
	s.selfMu.RLock()
	defer s.selfMu.RUnlock()
	return s.selfNodeID
}

func (s *Store) setSelfNodeID(nodeID string) {
	s.selfMu.Lock()
	s.selfNodeID = nodeID
	s.selfMu.Unlock()
}

// isSelfAgentToken reports whether id is this controlplane's own live agent
// token.
//
// Identification deliberately does NOT read the label: AgentTokenLabel is
// display text an operator can mint a lookalike of, and a token minted by an
// older api carries it too. It takes BOTH halves of what the store knows:
//
//   - the self_agent marker, which only adoptSelfAgentToken writes, and only
//     for the token EnsureAgentToken minted or found live in the agent token
//     file; and
//   - the bound node id matching this api's own node id, so a marked row that
//     arrived in a database copied or restored from ANOTHER controlplane
//     protects nothing here.
//
// A revoked row is not protected — it is already off the bus, and the operator
// may want it gone.
func (s *Store) isSelfAgentToken(ctx context.Context, id string) (bool, error) {
	self := s.SelfNodeID()
	if self == "" || id == "" {
		return false, nil
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `
        SELECT COUNT(*) FROM bus_tokens
        WHERE token_hash = ? AND node_id = ? AND self_agent = 1 AND revoked_at IS NULL`,
		id, self).Scan(&n); err != nil {
		return false, fmt.Errorf("busauth: check whether %q is the controlplane agent's token: %w", id, err)
	}
	return n > 0, nil
}

// nodeHasSelfAgentToken reports whether nodeID is this controlplane's own node
// id AND it holds a live marked agent token — the by-node form of the same
// question, for RevokeByNodeID.
func (s *Store) nodeHasSelfAgentToken(ctx context.Context, nodeID string) (bool, error) {
	self := s.SelfNodeID()
	if self == "" || nodeID != self {
		return false, nil
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `
        SELECT COUNT(*) FROM bus_tokens
        WHERE node_id = ? AND self_agent = 1 AND revoked_at IS NULL`, self).Scan(&n); err != nil {
		return false, fmt.Errorf("busauth: check whether node %q holds the controlplane agent's token: %w", nodeID, err)
	}
	return n > 0, nil
}

// adoptSelfAgentToken makes id the ONE token bound to nodeID that carries the
// self_agent marker: it marks id and clears the marker from every other row
// bound to nodeID. It is the only writer of the column. The marked row is the
// controlplane's own agent, so its role is proto.RoleControlPlane (role.go).
//
// Clearing the others is what keeps "at most one protected token per
// controlplane" true across a re-mint whose revoke of the replaced tokens
// failed, and across an upgrade from a build that never wrote the column —
// there the agent token file's own row is adopted at the first start, so a
// controlplane that has been running since before this change is protected
// without minting anything.
func (s *Store) adoptSelfAgentToken(ctx context.Context, id, nodeID string) error {
	if id == "" || nodeID == "" {
		return nil
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE bus_tokens SET self_agent = 1, role = ? WHERE token_hash = ? AND node_id = ?`,
		string(proto.RoleControlPlane), id, nodeID); err != nil {
		return fmt.Errorf("busauth: mark the controlplane agent's token: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE bus_tokens SET self_agent = 0 WHERE node_id = ? AND token_hash != ?`, nodeID, id); err != nil {
		return fmt.Errorf("busauth: unmark the controlplane agent's replaced tokens: %w", err)
	}
	s.refreshNodes(ctx, nodeID) // adoption can give the row its role
	return nil
}

// EnsureAgentToken makes sure path holds a live join token bound to nodeID —
// the controlplane's own node id — and returns why it minted a new one, or ""
// when the file it found was good.
//
// It checks VALIDITY, not existence. The file is replaced when it is missing,
// is not a regular file, is readable or writable by anyone but its owner (the
// token may have been read, so it is rotated rather than chmodded), is empty,
// or does not validate as a live token bound to nodeID. That last case is an
// identity restore (the restored database never saw this file's token), a
// revoke, or a file copied from another controlplane; each re-mints cleanly.
//
// A new token is minted and written (atomically, 0600, in a directory created
// 0700 if missing) BEFORE the tokens it replaces are revoked, so a failure at
// any step leaves the previous credential as it was: a mint whose write fails
// is revoked again, and nothing else changes.
//
// It is called at api start, before the auth-callout responder starts, so no
// session can yet hold a replaced token; the revoke still closes any that do.
func (s *Store) EnsureAgentToken(ctx context.Context, path, nodeID string) (reason string, err error) {
	if nodeID == "" {
		return "", ErrUnboundToken
	}
	if err := checkNodeID(nodeID); err != nil {
		return "", err
	}
	// From here on the store knows which node id is this controlplane's own,
	// so the operator revoke paths can refuse to cut its agent off the bus
	// (ErrSelfAgentToken). Set before anything can fail, so the protection is
	// armed even on a start where the mint below does not finish.
	s.setSelfNodeID(nodeID)

	reason, liveID, err := s.agentTokenProblem(ctx, path, nodeID)
	if err != nil {
		return "", err
	}
	if reason == "" {
		// The file is good. Adopt the row it names, which is how a token
		// minted by a build that predates the marker becomes protected.
		s.adopt(ctx, liveID, nodeID)
		return "", nil
	}

	plaintext, id, err := s.MintBound(ctx, AgentTokenLabel, nodeID, proto.RoleControlPlane)
	if err != nil {
		return "", fmt.Errorf("busauth: mint the controlplane agent's token: %w", err)
	}
	if err := atrest.WriteSecretFile(path, []byte(plaintext+"\n")); err != nil {
		// s.revoke, not Revoke: this is the api retiring a token of its own
		// that never reached the file, which the operator guard must not stop.
		if _, rerr := s.revoke(ctx, id); rerr != nil {
			log.Printf("busauth: revoking the unwritten controlplane agent token id=%q: %v", id, rerr)
		}
		return "", fmt.Errorf("busauth: write the controlplane agent's token to %s: %w", path, err)
	}
	s.adopt(ctx, id, nodeID)
	if _, _, err := s.revokeNodeTokensExcept(ctx, nodeID, id); err != nil {
		// The new token is written and live; the old ones stay live too
		// until the next start retries. Say so, and carry on.
		return reason, fmt.Errorf("busauth: the new controlplane agent token is in place, but revoking the ones it replaces failed: %w", err)
	}
	return reason, nil
}

// adopt records id as the controlplane agent's token, logging a failure rather
// than failing the start. A store that has answered every query up to here
// failing this UPDATE is not a reason to leave the controlplane without its
// agent; the cost is that this one token stays revocable until the next start.
func (s *Store) adopt(ctx context.Context, id, nodeID string) {
	if err := s.adoptSelfAgentToken(ctx, id, nodeID); err != nil {
		log.Printf("busauth: %v — a revoke of it would not be refused until the next start", err)
	}
}

// agentTokenProblem returns why the file at path is not a usable token for
// nodeID, or "" when it is. When it is usable, liveID is that token's id, so
// the caller can adopt the row it names. An error means the check itself could
// not run (the token store failed), and nothing should be minted on its
// account.
func (s *Store) agentTokenProblem(ctx context.Context, path, nodeID string) (reason, liveID string, err error) {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "there is no token file", "", nil
	case err != nil:
		return fmt.Sprintf("the token file cannot be inspected (%v)", err), "", nil
	case !fi.Mode().IsRegular():
		return fmt.Sprintf("the token file is not a regular file (%s)", fi.Mode().Type()), "", nil
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Sprintf("the token file's mode is %#o, open to more than its owner, so the token may have been read", fi.Mode().Perm()), "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("the token file cannot be read (%v)", err), "", nil
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "the token file is empty", "", nil
	}
	ok, err := s.Validate(ctx, token, nodeID)
	if err != nil {
		return "", "", err
	}
	if !ok {
		return fmt.Sprintf("the token in the file is not a live token bound to %q (revoked, from a restored database, or from another controlplane)", nodeID), "", nil
	}
	return "", HashToken(token), nil
}

// revokeNodeTokensExcept revokes every live token bound to nodeID except keep,
// and closes the sessions they admitted. RevokeByNodeID would close the new
// token's sessions too, which is why this is its own statement.
func (s *Store) revokeNodeTokensExcept(ctx context.Context, nodeID, keep string) (revoked, disconnected int, err error) {
	defer s.refreshNodes(ctx, nodeID)
	s.sess.mu.Lock()
	tombs, err := s.revokeReturning(ctx, time.Now().UTC(),
		`UPDATE bus_tokens SET revoked_at = ? WHERE node_id = ? AND token_hash != ? AND revoked_at IS NULL
         RETURNING token_hash, COALESCE(node_id, '')`, nodeID, keep)
	if err != nil {
		s.sess.mu.Unlock()
		return 0, 0, fmt.Errorf("busauth: revoke replaced tokens: %w", err)
	}
	taken := s.takeLocked(func(g grant) bool { return g.nodeID == nodeID && g.tokenID != keep })
	d := s.sess.disc
	s.sess.mu.Unlock()
	s.recordTombstones(tombs)
	return len(tombs), s.disconnect(d, taken), nil
}
