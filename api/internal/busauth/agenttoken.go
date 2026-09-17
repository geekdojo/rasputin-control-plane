package busauth

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The controlplane's own agent holds a join token like every other node
// (geekdojo/geekdojo-brain#140): the bus trusts no connection for coming from
// loopback. The api mints that token itself, so first boot needs no step from
// anyone — see proto.BusAgentTokenFileName for the file contract.

// AgentTokenLabel labels the token the api mints for its own agent, so an
// operator listing tokens can tell it from a provisioned one.
const AgentTokenLabel = "controlplane agent (minted by the api at start)"

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
	reason, err = s.agentTokenProblem(ctx, path, nodeID)
	if err != nil || reason == "" {
		return "", err
	}

	plaintext, id, err := s.MintBound(ctx, AgentTokenLabel, nodeID)
	if err != nil {
		return "", fmt.Errorf("busauth: mint the controlplane agent's token: %w", err)
	}
	if err := writeOwnerOnlyFile(path, []byte(plaintext+"\n")); err != nil {
		if _, rerr := s.Revoke(ctx, id); rerr != nil {
			log.Printf("busauth: revoking the unwritten controlplane agent token id=%q: %v", id, rerr)
		}
		return "", fmt.Errorf("busauth: write the controlplane agent's token to %s: %w", path, err)
	}
	if _, _, err := s.revokeNodeTokensExcept(ctx, nodeID, id); err != nil {
		// The new token is written and live; the old ones stay live too
		// until the next start retries. Say so, and carry on.
		return reason, fmt.Errorf("busauth: the new controlplane agent token is in place, but revoking the ones it replaces failed: %w", err)
	}
	return reason, nil
}

// agentTokenProblem returns why the file at path is not a usable token for
// nodeID, or "" when it is. An error means the check itself could not run
// (the token store failed), and nothing should be minted on its account.
func (s *Store) agentTokenProblem(ctx context.Context, path, nodeID string) (string, error) {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "there is no token file", nil
	case err != nil:
		return fmt.Sprintf("the token file cannot be inspected (%v)", err), nil
	case !fi.Mode().IsRegular():
		return fmt.Sprintf("the token file is not a regular file (%s)", fi.Mode().Type()), nil
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Sprintf("the token file's mode is %#o, open to more than its owner, so the token may have been read", fi.Mode().Perm()), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("the token file cannot be read (%v)", err), nil
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "the token file is empty", nil
	}
	ok, err := s.Validate(ctx, token, nodeID)
	if err != nil {
		return "", err
	}
	if !ok {
		return fmt.Sprintf("the token in the file is not a live token bound to %q (revoked, from a restored database, or from another controlplane)", nodeID), nil
	}
	return "", nil
}

// revokeNodeTokensExcept revokes every live token bound to nodeID except keep,
// and closes the sessions they admitted. RevokeByNodeID would close the new
// token's sessions too, which is why this is its own statement.
func (s *Store) revokeNodeTokensExcept(ctx context.Context, nodeID, keep string) (revoked, disconnected int, err error) {
	s.sess.mu.Lock()
	res, err := s.db.ExecContext(ctx,
		`UPDATE bus_tokens SET revoked_at = ? WHERE node_id = ? AND token_hash != ? AND revoked_at IS NULL`,
		ms(time.Now().UTC()), nodeID, keep)
	if err != nil {
		s.sess.mu.Unlock()
		return 0, 0, fmt.Errorf("busauth: revoke replaced tokens: %w", err)
	}
	n, _ := res.RowsAffected()
	taken := s.takeLocked(func(g grant) bool { return g.nodeID == nodeID && g.tokenID != keep })
	d := s.sess.disc
	s.sess.mu.Unlock()
	return int(n), s.disconnect(d, taken), nil
}

// writeOwnerOnlyFile replaces path with data atomically: a 0600 temporary file
// in the same directory, synced, renamed over path, and the directory synced.
// The rename replaces whatever was at path, a symlink included, and never
// writes through it. The directory is created 0700 when it does not exist; an
// existing one keeps its mode.
func writeOwnerOnlyFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // a no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync() // durability of the rename; not every platform supports it
		_ = d.Close()
	}
	return nil
}
