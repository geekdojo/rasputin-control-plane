package busauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// readTokenFile returns the token in an agent token file, failing the test if
// there is none.
func readTokenFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		t.Fatal("the token file is empty")
	}
	return tok
}

// agentTokenPath is a fresh <dataDir>/bus/agent.token whose bus dir does not
// exist yet, as on a first boot with no seed-written bus files.
func agentTokenPath(t *testing.T) string {
	return filepath.Join(t.TempDir(), "bus", proto.BusAgentTokenFileName)
}

// liveTokensFor returns the ids of the live tokens bound to nodeID.
func liveTokensFor(t *testing.T, s *Store, nodeID string) []string {
	t.Helper()
	infos, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var ids []string
	for _, i := range infos {
		if i.NodeID != nil && *i.NodeID == nodeID && i.RevokedAt == nil {
			ids = append(ids, i.ID)
		}
	}
	return ids
}

// assertAgentTokenFile checks path holds exactly one live token bound to
// nodeID, owner-only, and returns it.
func assertAgentTokenFile(t *testing.T, s *Store, path, nodeID string) string {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("token file mode %v, want a regular file", fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("token file perm %#o, want 0600", perm)
	}
	tok := readTokenFile(t, path)
	ok, err := s.Validate(context.Background(), tok, nodeID)
	if err != nil || !ok {
		t.Fatalf("the token in the file does not validate for %q: (%v, %v)", nodeID, ok, err)
	}
	if live := liveTokensFor(t, s, nodeID); len(live) != 1 || live[0] != HashToken(tok) {
		t.Fatalf("live tokens bound to %q = %v, want exactly the file's (%s)", nodeID, live, HashToken(tok))
	}
	return tok
}

func TestEnsureAgentToken_MintsWhenMissing(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	path := agentTokenPath(t)

	reason, err := s.EnsureAgentToken(ctx, path, "cp-1")
	if err != nil {
		t.Fatalf("EnsureAgentToken: %v", err)
	}
	if !strings.Contains(reason, "no token file") {
		t.Errorf("reason = %q, want it to say the file was missing", reason)
	}
	assertAgentTokenFile(t, s, path, "cp-1")
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o700 {
			t.Errorf("created bus dir perm %#o, want 0700", perm)
		}
	}
	infos, _ := s.List(ctx)
	if len(infos) != 1 || infos[0].Label != AgentTokenLabel {
		t.Errorf("token rows = %+v, want one labelled %q", infos, AgentTokenLabel)
	}
	// Only the token and a newline: the temp file is gone.
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("bus dir holds %d entries, want only the token file: %v", len(entries), entries)
	}
}

func TestEnsureAgentToken_KeepsAGoodFile(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	path := agentTokenPath(t)
	if _, err := s.EnsureAgentToken(ctx, path, "cp-1"); err != nil {
		t.Fatal(err)
	}
	first := readTokenFile(t, path)

	for i := 0; i < 3; i++ { // every restart
		reason, err := s.EnsureAgentToken(ctx, path, "cp-1")
		if err != nil || reason != "" {
			t.Fatalf("EnsureAgentToken on a good file = (%q, %v), want (\"\", nil)", reason, err)
		}
	}
	if got := assertAgentTokenFile(t, s, path, "cp-1"); got != first {
		t.Error("a good token was replaced")
	}
	if infos, _ := s.List(ctx); len(infos) != 1 {
		t.Errorf("%d token rows after restarts, want 1", len(infos))
	}
}

// Each way the file stops being a usable credential re-mints it, revokes what
// it replaced, and leaves every other node's token alone.
func TestEnsureAgentToken_ReMints(t *testing.T) {
	cases := []struct {
		name       string
		spoil      func(t *testing.T, s *Store, path string)
		wantReason string
	}{
		{"deleted", func(t *testing.T, _ *Store, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}, "no token file"},
		{"garbage", func(t *testing.T, _ *Store, path string) {
			if err := os.WriteFile(path, []byte("not-a-token\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "not a live token"},
		{"empty", func(t *testing.T, _ *Store, path string) {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "empty"},
		// s.revoke, not Revoke: the operator route now refuses this very token
		// (ErrSelfAgentToken, TestRevoke_RefusesTheSelfAgentToken). What is
		// simulated here is a row that IS revoked in the database — left that
		// way by a re-mint whose file write then failed, or arriving revoked
		// in a restored database — which must still re-mint cleanly.
		{"revoked", func(t *testing.T, s *Store, path string) {
			if _, err := s.revoke(context.Background(), HashToken(readTokenFile(t, path))); err != nil {
				t.Fatal(err)
			}
		}, "not a live token"},
		{"readable by others", func(t *testing.T, _ *Store, path string) {
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "open to more than its owner"},
		{"bound to another node", func(t *testing.T, s *Store, path string) {
			other, _, err := s.MintBound(context.Background(), "x", "cp-2")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(other+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "not a live token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := newTokenStore(t)
			path := agentTokenPath(t)
			bystander, _, err := s.MintBound(ctx, "compute", "compute-1")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.EnsureAgentToken(ctx, path, "cp-1"); err != nil {
				t.Fatal(err)
			}
			old := readTokenFile(t, path)

			tc.spoil(t, s, path)
			reason, err := s.EnsureAgentToken(ctx, path, "cp-1")
			if err != nil {
				t.Fatalf("EnsureAgentToken: %v", err)
			}
			if !strings.Contains(reason, tc.wantReason) {
				t.Errorf("reason = %q, want it to contain %q", reason, tc.wantReason)
			}
			got := assertAgentTokenFile(t, s, path, "cp-1")
			if got == old {
				t.Fatal("the token was not replaced")
			}
			if ok, _ := s.Validate(ctx, old, "cp-1"); ok {
				t.Error("the replaced token still validates")
			}
			if ok, _ := s.Validate(ctx, bystander, "compute-1"); !ok {
				t.Error("another node's token was revoked")
			}
		})
	}
}

// An identity restore swaps the database under a controlplane whose token file
// came from before it: the file names a token the restored store never held.
func TestEnsureAgentToken_ReMintsAfterARestoredDatabase(t *testing.T) {
	ctx := context.Background()
	path := agentTokenPath(t)
	before := newTokenStore(t)
	if _, err := before.EnsureAgentToken(ctx, path, "cp-1"); err != nil {
		t.Fatal(err)
	}
	old := readTokenFile(t, path)

	restored := newTokenStore(t)
	// The restored database still holds the token the backed-up controlplane
	// minted for its agent — a different one — which must not stay live.
	stale, _, err := restored.MintBound(ctx, AgentTokenLabel, "cp-1")
	if err != nil {
		t.Fatal(err)
	}
	reason, err := restored.EnsureAgentToken(ctx, path, "cp-1")
	if err != nil || !strings.Contains(reason, "not a live token") {
		t.Fatalf("EnsureAgentToken after restore = (%q, %v)", reason, err)
	}
	if got := assertAgentTokenFile(t, restored, path, "cp-1"); got == old || got == stale {
		t.Fatal("the file still holds a token from before the restore")
	}
	if ok, _ := restored.Validate(ctx, stale, "cp-1"); ok {
		t.Error("the restored database's old agent token is still live")
	}
}

// A symlink planted at the path is replaced, never written through.
func TestEnsureAgentToken_ReplacesASymlinkWithoutFollowingIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	ctx := context.Background()
	s := newTokenStore(t)
	path := agentTokenPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("untouched\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	reason, err := s.EnsureAgentToken(ctx, path, "cp-1")
	if err != nil || !strings.Contains(reason, "not a regular file") {
		t.Fatalf("EnsureAgentToken over a symlink = (%q, %v)", reason, err)
	}
	assertAgentTokenFile(t, s, path, "cp-1")
	if b, _ := os.ReadFile(target); string(b) != "untouched\n" {
		t.Errorf("the symlink's target was written: %q", b)
	}
}

// A mint whose file cannot be written leaves nothing new live and the previous
// credential exactly as it was.
func TestEnsureAgentToken_WriteFailureChangesNothing(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "good", proto.BusAgentTokenFileName)
	if _, err := s.EnsureAgentToken(ctx, good, "cp-1"); err != nil {
		t.Fatal(err)
	}
	prev := readTokenFile(t, good)

	// The parent "directory" is a file: nothing can be created under it.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	reason, err := s.EnsureAgentToken(ctx, filepath.Join(blocker, proto.BusAgentTokenFileName), "cp-1")
	if err == nil {
		t.Fatalf("EnsureAgentToken under a file succeeded (reason %q)", reason)
	}
	if live := liveTokensFor(t, s, "cp-1"); len(live) != 1 || live[0] != HashToken(prev) {
		t.Fatalf("live cp-1 tokens after a failed write = %v, want only the previous one", live)
	}
}

func TestEnsureAgentToken_RefusesAnInvalidNodeID(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	for _, id := range append([]string{""}, invalidNodeIDs...) {
		path := agentTokenPath(t)
		_, err := s.EnsureAgentToken(ctx, path, id)
		if err == nil {
			t.Errorf("EnsureAgentToken(%q) succeeded", id)
			continue
		}
		if !errors.Is(err, ErrInvalidNodeID) && !errors.Is(err, ErrUnboundToken) {
			t.Errorf("EnsureAgentToken(%q) = %v, want ErrInvalidNodeID or ErrUnboundToken", id, err)
		}
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("EnsureAgentToken(%q) wrote a file", id)
		}
	}
	if infos, _ := s.List(ctx); len(infos) != 0 {
		t.Errorf("%d token rows after refused ids, want 0", len(infos))
	}
}
