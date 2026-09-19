package busauth

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/atrest"
)

// The api refuses to revoke the controlplane's own agent token
// (geekdojo-brain#140, decided 2026-09-17). Revoking it takes the
// controlplane's agent off the bus until the api restarts, and nothing in the
// UI can mint a replacement.

// ensureSelf gives s a controlplane agent token for nodeID and returns its file
// path and the token's id.
func ensureSelf(t *testing.T, s *Store, nodeID string) (path, id string) {
	t.Helper()
	path = agentTokenPath(t)
	if _, err := s.EnsureAgentToken(context.Background(), path, nodeID); err != nil {
		t.Fatalf("EnsureAgentToken(%q): %v", nodeID, err)
	}
	return path, HashToken(readTokenFile(t, path))
}

// assertLiveFor fails unless the token in path still authenticates as nodeID.
func assertLiveFor(t *testing.T, s *Store, path, nodeID string) {
	t.Helper()
	ok, err := s.Validate(context.Background(), readTokenFile(t, path), nodeID)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !ok {
		t.Fatalf("the controlplane agent's token no longer authenticates as %q", nodeID)
	}
}

func TestRevoke_RefusesTheSelfAgentToken(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	path, id := ensureSelf(t, s, "cp-1")

	n, err := s.Revoke(ctx, id)
	if !errors.Is(err, ErrSelfAgentToken) {
		t.Fatalf("Revoke of the controlplane agent's token = (%d, %v), want ErrSelfAgentToken", n, err)
	}
	if n != 0 {
		t.Errorf("a refused revoke disconnected %d sessions, want 0", n)
	}
	// The refusal has to leave the credential working, not merely unrevoked.
	assertLiveFor(t, s, path, "cp-1")
	if ids := liveTokensFor(t, s, "cp-1"); len(ids) != 1 || ids[0] != id {
		t.Errorf("live tokens for cp-1 = %v, want exactly %s", ids, id)
	}
}

func TestRevokeByNodeID_RefusesTheControlplanesOwnNodeID(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	path, _ := ensureSelf(t, s, "cp-1")

	revoked, disconnected, err := s.RevokeByNodeID(ctx, "cp-1")
	if !errors.Is(err, ErrSelfAgentToken) {
		t.Fatalf("RevokeByNodeID(\"cp-1\") = (%d, %d, %v), want ErrSelfAgentToken", revoked, disconnected, err)
	}
	if revoked != 0 || disconnected != 0 {
		t.Errorf("a refused RevokeByNodeID revoked %d and disconnected %d, want 0 and 0", revoked, disconnected)
	}
	assertLiveFor(t, s, path, "cp-1")

	// Every other node is unaffected — this is the node-removal cascade, and
	// removing an ordinary node must still evict it.
	other, _, err := s.MintBound(ctx, "compute", "compute-1", "compute")
	if err != nil {
		t.Fatal(err)
	}
	if revoked, _, err := s.RevokeByNodeID(ctx, "compute-1"); err != nil || revoked != 1 {
		t.Fatalf("RevokeByNodeID(\"compute-1\") = (%d, _, %v), want (1, _, nil)", revoked, err)
	}
	if ok, _ := s.Validate(ctx, other, "compute-1"); ok {
		t.Error("an ordinary node's token survived RevokeByNodeID")
	}
}

// The refusal is scoped to the ONE token the api minted for its own agent.
// Everything else stays revocable — including a token an operator minted for
// the controlplane's node id, which is not the credential the agent reads.
func TestRevoke_ProtectsOnlyTheApiMintedToken(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	path, selfID := ensureSelf(t, s, "cp-1")

	node, nodeID, err := s.MintBound(ctx, "compute", "compute-1", "compute")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Revoke(ctx, nodeID); err != nil {
		t.Fatalf("revoking an ordinary node's token: %v", err)
	}
	if ok, _ := s.Validate(ctx, node, "compute-1"); ok {
		t.Error("an ordinary node's token survived a revoke")
	}

	// An operator-minted token bound to the controlplane's own node id. It is
	// not what the agent presents (that is the file's token), so refusing to
	// revoke it would strand a credential the operator wants gone.
	stray, strayID, err := s.MintBound(ctx, "a lookalike", "cp-1", "compute")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Revoke(ctx, strayID); err != nil {
		t.Fatalf("revoking a stray token bound to the controlplane's node id: %v", err)
	}
	if ok, _ := s.Validate(ctx, stray, "cp-1"); ok {
		t.Error("the stray token survived a revoke")
	}
	if _, err := s.Revoke(ctx, selfID); !errors.Is(err, ErrSelfAgentToken) {
		t.Errorf("the agent's own token = %v, want it still refused", err)
	}
	assertLiveFor(t, s, path, "cp-1")
}

// Identification never reads the label: an operator can mint a token carrying
// AgentTokenLabel, and on a store that minted no agent token nothing is
// protected at all.
func TestRevoke_DoesNotProtectByLabel(t *testing.T) {
	ctx := context.Background()

	// A store whose api has no self node id (a dev api): EnsureAgentToken was
	// never called, so there is no co-located agent to protect.
	dev := newTokenStore(t)
	if got := dev.SelfNodeID(); got != "" {
		t.Fatalf("SelfNodeID on a store that never ensured = %q, want \"\"", got)
	}
	lookalike, lookalikeID, err := dev.MintBound(ctx, AgentTokenLabel, "cp-1", "compute")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dev.Revoke(ctx, lookalikeID); err != nil {
		t.Fatalf("revoking a label lookalike on a dev api: %v", err)
	}
	if ok, _ := dev.Validate(ctx, lookalike, "cp-1"); ok {
		t.Error("the lookalike survived a revoke")
	}

	// And on a real controlplane, a second token carrying the same label is
	// still revocable — only the marked one is not.
	s := newTokenStore(t)
	_, selfID := ensureSelf(t, s, "cp-1")
	_, dupID, err := s.MintBound(ctx, AgentTokenLabel, "cp-1", "compute")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Revoke(ctx, dupID); err != nil {
		t.Errorf("revoking a same-label token: %v", err)
	}
	if _, err := s.Revoke(ctx, selfID); !errors.Is(err, ErrSelfAgentToken) {
		t.Errorf("the marked token = %v, want ErrSelfAgentToken", err)
	}
}

// A marker that arrived in a database copied or restored from ANOTHER
// controlplane protects nothing here: the bound node id has to be this api's
// own. Simulated by ensuring for cp-2 first and then starting as cp-1.
func TestRevoke_DoesNotProtectAnotherControlplanesMarkedToken(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	_, foreignID := ensureSelf(t, s, "cp-2")
	_, selfID := ensureSelf(t, s, "cp-1")

	if got := s.SelfNodeID(); got != "cp-1" {
		t.Fatalf("SelfNodeID = %q, want cp-1", got)
	}
	if _, err := s.Revoke(ctx, foreignID); err != nil {
		t.Errorf("revoking another controlplane's marked token: %v", err)
	}
	if _, err := s.Revoke(ctx, selfID); !errors.Is(err, ErrSelfAgentToken) {
		t.Errorf("this controlplane's own token = %v, want ErrSelfAgentToken", err)
	}
	if revoked, _, err := s.RevokeByNodeID(ctx, "cp-2"); err != nil {
		t.Errorf("RevokeByNodeID for another controlplane's id = (%d, _, %v), want no error", revoked, err)
	}
}

// A controlplane running since before the marker existed keeps a token its api
// minted with no self_agent column. The first start on this build adopts the
// row the token file names, so it is protected without anything being re-minted
// — no token churn on upgrade.
func TestEnsureAgentToken_AdoptsAnUnmarkedTokenFromAnEarlierBuild(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	path := agentTokenPath(t)

	// Exactly what the previous build left behind: a plain MintBound row (no
	// marker) whose plaintext is in the agent token file.
	plaintext, id, err := s.MintBound(ctx, AgentTokenLabel, "cp-1", "compute")
	if err != nil {
		t.Fatal(err)
	}
	if err := atrest.WriteSecretFile(path, []byte(plaintext+"\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Revoke(ctx, id); err != nil {
		t.Fatalf("before adoption the token is revocable, as on the old build: %v", err)
	}

	// Put it back the way the old build had it and start.
	plaintext, id, err = s.MintBound(ctx, AgentTokenLabel, "cp-1", "compute")
	if err != nil {
		t.Fatal(err)
	}
	if err := atrest.WriteSecretFile(path, []byte(plaintext+"\n")); err != nil {
		t.Fatal(err)
	}
	reason, err := s.EnsureAgentToken(ctx, path, "cp-1")
	if err != nil || reason != "" {
		t.Fatalf("EnsureAgentToken on a good pre-marker file = (%q, %v), want (\"\", nil) — it must not re-mint", reason, err)
	}
	if got := readTokenFile(t, path); got != plaintext {
		t.Error("the existing token was replaced on upgrade")
	}
	if _, err := s.Revoke(ctx, id); !errors.Is(err, ErrSelfAgentToken) {
		t.Errorf("after adoption Revoke = %v, want ErrSelfAgentToken", err)
	}
}

// The api's own re-mint must keep working: it retires the token it replaces
// even though that token is the protected one. Without an unguarded internal
// revoke, a re-mint would leave the old credential live forever.
func TestEnsureAgentToken_ReMintStillRetiresTheProtectedToken(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	path, oldID := ensureSelf(t, s, "cp-1")
	old := readTokenFile(t, path)

	if _, err := s.Revoke(ctx, oldID); !errors.Is(err, ErrSelfAgentToken) {
		t.Fatalf("premise: the token must be protected before the re-mint, got %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	reason, err := s.EnsureAgentToken(ctx, path, "cp-1")
	if err != nil || reason == "" {
		t.Fatalf("EnsureAgentToken after the file was deleted = (%q, %v), want a re-mint", reason, err)
	}
	if ok, _ := s.Validate(ctx, old, "cp-1"); ok {
		t.Error("the replaced token is still live — the re-mint's revoke was blocked by the guard")
	}
	// Exactly one live token, and it is the new one, still protected.
	newID := HashToken(readTokenFile(t, path))
	if ids := liveTokensFor(t, s, "cp-1"); len(ids) != 1 || ids[0] != newID {
		t.Errorf("live tokens for cp-1 = %v, want exactly the new one (%s)", ids, newID)
	}
	if _, err := s.Revoke(ctx, newID); !errors.Is(err, ErrSelfAgentToken) {
		t.Errorf("the freshly minted token = %v, want ErrSelfAgentToken", err)
	}
	// And the marker did not stay on the retired row, so a controlplane never
	// carries two protected tokens.
	if _, err := s.Revoke(ctx, oldID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("revoking the already-retired row = %v, want sql.ErrNoRows (it is not protected any more)", err)
	}
}

// List marks the token a client must not offer to revoke, and marks nothing
// else — the UI reads this and hides the action (no dead button).
func TestList_MarksTheSelfAgentToken(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)
	_, selfID := ensureSelf(t, s, "cp-1")
	if _, _, err := s.MintBound(ctx, "compute", "compute-1", "compute"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.MintBound(ctx, AgentTokenLabel, "cp-1", "compute"); err != nil {
		t.Fatal(err)
	}

	infos, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	marked := 0
	for _, i := range infos {
		if !i.SelfAgent {
			continue
		}
		marked++
		if i.ID != selfID {
			t.Errorf("List marked %s (label %q), want only %s", i.ID, i.Label, selfID)
		}
	}
	if marked != 1 {
		t.Errorf("List marked %d tokens, want exactly 1", marked)
	}

	// A dev api marks nothing, because it protects nothing.
	dev := newTokenStore(t)
	if _, _, err := dev.MintBound(ctx, AgentTokenLabel, "cp-1", "compute"); err != nil {
		t.Fatal(err)
	}
	devInfos, err := dev.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, i := range devInfos {
		if i.SelfAgent {
			t.Errorf("a store with no self node id marked %s", i.ID)
		}
	}
}
