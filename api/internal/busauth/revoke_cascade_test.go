package busauth

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// NodeHasLiveToken is what the collector ingress admits on: a token the bus
// would admit the node with — unrevoked, bound to it, naming a role.
func TestNodeHasLiveToken(t *testing.T) {
	ctx := context.Background()
	s := newTokenStore(t)

	check := func(node string, want bool) {
		t.Helper()
		if got, err := s.NodeHasLiveToken(ctx, node); err != nil || got != want {
			t.Errorf("NodeHasLiveToken(%q) = (%v, %v), want (%v, nil)", node, got, err, want)
		}
	}
	check("", false)
	check("c1", false) // no token at all

	_, id1, err := s.MintBound(ctx, "compute", "c1", proto.RoleCompute)
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}
	check("c1", true)
	check("c2", false) // someone else's token does not count

	_, id2, err := s.MintBound(ctx, "compute", "c1", proto.RoleCompute)
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}
	if _, err := s.Revoke(ctx, id1); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	check("c1", true) // the second token is still live
	if _, err := s.Revoke(ctx, id2); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	check("c1", false)

	// A live token whose row names no role is not one the bus admits.
	_, id, _ := GenerateToken()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO bus_tokens (token_hash, label, created_at, node_id) VALUES (?, 'laptop agent', ?, 'dev1')`,
		id, ms(time.Now().UTC())); err != nil {
		t.Fatalf("insert: %v", err)
	}
	check("dev1", false)
}

// The refusal names a rotation that works: with the token file removed, the
// next start mints a fresh token and revokes the refused one. A bare restart
// with the file in place keeps the same token, so the message must not say
// that is enough.
func TestErrSelfAgentToken_NamesAWorkingRotation(t *testing.T) {
	msg := ErrSelfAgentToken.Error()
	if !strings.Contains(msg, "bus/"+proto.BusAgentTokenFileName) || !strings.Contains(msg, "restart the api") {
		t.Fatalf("ErrSelfAgentToken = %q; want it to name deleting bus/%s and restarting", msg, proto.BusAgentTokenFileName)
	}

	ctx := context.Background()
	s := newTokenStore(t)
	path := agentTokenPath(t)
	if _, err := s.EnsureAgentToken(ctx, path, "cp-1"); err != nil {
		t.Fatalf("EnsureAgentToken: %v", err)
	}
	old := readTokenFile(t, path)

	// A restart with the file in place: same token.
	if reason, err := s.EnsureAgentToken(ctx, path, "cp-1"); err != nil || reason != "" {
		t.Fatalf("restart with the file = (%q, %v), want no re-mint", reason, err)
	}
	if readTokenFile(t, path) != old {
		t.Fatal("a bare restart rotated the token")
	}

	// The remedy the message names: delete the file, restart.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if reason, err := s.EnsureAgentToken(ctx, path, "cp-1"); err != nil || reason == "" {
		t.Fatalf("restart without the file = (%q, %v), want a re-mint", reason, err)
	}
	fresh := readTokenFile(t, path)
	if fresh == old {
		t.Fatal("the token was not rotated")
	}
	if ok, _ := s.Validate(ctx, old, "cp-1"); ok {
		t.Error("the replaced token still validates")
	}
	if ok, _ := s.Validate(ctx, fresh, "cp-1"); !ok {
		t.Error("the fresh token does not validate")
	}
}
