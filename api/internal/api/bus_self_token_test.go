package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The api refuses every operator route that would revoke the controlplane's own
// agent token (geekdojo-brain#140, decided 2026-09-17). The routes are:
//
//  1. DELETE /api/bus/tokens/{id} — the token revoke;
//  2. the same route again as the node grid's "cancel this pending enrollment",
//     which is the only other thing that calls it;
//  3. DELETE /api/nodes/{id} → busauth.RevokeByNodeID, already refused a step
//     earlier because the controlplane node cannot be removed.

// ensureCPAgentToken mints the fixture api's own agent token for nodeID, as a
// real start does, and returns the plaintext its agent would present.
func ensureCPAgentToken(t *testing.T, f *apiFixture, nodeID string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bus", proto.BusAgentTokenFileName)
	if _, err := f.srv.busTokens.EnsureAgentToken(f.ctx, path, nodeID); err != nil {
		t.Fatalf("EnsureAgentToken: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the agent token file: %v", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		t.Fatal("the agent token file is empty")
	}
	return tok
}

// selfAgentTokenID returns the id of the token GET /api/bus/tokens marks as the
// controlplane's own, failing unless there is exactly one.
func selfAgentTokenID(t *testing.T, f *apiFixture, cookie *http.Cookie) string {
	t.Helper()
	w := f.do(t, http.MethodGet, "/api/bus/tokens", "", cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("list tokens = %d %s", w.Code, w.Body.String())
	}
	var tokens []busauth.TokenInfo
	if err := json.Unmarshal(w.Body.Bytes(), &tokens); err != nil {
		t.Fatalf("decode token list: %v", err)
	}
	var ids []string
	for _, tk := range tokens {
		if tk.SelfAgent {
			ids = append(ids, tk.ID)
		}
	}
	if len(ids) != 1 {
		t.Fatalf("GET /api/bus/tokens marked %d tokens selfAgent, want 1 (body %s)", len(ids), w.Body.String())
	}
	return ids[0]
}

func TestRevokeBusToken_RefusesTheControlplanesOwnAgentToken(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	cpToken := ensureCPAgentToken(t, f, "cp-1")
	selfID := selfAgentTokenID(t, f, cookie)

	// The revoke route, which is also the node grid's "cancel pending
	// enrollment" — the controlplane shows as a pending bay until its agent
	// registers, and that click lands here.
	w := f.do(t, http.MethodDelete, "/api/bus/tokens/"+selfID, "", cookie)
	if w.Code != http.StatusConflict {
		t.Fatalf("revoke of the controlplane agent's token = %d, want 409 (body %s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{"cannot be revoked", "restart the api"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal %s should say %q", body, want)
		}
	}

	// Refused means the agent keeps working, not merely that the row survives.
	if ok, err := f.srv.busTokens.Validate(f.ctx, cpToken, "cp-1"); err != nil || !ok {
		t.Fatalf("the controlplane agent's token stopped authenticating after the refused revoke (%v, %v)", ok, err)
	}
	if got := selfAgentTokenID(t, f, cookie); got != selfID {
		t.Errorf("the marked token is now %s, want the unchanged %s", got, selfID)
	}

	// Every other node's token is still revocable through the same route.
	_, nodeID := mintBoundViaAPI(t, f, cookie, "compute-1")
	if w := f.do(t, http.MethodDelete, "/api/bus/tokens/"+nodeID, "", cookie); w.Code != http.StatusOK {
		t.Errorf("revoke of an ordinary node's token = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
}

// Node removal is the third way to reach a revoke (RevokeByNodeID). It is
// refused a step earlier — the controlplane node cannot be removed — and this
// nails down that the refusal leaves the agent's credential alone rather than
// cascading first and failing after.
func TestDeleteNode_CannotReachTheControlplaneAgentToken(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	now := time.Now().UTC()
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "cp-1", Role: proto.RoleControlPlane, Hostname: "cp-1",
		FirstSeen: now, LastSeen: now, Status: proto.StatusOnline,
	}); err != nil {
		t.Fatal(err)
	}
	cpToken := ensureCPAgentToken(t, f, "cp-1")

	w := f.do(t, http.MethodDelete, "/api/nodes/cp-1", "", cookie)
	if w.Code != http.StatusConflict {
		t.Fatalf("remove the controlplane = %d, want 409 (body %s)", w.Code, w.Body.String())
	}
	if ok, err := f.srv.busTokens.Validate(f.ctx, cpToken, "cp-1"); err != nil || !ok {
		t.Fatalf("the controlplane agent's token stopped authenticating after the refused removal (%v, %v)", ok, err)
	}

	// And the cascade still evicts an ordinary node.
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "compute-1", Role: proto.RoleCompute, Hostname: "compute-1",
		FirstSeen: now, LastSeen: now, Status: proto.StatusOnline,
	}); err != nil {
		t.Fatal(err)
	}
	nodeToken, _ := mintBoundViaAPI(t, f, cookie, "compute-1")
	if w := f.do(t, http.MethodDelete, "/api/nodes/compute-1", "", cookie); w.Code != http.StatusOK {
		t.Fatalf("remove an ordinary node = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if ok, _ := f.srv.busTokens.Validate(f.ctx, nodeToken, "compute-1"); ok {
		t.Error("a removed node's token was not revoked")
	}
}
