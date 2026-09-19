package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Cluster-size cap on token minting (proto.MaxClusterNodes): a mint that would
// commit a NEW node id past the cap is refused with 409; re-mints for live or
// already-pending ids are token replacements and always allowed.
func TestMintBusToken_ClusterCap(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	now := time.Now().UTC()
	for i := 0; i < proto.MaxClusterNodes-1; i++ {
		if err := f.inv.Insert(f.ctx, &proto.Node{
			ID: fmt.Sprintf("n-%02d", i), Role: proto.RoleCompute,
			FirstSeen: now, LastSeen: now,
		}); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}

	mint := func(body string) int {
		t.Helper()
		return f.do(t, http.MethodPost, "/api/bus/tokens", body, cookie).Code
	}

	// 23 live: a new bound mint commits the 24th slot.
	if code := mint(`{"role":"compute","label":"t","nodeId":"pend-24"}`); code != http.StatusCreated {
		t.Fatalf("mint under cap = %d, want 201", code)
	}

	// 23 live + 1 pending = at the cap: a mint for another new id is refused.
	if code := mint(`{"role":"compute","label":"t","nodeId":"new-25"}`); code != http.StatusConflict {
		t.Fatalf("mint past cap = %d, want 409", code)
	}

	// Re-mint for a live node id is a replacement, not growth.
	if code := mint(`{"role":"compute","label":"replace","nodeId":"n-00"}`); code != http.StatusCreated {
		t.Fatalf("re-mint for live node = %d, want 201", code)
	}

	// Re-mint for the already-pending id is allowed for the same reason.
	if code := mint(`{"role":"compute","label":"again","nodeId":"pend-24"}`); code != http.StatusCreated {
		t.Fatalf("re-mint for pending id = %d, want 201", code)
	}

	// Revoking a pending token frees the slot again. Find the pend-24 tokens
	// and revoke them via the API, then a new id mints fine.
	tokens, err := f.srv.busTokens.List(f.ctx)
	if err != nil {
		t.Fatalf("List tokens: %v", err)
	}
	for _, tk := range tokens {
		if tk.NodeID != nil && *tk.NodeID == "pend-24" && tk.RevokedAt == nil {
			if w := f.do(t, http.MethodDelete, "/api/bus/tokens/"+tk.ID, "", cookie); w.Code != http.StatusOK {
				t.Fatalf("revoke = %d, want 200", w.Code)
			}
		}
	}
	if code := mint(`{"role":"compute","label":"t","nodeId":"new-25"}`); code != http.StatusCreated {
		t.Fatalf("mint after revoke = %d, want 201", code)
	}
}

// nodeId must be a valid node id (a lowercase DNS label): a token bound to
// anything else could never authenticate on the bus.
func TestMintBusToken_RejectsInvalidNodeID(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	for _, id := range []string{
		"*", ">", "a.b", "a b", "a\\tb", "Alpha", "node_1", "-alpha", "alpha-",
		strings.Repeat("a", 64),
	} {
		body := fmt.Sprintf(`{"role":"compute","label":"t","nodeId":"%s"}`, id)
		if w := f.do(t, http.MethodPost, "/api/bus/tokens", body, cookie); w.Code != http.StatusBadRequest {
			t.Errorf("mint with nodeId %q = %d, want 400 (body %s)", id, w.Code, w.Body.String())
		}
	}
	tokens, err := f.srv.busTokens.List(f.ctx)
	if err != nil {
		t.Fatalf("List tokens: %v", err)
	}
	if len(tokens) != 0 {
		t.Fatalf("rejected mints stored %d tokens, want 0", len(tokens))
	}

	if w := f.do(t, http.MethodPost, "/api/bus/tokens", `{"role":"compute","label":"t","nodeId":"e3bench-compute1"}`, cookie); w.Code != http.StatusCreated {
		t.Errorf("mint with a valid nodeId = %d, want 201", w.Code)
	}
}

// There is no unbound mint (geekdojo-brain#423): a request that names no node
// id — omitted, empty, or no body at all — is a 400 and stores nothing.
func TestMintBusToken_RequiresNodeID(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	for _, body := range []string{`{"label":"unbound"}`, `{"role":"compute","label":"t","nodeId":""}`, `{}`, ``} {
		w := f.do(t, http.MethodPost, "/api/bus/tokens", body, cookie)
		if w.Code != http.StatusBadRequest {
			t.Errorf("mint with body %q = %d, want 400 (body %s)", body, w.Code, w.Body.String())
			continue
		}
		if !strings.Contains(w.Body.String(), "nodeId is required") {
			t.Errorf("mint with body %q: error %s should say nodeId is required", body, w.Body.String())
		}
	}
	tokens, err := f.srv.busTokens.List(f.ctx)
	if err != nil {
		t.Fatalf("List tokens: %v", err)
	}
	if len(tokens) != 0 {
		t.Fatalf("refused unbound mints stored %d tokens, want 0", len(tokens))
	}
}

// Every token is bound to the role of the node it is for (busauth role.go).
// The role is the request's role, or — as the Add-node wizard has always sent
// it — the label when the label is a role. A mint that names no role, an
// unknown one, or the controlplane's is a 400 and stores nothing; the minted
// role is in the reply and in the list.
func TestMintBusToken_Role(t *testing.T) {
	f := newAPIFixture(t)
	cookie := f.authenticate(t)

	for _, body := range []string{
		`{"label":"laptop agent","nodeId":"a1"}`,
		`{"nodeId":"a1"}`,
		`{"role":"nonsense","label":"compute","nodeId":"a1"}`,
		`{"role":"controlplane","nodeId":"a1"}`,
		`{"label":"controlplane","nodeId":"a1"}`,
	} {
		w := f.do(t, http.MethodPost, "/api/bus/tokens", body, cookie)
		if w.Code != http.StatusBadRequest {
			t.Errorf("mint %s = %d, want 400 (body %s)", body, w.Code, w.Body.String())
		}
	}
	if tokens, err := f.srv.busTokens.List(f.ctx); err != nil || len(tokens) != 0 {
		t.Fatalf("refused mints: List = (%d tokens, %v), want none", len(tokens), err)
	}

	for body, want := range map[string]proto.NodeRole{
		`{"role":"firewall","label":"edge","nodeId":"fw1"}`:  proto.RoleFirewall,
		`{"label":"compute","nodeId":"c1"}`:                  proto.RoleCompute,
		`{"role":"storage","label":"compute","nodeId":"s1"}`: proto.RoleStorage,
	} {
		w := f.do(t, http.MethodPost, "/api/bus/tokens", body, cookie)
		if w.Code != http.StatusCreated {
			t.Fatalf("mint %s = %d, want 201 (body %s)", body, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"role":"`+string(want)+`"`) {
			t.Errorf("mint %s: reply %s does not carry role %q", body, w.Body.String(), want)
		}
	}
	tokens, err := f.srv.busTokens.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := map[string]proto.NodeRole{}
	for _, tk := range tokens {
		got[*tk.NodeID] = tk.Role
	}
	for node, want := range map[string]proto.NodeRole{"fw1": proto.RoleFirewall, "c1": proto.RoleCompute, "s1": proto.RoleStorage} {
		if got[node] != want {
			t.Errorf("listed role for %s = %q, want %q", node, got[node], want)
		}
	}
}
