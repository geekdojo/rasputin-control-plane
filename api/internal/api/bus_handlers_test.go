package api

import (
	"fmt"
	"net/http"
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
	if code := mint(`{"label":"t","nodeId":"pend-24"}`); code != http.StatusCreated {
		t.Fatalf("mint under cap = %d, want 201", code)
	}

	// 23 live + 1 pending = at the cap: a mint for another new id is refused.
	if code := mint(`{"label":"t","nodeId":"new-25"}`); code != http.StatusConflict {
		t.Fatalf("mint past cap = %d, want 409", code)
	}

	// Unbound tokens are only useful for growth — refused at the cap too.
	if code := mint(`{"label":"unbound"}`); code != http.StatusConflict {
		t.Fatalf("unbound mint at cap = %d, want 409", code)
	}

	// Re-mint for a live node id is a replacement, not growth.
	if code := mint(`{"label":"replace","nodeId":"n-00"}`); code != http.StatusCreated {
		t.Fatalf("re-mint for live node = %d, want 201", code)
	}

	// Re-mint for the already-pending id is allowed for the same reason.
	if code := mint(`{"label":"again","nodeId":"pend-24"}`); code != http.StatusCreated {
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
			if w := f.do(t, http.MethodDelete, "/api/bus/tokens/"+tk.ID, "", cookie); w.Code != http.StatusNoContent {
				t.Fatalf("revoke = %d, want 204", w.Code)
			}
		}
	}
	if code := mint(`{"label":"t","nodeId":"new-25"}`); code != http.StatusCreated {
		t.Fatalf("mint after revoke = %d, want 201", code)
	}
}
