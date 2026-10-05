package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// appliedPPPoEHash is the FirewallApplyCmd.IntentHash the previous release
// (origin/main 1c44e02) sent for exactly the two intents this test creates:
// the port forward "web" and the PPPoE wan_config "isp" with the password
// SENTINEL-PPPOE-PASSWORD. The firewall package pins the same vector against
// the apply command (TC-825-28), so a node holding it is a node that applied
// this state.
const appliedPPPoEHash = "23dba914fbe610d66dedb1e3140395ddd7019e045844650e8a62b275840fa71d"

// TC-825-30: the firewall state handler compiles with the stored PPPoE secret,
// so a firewall that applied the state reads as not pending, and changing only
// the secret makes it pending. The empty-firewall row is
// TestHandleGetFirewallState_PendingFalseWhenFreshAndEmpty.
func TestHandleGetFirewallState_PendingHashIncludesThePPPoESecret(t *testing.T) {
	f := newAPIFixture(t)
	_ = f.inv.Insert(f.ctx, &proto.Node{
		ID: "node-fw", Role: proto.RoleFirewall, Hostname: "fw",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	})
	c := f.authenticate(t)
	for _, body := range []string{
		`{"kind":"port_forward","name":"web","enabled":true,"spec":{"wanPort":8080,"lanHost":"192.168.1.10","lanPort":80,"protocol":"tcp"}}`,
		`{"kind":"wan_config","name":"isp","enabled":true,"spec":{"proto":"pppoe","username":"user@isp","secret":"SENTINEL-PPPOE-PASSWORD","service":"internet"}}`,
	} {
		if w := f.do(t, http.MethodPost, "/api/firewall/intents", body, c); w.Code != http.StatusCreated {
			t.Fatalf("create intent: %d %s", w.Code, w.Body.String())
		}
	}
	if err := f.fw.UpdateAfterApply(f.ctx, "node-fw", appliedPPPoEHash, time.Now().UTC()); err != nil {
		t.Fatalf("UpdateAfterApply: %v", err)
	}

	pending := func() bool {
		t.Helper()
		w := f.do(t, http.MethodGet, "/api/firewall/state", "", c)
		if w.Code != http.StatusOK {
			t.Fatalf("get state: %d %s", w.Code, w.Body.String())
		}
		var out []firewall.NodeState
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out) != 1 {
			t.Fatalf("decode state: %v (%s)", err, w.Body.String())
		}
		return out[0].Pending
	}
	if pending() {
		t.Error("the applied PPPoE state reads as pending: the handler's hash is not the applied hash")
	}

	// Change only the secret.
	intents, err := f.fw.ListIntents(f.ctx)
	if err != nil {
		t.Fatalf("ListIntents: %v", err)
	}
	var wanID string
	for _, in := range intents {
		if in.Kind == string(proto.IntentWANConfig) {
			wanID = in.ID
		}
	}
	upd := `{"spec":{"proto":"pppoe","username":"user@isp","secret":"SENTINEL-ROTATED","service":"internet"}}`
	if w := f.do(t, http.MethodPatch, "/api/firewall/intents/"+wanID, upd, c); w.Code != http.StatusOK {
		t.Fatalf("update intent: %d %s", w.Code, w.Body.String())
	}
	if !pending() {
		t.Error("after only the PPPoE secret changed, the firewall is not pending")
	}
}
