package inventory

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TestService_Registered_LANIPLearnAndKeep exercises the Slice-2a node-IP flow
// end to end through the real NodeRegisteredEvt path (ADR-0004 §8): a reported
// LAN IP is learned and persisted; a fresh IP (the reboot case — no DHCP
// reservations, so the address moves) overwrites; and a pre-LANIP agent
// reporting "" must not wipe a learned IP.
func TestService_Registered_LANIPLearnAndKeep(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	svc := NewService(store, nc)

	changeSub, err := nc.SubscribeSync("rasputin.inventory.>")
	if err != nil {
		t.Fatalf("change sub: %v", err)
	}
	defer func() { _ = changeSub.Unsubscribe() }()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(svc.Stop)

	const nodeID = "n-ip"
	register := func(lanIP string) {
		t.Helper()
		reg, _ := json.Marshal(proto.NodeRegisteredEvt{
			NodeID:   nodeID,
			Role:     proto.RoleCompute,
			Hostname: "ip.test",
			LANIP:    lanIP,
		})
		if err := nc.Publish(proto.NodeRegisteredSubject(nodeID), reg); err != nil {
			t.Fatalf("publish reg: %v", err)
		}
		_ = nc.Flush()
		waitForMsg(t, changeSub, 2*time.Second)
	}

	// Learned on first register.
	register("192.168.1.10")
	if got, _ := store.Get(ctx, nodeID); got == nil || got.LANIP != "192.168.1.10" {
		t.Fatalf("LAN IP not learned on first register: %+v", got)
	}

	// Reboot onto a new lease: a fresh IP overwrites.
	register("10.0.0.5")
	if got, _ := store.Get(ctx, nodeID); got == nil || got.LANIP != "10.0.0.5" {
		t.Fatalf("fresh LAN IP did not overwrite: %+v", got)
	}

	// A pre-LANIP agent (reports "") must not wipe the learned IP.
	register("")
	if got, _ := store.Get(ctx, nodeID); got == nil || got.LANIP != "10.0.0.5" {
		t.Fatalf("empty re-register wiped the learned LAN IP: %+v", got)
	}
}
