package inventory

import (
	"context"
	"encoding/json"
	"sync"
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

// TestService_SelfLANIP covers the control plane's own row (#431): the api's
// kernel-derived address wins over what the co-located agent reports, follows a
// change without any registration, and leaves every other node alone.
func TestService_SelfLANIP(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStore(t)
	svc := NewService(store, nc)

	var mu sync.Mutex
	selfIP := "192.168.1.2" // booted with no DHCP: only the fallback
	svc.SetSelfLANIP("cp-1", func() string {
		mu.Lock()
		defer mu.Unlock()
		return selfIP
	})
	setSelf := func(ip string) {
		mu.Lock()
		selfIP = ip
		mu.Unlock()
	}

	changeSub, err := nc.SubscribeSync("rasputin.inventory.>")
	if err != nil {
		t.Fatalf("change sub: %v", err)
	}
	defer func() { _ = changeSub.Unsubscribe() }()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(svc.Stop)

	register := func(nodeID, lanIP string) {
		t.Helper()
		reg, _ := json.Marshal(proto.NodeRegisteredEvt{NodeID: nodeID, Role: proto.RoleControlPlane, Hostname: nodeID, LANIP: lanIP})
		if err := nc.Publish(proto.NodeRegisteredSubject(nodeID), reg); err != nil {
			t.Fatalf("publish reg: %v", err)
		}
		_ = nc.Flush()
		waitForMsg(t, changeSub, 2*time.Second)
	}
	lanIP := func(nodeID string) string {
		t.Helper()
		n, err := store.Get(ctx, nodeID)
		if err != nil || n == nil {
			t.Fatalf("get %s: %v %v", nodeID, n, err)
		}
		return n.LANIP
	}

	// No usable default route, so the agent reports nothing; the api knows .2.
	if err := svc.RefreshSelfLANIP(ctx); err != nil {
		t.Fatalf("refresh before the row exists: %v", err)
	}
	register("cp-1", "")
	if got := lanIP("cp-1"); got != "192.168.1.2" {
		t.Fatalf("self row after registration = %q, want the api's 192.168.1.2", got)
	}

	// A late lease, with no registration: the refresh moves the row and emits.
	setSelf("192.168.1.226")
	if err := svc.RefreshSelfLANIP(ctx); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	msg := waitForMsg(t, changeSub, 2*time.Second)
	var evt proto.InventoryChangeEvt
	if err := json.Unmarshal(msg.Data, &evt); err != nil {
		t.Fatal(err)
	}
	if evt.Change != proto.InventoryUpdated || evt.Node.LANIP != "192.168.1.226" {
		t.Fatalf("refresh emitted %s with lanIP %q", evt.Change, evt.Node.LANIP)
	}
	if got := lanIP("cp-1"); got != "192.168.1.226" {
		t.Fatalf("self row after refresh = %q", got)
	}

	// An unchanged refresh writes and emits nothing.
	if err := svc.RefreshSelfLANIP(ctx); err != nil {
		t.Fatal(err)
	}
	if m, err := changeSub.NextMsg(200 * time.Millisecond); err == nil {
		t.Fatalf("unchanged refresh emitted %s", m.Subject)
	}

	// An agent reconnect carrying a stale address does not undo it.
	register("cp-1", "192.168.1.225")
	if got := lanIP("cp-1"); got != "192.168.1.226" {
		t.Fatalf("stale agent report overwrote the self row: %q", got)
	}

	// Another node's report is its own.
	register("cp-compute1", "192.168.1.50")
	if got := lanIP("cp-compute1"); got != "192.168.1.50" {
		t.Fatalf("non-self node = %q", got)
	}

	// The address is gone: the row stops advertising it.
	setSelf("")
	if err := svc.RefreshSelfLANIP(ctx); err != nil {
		t.Fatal(err)
	}
	waitForMsg(t, changeSub, 2*time.Second)
	if got := lanIP("cp-1"); got != "" {
		t.Fatalf("self row with no address = %q, want empty", got)
	}
}
