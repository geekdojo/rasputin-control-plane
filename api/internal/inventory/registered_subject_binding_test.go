package inventory

// A registration's node identity comes from the subject it arrived on
// (rasputin.node.<id>.evt.registered), which the bus scopes to the publishing
// node's credential — never from the nodeId field in the payload. A
// registration whose payload names a different node is dropped, so it can
// neither create nor update that node's row.

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// firstNonLoopbackIPv4 returns an up, non-loopback IPv4 address so the bus can
// be bound where the callout really validates the join token (loopback is
// trusted tokenless). Empty when the machine has none.
func firstNonLoopbackIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
					return ip4.String()
				}
			}
		}
	}
	return ""
}

// TestHandleRegistered_PayloadNodeIDMustMatchSubject runs end to end with bus
// auth ENFORCED: node "alpha" holds a join token BOUND to "alpha", so the
// credential the callout mints only lets it publish rasputin.node.alpha.>. It
// publishes a registration on its own subject — which the bus permits — whose
// payload carries a mismatched node id (the controlplane's).
func TestHandleRegistered_PayloadNodeIDMustMatchSubject(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	host := firstNonLoopbackIPv4()
	if host == "" {
		host = "127.0.0.1"
		t.Logf("no non-loopback IPv4 interface: binding loopback, so the join token is not " +
			"checked — the minted scope (rasputin.node.alpha.>) is the same either way")
	}

	issuer, err := busauth.EnsureIssuer(filepath.Join(dir, "bus"))
	if err != nil {
		t.Fatalf("EnsureIssuer: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "nats"), 0o755); err != nil {
		t.Fatalf("mkdir nats: %v", err)
	}
	tokens, err := busauth.OpenStore(ctx, filepath.Join(dir, "bus.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = tokens.Close() })
	alphaToken, _, err := tokens.MintBound(ctx, "alpha", "alpha", "compute")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}

	srv, err := bus.Start(ctx, bus.Config{
		Host: host, Port: -1,
		StoreDir:        filepath.Join(dir, "nats"),
		AuthEnforce:     true,
		IssuerPublicKey: issuer.PublicKey(),
		APIUser:         "rasputin-api",
		APIPass:         "test-secret",
	})
	if err != nil {
		t.Fatalf("bus.Start: %v", err)
	}
	t.Cleanup(srv.Stop)
	resp := busauth.NewResponder(srv.Conn(), issuer, tokens)
	if err := resp.Start(); err != nil {
		t.Fatalf("responder.Start: %v", err)
	}
	t.Cleanup(resp.Stop)

	// The controlplane's row, already registered and confirmed.
	store := newStore(t)
	confirmed := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	cp := makeNode("controlplane", proto.RoleControlPlane, 0)
	cp.Hostname = "cp.test"
	cp.ImageVersion = "2026.09.0"
	cp.ImageVersionConfirmedAt = &confirmed
	cp.LANIP = "192.168.1.10"
	cp.Architecture = "amd64"
	if err := store.Insert(ctx, cp); err != nil {
		t.Fatalf("seed controlplane: %v", err)
	}
	before, _ := store.Get(ctx, "controlplane")

	api := srv.Conn()
	svc := NewService(store, api)
	changes, err := api.SubscribeSync("rasputin.inventory.>")
	if err != nil {
		t.Fatalf("change sub: %v", err)
	}
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(svc.Stop)
	if err := api.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	permErr := make(chan error, 4)
	alpha, err := nats.Connect(srv.ClientURL(),
		nats.UserInfo("alpha", alphaToken),
		nats.MaxReconnects(0),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) { permErr <- e }),
	)
	if err != nil {
		t.Fatalf("alpha connect (bound token, own node id) should succeed: %v", err)
	}
	defer alpha.Close()

	mismatched, _ := json.Marshal(proto.NodeRegisteredEvt{
		NodeID:       "controlplane", // ≠ the subject's node token
		Role:         proto.RoleCompute,
		Hostname:     "mismatched.test",
		AgentVersion: "0.0.0-mismatched",
		ImageVersion: "2099.01.0",
		Architecture: "arm64",
		LANIP:        "10.0.0.99",
	})
	if err := alpha.Publish(proto.NodeRegisteredSubject("alpha"), mismatched); err != nil {
		t.Fatalf("publish mismatched: %v", err)
	}
	// Sync point: alpha's own registration rides the same subscription right
	// behind the mismatched one, so once its "added" event is out, the
	// mismatched message has already been handled.
	own, _ := json.Marshal(proto.NodeRegisteredEvt{NodeID: "alpha", Role: proto.RoleCompute, Hostname: "alpha.test"})
	if err := alpha.Publish(proto.NodeRegisteredSubject("alpha"), own); err != nil {
		t.Fatalf("publish own: %v", err)
	}
	if err := alpha.Flush(); err != nil {
		t.Fatalf("alpha flush: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		m, err := changes.NextMsg(time.Until(deadline))
		if err != nil {
			t.Fatalf("never saw alpha's own registration land: %v", err)
		}
		t.Logf("inventory change event: %s", m.Subject)
		if m.Subject == proto.InventoryChangedSubject("controlplane", string(proto.InventoryOnline)) ||
			m.Subject == proto.InventoryChangedSubject("controlplane", string(proto.InventoryUpdated)) {
			t.Errorf("a registration on %s emitted a change for node controlplane: %s",
				proto.NodeRegisteredSubject("alpha"), m.Subject)
		}
		if m.Subject == proto.InventoryChangedSubject("alpha", string(proto.InventoryAdded)) {
			break
		}
	}
	select {
	case e := <-permErr:
		t.Fatalf("bus denied alpha's publish, so this run does not exercise the handler: %v", e)
	default:
		t.Logf("bus permitted both publishes on %s (subject permissions do not cover the payload)",
			proto.NodeRegisteredSubject("alpha"))
	}

	after, err := store.Get(ctx, "controlplane")
	if err != nil || after == nil {
		t.Fatalf("Get controlplane: %v, %+v", err, after)
	}
	if after.ImageVersion != before.ImageVersion ||
		after.Role != before.Role ||
		after.Hostname != before.Hostname ||
		after.LANIP != before.LANIP ||
		after.Architecture != before.Architecture ||
		after.AgentVersion != before.AgentVersion {
		t.Errorf("a registration on %s with a mismatched node id changed node controlplane's row:\n"+
			" before: role=%s host=%s agent=%s image=%q arch=%s lan=%s\n"+
			" after:  role=%s host=%s agent=%s image=%q arch=%s lan=%s",
			proto.NodeRegisteredSubject("alpha"),
			before.Role, before.Hostname, before.AgentVersion, before.ImageVersion, before.Architecture, before.LANIP,
			after.Role, after.Hostname, after.AgentVersion, after.ImageVersion, after.Architecture, after.LANIP)
	}
	if after.ImageVersionConfirmedAt == nil || !after.ImageVersionConfirmedAt.Equal(*before.ImageVersionConfirmedAt) {
		t.Errorf("a registration with a mismatched node id changed controlplane's imageVersionConfirmedAt (%v → %v)",
			before.ImageVersionConfirmedAt, after.ImageVersionConfirmedAt)
	}
	if own, _ := store.Get(ctx, "alpha"); own == nil || own.Hostname != "alpha.test" {
		t.Errorf("alpha's own registration did not create its row: %+v", own)
	}
}
