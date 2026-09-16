package busauth

// Every join token is bound to one node id (geekdojo-brain#423). This drives
// the real embedded nats-server with enforced auth and the real callout
// responder, and connects the way agents do, to pin the three outcomes on the
// bus itself: a legacy unbound token is refused at connect, a token bound to
// the node presenting it still connects and works, and the controlplane's
// tokenless loopback agent is unaffected.

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// startEnforcedBusAllInterfaces starts the enforced bus listening on every
// interface and returns URLs reaching it over loopback and over ip, so one
// server sees both a trusted loopback client and a token-checked remote one.
func startEnforcedBusAllInterfaces(t *testing.T, ip string) (eb *enforcedBus, loopbackURL, remoteURL string) {
	t.Helper()
	eb = startEnforcedBus(t, "0.0.0.0")
	u, err := url.Parse(eb.url)
	if err != nil {
		t.Fatalf("parse client URL %q: %v", eb.url, err)
	}
	port := u.Port()
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatalf("client URL %q has no port", eb.url)
	}
	return eb, "nats://" + net.JoinHostPort("127.0.0.1", port), "nats://" + net.JoinHostPort(ip, port)
}

func TestBus_UnboundTokenRefused_BoundAndLoopbackUnaffected(t *testing.T) {
	ip := nonLoopbackIPv4()
	if ip == "" {
		t.Skip("no non-loopback IPv4 interface on this machine; the token check only runs for a non-loopback client")
	}
	eb, loopbackURL, remoteURL := startEnforcedBusAllInterfaces(t, ip)
	ctx := context.Background()
	api := eb.srv.Conn()

	legacy, legacyID := insertLegacyUnbound(t, eb.tokens, "legacy")
	bound, _, err := eb.tokens.MintBound(ctx, "beta", "beta")
	if err != nil {
		t.Fatalf("MintBound: %v", err)
	}

	// 1. The legacy unbound token is refused at connect, under the id a node
	//    seeded with it would present and under any other.
	for _, node := range []string{"alpha", "beta"} {
		nc, err := connect(remoteURL, node, legacy)
		if err == nil {
			nc.Close()
			t.Errorf("unbound token presented as %q from %s connected; want it refused", node, ip)
			continue
		}
		t.Logf("unbound token as %q refused: %v", node, err)
	}

	// 2. A token bound to the node presenting it connects from the same
	//    address, and its grant works: the api receives its event and it
	//    receives the api's command.
	beta, err := connect(remoteURL, "beta", bound)
	if err != nil {
		t.Fatalf("bound token presented as its own node was refused: %v", err)
	}
	defer beta.Close()
	assertNodeRoundTrip(t, api, beta, "beta")

	// 3. The controlplane's co-located agent connects over loopback with no
	//    token, exactly as before.
	cp, err := connect(loopbackURL, "controlplane1", "")
	if err != nil {
		t.Fatalf("tokenless loopback agent was refused: %v", err)
	}
	defer cp.Close()
	assertNodeRoundTrip(t, api, cp, "controlplane1")

	// Refusing the token did not revoke it: it stays counted — and listed —
	// until the operator revokes it, which clears it.
	if n, err := eb.tokens.CountActiveUnbound(ctx); err != nil || n != 1 {
		t.Fatalf("CountActiveUnbound = (%d, %v); want (1, nil)", n, err)
	}
	if _, err := eb.tokens.Revoke(ctx, legacyID); err != nil {
		t.Fatalf("Revoke(legacy): %v", err)
	}
	if n, err := eb.tokens.CountActiveUnbound(ctx); err != nil || n != 0 {
		t.Fatalf("CountActiveUnbound after revoke = (%d, %v); want (0, nil)", n, err)
	}

	// Neither admitted session was touched by any of it.
	if !beta.IsConnected() || !cp.IsConnected() {
		t.Errorf("admitted sessions dropped: beta connected=%v, controlplane1 connected=%v", beta.IsConnected(), cp.IsConnected())
	}
}

// assertNodeRoundTrip checks nc holds node's grant on the bus: an event it
// publishes on its own subjects reaches the api, and a command the api
// publishes to it arrives. Each wait is bounded; a miss fails the test.
func assertNodeRoundTrip(t *testing.T, api, nc *nats.Conn, node string) {
	t.Helper()
	scope := "rasputin.node." + node

	evt, err := api.SubscribeSync(scope + ".evt.registered")
	if err != nil {
		t.Fatalf("api subscribe: %v", err)
	}
	defer func() { _ = evt.Unsubscribe() }()
	if err := api.Flush(); err != nil {
		t.Fatalf("api flush: %v", err)
	}
	if err := nc.Publish(scope+".evt.registered", []byte(`{}`)); err != nil {
		t.Fatalf("%s publish: %v", node, err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("%s flush: %v", node, err)
	}
	if _, err := evt.NextMsg(5 * time.Second); err != nil {
		t.Errorf("%s published its own event and the api did not receive it: %v", node, err)
	}

	cmd, err := nc.SubscribeSync(scope + ".cmd.diag.ping")
	if err != nil {
		t.Fatalf("%s subscribe: %v", node, err)
	}
	defer func() { _ = cmd.Unsubscribe() }()
	// Flush is a PING/PONG round trip, so the server has processed the SUB
	// (and would have reported a permissions violation) before the publish.
	if err := nc.Flush(); err != nil {
		t.Fatalf("%s flush: %v", node, err)
	}
	if err := api.Publish(scope+".cmd.diag.ping", []byte(`{}`)); err != nil {
		t.Fatalf("api publish: %v", err)
	}
	if err := api.Flush(); err != nil {
		t.Fatalf("api flush: %v", err)
	}
	if _, err := cmd.NextMsg(5 * time.Second); err != nil {
		t.Errorf("%s did not receive the api's command: %v", node, err)
	}
}
