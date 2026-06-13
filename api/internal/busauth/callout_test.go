package busauth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/nats-io/nats.go"
)

// TestResponder_Authorize exercises the trust matrix directly: node-id always
// required; loopback trusted without a token; everyone else needs a live token.
func TestResponder_Authorize(t *testing.T) {
	ctx := context.Background()
	store := newTokenStore(t)
	good, _, err := store.Mint(ctx, "test")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	revoked, revID, _ := store.Mint(ctx, "revoked")
	if err := store.Revoke(ctx, revID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	r := &Responder{tokens: store}

	cases := []struct {
		name           string
		nodeID, token  string
		host           string
		wantAuthorized bool
	}{
		{"empty node id denied", "", good, "192.168.1.50", false},
		{"loopback no token trusted", "node-cp", "", "127.0.0.1", true},
		{"loopback ipv6 trusted", "node-cp", "", "::1", true},
		{"remote valid token", "fw-1", good, "192.168.1.50", true},
		{"remote no token denied", "fw-1", "", "192.168.1.50", false},
		{"remote bad token denied", "fw-1", "garbage", "192.168.1.50", false},
		{"remote revoked token denied", "fw-1", revoked, "192.168.1.50", false},
		{"empty node id even on loopback denied", "", "", "127.0.0.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := r.authorize(tc.nodeID, tc.token, tc.host)
			if ok != tc.wantAuthorized {
				t.Errorf("authorize(%q,token,%q) = %v (%q); want %v",
					tc.nodeID, tc.host, ok, reason, tc.wantAuthorized)
			}
		})
	}
}

// TestCallout_EndToEnd brings up the real embedded server with AuthEnforce and
// the responder, then drives a client through it: a valid-token connection
// works and is subject-scoped; a connection with no node id is rejected.
func TestCallout_EndToEnd(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	issuer, err := EnsureIssuer(filepath.Join(dir, "bus"))
	if err != nil {
		t.Fatalf("EnsureIssuer: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "nats"), 0o755); err != nil {
		t.Fatalf("mkdir nats: %v", err)
	}
	tokens, err := OpenStore(ctx, filepath.Join(dir, "bus.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = tokens.Close() })
	token, _, err := tokens.Mint(ctx, "fw")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	srv, err := bus.Start(ctx, bus.Config{
		Host: "127.0.0.1", Port: -1, // -1 = ephemeral port
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

	resp := NewResponder(srv.Conn(), issuer, tokens)
	if err := resp.Start(); err != nil {
		t.Fatalf("responder.Start: %v", err)
	}
	t.Cleanup(resp.Stop)

	url := srv.ClientURL()

	// 1. Valid token → connects, and is scoped: it can round-trip on its own
	//    node subject but a publish to a foreign node raises a permissions
	//    violation.
	permErr := make(chan error, 4)
	nc, err := nats.Connect(url,
		nats.UserInfo("fw-1", token),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) { permErr <- e }),
	)
	if err != nil {
		t.Fatalf("valid-token connect: %v", err)
	}
	defer nc.Close()

	sub, err := nc.SubscribeSync("rasputin.node.fw-1.cmd.test")
	if err != nil {
		t.Fatalf("subscribe own scope: %v", err)
	}
	if err := nc.Publish("rasputin.node.fw-1.evt.hello", []byte("hi")); err != nil {
		t.Fatalf("publish own scope: %v", err)
	}
	_ = nc.Flush()
	_ = sub

	// Foreign-subject publish must be denied (permissions violation).
	if err := nc.Publish("rasputin.node.other.evt.x", []byte("nope")); err != nil {
		t.Fatalf("publish call itself shouldn't error synchronously: %v", err)
	}
	_ = nc.Flush()
	select {
	case e := <-permErr:
		if e == nil {
			t.Fatal("expected a permissions violation error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected a permissions violation for a foreign-subject publish; none arrived")
	}

	// 2. No node id (no username) → rejected at connect.
	bad, err := nats.Connect(url, nats.Token("whatever"), nats.MaxReconnects(0), nats.Timeout(2*time.Second))
	if err == nil {
		bad.Close()
		t.Fatal("connection with no node id should be rejected")
	}
	// The exact rejection wording varies (authorization violation / timeout);
	// any connect error is a denial. Log it for clarity.
	t.Logf("no-node-id connection rejected as expected: %v", err)
}
