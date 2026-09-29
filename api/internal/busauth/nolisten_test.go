package busauth

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// TC-517-16: with auth enforced and no listener — the api whose bus key did
// not load — the callout responder starts, the api's own in-process connection
// round-trips a request, the JOBS stream exists, and nothing listens on the
// configured port.
func TestNoListen_WithAuthEnforced(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	issuer, err := EnsureIssuer(filepath.Join(dir, "bus"))
	if err != nil {
		t.Fatalf("EnsureIssuer: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "nats"), 0o755); err != nil {
		t.Fatal(err)
	}
	tokens, err := OpenStore(ctx, filepath.Join(dir, "bus.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = tokens.Close() })
	if err := tokens.SetNodeRegistry(ctx, newRecordingRegistry()); err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	srv, err := bus.Start(ctx, bus.Config{
		Host: "127.0.0.1", Port: port,
		StoreDir:        filepath.Join(dir, "nats"),
		AuthEnforce:     true,
		IssuerPublicKey: issuer.PublicKey(),
		APIUser:         "rasputin-api",
		APIPass:         "test-secret",
		NoListen:        true,
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
	if resp.sub == nil || !resp.sub.IsValid() {
		t.Fatal("the callout responder holds no live subscription")
	}

	if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second); err == nil {
		_ = c.Close()
		t.Fatalf("something accepts on port %d", port)
	}
	if url, listening := srv.ClientURL(); listening || url != "" {
		t.Fatalf("ClientURL = (%q, %v), want (\"\", false)", url, listening)
	}

	nc := srv.Conn()
	sub, err := nc.Subscribe("test.echo", func(m *nats.Msg) { _ = m.Respond([]byte("pong")) })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	reply, err := nc.Request("test.echo", nil, 5*time.Second)
	if err != nil || string(reply.Data) != "pong" {
		t.Fatalf("in-process request = (%v, %v), want pong", reply, err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Stream(ctx, "JOBS"); err != nil {
		t.Fatalf("JOBS stream: %v", err)
	}
}
