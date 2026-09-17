package bus

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// ClientOpen and DisconnectClient are what busauth closes a revoked token's
// live session with. The end-to-end behaviour (auth callout, revoke, refused
// reconnect) is tested in busauth and api; this pins the two primitives
// against a real embedded server.
func TestClientOpenAndDisconnectClient(t *testing.T) {
	srv, err := Start(context.Background(), Config{Host: "127.0.0.1", Port: -1, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(srv.Stop)

	closed := make(chan struct{})
	nc, err := nats.Connect(srv.ClientURL(), nats.NoReconnect(),
		nats.ClosedHandler(func(*nats.Conn) { close(closed) }))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(nc.Close)
	cid, err := nc.GetClientID()
	if err != nil {
		t.Fatalf("client id: %v", err)
	}

	id := srv.ServerID()
	if id == "" {
		t.Fatal("ServerID is empty on a running server")
	}
	if !srv.ClientOpen(id, cid) {
		t.Fatalf("ClientOpen(%d) = false for a connected client", cid)
	}
	if srv.ClientOpen("another-server", cid) || srv.DisconnectClient("another-server", cid) {
		t.Fatal("a connection id on another server's id names this server's connection")
	}
	if srv.ClientOpen(id, cid+1000) {
		t.Errorf("ClientOpen reports an id no client has as open")
	}

	if !srv.DisconnectClient(id, cid) {
		t.Fatalf("DisconnectClient(%d) = false for a connected client", cid)
	}
	// Closing unregisters the client synchronously, before DisconnectClient returns.
	if srv.ClientOpen(id, cid) {
		t.Errorf("ClientOpen(%d) = true after DisconnectClient returned", cid)
	}
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("the client did not observe the disconnect within 10s")
	}
	if srv.DisconnectClient(id, cid) {
		t.Errorf("DisconnectClient(%d) = true for a connection that is already closed", cid)
	}
}
