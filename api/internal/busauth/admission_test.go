package busauth

// StartAdmission on a real embedded TLS bus with enforcement, the real token
// store and the real node registry (inventory) on one SQLite file, as
// cmd/rasputin-api wires them.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bus"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// admissionBus is an enforced bus with NO responder yet: the caller starts
// admission itself.
type admissionBus struct {
	srv    *bus.Server
	issuer *Issuer
	tokens *Store
	url    string
}

func startAdmissionBus(t *testing.T) *admissionBus {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "rasputin.db")
	issuer, err := EnsureIssuer(filepath.Join(dir, "bus"))
	if err != nil {
		t.Fatalf("EnsureIssuer: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "nats"), 0o755); err != nil {
		t.Fatal(err)
	}
	tokens, err := OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = tokens.Close() })
	inv, err := inventory.OpenStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("inventory.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	if err := tokens.SetNodeRegistry(ctx, inv.Registry()); err != nil {
		t.Fatalf("SetNodeRegistry: %v", err)
	}
	srv, err := bus.Start(ctx, bus.Config{
		Host: "127.0.0.1", Port: -1,
		StoreDir:        filepath.Join(dir, "nats"),
		AuthEnforce:     true,
		IssuerPublicKey: issuer.PublicKey(),
		APIUser:         "rasputin-api",
		APIPass:         "test-secret",
		TLS:             busKit.Server,
	})
	if err != nil {
		t.Fatalf("bus.Start: %v", err)
	}
	t.Cleanup(srv.Stop)
	url, listening := srv.ClientURL()
	if !listening {
		t.Fatal("the bus reports no listener")
	}
	return &admissionBus{srv: srv, issuer: issuer, tokens: tokens, url: url}
}

func (b *admissionBus) mint(t *testing.T, id string) string {
	t.Helper()
	tok, _, err := b.tokens.MintBound(context.Background(), id, id, proto.RoleCompute)
	if err != nil {
		t.Fatalf("MintBound(%s): %v", id, err)
	}
	return tok
}

// TC-623-08: once StartAdmission returns, a node presenting its bound token is
// admitted, and its session is tracked: DisconnectNode closes it.
func TestStartAdmission_AdmitsAndTracksSessions(t *testing.T) {
	b := startAdmissionBus(t)
	tok := b.mint(t, "n1")

	stop, err := StartAdmission(true, b.srv, b.issuer, b.tokens)
	if err != nil {
		t.Fatalf("StartAdmission: %v", err)
	}
	t.Cleanup(stop)

	closed := make(chan struct{})
	nc, err := connect(b.url, "n1", tok, nats.Timeout(busWaitLimit), nats.ClosedHandler(func(*nats.Conn) { close(closed) }))
	if err != nil {
		t.Fatalf("n1 with its bound token was not admitted: %v", err)
	}
	t.Cleanup(nc.Close)

	if n := b.tokens.DisconnectNode("n1"); n != 1 {
		t.Fatalf("DisconnectNode(n1) closed %d session(s), want 1: sessions are not tracked", n)
	}
	select {
	case <-closed:
	case <-time.After(busWaitLimit):
		t.Fatalf("n1's connection was not closed within %s of DisconnectNode (status %v)", busWaitLimit, nc.Status())
	}
}

// TC-623-09: with enforcement off, StartAdmission adds no subscription and its
// stop is safe to call, twice.
func TestStartAdmission_EnforcementOff(t *testing.T) {
	b := startAdmissionBus(t)
	before := b.srv.Conn().NumSubscriptions()

	stop, err := StartAdmission(false, b.srv, b.issuer, b.tokens)
	if err != nil {
		t.Fatalf("StartAdmission(false): %v", err)
	}
	if after := b.srv.Conn().NumSubscriptions(); after != before {
		t.Fatalf("subscriptions %d → %d with enforcement off, want unchanged", before, after)
	}
	stop()
	stop()
}

// TC-623-10: on a closed connection admission fails closed, with an error
// that names it and wraps the subscribe error.
func TestStartAdmission_FailsClosed(t *testing.T) {
	b := startAdmissionBus(t)
	b.srv.Conn().Close()

	stop, err := StartAdmission(true, b.srv, b.issuer, b.tokens)
	if err == nil {
		stop()
		t.Fatal("StartAdmission on a closed connection returned no error")
	}
	if !strings.HasPrefix(err.Error(), "bus admission:") {
		t.Fatalf("error %q does not start with %q", err, "bus admission:")
	}
	if !errors.Is(err, nats.ErrConnectionClosed) {
		t.Fatalf("error %v does not wrap nats.ErrConnectionClosed", err)
	}
}

// TC-623-11: after stop, a node presenting a bound token is not admitted.
//
// With no responder, nats-server refuses the connection only at its auth
// timeout (TLSTimeout+1 = 6 s), and its first PING to the client goes out
// before that, so nats.go reports the refusal as a protocol error ("expected
// 'PONG', got 'PING'") rather than nats.ErrAuthorization; the server logs the
// authentication error. Either form is a refusal. The same token admitted
// before stop proves the refusal is stop's doing.
func TestStartAdmission_StopEndsAdmission(t *testing.T) {
	b := startAdmissionBus(t)
	tok := b.mint(t, "n1")
	baseline := b.srv.Conn().NumSubscriptions()

	stop, err := StartAdmission(true, b.srv, b.issuer, b.tokens)
	if err != nil {
		t.Fatalf("StartAdmission: %v", err)
	}
	nc, err := connect(b.url, "n1", tok, nats.Timeout(busWaitLimit))
	if err != nil {
		t.Fatalf("n1 was not admitted while admission ran: %v", err)
	}
	nc.Close()

	stop()
	// The unsubscribe has reached the server once a round trip returns.
	if err := b.srv.Conn().Flush(); err != nil {
		t.Fatal(err)
	}
	if got := b.srv.Conn().NumSubscriptions(); got != baseline {
		t.Fatalf("%d subscriptions after stop, want the %d before admission", got, baseline)
	}

	// The dial bound is above the server's auth timeout.
	nc, err = connect(b.url, "n1", tok, nats.Timeout(busWaitLimit))
	if err == nil {
		nc.Close()
		t.Fatal("a bound token was admitted after admission stopped")
	}
	if !errors.Is(err, nats.ErrAuthorization) && !strings.Contains(err.Error(), "expected 'PONG'") {
		t.Fatalf("connect after stop failed with %v, want the server's refusal of the CONNECT", err)
	}
}
