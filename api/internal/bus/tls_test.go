package bus

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls/bustlstest"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// startTLSBus starts a bus the way the api does when its key loaded.
func startTLSBus(t *testing.T) (*Server, bustlstest.Kit) {
	t.Helper()
	kit := bustlstest.Bus(t)
	s, err := Start(context.Background(), Config{Host: "127.0.0.1", Port: -1, StoreDir: t.TempDir(), TLS: kit.Server})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(s.Stop)
	return s, kit
}

func addrOf(s *Server) string { return s.current().Addr().String() }

// freePort is a port nothing listens on when the function returns.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// assertNothingListens proves nothing accepts on port.
func assertNothingListens(t *testing.T, port int) {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err == nil {
		_ = c.Close()
		t.Fatalf("something accepted a connection on port %d", port)
	}
}

// TC-517-17: TLS-required is enforced by the SERVER, on the wire: its INFO says
// so, and a client that writes its CONNECT in plaintext anyway gets no PONG.
func TestStart_TLSRequiredRefusesPlaintextOnTheWire(t *testing.T) {
	s, _ := startTLSBus(t)
	bustlstest.AssertPlaintextRefused(t, addrOf(s))
}

// A client that trusts the bus certificate connects over TLS.
func TestStart_TLSClientConnects(t *testing.T) {
	s, kit := startTLSBus(t)
	url, listening := s.ClientURL()
	if !listening || url == "" {
		t.Fatalf("ClientURL = (%q, %v), want a listener", url, listening)
	}
	nc, err := nats.Connect("nats://"+addrOf(s), kit.Option)
	if err != nil {
		t.Fatalf("TLS connect: %v", err)
	}
	defer nc.Close()
	if _, err := nc.TLSConnectionState(); err != nil {
		t.Fatalf("not TLS: %v", err)
	}
}

// TC-517-15: a config that would listen in plaintext is refused, and nothing
// is bound.
func TestStart_RefusesToListenWithoutTLS(t *testing.T) {
	port := freePort(t)
	s, err := Start(context.Background(), Config{Host: "127.0.0.1", Port: port, StoreDir: t.TempDir()})
	if s != nil || !errors.Is(err, ErrNoTLS) {
		t.Fatalf("Start with neither TLS nor NoListen = (%v, %v), want (nil, ErrNoTLS)", s, err)
	}
	if !strings.Contains(err.Error(), "refusing to listen without TLS") {
		t.Errorf("error %q does not say it refuses to listen without TLS", err)
	}
	assertNothingListens(t, port)
}

// TC-517-18: TLS and NoListen together are refused; nothing is bound and no
// server is returned.
func TestStart_RefusesTLSAndNoListenTogether(t *testing.T) {
	kit := bustlstest.Bus(t)
	port := freePort(t)
	s, err := Start(context.Background(), Config{Host: "127.0.0.1", Port: port, StoreDir: t.TempDir(), TLS: kit.Server, NoListen: true})
	if s != nil || !errors.Is(err, ErrTLSAndNoListen) {
		t.Fatalf("Start with both = (%v, %v), want (nil, ErrTLSAndNoListen)", s, err)
	}
	assertNothingListens(t, port)
}

// TC-517-16: NoListen serves no network listener, while the api's own
// in-process connection round-trips a request, the JOBS stream exists, and
// ClientURL says there is nothing to dial.
func TestStart_NoListen(t *testing.T) {
	port := freePort(t)
	s, err := Start(context.Background(), Config{Host: "127.0.0.1", Port: port, StoreDir: t.TempDir(), NoListen: true})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(s.Stop)
	assertNothingListens(t, port)

	url, listening := s.ClientURL()
	if listening || url != "" {
		t.Fatalf("ClientURL = (%q, %v), want (\"\", false)", url, listening)
	}

	sub, err := s.Conn().Subscribe("test.echo", func(m *nats.Msg) { _ = m.Respond([]byte("pong")) })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	reply, err := s.Conn().Request("test.echo", nil, 5*time.Second)
	if err != nil || string(reply.Data) != "pong" {
		t.Fatalf("in-process request = (%v, %v), want pong", reply, err)
	}
	js, err := jetstream.New(s.Conn())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Stream(context.Background(), "JOBS"); err != nil {
		t.Fatalf("JOBS stream: %v", err)
	}
}
