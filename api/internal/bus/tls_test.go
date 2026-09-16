package bus

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// serverTLS is a throwaway self-signed server config — the shape
// bustls.Key.ServerTLSConfig builds (bustls imports this package, so the test
// cannot import it back).
func serverTLS(t *testing.T) *tls.Config {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rasputin-bus"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}
}

func startTLSBus(t *testing.T, allowPlain bool) *Server {
	t.Helper()
	s, err := Start(context.Background(), Config{
		Host: "127.0.0.1", Port: -1, StoreDir: t.TempDir(),
		TLS: serverTLS(t), AllowNonTLS: allowPlain,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(s.Stop)
	return s
}

func addrOf(s *Server) string { return s.ns.Addr().String() }

// readInfo reads the server's INFO line off a raw socket.
func readInfo(t *testing.T, conn net.Conn) (map[string]any, *bufio.Reader) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read INFO: %v", err)
	}
	body, ok := strings.CutPrefix(strings.TrimSpace(line), "INFO ")
	if !ok {
		t.Fatalf("first line is not INFO: %q", line)
	}
	info := map[string]any{}
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		t.Fatalf("decode INFO: %v", err)
	}
	return info, r
}

// TLS-required is enforced by the SERVER, on the wire: its INFO says so, and a
// client that writes its CONNECT in plaintext anyway gets no PONG — the
// connection is dropped. (#448 done-means: ":4222 refuses a plaintext
// connection".)
func TestStart_TLSRequiredRefusesPlaintextOnTheWire(t *testing.T) {
	s := startTLSBus(t, false)
	conn, err := net.DialTimeout("tcp", addrOf(s), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	info, r := readInfo(t, conn)
	if info["tls_required"] != true {
		t.Fatalf("INFO tls_required = %v, want true: %v", info["tls_required"], info)
	}
	if _, err := conn.Write([]byte("CONNECT {\"verbose\":false,\"user\":\"n1\",\"pass\":\"tok\"}\r\nPING\r\n")); err != nil {
		t.Fatal(err)
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("the server neither answered nor closed a plaintext CONNECT within the deadline: %v", err)
			}
			return // closed by the server: refused
		}
		if strings.HasPrefix(line, "PONG") {
			t.Fatal("a plaintext client got PONG from a TLS-required bus")
		}
	}
}

// Migration mode: the same server takes both, and PlaintextClients sees the
// plaintext one and neither the TLS one nor the api's own in-process conn.
func TestStart_MigrationAcceptsBothAndListsOnlyPlaintext(t *testing.T) {
	s := startTLSBus(t, true)
	url := "nats://" + addrOf(s)

	plain, err := nats.Connect(url, nats.Name("plain-agent"))
	if err != nil {
		t.Fatalf("plaintext connect during migration: %v", err)
	}
	defer plain.Close()
	secure, err := nats.Connect(url, nats.Name("tls-agent"), nats.Secure(&tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // loopback test client; pin verification is the agent's, tested there
	}))
	if err != nil {
		t.Fatalf("TLS connect during migration: %v", err)
	}
	defer secure.Close()
	if _, err := secure.TLSConnectionState(); err != nil {
		t.Fatalf("the TLS client is not on TLS: %v", err)
	}

	got, err := s.PlaintextClients()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "plain-agent" {
		t.Fatalf("PlaintextClients = %+v, want only plain-agent", got)
	}
}

// A connection counts as a plaintext CLIENT only once its CONNECT is processed.
// The server lists a socket from accept, so one still negotiating TLS — the
// flake this rule fixed: an unpinned agent mid-refusal on a TLS-required bus —
// shows no TLS version yet and must not count. (Driven through the pure rule:
// a real stalled socket holds the server's client lock for TLSTimeout inside
// Connz, see PlaintextClients.)
func TestPlaintextClientRule(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    server.ConnInfo
		want bool
	}{
		{"plaintext client after CONNECT (auth on)", server.ConnInfo{AuthorizedUser: "n1", Lang: "go"}, true},
		{"plaintext client after CONNECT (auth off)", server.ConnInfo{Lang: "go"}, true},
		{"TLS client", server.ConnInfo{TLSVersion: "1.3", Lang: "go", AuthorizedUser: "n1"}, false},
		{"socket still negotiating TLS / never spoke", server.ConnInfo{}, false},
		{"the api's own in-process connection", server.ConnInfo{Name: InProcessClientName, Lang: "go"}, false},
	} {
		if got := isPlaintextClient(&tc.c); got != tc.want {
			t.Errorf("%s: isPlaintextClient = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// No TLS configured: exactly the bus as it was.
func TestStart_NoTLSIsPlaintextAsBefore(t *testing.T) {
	s, err := Start(context.Background(), Config{Host: "127.0.0.1", Port: -1, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	conn, err := net.DialTimeout("tcp", addrOf(s), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	info, _ := readInfo(t, conn)
	if info["tls_required"] == true || info["tls_available"] == true {
		t.Fatalf("a server with no TLS config advertises TLS: %v", info)
	}
}

// A client closing is an event the api receives, carrying the id the
// plaintext listing reports for that connection — the pair a readiness check
// needs to re-decide when the last plaintext connection goes.
func TestOnClientDisconnect_ReportsTheClosedConnection(t *testing.T) {
	s := startTLSBus(t, true)
	closed := make(chan uint64, 8)
	if err := s.OnClientDisconnect(func(cid uint64) { closed <- cid }); err != nil {
		t.Fatalf("OnClientDisconnect: %v", err)
	}
	plain, err := nats.Connect("nats://"+addrOf(s), nats.Name("leaving"))
	if err != nil {
		t.Fatal(err)
	}
	listed, err := s.PlaintextClients()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Name != "leaving" || listed[0].CID == 0 {
		t.Fatalf("PlaintextClients = %+v, want the one client with its id", listed)
	}
	plain.Close()
	select {
	case cid := <-closed:
		if cid != listed[0].CID {
			t.Fatalf("disconnect reported cid %d, the listing said %d", cid, listed[0].CID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no disconnect event within 10s")
	}
}
