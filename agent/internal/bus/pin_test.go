package bus

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// --- pin sources -----------------------------------------------------------

func mustPin(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	pin, err := proto.BusPinForPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestResolvePin(t *testing.T) {
	envPin := mustPin(t, newKey(t))
	filePin := mustPin(t, newKey(t))
	dir := t.TempDir()
	file := PinFilePath(dir)

	// Nothing anywhere: unpinned, no fault.
	if pin, src, envErr, fileErr := ResolvePin("", file); pin != "" || src != "" || envErr != nil || fileErr != nil {
		t.Fatalf("empty: got (%q, %q, %v, %v)", pin, src, envErr, fileErr)
	}
	if err := WritePinFile(file, filePin); err != nil {
		t.Fatal(err)
	}
	// File only.
	if pin, src, _, _ := ResolvePin("", file); pin != filePin || src != "file" {
		t.Fatalf("file: got (%q, %q)", pin, src)
	}
	// Env wins over the file.
	if pin, src, _, _ := ResolvePin("  "+envPin+"\n", file); pin != envPin || src != "env" {
		t.Fatalf("env: got (%q, %q)", pin, src)
	}
	// A bad env pin is a fault and falls through to the file.
	pin, src, envErr, fileErr := ResolvePin("sha256/nope", file)
	if envErr == nil || fileErr != nil || pin != filePin || src != "file" {
		t.Fatalf("bad env: got (%q, %q, %v, %v)", pin, src, envErr, fileErr)
	}
	// A corrupt file is a fault and leaves the node unpinned.
	if err := os.WriteFile(file, []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pin, src, envErr, fileErr = ResolvePin("", file)
	if fileErr == nil || envErr != nil || pin != "" || src != "" {
		t.Fatalf("corrupt file: got (%q, %q, %v, %v)", pin, src, envErr, fileErr)
	}
}

func TestWritePinFile_RefusesAMalformedPinAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	file := PinFilePath(dir)
	if err := WritePinFile(file, "sha256/short"); !errors.Is(err, proto.ErrBusPinFormat) {
		t.Fatalf("WritePinFile(bad) = %v, want ErrBusPinFormat", err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("a malformed pin was written: %v", err)
	}
	pin := mustPin(t, newKey(t))
	if err := WritePinFile(file, pin); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != pin+"\n" {
		t.Fatalf("file = %q, want %q", got, pin+"\n")
	}
	entries, err := os.ReadDir(filepath.Dir(file))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("pin dir holds %d entries, want only the pin file: %v", len(entries), entries)
	}
}

// --- a TLS bus -------------------------------------------------------------

// selfSigned wraps k in a certificate valid from notBefore to notAfter — the
// same shape bustls.SelfSignedCert produces on the api (which this module
// cannot import).
func selfSigned(t *testing.T, k *ecdsa.PrivateKey, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rasputin-bus"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func alwaysValid(t *testing.T, k *ecdsa.PrivateKey) tls.Certificate {
	return selfSigned(t, k, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

// startTLSServer runs a user/password nats-server serving cert. allowPlain is
// the migration window (AllowNonTLS); false is TLS-required.
func startTLSServer(t *testing.T, cert tls.Certificate, allowPlain bool) *natsserver.Server {
	t.Helper()
	s, err := natsserver.NewServer(&natsserver.Options{
		Host: "127.0.0.1", Port: -1, Username: testNode, Password: "tok-A", NoLog: true, NoSigs: true,
		TLSConfig:   &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}},
		TLSTimeout:  5,
		AllowNonTLS: allowPlain,
	})
	if err != nil {
		t.Fatalf("nats server: %v", err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server not ready")
	}
	t.Cleanup(func() {
		s.Shutdown()
		s.WaitForShutdown()
	})
	return s
}

// natsURL is the server's address as a nats:// URL. A TLS server's ClientURL
// says tls://, and nats.go turns TLS on for that scheme by itself — which is
// not how a node dials (seeds carry nats://), so it would hide exactly the
// behaviour under test.
func natsURL(t *testing.T, s *natsserver.Server) string {
	t.Helper()
	return "nats://" + s.Addr().String()
}

func dialWithPin(t *testing.T, url, pin string) (*testClient, error) {
	t.Helper()
	tc := newTestClient(t, url, "tok-A")
	if err := tc.SetPin(pin); err != nil {
		t.Fatalf("SetPin: %v", err)
	}
	return tc, tc.Dial()
}

func TestClient_PinnedTLS(t *testing.T) {
	key := newKey(t)
	pin := mustPin(t, key)
	other := mustPin(t, newKey(t))

	t.Run("right pin connects over TLS and reports it", func(t *testing.T) {
		s := startTLSServer(t, alwaysValid(t, key), true)
		tc, err := dialWithPin(t, natsURL(t, s), pin)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if !tc.BusTLS(tc.Conn()) {
			t.Fatal("BusTLS = false on a pinned TLS connection")
		}
		if _, err := tc.Conn().TLSConnectionState(); err != nil {
			t.Fatalf("connection is not TLS: %v", err)
		}
	})

	t.Run("wrong pin is refused", func(t *testing.T) {
		s := startTLSServer(t, alwaysValid(t, key), true)
		_, err := dialWithPin(t, natsURL(t, s), other)
		if err == nil || !strings.Contains(err.Error(), "does not match RASPUTIN_BUS_PIN") {
			t.Fatalf("Dial with the wrong pin = %v, want the pin mismatch", err)
		}
		// The server notices the aborted handshake on its own goroutine.
		waitFor(t, "the server to drop the refused connection", 5*time.Second, func() bool { return s.NumClients() == 0 })
	})

	t.Run("no pin still connects in plaintext during migration", func(t *testing.T) {
		s := startTLSServer(t, alwaysValid(t, key), true)
		tc := newTestClient(t, natsURL(t, s), "tok-A")
		if err := tc.Dial(); err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if tc.BusTLS(tc.Conn()) {
			t.Fatal("BusTLS = true on a plaintext connection")
		}
		if _, err := tc.Conn().TLSConnectionState(); !errors.Is(err, nats.ErrConnectionNotTLS) {
			t.Fatalf("TLSConnectionState = %v, want ErrConnectionNotTLS", err)
		}
	})

	t.Run("TLS-required refuses a client with no pin", func(t *testing.T) {
		s := startTLSServer(t, alwaysValid(t, key), false)
		tc := newTestClient(t, natsURL(t, s), "tok-A")
		// nats.go upgrades to TLS on its own when the server requires it, and
		// then verifies against the system roots — which the self-signed bus
		// certificate is not in. Refused either way, and before CONNECT.
		if err := tc.Dial(); err == nil {
			t.Fatal("an unpinned client connected to a TLS-required bus")
		}
	})

	t.Run("a pinned client refuses a server that offers no TLS", func(t *testing.T) {
		s := startServer(t, -1, testNode, "tok-A") // plaintext only: an old, or a man-in-the-middle, server
		_, err := dialWithPin(t, natsURL(t, s), pin)
		if !errors.Is(err, nats.ErrSecureConnWanted) {
			t.Fatalf("Dial = %v, want nats.ErrSecureConnWanted (no CONNECT, so no token, over plaintext)", err)
		}
	})

	// Clock independence (#448 "a node that boots with a wrong clock still
	// joins the bus"): the check is the key, never the dates.
	for name, cert := range map[string]tls.Certificate{
		"certificate not valid until 2099": selfSigned(t, key, time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)),
		"certificate expired in 1999":      selfSigned(t, key, time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)),
	} {
		t.Run(name, func(t *testing.T) {
			s := startTLSServer(t, cert, false)
			tc, err := dialWithPin(t, natsURL(t, s), pin)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			if !tc.BusTLS(tc.Conn()) {
				t.Fatal("BusTLS = false")
			}
		})
	}
}

// --- delivery --------------------------------------------------------------

// requestPin delivers a pin to the node's bus.pin handler from a separate
// probe connection. It flushes the Client's own connection first for the same
// reason ping does (see ping in client_test.go): nats.go buffers SUB and
// writes it from another goroutine, so a probe on a second connection can
// reach the server before the handler's subscription does and be answered
// "no responders".
func requestPin(t *testing.T, c connHolder, s *natsserver.Server, pin string) proto.BusPinAck {
	t.Helper()
	nc := c.Conn()
	if nc == nil {
		t.Fatal("the Client has no connection: nothing could be subscribed")
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush the agent's connection: %v (its subscriptions never reached the server)", err)
	}
	probe, err := nats.Connect(natsURL(t, s), nats.UserInfo(testNode, "tok-A"), nats.Secure(&tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // test probe on loopback; the pin check under test is the agent's
	}))
	if err != nil {
		t.Fatalf("probe connect: %v", err)
	}
	defer probe.Close()
	payload, err := json.Marshal(proto.BusPinCmd{Pin: pin})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := probe.Request(proto.NodeCmdSubject(testNode, proto.BusPinVerb), payload, 5*time.Second)
	if err != nil {
		t.Fatalf("request bus.pin: %v", err)
	}
	var ack proto.BusPinAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatal(err)
	}
	return ack
}

// A plaintext node handed the pin saves it, answers, and comes back on a new
// connection over TLS — onConn and onConnected re-run, so the registration
// that follows can say busTls=true.
func TestClient_PinDeliveryReconnectsOverTLS(t *testing.T) {
	key := newKey(t)
	pin := mustPin(t, key)
	s := startTLSServer(t, alwaysValid(t, key), true)
	stateDir := t.TempDir()
	pinFile := PinFilePath(stateDir)

	tc := &testClient{}
	var sub func(*nats.Conn) error
	tc.Client = New(natsURL(t, s), testNode, "tok-A",
		func(nc *nats.Conn) error {
			tc.conns.Add(1)
			return sub(nc)
		},
		func(*nats.Conn) { tc.connected.Add(1) },
	)
	sub = tc.PinSubscriber(testNode, pinFile)
	tc.reconnectWait = 50 * time.Millisecond
	tc.backoff = Backoff{Min: 50 * time.Millisecond, Max: 200 * time.Millisecond}
	t.Cleanup(tc.Close)
	if err := tc.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	first := tc.Conn()
	if tc.BusTLS(first) {
		t.Fatal("started on TLS without a pin")
	}

	ack := requestPin(t, tc, s, "sha256/garbage")
	if ack.OK {
		t.Fatalf("a malformed pin was accepted: %+v", ack)
	}

	ack = requestPin(t, tc, s, pin)
	if !ack.OK || !ack.Reconnecting || ack.Pin != pin || ack.NodeID != testNode {
		t.Fatalf("ack = %+v, want OK, reconnecting, pin %s", ack, pin)
	}
	if got, err := ReadPinFile(pinFile); err != nil || got != pin {
		t.Fatalf("pin file = (%q, %v), want %q — the pin must be persisted before the ack", got, err, pin)
	}
	waitFor(t, "the Client to re-dial over TLS", 10*time.Second, func() bool {
		nc := tc.Conn()
		return nc != first && nc.IsConnected() && tc.BusTLS(nc)
	})
	if got := tc.conns.Load(); got != 2 {
		t.Errorf("onConn calls = %d, want 2 (the TLS conn re-subscribes)", got)
	}

	// Same pin again: acknowledged, nothing replaced.
	cur := tc.Conn()
	ack = requestPin(t, tc, s, pin)
	if !ack.OK || ack.Reconnecting {
		t.Fatalf("repeat delivery ack = %+v, want OK without reconnecting", ack)
	}
	// A different pin: key rotation, refused, and the node keeps its pin.
	ack = requestPin(t, tc, s, mustPin(t, newKey(t)))
	if ack.OK || ack.Pin != pin {
		t.Fatalf("rotation ack = %+v, want a refusal naming the held pin", ack)
	}
	if tc.Conn() != cur || !tc.BusTLS(cur) {
		t.Fatal("a refused or repeated delivery replaced the TLS connection")
	}
	if got, _ := ReadPinFile(pinFile); got != pin {
		t.Fatalf("pin file changed to %q after a refused rotation", got)
	}
}
