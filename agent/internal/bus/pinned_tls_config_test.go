package bus

// The proofs behind the CodeQL go/disabled-certificate-check verdict on
// pinnedTLSConfig (.github/codeql-register.tsv, geekdojo/geekdojo-brain#448).
// The flagged line sets InsecureSkipVerify; these tests are what make "the pin
// check replaces the chain check, on every handshake" a checked claim rather
// than a comment. If one of them has to change, the register row's reasoning
// has to be re-derived with it.

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TRIP-WIRE. The register verdict is void the moment pinnedTLSConfig returns a
// config that skips chain verification without a pin check in its place. The
// verdict's fingerprint covers only the InsecureSkipVerify line, so this test
// is the only thing that notices.
func TestPinnedTLSConfig_TripWire_NeverSkipsVerificationWithoutAPinCheck(t *testing.T) {
	cfg := pinnedTLSConfig(sha256.Sum256([]byte("any pin")))
	if cfg.InsecureSkipVerify && cfg.VerifyConnection == nil {
		t.Fatal("pinnedTLSConfig skips chain verification and installs no VerifyConnection: this accepts ANY server")
	}
	if cfg.VerifyPeerCertificate != nil {
		t.Fatal("pinnedTLSConfig uses VerifyPeerCertificate, which does not run on resumed handshakes; the pin check must be VerifyConnection")
	}
	if cfg.MinVersion < tls.VersionTLS13 {
		t.Errorf("MinVersion = %#x, want TLS 1.3", cfg.MinVersion)
	}
	// And the callback is a pin check, not a placeholder: it refuses a
	// connection whose leaf is some other key.
	cert := alwaysValid(t, newKey(t))
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); !errors.Is(err, errPinMismatch) {
		t.Fatalf("VerifyConnection on a different key = %v, want errPinMismatch", err)
	}
}

// A server that presents no certificate at all is refused, not waved through
// for lack of anything to compare.
func TestPinnedTLSConfig_RefusesAServerWithNoCertificate(t *testing.T) {
	k := newKey(t)
	cfg := pinnedTLSConfig(pinDigest(t, k))
	if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("VerifyConnection accepted a handshake with no peer certificate")
	}
}

// A server with a different key is refused in a real handshake — the TLS layer
// itself, not only the callback in isolation.
func TestPinnedTLSConfig_RefusesADifferentKeyInARealHandshake(t *testing.T) {
	served := newKey(t)
	addr := tlsEcho(t, alwaysValid(t, served))
	pinned := pinnedTLSConfig(pinDigest(t, newKey(t)))
	if err := handshake(addr, pinned); !errors.Is(err, errPinMismatch) {
		t.Fatalf("handshake against a different key = %v, want errPinMismatch", err)
	}
	if err := handshake(addr, pinnedTLSConfig(pinDigest(t, served))); err != nil {
		t.Fatalf("handshake against the pinned key = %v, want success", err)
	}
}

// Session resumption must not skip the pin check. A client whose session cache
// holds a ticket from a good handshake resumes the next one — the test proves
// the resumption actually happens — and a config pinning a DIFFERENT key that
// shares the cache is still refused on the resumed handshake.
func TestPinnedTLSConfig_PinCheckRunsOnResumedSessions(t *testing.T) {
	served := newKey(t)
	addr := tlsEcho(t, alwaysValid(t, served))
	cache := tls.NewLRUClientSessionCache(4)

	good := pinnedTLSConfig(pinDigest(t, served))
	good.ClientSessionCache = cache
	good.ServerName = "rasputin-bus"
	if err := handshake(addr, good); err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	st, err := handshakeState(addr, good)
	if err != nil {
		t.Fatalf("second handshake: %v", err)
	}
	if !st.DidResume {
		t.Fatal("the second handshake did not resume, so this test would prove nothing about resumption")
	}

	wrong := pinnedTLSConfig(pinDigest(t, newKey(t)))
	wrong.ClientSessionCache = cache
	wrong.ServerName = "rasputin-bus"
	if err := handshake(addr, wrong); !errors.Is(err, errPinMismatch) {
		t.Fatalf("resumable handshake pinning a different key = %v, want errPinMismatch", err)
	}
}

// --- helpers -----------------------------------------------------------------

func pinDigest(t *testing.T, k *ecdsa.PrivateKey) [sha256.Size]byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(der)
}

// tlsEcho serves TLS 1.3 with cert on loopback and, per connection, completes
// the handshake, writes one byte (so the client reads a session ticket) and
// closes.
func tlsEcho(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				if tc, ok := c.(*tls.Conn); ok && tc.Handshake() == nil {
					_, _ = tc.Write([]byte{1})
				}
			}(c)
		}
	}()
	return l.Addr().String()
}

func handshake(addr string, cfg *tls.Config) error {
	_, err := handshakeState(addr, cfg)
	return err
}

// handshakeState dials, handshakes and reads the server's one byte — which is
// also what lets a TLS 1.3 client receive the session ticket for next time.
func handshakeState(addr string, cfg *tls.Config) (tls.ConnectionState, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(c, buf); err != nil {
		return tls.ConnectionState{}, err
	}
	return c.ConnectionState(), nil
}
