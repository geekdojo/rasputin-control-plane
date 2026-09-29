// Package bustlstest builds the TLS material a test needs to stand up the
// api's bus the way production does — TLS required, the bus key's
// certificate — and to reach it as a client. Tests import it; nothing in a
// shipped binary does.
//
// It is the one copy of what several packages' tests each carried before the
// bus stopped accepting plaintext (geekdojo/geekdojo-brain#517): a throwaway
// bus certificate, a client that trusts it, and the check that a plaintext
// CONNECT is refused on the wire.
package bustlstest

import (
	"bufio"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Kit is one throwaway bus identity: the server side and a client side that
// trusts it.
type Kit struct {
	// Server is what bus.Config.TLS takes.
	Server *tls.Config
	// Client verifies the server by chain and name: the certificate is its
	// only root, and bustls.BusDNSName is the name. No InsecureSkipVerify.
	Client *tls.Config
	// Option is nats.Secure(Client), for nats.Connect.
	Option nats.Option
	// Pin is the bus pin of the key, as a seed would carry it.
	Pin string
	// Cert is the certificate the server presents.
	Cert tls.Certificate
	// Signer is the bus key.
	Signer crypto.Signer
}

// Bus returns a fresh Kit, failing the test if one cannot be made.
func Bus(t testing.TB) Kit {
	t.Helper()
	k, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// New returns a fresh Kit. For a test package that shares one bus identity
// across its tests, built once at package level where there is no t.
func New() (Kit, error) {
	signer, cert, err := newCert()
	if err != nil {
		return Kit{}, err
	}
	pin, err := proto.BusPinForPublicKey(signer.Public())
	if err != nil {
		return Kit{}, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	client := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: bustls.BusDNSName}
	return Kit{
		Server: bustls.ServerTLSConfigFor(cert),
		Client: client,
		Option: nats.Secure(client),
		Pin:    pin,
		Cert:   cert,
		Signer: signer,
	}, nil
}

// MustNew is New for a package-level variable; it panics if a Kit cannot be
// made, which only a broken crypto/rand can cause.
func MustNew() Kit {
	k, err := New()
	if err != nil {
		panic(err)
	}
	return k
}

// Cert returns a fresh bus key and the self-signed certificate around it, dated
// 1970 to 9999 like the one the api persists.
func Cert(t testing.TB) (crypto.Signer, tls.Certificate) {
	t.Helper()
	signer, cert, err := newCert()
	if err != nil {
		t.Fatal(err)
	}
	return signer, cert
}

func newCert() (crypto.Signer, tls.Certificate, error) {
	signer, err := bustls.GenerateKey()
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	cert, err := bustls.SelfSignedCert(signer, time.Unix(0, 0).UTC(), time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC))
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	return signer, cert, nil
}

// AssertPlaintextRefused proves, on the wire, that the bus at addr refuses a
// plaintext client: its INFO says tls_required, and a CONNECT and PING written
// in plaintext get no PONG — the server drops the connection.
func AssertPlaintextRefused(t testing.TB, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()
	// Bounds this one exchange; the server's own TLS timeout closes it first.
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read INFO from %s: %v", addr, err)
	}
	body, ok := strings.CutPrefix(strings.TrimSpace(line), "INFO ")
	if !ok {
		t.Fatalf("first line from %s is not INFO: %q", addr, line)
	}
	info := map[string]any{}
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		t.Fatalf("decode INFO: %v", err)
	}
	if info["tls_required"] != true {
		t.Fatalf("INFO tls_required = %v, want true: %v", info["tls_required"], info)
	}
	if _, err := conn.Write([]byte("CONNECT {\"verbose\":false,\"user\":\"n1\",\"pass\":\"tok\"}\r\nPING\r\n")); err != nil {
		return // already closed by the server: refused
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("the bus at %s neither answered nor closed a plaintext CONNECT: %v", addr, err)
			}
			return // closed by the server: refused
		}
		if strings.HasPrefix(line, "PONG") {
			t.Fatalf("a plaintext client got PONG from the bus at %s", addr)
		}
	}
}
