package api

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// selfSignedClient builds the certificate a node presents on the node
// listener: its own key, wrapped in a certificate IT signed, dated 1970-9999,
// with the clientAuth EKU. No CA issues it, and nothing on the server reads
// anything but the key — which is the whole point.
func selfSignedClient(t *testing.T, cn string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := proto.NodeKeySPKIHash(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hash
}

// keyClientTLS dials the listener with a self-signed client certificate.
func (it *ingressTLS) keyClientTLS(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      it.roots,
		Certificates: []tls.Certificate{cert},
		ServerName:   "127.0.0.1",
	}
}

func (it *ingressTLS) dialKey(t *testing.T, cert tls.Certificate) (*tls.Conn, error) {
	t.Helper()
	conn, err := tls.Dial("tcp", strings.TrimPrefix(it.srv.URL, "https://"), it.keyClientTLS(cert))
	if err != nil {
		return nil, err
	}
	// TLS 1.3 reports the server's refusal on the first read, not in Dial.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("POST /api/obs/ingest HTTP/1.1\r\nHost: ingest\r\nContent-Length: 1\r\n\r\nx")); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// readStatus reads one response off conn.
func readStatus(t *testing.T, conn *tls.Conn) (int, error) {
	t.Helper()
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// keyListener is startIngress plus an inventory-backed registry with real
// nodes, so admission is decided by the production types.
func keyListener(t *testing.T, nodes ...string) (*Server, *inventory.Store, *ingressTLS) {
	t.Helper()
	s := newKeyIngestServer(t, nodes...)
	inv, _ := realRegistry(t, s, nodes...)
	it := startIngress(t, s, inv.Registry(), nodes...)
	return s, inv, it
}

// newKeyIngestServer is newIngestServer without the collector keys its seeded
// nodes get, so each test registers exactly the keys it means to.
func newKeyIngestServer(t *testing.T, seedNodes ...string) *Server {
	t.Helper()
	s := newIngestServer(t, obs.NewStatus(obs.NewNoopSupervisor(), nil, nil))
	ctx := context.Background()
	for _, id := range seedNodes {
		if err := s.inv.Insert(ctx, &proto.Node{ID: id, Role: proto.RoleCompute, Hostname: id}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// A node presenting a key it registered is admitted, although nothing signed
// its certificate: the listener checks the key and ignores the wrapper.
func TestNodeListener_AdmitsARegisteredKey(t *testing.T) {
	_, inv, it := keyListener(t, "c02")
	cert, hash := selfSignedClient(t, "c02")
	if _, err := inv.SetNodeKeys(context.Background(), "c02", proto.NodeKeys{proto.NodeKeyCollector: hash}); err != nil {
		t.Fatal(err)
	}
	conn, err := it.dialKey(t, cert)
	if err != nil {
		t.Fatalf("a registered key was refused: %v", err)
	}
	defer func() { _ = conn.Close() }()
	code, err := readStatus(t, conn)
	if err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("got (%d, %v), want 503 backend-not-ready", code, err)
	}
}

// A key nobody registered is refused, even in a certificate that names an
// admitted node: with no chain to verify, the CommonName is just a string the
// caller chose.
func TestNodeListener_RefusesAnUnregisteredKey(t *testing.T) {
	_, _, it := keyListener(t, "c02")
	cert, _ := selfSignedClient(t, "c02")
	conn, err := it.dialKey(t, cert)
	if err == nil {
		_, err = readStatus(t, conn)
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("a self-signed certificate naming an admitted node was admitted on its CommonName")
	}
	t.Logf("refused: %v", err)
}

// A key registered to one node does not let a caller act as another: the
// identity is the key's owner, never anything the certificate says.
func TestNodeListener_IdentityIsTheKeysOwner(t *testing.T) {
	_, inv, it := keyListener(t, "c02", "c03")
	// c03's key, in a certificate claiming to be c02.
	cert, hash := selfSignedClient(t, "c02")
	if _, err := inv.SetNodeKeys(context.Background(), "c03", proto.NodeKeys{proto.NodeKeyCollector: hash}); err != nil {
		t.Fatal(err)
	}
	conn, err := it.dialKey(t, cert)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if code, err := readStatus(t, conn); err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("got (%d, %v), want 503 — the request is served as c03", code, err)
	}
	// Removing c03 closes it; c02 was never the owner, so nothing about c02
	// would have.
	if err := inv.Delete(context.Background(), "c03"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("removing the key's owner did not close the connection")
	}
}

// A collector deployed before node keys existed keeps working: its mesh chain
// is verified explicitly, since RequireAnyClientCert verifies nothing.
func TestNodeListener_StillAdmitsAMeshChainClient(t *testing.T) {
	s := newKeyIngestServer(t, "c02")
	inv, _ := realRegistry(t, s, "c02")
	it := startIngress(t, s, inv.Registry(), "c02")
	if code, err := postIngest(it.keepAliveClient("c02"), it.srv.URL); err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("a mesh-chain collector = (%d, %v), want 503 backend-not-ready", code, err)
	}
}

// Replacing a node's key ends the sessions held under the OLD key and leaves
// the ones under the new key alone.
func TestNodeListener_AKeyChangeClosesTheOldKeysSessions(t *testing.T) {
	ctx := context.Background()
	_, inv, it := keyListener(t, "c02")
	oldCert, oldHash := selfSignedClient(t, "c02")
	if _, err := inv.SetNodeKeys(ctx, "c02", proto.NodeKeys{proto.NodeKeyCollector: oldHash}); err != nil {
		t.Fatal(err)
	}
	oldConn, err := it.dialKey(t, oldCert)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = oldConn.Close() }()
	if code, err := readStatus(t, oldConn); err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("the old key's first request = (%d, %v)", code, err)
	}

	newCert, newHash := selfSignedClient(t, "c02")
	if _, err := inv.SetNodeKeys(ctx, "c02", proto.NodeKeys{proto.NodeKeyCollector: newHash}); err != nil {
		t.Fatal(err)
	}
	_ = oldConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := oldConn.Read(make([]byte, 1)); err == nil {
		t.Error("the connection held under the replaced key is still open")
	}
	newConn, err := it.dialKey(t, newCert)
	if err != nil {
		t.Fatalf("the new key was refused: %v", err)
	}
	defer func() { _ = newConn.Close() }()
	if code, err := readStatus(t, newConn); err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("the new key = (%d, %v), want 503", code, err)
	}
	// And the old key cannot come back.
	if conn, err := it.dialKey(t, oldCert); err == nil {
		_, err = readStatus(t, conn)
		_ = conn.Close()
		if err == nil {
			t.Error("the replaced key still completes a request")
		}
	}
}

// A node's AGENT key is not its collector: the same node, admitted, is still
// refused on the collector's routes when it presents the wrong key.
func TestNodeListener_KeyPurposeIsCheckedPerRoute(t *testing.T) {
	_, inv, it := keyListener(t, "c02")
	cert, hash := selfSignedClient(t, "c02")
	if _, err := inv.SetNodeKeys(context.Background(), "c02", proto.NodeKeys{proto.NodeKeyAgent: hash}); err != nil {
		t.Fatal(err)
	}
	conn, err := it.dialKey(t, cert)
	if err != nil {
		t.Fatalf("the agent key was refused at the handshake; the route check should refuse it instead: %v", err)
	}
	defer func() { _ = conn.Close() }()
	code, err := readStatus(t, conn)
	if err != nil || code != http.StatusForbidden {
		t.Fatalf("got (%d, %v), want 403", code, err)
	}
}

// With no mesh pool — the state after the legacy collectors are gone — only a
// registered key is admitted.
func TestIdentify_WithoutAMeshPoolOnlyKeysAreAdmitted(t *testing.T) {
	gate := &countingLiveness{
		live: map[string]bool{"c02": true},
		keys: map[string]inventory.KeyOwner{},
	}
	c := newIngestConns(gate, nil)
	cert, hash := selfSignedClient(t, "c02")
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	cs := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if _, err := c.identify(cs); err == nil {
		t.Error("an unregistered key was admitted with no mesh pool")
	}
	gate.keys[hash] = inventory.KeyOwner{NodeID: "c02", Purpose: proto.NodeKeyCollector}
	id, err := c.identify(cs)
	if err != nil {
		t.Fatalf("a registered key was refused: %v", err)
	}
	if id.nodeID != "c02" || id.purpose != proto.NodeKeyCollector || id.spki != hash {
		t.Errorf("identity = %+v", id)
	}
}

func TestIdentify_RefusesWithoutACertificate(t *testing.T) {
	c := newIngestConns(&countingLiveness{}, nil)
	if _, err := c.identify(nil); err == nil {
		t.Error("no TLS state was admitted")
	}
	if _, err := c.identify(&tls.ConnectionState{}); err == nil {
		t.Error("no client certificate was admitted")
	}
}
