//go:build linux

package proxy

// Functional regression for geekdojo-brain#611 against a REAL Caddy binary:
// a renewed app leaf must be SERVED, not merely written to disk.
//
// On the bench (2026-09-26) the leaf sweep rotated an app's leaf, the agent
// wrote it and pushed its config, and Caddy went on serving the old
// certificate until the next restart — because the config names the leaf by
// file path, the path never changes, and Caddy's /load no-ops a byte-identical
// config. Only a real Caddy shows that; a fake admin API would accept anything.
//
// The test drives the agent's own delivery path end to end: leaves arrive as
// app.leaf commands over NATS (RegisterHandlers → handleLeaf → LeafStore.Write
// → Reconcile → /load), and Caddy runs under the agent's own supervisor
// (RunCaddy). It asserts, on the TLS handshake Caddy actually serves:
//
//   - after a renewal (same app, same paths, new bytes) the served serial is
//     the new one — checked the moment the delivery is acknowledged, because
//     the ack follows the /load and /load returns only once the new config is
//     running and the old one is cleaned up, so there is nothing to wait for;
//   - Caddy was not restarted to get there (same pid), and a second app on the
//     same Caddy keeps its own certificate and keeps answering requests;
//   - re-delivering an UNCHANGED leaf — what the daily sweep does for every
//     app — does not reload Caddy at all: an established keep-alive connection
//     to the other app survives it. A reload would have closed it (and every
//     proxied WebSocket on the node with it).
//
// Needs root (the app server binds :443) and a caddy binary, so it skips unless
// RASPUTIN_CADDY_BIN is set; CI's "caddy admin socket" job runs it as root with
// RASPUTIN_CADDY_FUNCTIONAL=required, which turns every skip into a failure.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func TestCaddyServesRenewedLeaf_RealCaddy(t *testing.T) {
	caddyBin := requireFunctional(t)

	base, err := os.MkdirTemp("", "crnw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "xdg-config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(base, "xdg-data"))

	ca := newTestCA(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	// Two apps behind the same Caddy, each with a real loopback upstream.
	const nodeID = "node-611"
	kuma := testApp{id: "kuma", lan: "kuma.lan.bench.internal", tailnet: "kuma.bench.internal", body: "kuma"}
	other := testApp{id: "other", lan: "other.lan.bench.internal", tailnet: "other.bench.internal", body: "other"}
	for _, a := range []*testApp{&kuma, &other} {
		body := a.body
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(up.Close)
		a.port = mustAtoi(t, up.URL[strings.LastIndexByte(up.URL, ':')+1:])
	}

	store := NewLeafStore(filepath.Join(base, "leaves"))
	sock := filepath.Join(base, "caddy", "admin.sock")
	r := NewReconciler(store, sock, func() string { return "" }, func() string { return "127.0.0.1" })
	r.legacyAdmin = ""

	nc := startNATS(t)
	sub, err := RegisterHandlers(nc, nodeID, store, r.Reconcile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	deliver := func(a testApp, l testLeaf) {
		t.Helper()
		ack := requestLeaf(t, nc, nodeID, proto.AppLeafCmd{
			AppID: a.id, Name: a.id, CertPEM: l.certPEM, KeyPEM: l.keyPEM,
			TailnetFQDN: a.tailnet, LANFQDN: a.lan, UpstreamPort: a.port,
		})
		if !ack.OK {
			t.Fatalf("deliver %s: agent refused: %s", a.id, ack.Detail)
		}
	}

	// Deploy: both leaves delivered, then Caddy started by the agent's
	// supervisor, which pushes the config once its admin API answers.
	kuma1, other1 := ca.leaf(t, kuma.lan), ca.leaf(t, other.lan)
	deliver(kuma, kuma1)
	deliver(other, other1)
	stop := superviseCaddy(t, r, caddyBin)
	defer stop()
	waitFor(t, convergeWithin, "caddy serving kuma's deploy-time leaf on 127.0.0.1:443", func() bool {
		serial, err := servedSerial(roots, kuma.lan)
		return err == nil && serial == kuma1.serial
	})
	pids := caddyPIDs(caddyBin)
	if len(pids) != 1 {
		t.Fatalf("want exactly one supervised caddy, got %v", pids)
	}
	pid := pids[0]

	// A keep-alive connection to the OTHER app, established before anything
	// else happens: whether it survives is how the test sees a reload.
	otherClient, otherConnReused := keepAliveClient(roots)
	if got := get(t, otherClient, other.lan); got != other.body {
		t.Fatalf("other app via caddy = %q, want %q", got, other.body)
	}

	// Renewal: same app, same paths on disk, new bytes.
	kuma2 := ca.leaf(t, kuma.lan)
	deliver(kuma, kuma2)

	serial, err := servedSerial(roots, kuma.lan)
	if err != nil {
		t.Fatalf("handshake with kuma after renewal: %v", err)
	}
	if serial != kuma2.serial {
		t.Fatalf("after renewal caddy serves serial %s, want the renewed %s (deploy-time was %s): "+
			"the leaf reached disk but was never loaded (#611)", serial, kuma2.serial, kuma1.serial)
	}
	if now := caddyPIDs(caddyBin); len(now) != 1 || now[0] != pid {
		t.Fatalf("caddy pids = %v after renewal, want the same process %d: the renewal must not restart caddy", now, pid)
	}
	if s, err := servedSerial(roots, other.lan); err != nil || s != other1.serial {
		t.Fatalf("other app serves %s (err %v), want its own untouched leaf %s", s, err, other1.serial)
	}
	if got := get(t, otherClient, other.lan); got != other.body {
		t.Fatalf("other app via caddy after kuma's renewal = %q, want %q", got, other.body)
	}

	// The daily sweep re-delivers every app's CURRENT leaf. That must not
	// reload Caddy: the keep-alive connection just (re)established must be the
	// one the next request rides on.
	*otherConnReused = false
	if got := get(t, otherClient, other.lan); got != other.body || !*otherConnReused {
		t.Fatalf("control: a second request on the keep-alive client got %q, reused=%v; want %q on a reused connection",
			got, *otherConnReused, other.body)
	}
	deliver(kuma, kuma2)
	deliver(other, other1)
	*otherConnReused = false
	if got := get(t, otherClient, other.lan); got != other.body {
		t.Fatalf("other app after an unchanged re-delivery = %q, want %q", got, other.body)
	}
	if !*otherConnReused {
		t.Fatal("re-delivering unchanged leaves closed an established connection to another app: " +
			"caddy reloaded on a no-op delivery, which cuts every app's streams on every daily sweep")
	}
	if s, err := servedSerial(roots, kuma.lan); err != nil || s != kuma2.serial {
		t.Fatalf("kuma after an unchanged re-delivery serves %s (err %v), want %s", s, err, kuma2.serial)
	}
}

type testApp struct {
	id, lan, tailnet, body string
	port                   int
}

type testLeaf struct {
	certPEM, keyPEM []byte
	serial          string
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(t),
		Subject:               pkix.Name{CommonName: "611 test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key}
}

// leaf mints a fresh key and a leaf for host, as the controlplane's renewal
// does: a new serial and new bytes every time.
func (ca testCA) leaf(t *testing.T, host string) testLeaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial := randSerial(t)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return testLeaf{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		serial:  fmt.Sprintf("%X", serial),
	}
}

func randSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// servedSerial handshakes with Caddy's app server for host (SNI) and returns
// the serial of the leaf it presents, verified against roots.
func servedSerial(roots *x509.CertPool, host string) (string, error) {
	d := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", "127.0.0.1:"+strconv.Itoa(certPort), &tls.Config{
		ServerName: host,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return fmt.Sprintf("%X", conn.ConnectionState().PeerCertificates[0].SerialNumber), nil
}

// keepAliveClient returns an HTTPS client that always dials Caddy's app server
// and keeps at most one idle connection, plus a flag get sets to whether the
// last request rode an already-established connection.
func keepAliveClient(roots *x509.CertPool) (*http.Client, *bool) {
	reused := new(bool)
	d := &net.Dialer{Timeout: 2 * time.Second}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &reusedTracker{reused: reused, rt: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return d.DialContext(ctx, "tcp", "127.0.0.1:"+strconv.Itoa(certPort))
			},
			TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			MaxIdleConnsPerHost: 1,
			// HTTP/1.1, so "the connection" is one TCP connection. If the
			// transport retries a request onto a fresh connection because the
			// idle one was closed, GotConn fires again with Reused=false and
			// that is the value left in the flag.
			ForceAttemptHTTP2: false,
		}},
	}, reused
}

type reusedTracker struct {
	reused *bool
	rt     http.RoundTripper
}

func (r *reusedTracker) RoundTrip(req *http.Request) (*http.Response, error) {
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { *r.reused = info.Reused }}
	return r.rt.RoundTrip(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
}

func get(t *testing.T, c *http.Client, host string) string {
	t.Helper()
	resp, err := c.Get("https://" + host + "/")
	if err != nil {
		t.Fatalf("GET https://%s/ via caddy: %v", host, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET https://%s/ via caddy: %d %s", host, resp.StatusCode, b)
	}
	return string(b)
}
