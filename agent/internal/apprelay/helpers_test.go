package apprelay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

const (
	appA = "01J9ZK3Q0M8X7Y6W5V4T3S2R1A"
	appB = "01J9ZK3Q0M8X7Y6W5V4T3S2R1B"
)

// shortDir is a state root short enough for a Unix socket path under it
// (macOS caps one at 104 bytes; t.TempDir is too deep there).
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "ar")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// testCA is a throwaway CA standing in for the controlplane CA.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// sign is a serverAuth leaf for AppRelayServerName over the PKIX DER key,
// with serial.
func (c *testCA) sign(t *testing.T, pubDER []byte, serial int64) []byte {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "rasputin-app-relay"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{proto.AppRelayServerName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (c *testCA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// fakeForwarder answers every call from its fields and records it.
type fakeForwarder struct {
	mu    sync.Mutex
	calls []proto.AppSecretCall
	reply proto.AppSecretReply
}

func (f *fakeForwarder) Forward(appID string, call proto.AppSecretCall, cid string) proto.AppSecretReply {
	f.mu.Lock()
	defer f.mu.Unlock()
	call.AppID = appID
	f.calls = append(f.calls, call)
	r := f.reply
	if r.CorrelationID == "" {
		r.CorrelationID = cid
	}
	return r
}

func (f *fakeForwarder) seen() []proto.AppSecretCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]proto.AppSecretCall(nil), f.calls...)
}

// counter is a correlation id source.
func counter() func() string {
	var mu sync.Mutex
	n := 0
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		n++
		return fmt.Sprintf("CID%d", n)
	}
}

func newTestManager(t *testing.T, dir string, fwd Forwarder) (*Manager, *logkittest.Recorder) {
	t.Helper()
	log, rec := logkittest.New()
	m, err := NewManager(ManagerDeps{Dir: dir, Rand: rand.Reader, Forward: fwd, IDs: counter(), Log: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m, rec
}

// installed prepares and installs appID under ca, returning the leaf's serial.
func installed(t *testing.T, m *Manager, ca *testCA, appID string, serial int64) {
	t.Helper()
	der, err := m.Prepare(appID)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Install(appID, ca.sign(t, der, serial), ca.pem); err != nil {
		t.Fatal(err)
	}
}

// client is an HTTPS client over the Unix socket sock, trusting roots under
// serverName, with TLS versions min..max (0 for Go's defaults).
func client(sock string, roots *x509.CertPool, serverName string, maxVersion uint16) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
			TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: serverName, MaxVersion: maxVersion},
		},
	}
}

// do sends method on /v1/secrets/name with body, and returns the status and
// the decoded JSON body (nil when there is none).
func do(t *testing.T, c *http.Client, method, name, body string) (int, map[string]string, error) {
	t.Helper()
	req, err := http.NewRequest(method, "https://"+proto.AppRelayServerName+"/v1/secrets/"+name, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, nil
}
