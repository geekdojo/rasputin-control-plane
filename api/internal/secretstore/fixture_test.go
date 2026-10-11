package secretstore_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// testCallTimeout bounds each call in the unit tests. Only the stall test
// waits it out.
const testCallTimeout = 2 * time.Second

// storeCA is a fresh store CA in a temp dir.
func storeCA(t *testing.T) *tlsca.CA {
	t.Helper()
	ca, err := tlsca.Ensure(tlsca.StoreConfig(), t.TempDir(), "test", tlscatest.Deps())
	if err != nil {
		t.Fatalf("store CA: %v", err)
	}
	return ca
}

// clientLeaf mints a store-CA client leaf in a temp dir.
func clientLeaf(t *testing.T, ca *tlsca.CA) tlsca.LeafPaths {
	t.Helper()
	p, err := ca.MintLeafToDisk(filepath.Join(t.TempDir(), "client"), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
	if err != nil {
		t.Fatalf("client leaf: %v", err)
	}
	return p
}

// serverCert mints a serverAuth leaf for 127.0.0.1 under ca.
func serverCert(t *testing.T, ca *tlsca.CA) tls.Certificate {
	t.Helper()
	p, err := ca.MintLeafToDisk(filepath.Join(t.TempDir(), "server"), tlsca.LeafSpec{
		Usage: tlsca.UsageServer, CommonName: "test store", IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	})
	if err != nil {
		t.Fatalf("server leaf: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(p.CertPath, p.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// fixture is an httptest TLS 1.3 server that requires and verifies a
// store-CA client certificate, and a Client built for it.
type fixture struct {
	ca     *tlsca.CA
	leaf   tlsca.LeafPaths
	srv    *httptest.Server
	hits   atomic.Int64
	client *secretstore.Client
	rec    *logkittest.Recorder
}

func newFixture(t *testing.T, h http.HandlerFunc) *fixture {
	t.Helper()
	f := &fixture{ca: storeCA(t)}
	f.leaf = clientLeaf(t, f.ca)
	f.srv = startTLSServer(t, serverCert(t, f.ca), f.ca, tls.VersionTLS13, tls.VersionTLS13,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.hits.Add(1)
			h(w, r)
		}))
	tc, err := secretstore.NewTLSConfig(f.ca.CertPEM, f.leaf.CertPath, f.leaf.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	var lg *slog.Logger
	lg, f.rec = logkittest.New()
	f.client = newClient(t, f.srv.URL, tc, lg)
	return f
}

// startTLSServer serves h with cert, requiring a client certificate from
// clientCA, between TLS versions lo and hi.
func startTLSServer(t *testing.T, cert tls.Certificate, clientCA *tlsca.CA, lo, hi uint16, h http.Handler) *httptest.Server {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(clientCA.CertPEM)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   lo,
		MaxVersion:   hi,
	}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func newClient(t *testing.T, addr string, tc *tls.Config, lg *slog.Logger) *secretstore.Client {
	t.Helper()
	u, err := url.Parse(addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := secretstore.New(secretstore.Config{Addr: u, TLS: tc, CallTimeout: testCallTimeout, Logger: lg})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func kvPath(t *testing.T, mount, path string) secretstore.KVPath {
	t.Helper()
	p, err := secretstore.NewKVPath(mount, path)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// kvBody is a kv-v2 read answer for version with data.
func kvBody(version int, data map[string]any) map[string]any {
	return map[string]any{"data": map[string]any{
		"data": data,
		"metadata": map[string]any{
			"created_time": "2026-10-11T09:00:00.123456789Z", "deletion_time": "", "destroyed": false, "version": version,
		},
	}}
}

func healthBody(initialized, sealed bool) map[string]any {
	return map[string]any{"initialized": initialized, "sealed": sealed, "standby": false, "version": "2.7.1"}
}

func tok(s string) secret.Value { return secret.New([]byte(s)) }
