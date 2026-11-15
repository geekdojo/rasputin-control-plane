package idclient

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/looptls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// pki is a test identity CA with a loopback server leaf and the api's client
// leaf on disk.
type pki struct {
	ca         *tlsca.CA
	server     tls.Certificate
	clientLeaf tlsca.LeafPaths
}

func newPKI(t *testing.T) pki {
	t.Helper()
	dir := t.TempDir()
	ca, err := tlsca.Ensure(tlsca.IdentityConfig(), filepath.Join(dir, "ca"), "test", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ca.MintLeafToDisk(filepath.Join(dir, "server"), tlsca.LeafSpec{
		Usage: tlsca.UsageServer, CommonName: "test identity", IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := tls.LoadX509KeyPair(sp.CertPath, sp.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := ca.MintLeafToDisk(filepath.Join(dir, "client"), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
	if err != nil {
		t.Fatal(err)
	}
	return pki{ca: ca, server: server, clientLeaf: cp}
}

func (p pki) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.ca.Cert)
	return pool
}

// counted is a TLS test server that requires a client leaf on the CA and
// counts the requests its handler sees.
type counted struct {
	*httptest.Server
	n atomic.Int64
}

func (c *counted) requests() int64 { return c.n.Load() }

// newServer starts a mutual-TLS server on p's leaf running h. tweak, when not
// nil, adjusts its TLS config before it starts.
func newServer(t *testing.T, p pki, h http.HandlerFunc, tweak func(*tls.Config)) *counted {
	t.Helper()
	c := &counted{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.n.Add(1)
		h(w, r)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{p.server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.pool(),
	}
	if tweak != nil {
		tweak(srv.TLS)
	}
	srv.Config.ErrorLog = slog.NewLogLogger(slog.DiscardHandler, slog.LevelError)
	srv.StartTLS()
	c.Server = srv
	t.Cleanup(srv.Close)
	return c
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// newClient is a Client for srv (both listeners) presenting p's client leaf,
// logging to a recorder.
func newClient(t *testing.T, p pki, base string) (*Client, *logkittest.Recorder) {
	t.Helper()
	cfg, err := looptls.NewClientTLS(p.ca.CertPEM, p.clientLeaf.CertPath, p.clientLeaf.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	log, rec := logkittest.New()
	c, err := New(Config{Addr: mustURL(t, base), MgmtAddr: mustURL(t, base), TLS: cfg, CallTimeout: 10 * time.Second, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c, rec
}

// writeFile writes b to a file in a temp dir and returns its path.
func writeFile(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
