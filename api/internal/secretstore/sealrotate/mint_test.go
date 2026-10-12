package sealrotate

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-830-13: the rotation client presents a new leaf on each handshake (a
// new serial), CN rasputin-seal-rotate, clientAuth only, signed by the store
// CA, over TLS 1.3 to a server trusted only through the store CA; nothing is
// written to disk.
func TestMintRotationLeaf_EachHandshakeANewLeaf(t *testing.T) {
	ca, err := tlsca.Ensure(tlsca.StoreConfig(), t.TempDir(), "test", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	server, err := ca.MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{
		Usage: tlsca.UsageServer, CommonName: "rasputin secret store", IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(server.CertPath, server.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	var mu sync.Mutex
	var seen []*x509.Certificate
	var versions []uint16
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.TLS.PeerCertificates[0])
		versions = append(versions, r.TLS.Version)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	before := listDir(t, cwd)
	leaves := &leafKeys{}
	tlsCfg, err := secretstore.NewMintedTLSConfig(ca.CertPEM, leaves.tee(t, MintRotationLeaf(ca)))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	lg, rec := logkittest.New()
	c, err := secretstore.New(secretstore.Config{Addr: u, TLS: tlsCfg, CallTimeout: 5 * time.Second, Logger: lg})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := c.RotateRoot(t.Context(), secret.New([]byte("test-token"))); err != nil {
			t.Fatal(err)
		}
		c.CloseIdleConnections() // the next call makes a new handshake
	}
	if len(seen) != 2 {
		t.Fatalf("%d requests", len(seen))
	}
	if seen[0].SerialNumber.Cmp(seen[1].SerialNumber) == 0 {
		t.Error("both handshakes presented the same leaf")
	}
	for i, leaf := range seen {
		if leaf.Subject.CommonName != RotationRole {
			t.Errorf("leaf %d CN = %q", i, leaf.Subject.CommonName)
		}
		if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
			t.Errorf("leaf %d EKU = %v, want clientAuth only", i, leaf.ExtKeyUsage)
		}
		if err := leaf.CheckSignatureFrom(ca.Cert); err != nil {
			t.Errorf("leaf %d is not signed by the store CA: %v", i, err)
		}
		if versions[i] != tls.VersionTLS13 {
			t.Errorf("handshake %d version %x, want TLS 1.3", i, versions[i])
		}
	}
	if after := listDir(t, cwd); !slices.Equal(before, after) {
		t.Errorf("the working directory changed: %v -> %v", before, after)
	}

	// A mint that fails fails the handshake as unreachable.
	broken := MintRotationLeaf(nil)
	if _, err := broken(); err == nil {
		t.Fatal("a mint with no CA succeeded")
	}
	badCfg, err := secretstore.NewMintedTLSConfig(ca.CertPEM, broken)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := secretstore.New(secretstore.Config{Addr: u, TLS: badCfg, CallTimeout: 5 * time.Second, Logger: lg})
	if err != nil {
		t.Fatal(err)
	}
	badErr := bad.RotateRoot(t.Context(), secret.New([]byte("test-token")))
	if !errors.Is(badErr, secretstore.ErrUnreachable) {
		t.Errorf("RotateRoot with a failing mint = %v, want unreachable", badErr)
	}

	// TC-830-15: the leaf key each handshake presented reaches neither the
	// client's log nor an error it returns.
	surfaces := rec.Text() + badErr.Error()
	for _, enc := range leaves.needles(t) {
		if strings.Contains(surfaces, enc) {
			t.Fatal("a rotation leaf key reached the log or an error")
		}
	}
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}
