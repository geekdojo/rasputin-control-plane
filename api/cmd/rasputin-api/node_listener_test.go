package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bustls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nodekeytest"
	"github.com/geekdojo/rasputin-control-plane/logkit"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"log/slog"
)

// The node listener serves the api's Mesh-CA-signed leaf for every name, and a
// collector verifies it by chain (geekdojo/geekdojo-brain#672). The bus
// certificate is never served here.

// meshLeafOnDisk is an apiLeaf whose mint writes a FRESH leaf (new key, new
// serial) under ca for the cluster "home1" on every call, so refresh swaps in
// a genuinely re-minted certificate the way the leaf sweep's renewal does.
func meshLeafOnDisk(t *testing.T, ca *mesh.MeshCA) *apiLeaf {
	t.Helper()
	dir := t.TempDir()
	var n atomic.Int32
	return &apiLeaf{mint: func(lanIP net.IP) (mesh.LeafPaths, error) {
		certPEM, keyPEM, err := mesh.MintLeaf(ca, apiLeafSpec("home1", lanIP))
		if err != nil {
			return mesh.LeafPaths{}, err
		}
		i := n.Add(1)
		p := mesh.LeafPaths{
			CertPath: filepath.Join(dir, fmt.Sprintf("leaf%d.pem", i)),
			KeyPath:  filepath.Join(dir, fmt.Sprintf("leaf%d.key", i)),
		}
		if err := os.WriteFile(p.CertPath, certPEM, 0o600); err != nil {
			return p, err
		}
		return p, os.WriteFile(p.KeyPath, keyPEM, 0o600)
	}}
}

func testMeshCA(t *testing.T) *mesh.MeshCA {
	t.Helper()
	ca, err := mesh.EnsureMeshCA(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// TC-672-11: with the leaf loaded, every SNI — the cluster name, the old bus
// name, and none at all — gets the same Mesh leaf, and it chains to the Mesh CA.
func TestNodeListenerCert_ServesTheMeshLeafForEveryName(t *testing.T) {
	ca := testMeshCA(t)
	leaf := meshLeafOnDisk(t, ca)
	if err := leaf.load(net.IPv4(192, 168, 1, 10)); err != nil {
		t.Fatal(err)
	}
	served := leaf.cert.Load()
	get := nodeListenerCert(leaf)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	for _, sni := range []string{"home1.local", bustls.BusDNSName, ""} {
		got, err := get(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil {
			t.Fatalf("SNI %q: %v", sni, err)
		}
		if got != served {
			t.Errorf("SNI %q served a certificate other than the loaded Mesh leaf", sni)
		}
		x, err := x509.ParseCertificate(got.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
			t.Errorf("SNI %q: served certificate does not chain to the Mesh CA: %v", sni, err)
		}
	}
}

// TC-672-12: no leaf yet means errNoAPILeaf; no apiLeaf at all (HTTPS off)
// means an error naming RASPUTIN_HTTPS_ADDR. Never a certificate.
func TestNodeListenerCert_NoLeafRefuses(t *testing.T) {
	notYet := nodeListenerCert(&apiLeaf{})
	for _, sni := range []string{"home1.local", bustls.BusDNSName, ""} {
		got, err := notYet(&tls.ClientHelloInfo{ServerName: sni})
		if got != nil || !errors.Is(err, errNoAPILeaf) {
			t.Errorf("unloaded leaf, SNI %q = (%v, %v), want (nil, errNoAPILeaf)", sni, got, err)
		}
	}
	off := nodeListenerCert(nil)
	got, err := off(&tls.ClientHelloInfo{ServerName: "home1.local"})
	if got != nil || err == nil || !strings.Contains(err.Error(), "RASPUTIN_HTTPS_ADDR") {
		t.Errorf("HTTPS off = (%v, %v), want (nil, an error naming RASPUTIN_HTTPS_ADDR)", got, err)
	}
}

// TC-672-13: collectors are wired only when both the node listener and HTTPS
// are on, and each refusal names the missing variable.
func TestCollectorsWired(t *testing.T) {
	for _, tc := range []struct {
		obs, https string
		want       bool
		names      []string
	}{
		{":8443", ":443", true, nil},
		{":8443", "", false, []string{"RASPUTIN_HTTPS_ADDR"}},
		{"", ":443", false, []string{"RASPUTIN_OBS_INGEST_ADDR"}},
		{"", "", false, []string{"RASPUTIN_OBS_INGEST_ADDR", "RASPUTIN_HTTPS_ADDR"}},
	} {
		got, why := collectorsWired(tc.obs, tc.https)
		if got != tc.want {
			t.Errorf("collectorsWired(%q, %q) = %v, want %v", tc.obs, tc.https, got, tc.want)
		}
		if tc.want && why != "" {
			t.Errorf("collectorsWired(%q, %q) wired but gave a reason %q", tc.obs, tc.https, why)
		}
		for _, n := range tc.names {
			if !strings.Contains(why, n) {
				t.Errorf("collectorsWired(%q, %q) reason %q does not name %s", tc.obs, tc.https, why, n)
			}
		}
	}
}

// handshake runs one in-process TLS handshake and returns the client-side
// view, the SPKI the server saw, and the client's error.
func handshake(t *testing.T, server, client *tls.Config) (tls.ConnectionState, []byte, error) {
	t.Helper()
	var seen []byte
	srvCfg := server.Clone()
	srvCfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) > 0 {
			seen = cs.PeerCertificates[0].RawSubjectPublicKeyInfo
		}
		return nil
	}
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	srvDone := make(chan error, 1)
	go func() {
		ts := tls.Server(s, srvCfg)
		err := ts.Handshake()
		srvDone <- err
		_ = ts.Close()
	}()
	tc := tls.Client(c, client)
	err := tc.Handshake()
	if err != nil {
		_ = c.Close()
	}
	<-srvDone
	return tc.ConnectionState(), seen, err
}

// TC-672-14: the collector's trust, end to end in-process. Mesh CA as the only
// root plus the cluster name verifies the served leaf, and the server sees the
// client's own SPKI. A re-minted leaf (new key, same CA) is accepted with the
// client config untouched: nothing is pinned. A client that trusts only the
// bus certificate — the old pin — fails with an x509 error.
func TestNodeListener_HandshakeByChainSurvivesReMint(t *testing.T) {
	ca := testMeshCA(t)
	leaf := meshLeafOnDisk(t, ca)
	ip := net.IPv4(192, 168, 1, 10)
	if err := leaf.load(ip); err != nil {
		t.Fatal(err)
	}
	// The listener's own server configuration, as main builds it.
	server := newNodeListenerServer("", nil, leaf).TLSConfig
	if server.MinVersion != tls.VersionTLS13 || server.ClientAuth != tls.RequireAnyClientCert {
		t.Fatalf("node listener TLS = min %x, client auth %v; want TLS 1.3 and RequireAnyClientCert", server.MinVersion, server.ClientAuth)
	}
	clientCert := nodekeytest.New(t, "collector").TLS() // made the way the agent makes its collector key
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	client := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		ServerName:   "home1.local",
		Certificates: []tls.Certificate{clientCert},
	}

	cs, seen, err := handshake(t, server, client)
	if err != nil {
		t.Fatalf("handshake by Mesh chain: %v", err)
	}
	if !bytes.Equal(seen, clientCert.Leaf.RawSubjectPublicKeyInfo) {
		t.Error("the server did not see the client's own SPKI")
	}
	firstSerial := cs.PeerCertificates[0].SerialNumber

	if err := leaf.refresh(ip); err != nil {
		t.Fatal(err)
	}
	cs, _, err = handshake(t, server, client)
	if err != nil {
		t.Fatalf("handshake after the leaf was re-minted: %v", err)
	}
	if cs.PeerCertificates[0].SerialNumber.Cmp(firstSerial) == 0 {
		t.Fatal("refresh did not swap in a re-minted leaf; the renewal case proved nothing")
	}

	busKey, err := bustls.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	busCert, err := bustls.SelfSignedCert(busKey, time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	busOnly := x509.NewCertPool()
	busOnly.AddCert(busCert.Leaf)
	pinned := client.Clone()
	pinned.RootCAs = busOnly
	_, _, err = handshake(t, server, pinned)
	var verr *tls.CertificateVerificationError
	if err == nil || !errors.As(err, &verr) || !strings.Contains(err.Error(), "x509:") {
		t.Fatalf("a client trusting only the bus certificate = %v, want an x509 verification error", err)
	}
}

// logCollectorWiring logs at INFO exactly when collectors are not wired, with
// the fields an operator acts on: the HTTPS-off case names the listener and
// the fix (TC-672-23's log line, at unit level).
func TestLogCollectorWiring(t *testing.T) {
	var buf bytes.Buffer
	if !logCollectorWiring(logkit.New(&buf), ":8443", ":443") || buf.Len() != 0 {
		t.Errorf("wired: logged %q", buf.String())
	}

	buf.Reset()
	if logCollectorWiring(logkit.New(&buf), "127.0.0.1:8443", "") {
		t.Fatal("wired with HTTPS off")
	}
	for _, want := range []string{"level=INFO", `msg="rasputin-api: obs collectors not wired"`,
		"obs_ingest_addr=127.0.0.1:8443", `fix="set RASPUTIN_HTTPS_ADDR"`, "RASPUTIN_HTTPS_ADDR is unset"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("HTTPS-off entry lacks %q: %s", want, buf.String())
		}
	}

	buf.Reset()
	if logCollectorWiring(logkit.New(&buf), "", ":443") {
		t.Fatal("wired with the node listener off")
	}
	if !strings.Contains(buf.String(), "obs collectors not wired") || strings.Contains(buf.String(), "fix=") {
		t.Errorf("listener-off entry = %q, want a not-wired line with no fix", buf.String())
	}
}

// collectorLeafMinter writes a legacy node's client leaf under the Mesh CA
// and hands back its PEMs; a second call returns the same leaf.
func TestCollectorLeafMinter(t *testing.T) {
	ca := testMeshCA(t)
	dataDir := t.TempDir()
	mint := collectorLeafMinter(ca, dataDir)
	certPEM, keyPEM, err := mint("c03")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("minted pair does not load: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("minted leaf is not a Mesh-CA client leaf: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "tls", "collectors", "c03")); err != nil {
		t.Errorf("leaf not written under tls/collectors/c03: %v", err)
	}
	again, _, err := mint("c03")
	if err != nil || again != certPEM {
		t.Errorf("second mint = (%d bytes, %v), want the same leaf", len(again), err)
	}

	// A data dir the leaf cannot be written under is an error, not a leaf.
	blocked := t.TempDir()
	if err := os.WriteFile(filepath.Join(blocked, "tls"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := collectorLeafMinter(ca, blocked)("c03"); err == nil {
		t.Error("mint into an unwritable data dir succeeded")
	}
}

// TC-514-27: the node-listener base main derives once for the backup router
// and the collectors, the WARN when there is none, and an error — never a
// silent "" — when a wired listener yields no URL (F-514-08).
func TestNodeListenerBaseURL(t *testing.T) {
	logger, rec := logkittest.New()
	base, serverName, err := nodeListenerBaseURL(logger, "https://c.local", ":8443", ":443")
	if err != nil || base != "https://c.local:8443" || len(rec.Records()) != 0 {
		t.Errorf("wired: %q, %v, records:\n%s", base, err, rec.Text())
	}
	// The collectors' server name comes back with the base: the cluster name.
	if serverName != "c.local" {
		t.Errorf("wired: server name %q, want c.local", serverName)
	}

	logger, rec = logkittest.New()
	base, serverName, err = nodeListenerBaseURL(logger, "https://c.local", ":8443", "")
	if err != nil || base != "" || serverName != "" {
		t.Fatalf("HTTPS off: %q, %q, %v", base, serverName, err)
	}
	warns := rec.Matching(slog.LevelWarn, "backup transfer: no node listener")
	if len(warns) != 1 || len(rec.Records()) != 1 {
		t.Fatalf("HTTPS off records:\n%s", rec.Text())
	}
	for k, want := range map[string]string{"obs_ingest_addr": ":8443", "https_addr": ""} {
		if v, ok := logkittest.Attr(warns[0], k); !ok || v != want {
			t.Errorf("%s = %q (present %v), want %q", k, v, ok, want)
		}
	}

	logger, _ = logkittest.New()
	base, serverName, err = nodeListenerBaseURL(logger, "https://c.local", "0.0.0.0:", ":443")
	if err == nil || base != "" || serverName != "" || !strings.Contains(err.Error(), "0.0.0.0:") {
		t.Fatalf("no port: %q, %q, %v; want an error naming the ingest address", base, serverName, err)
	}
}
