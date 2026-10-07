package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nodetrust"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-741-12: a store CA in partial state is one ERROR "store CA unavailable"
// with ca=store and err, no exit, and a nil store CA beside a loaded
// controlplane CA; a controlplane CA in partial state is FATAL and exit(1).
func TestEnsureCAs_Outcomes(t *testing.T) {
	t.Run("store CA partial: ERROR, no exit, nil store CA", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, tlsca.StoreCertFile), []byte("half"), 0o600); err != nil {
			t.Fatal(err)
		}
		h := &recordsHandler{}
		var codes []int
		d := tlscatest.Deps()
		d.Log = slog.New(h)
		cp, store := ensureCAs(context.Background(), slog.New(h), func(c int) { codes = append(codes, c) }, dir, "home1", d)
		if len(codes) != 0 {
			t.Fatalf("exit called %v", codes)
		}
		if cp == nil || store != nil {
			t.Fatalf("cp=%v store=%v, want a controlplane CA and a nil store CA", cp != nil, store)
		}
		recs := h.matching(slog.LevelError, "store CA unavailable")
		if len(recs) != 1 {
			t.Fatalf("%d ERROR store CA records, want 1", len(recs))
		}
		if attrOf(recs[0], "ca") != "store" || attrOf(recs[0], "err") == "" {
			t.Errorf("record ca=%q err=%q", attrOf(recs[0], "ca"), attrOf(recs[0], "err"))
		}
	})
	t.Run("controlplane CA partial: FATAL and exit(1)", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, tlsca.ControlplaneKeyFile), []byte("half"), 0o600); err != nil {
			t.Fatal(err)
		}
		h := &recordsHandler{}
		var codes []int
		cp, store := ensureCAs(context.Background(), slog.New(h), func(c int) { codes = append(codes, c) }, dir, "home1", tlscatest.Deps())
		if len(codes) != 1 || codes[0] == 0 {
			t.Fatalf("exit calls %v, want one non-zero exit", codes)
		}
		if cp != nil || store != nil {
			t.Error("CAs returned after a fatal load")
		}
		recs := h.matching(logkit.LevelFatal, "controlplane CA did not load")
		if len(recs) != 1 || attrOf(recs[0], "err") == "" {
			t.Errorf("%d FATAL records, want 1 carrying err", len(recs))
		}
	})
	t.Run("both load", func(t *testing.T) {
		var codes []int
		cp, store := ensureCAs(context.Background(), slog.New(&recordsHandler{}), func(c int) { codes = append(codes, c) }, t.TempDir(), "home1", tlscatest.Deps())
		if cp == nil || store == nil || len(codes) != 0 {
			t.Fatalf("cp=%v store=%v exits=%v", cp != nil, store != nil, codes)
		}
		if cp.Name() != "controlplane" || store.Name() != "store" {
			t.Errorf("names %s/%s", cp.Name(), store.Name())
		}
	})
}

// fakeNodes satisfies nodetrust.Nodes for a construction check.
type fakeNodes struct{}

func (fakeNodes) List(context.Context) ([]*proto.Node, error) { return nil, nil }
func (fakeNodes) Presence(context.Context, []*proto.Node)     {}
func (fakeNodes) ExplainNoResponder(context.Context, string) inventory.NoResponder {
	return inventory.NoResponder{}
}

// operatorHeadscale is an HTTPS server whose leaf the operator's CA signed,
// answering Headscale's node list.
func operatorHeadscale(t *testing.T, op *tlsca.CA) *httptest.Server {
	t.Helper()
	certPEM, key, err := op.MintLeaf(tlsca.LeafSpec{Usage: tlsca.UsageServer, CommonName: "hs", IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, key.Reveal())
	key.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"nodes": []any{}})
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func certsIn(t *testing.T, bundle []byte) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for rest := bundle; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return out
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
}

// TC-741-10 and TC-741-11 (per-backend half): with both CAs ensured in one
// trust dir and RASPUTIN_HEADSCALE_CA_FILE set, every backend's node bundle
// carries the controlplane CA — the operator's too on the external path only —
// and never the store CA. The self-hosted, mock and unavailable bundles equal
// the controlplane-only golden, so nodetrust.New accepts them and the api
// starts (F-741-12), and an unreadable CA file there is not an error. On the
// external path the bundle and wireExternalMesh's TLS pool come from the same
// file bytes, and an unreadable file is an error.
func TestBundle_PerBackend(t *testing.T) {
	trustDir := filepath.Join(t.TempDir(), "trust")
	cp := tlscatest.Controlplane(t, trustDir)
	store, err := tlsca.Ensure(tlsca.StoreConfig(), trustDir, "home1", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	op := tlscatest.Controlplane(t, "")
	caFile := filepath.Join(t.TempDir(), "operator-ca.pem")
	if err := os.WriteFile(caFile, op.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RASPUTIN_HEADSCALE_CA_FILE", caFile)
	t.Setenv("RASPUTIN_HEADSCALE_SUPERVISOR", "noop")
	t.Setenv("RASPUTIN_HEADSCALE_URL", "https://127.0.0.1:18080")

	hs := operatorHeadscale(t, op)
	wired := map[string]func() (meshWiring, error){
		"self-hosted": func() (meshWiring, error) { return wireSelfHostedMesh(t.TempDir(), cp, "dev@example.com") },
		"external": func() (meshWiring, error) {
			return wireExternalMesh(t.TempDir(), cp, "dev@example.com", hs.URL, "hskey-test")
		},
		"mock":        func() (meshWiring, error) { return wireMockMesh(t.TempDir(), "dev@example.com") },
		"unavailable": func() (meshWiring, error) { return wireUnavailableMesh("dev@example.com", "test") },
	}
	storeDER := store.Cert.Raw
	for name, wire := range wired {
		t.Run(name, func(t *testing.T) {
			mw, err := wire()
			if err != nil {
				t.Fatalf("wire: %v", err)
			}
			bundle := nodeTrustBundle(cp, mw)
			want := [][]byte{cp.Cert.Raw}
			if name == "external" {
				want = append(want, op.Cert.Raw)
				if !bytes.Equal(mw.operatorCA, op.CertPEM) {
					t.Error("the bundle's operator CA is not the CA file's bytes")
				}
				if _, err := mw.client.ListNodes(context.Background()); err != nil {
					t.Errorf("the external client does not trust the CA file's root: %v", err)
				}
			} else if !bytes.Equal(bundle, cp.CertPEM) {
				t.Errorf("bundle is not the controlplane-only golden (the CA's own PEM, byte for byte)")
			}
			got := certsIn(t, bundle)
			if len(got) != len(want) {
				t.Fatalf("%d certificates in the bundle, want %d", len(got), len(want))
			}
			for i, c := range got {
				if !bytes.Equal(c.Raw, want[i]) {
					t.Errorf("certificate %d is not the expected CA", i)
				}
				if bytes.Equal(c.Raw, storeDER) {
					t.Error("the store CA is in the node bundle")
				}
			}
			if _, err := nodetrust.New(nodetrust.Options{Bundle: bundle, Nodes: fakeNodes{}, Log: slog.New(&recordsHandler{})}); err != nil {
				t.Errorf("nodetrust.New refused the %s bundle: %v", name, err)
			}
		})
	}
	// What main hands the collector as its CA is the controlplane CA's PEM.
	if bytes.Contains(cp.CertPEM, bytes.TrimSpace(store.CertPEM)) {
		t.Error("the collector CA carries the store CA")
	}

	t.Run("unreadable CA file", func(t *testing.T) {
		t.Setenv("RASPUTIN_HEADSCALE_CA_FILE", filepath.Join(t.TempDir(), "absent.pem"))
		for _, name := range []string{"self-hosted", "mock", "unavailable"} {
			if _, err := wired[name](); err != nil {
				t.Errorf("%s: an unreadable RASPUTIN_HEADSCALE_CA_FILE is an error off the external path: %v", name, err)
			}
		}
		if _, err := wired["external"](); err == nil {
			t.Error("external: an unreadable RASPUTIN_HEADSCALE_CA_FILE was accepted")
		}
	})
}

// TC-741-09 (api leaf): the api's HTTPS leaf spec asks for a server leaf, and
// the leaf carries exactly ServerAuth.
func TestAPILeafSpec_IsAServerLeaf(t *testing.T) {
	spec := apiLeafSpec("home1", net.IPv4(192, 168, 1, 2))
	if spec.Usage != tlsca.UsageServer {
		t.Fatalf("Usage %v, want UsageServer", spec.Usage)
	}
	certPEM, key, err := tlscatest.Controlplane(t, "").MintLeaf(spec)
	if err != nil {
		t.Fatal(err)
	}
	key.Destroy()
	c := certsIn(t, certPEM)[0]
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage %v, want exactly [ServerAuth]", c.ExtKeyUsage)
	}
}
