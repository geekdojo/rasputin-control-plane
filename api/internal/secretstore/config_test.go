package secretstore_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// TC-758-01: New refuses every incomplete or unsafe config, and builds a
// client from the valid base.
func TestNew_RefusesIncompleteOrUnsafeConfig(t *testing.T) {
	ca := storeCA(t)
	leaf := clientLeaf(t, ca)
	base := func() secretstore.Config {
		tc, err := secretstore.NewTLSConfig(ca.CertPEM, leaf.CertPath, leaf.KeyPath)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse("https://127.0.0.1:8200")
		return secretstore.Config{Addr: u, TLS: tc, CallTimeout: time.Second, Logger: slog.New(slog.DiscardHandler)}
	}
	if c, err := secretstore.New(base()); c == nil || err != nil {
		t.Fatalf("valid base: client %v, err %v; want a client", c, err)
	}
	addr := func(s string) func(*secretstore.Config) {
		return func(c *secretstore.Config) { c.Addr, _ = url.Parse(s) }
	}
	for name, mutate := range map[string]func(*secretstore.Config){
		"nil logger":          func(c *secretstore.Config) { c.Logger = nil },
		"nil addr":            func(c *secretstore.Config) { c.Addr = nil },
		"nil TLS":             func(c *secretstore.Config) { c.TLS = nil },
		"InsecureSkipVerify":  func(c *secretstore.Config) { c.TLS.InsecureSkipVerify = true },
		"nil RootCAs":         func(c *secretstore.Config) { c.TLS.RootCAs = nil },
		"zero CallTimeout":    func(c *secretstore.Config) { c.CallTimeout = 0 },
		"negative timeout":    func(c *secretstore.Config) { c.CallTimeout = -time.Second },
		"http":                addr("http://127.0.0.1:8200"),
		"localhost":           addr("https://localhost:8200"),
		"non-loopback":        addr("https://10.0.0.1:8200"),
		"no port":             addr("https://127.0.0.1"),
		"path":                addr("https://127.0.0.1:8200/v1"),
		"query":               addr("https://127.0.0.1:8200?x=1"),
		"userinfo":            addr("https://u:p@127.0.0.1:8200"),
		"fragment":            addr("https://127.0.0.1:8200#f"),
		"empty query (force)": addr("https://127.0.0.1:8200?"),
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			mutate(&cfg)
			c, err := secretstore.New(cfg)
			if c != nil || err == nil {
				t.Errorf("New = %v, %v; want nil and an error", c, err)
			}
		})
	}
}

// TC-758-02: only https, a loopback IP literal and an explicit port parse.
func TestParseAddr(t *testing.T) {
	for _, ok := range []struct{ in, host, port string }{
		{"https://127.0.0.1:8200", "127.0.0.1", "8200"},
		{"https://127.0.0.1:18200", "127.0.0.1", "18200"},
		// The port range's two ends; 0 and 65536 are refused below.
		{"https://127.0.0.1:1", "127.0.0.1", "1"},
		{"https://127.0.0.1:65535", "127.0.0.1", "65535"},
	} {
		u, err := secretstore.ParseAddr(ok.in)
		if err != nil {
			t.Errorf("ParseAddr(%q) = %v", ok.in, err)
			continue
		}
		if u.Scheme != "https" || u.Hostname() != ok.host || u.Port() != ok.port || u.String() != ok.in {
			t.Errorf("ParseAddr(%q) = %v, want host %s port %s", ok.in, u, ok.host, ok.port)
		}
	}
	for _, bad := range []string{
		"", "127.0.0.1:8200", "http://127.0.0.1:8200", "https://store.local:8200", "https://localhost:8200",
		"https://192.168.1.5:8200", "https://127.0.0.1", "https://127.0.0.1:", "https://127.0.0.1:0",
		"https://127.0.0.1:65536", "https://127.0.0.1:08200", "https://127.0.0.1:8200/", "https://127.0.0.1:8200/v1",
		"https://127.0.0.1:8200?a=b", "https://127.0.0.1:8200#frag", "https://user@127.0.0.1:8200",
		"https://u:p@127.0.0.1:8200", "::garbage::", "https:127.0.0.1:8200",
	} {
		if u, err := secretstore.ParseAddr(bad); err == nil {
			t.Errorf("ParseAddr(%q) = %v, want an error", bad, u)
		}
	}
}

// TC-758-03: NewTLSConfig trusts only the store CA, speaks TLS 1.3 only, and
// reads the client leaf at each handshake.
func TestNewTLSConfig(t *testing.T) {
	t.Run("(a) a replaced leaf is presented on the next connection", func(t *testing.T) {
		var mu sync.Mutex
		var serials []*big.Int
		f := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			serials = append(serials, r.TLS.PeerCertificates[0].SerialNumber)
			mu.Unlock()
			writeJSON(w, http.StatusOK, healthBody(true, false))
		})
		if _, err := f.client.Health(t.Context()); err != nil {
			t.Fatal(err)
		}
		cert, key, err := f.ca.MintLeaf(tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
		if err != nil {
			t.Fatal(err)
		}
		if err := tlsca.WriteLeafFiles(f.leaf, cert, key); err != nil {
			t.Fatal(err)
		}
		key.Destroy()
		f.client.CloseIdleConnections()
		if _, err := f.client.Health(t.Context()); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(serials) != 2 || serials[0].Cmp(serials[1]) == 0 {
			t.Fatalf("serials seen = %v, want two different ones", serials)
		}
		if want := leafSerial(t, cert); serials[1].Cmp(want) != 0 {
			t.Errorf("second serial = %v, want the new leaf's %v", serials[1], want)
		}
	})

	t.Run("(b) a server leaf from another CA is ErrUnreachable", func(t *testing.T) {
		ca := storeCA(t)
		leaf := clientLeaf(t, ca)
		cp := tlscatest.Controlplane(t, "")
		srv := startTLSServer(t, serverCert(t, cp), ca, tls.VersionTLS13, tls.VersionTLS13, okHandler())
		c := newClient(t, srv.URL, mustTLS(t, ca.CertPEM, leaf), slog.New(slog.DiscardHandler))
		_, err := c.Health(t.Context())
		if !errors.Is(err, secretstore.ErrUnreachable) {
			t.Fatalf("err = %v, want ErrUnreachable", err)
		}
		var verr *tls.CertificateVerificationError
		if !errors.As(err, &verr) {
			t.Errorf("err = %v, want the verification error in the chain", err)
		}
	})

	t.Run("(c) a server capped at TLS 1.2 fails", func(t *testing.T) {
		ca := storeCA(t)
		leaf := clientLeaf(t, ca)
		srv := startTLSServer(t, serverCert(t, ca), ca, tls.VersionTLS12, tls.VersionTLS12, okHandler())
		c := newClient(t, srv.URL, mustTLS(t, ca.CertPEM, leaf), slog.New(slog.DiscardHandler))
		if _, err := c.Health(t.Context()); !errors.Is(err, secretstore.ErrUnreachable) {
			t.Fatalf("err = %v, want ErrUnreachable", err)
		}
	})

	t.Run("(d) a CA PEM holding no certificate is refused", func(t *testing.T) {
		if _, err := secretstore.NewTLSConfig([]byte("not a pem"), "/c", "/k"); err == nil {
			t.Error("NewTLSConfig accepted a CA PEM with no certificate")
		}
	})

	t.Run("(e) absent leaf paths are not read at construction", func(t *testing.T) {
		dir := t.TempDir()
		tc, err := secretstore.NewTLSConfig(storeCA(t).CertPEM, filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "leaf.key"))
		if err != nil {
			t.Fatalf("NewTLSConfig with absent leaf = %v, want nil", err)
		}
		if tc.MinVersion != tls.VersionTLS13 || tc.RootCAs == nil || tc.GetClientCertificate == nil || len(tc.Certificates) != 0 {
			t.Errorf("config = %+v, want TLS 1.3, the store CA and a per-handshake leaf", tc)
		}
	})
}

func okHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, healthBody(true, false)) }
}

func mustTLS(t *testing.T, caPEM []byte, leaf tlsca.LeafPaths) *tls.Config {
	t.Helper()
	tc, err := secretstore.NewTLSConfig(caPEM, leaf.CertPath, leaf.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	return tc
}

func leafSerial(t *testing.T, certPEM []byte) *big.Int {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("minted leaf is not PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c.SerialNumber
}

// TC-758-10: NewKVPath accepts only a valid mount and path.
func TestNewKVPath(t *testing.T) {
	p, err := secretstore.NewKVPath("kv", "apps/web_1.db-pass")
	if err != nil || p.Mount() != "kv" || p.Path() != "apps/web_1.db-pass" || p.String() != "kv/apps/web_1.db-pass" {
		t.Fatalf("valid pair = %v, %v", p, err)
	}
	// Each end of each allowed character range is accepted.
	for _, r := range []string{"a", "z", "A", "Z", "0", "9", "-", "_", "x.y"} {
		if _, err := secretstore.NewKVPath(r, r); err != nil {
			t.Errorf("NewKVPath(%q, %q) = %v, want accepted", r, r, err)
		}
	}
	for _, bad := range [][2]string{
		{"", "a"}, {"kv", ""}, {"kv", "/a"}, {"kv", "a/"}, {"/kv", "a"}, {"kv/", "a"}, {"kv", "a//b"},
		{"kv", "."}, {"kv", ".."}, {"kv", "a/../b"}, {"..", "a"}, {"kv", "a b"}, {"kv", "a%2fb"},
		{"kv", "a?b"}, {"kv", "a#b"}, {"kv", "café"}, {"k v", "a"},
		// The neighbours of each allowed range's ends ('/' below '0' is the
		// separator, refused above as an empty segment).
		{"kv", "`"}, {"kv", "{"}, {"kv", "@"}, {"kv", "["}, {"kv", ":"}, {"`", "a"}, {"{", "a"},
	} {
		if _, err := secretstore.NewKVPath(bad[0], bad[1]); err == nil {
			t.Errorf("NewKVPath(%q, %q) accepted", bad[0], bad[1])
		}
	}
}

// TC-758-12: every Disabled method returns ErrDisabled, with no network.
func TestDisabled(t *testing.T) {
	var d secretstore.Disabled
	p := kvPath(t, "kv", "a")
	ctx := context.Background()
	_, e1 := d.Health(ctx)
	kv, e2 := d.Read(ctx, secret.Value{}, p, 0)
	n, e3 := d.Write(ctx, secret.Value{}, p, map[string]secret.Value{"k": tok("v")}, 0)
	md, e4 := d.Versions(ctx, secret.Value{}, p)
	for i, err := range []error{e1, e2, e3, e4} {
		if !errors.Is(err, secretstore.ErrDisabled) {
			t.Errorf("method %d: err = %v, want ErrDisabled", i, err)
		}
	}
	if kv.Data != nil || n != 0 || md.Versions != nil {
		t.Errorf("Disabled returned data: %v %d %v", kv, n, md)
	}
}
