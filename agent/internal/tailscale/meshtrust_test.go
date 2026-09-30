package tailscale

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto/tlstest"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
}

func writeBundle(t *testing.T, path string, pem []byte) {
	t.Helper()
	// Atomic, the way installMeshCA replaces it.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pem, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// TC-590-04 (resolver R27): every shape of bundle the agent can find on disk
// that is not a usable CA is refused — a nil config, never one that falls
// back to the system roots — and the error names the path. The absent
// bundle's error also says what it means and what installs it.
func TestMeshTrust_ClientTLSConfig_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	dir := t.TempDir()
	file := func(name string, content []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	subdir := filepath.Join(dir, "a-directory")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		path       string
		actionable bool
	}{
		{"a path that does not exist", filepath.Join(dir, "absent.pem"), true},
		{"an empty file", file("empty.pem", nil), false},
		{"a whitespace-only file", file("blank.pem", []byte("  \n\t\n")), false},
		{"a garbage file", file("garbage.pem", []byte("not a certificate at all")), false},
		{"a key-only PEM", file("key.pem", tlstest.KeyOnlyPEM(t)), false},
		{"a path that is a directory", subdir, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewMeshTrust(tc.path).ClientTLSConfig()
			if cfg != nil {
				t.Errorf("config = %+v, want nil", cfg)
			}
			if err == nil {
				t.Fatal("err = nil, want a refusal")
			}
			if !strings.Contains(err.Error(), tc.path) {
				t.Errorf("err = %q, want it to name %s", err, tc.path)
			}
			if tc.actionable {
				for _, want := range []string{"this node trusts no mesh CA", "mesh.enroll"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("err = %q, want it to say %q", err, want)
					}
				}
			}
		})
	}
}

// TC-590-05: the config trusts the bundle and only the bundle. A server under
// the bundle's CA handshakes; one under an unrelated CA is refused. A bundle
// that holds two CAs (the Mesh CA and the operator's) trusts both.
func TestMeshTrust_TrustsTheBundleAndOnlyTheBundle(t *testing.T) {
	a := tlstest.NewCA(t, "mesh-A")
	b := tlstest.NewCA(t, "unrelated-B")
	c := tlstest.NewCA(t, "operator-C")
	srvA := a.NewServer(t, okHandler())
	srvB := b.NewServer(t, okHandler())
	srvC := c.NewServer(t, okHandler())

	path := filepath.Join(t.TempDir(), "tailscaled-ca.pem")
	writeBundle(t, path, a.PEM)
	cfg, err := NewMeshTrust(path).ClientTLSConfig()
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	if cfg.RootCAs == nil || !cfg.RootCAs.Equal(a.Pool()) {
		t.Error("RootCAs is not a pool of the bundle's CA alone")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want at least TLS 1.2", cfg.MinVersion)
	}
	if err := tlstest.Get(cfg, srvA.URL); err != nil {
		t.Errorf("server under the bundle's CA refused: %v", err)
	}
	if err := tlstest.Get(cfg, srvB.URL); !tlstest.IsUnknownAuthority(err) {
		t.Errorf("server under an unrelated CA: err = %v, want unknown authority", err)
	}

	writeBundle(t, path, append(append(append([]byte{}, a.PEM...), '\n'), c.PEM...))
	cfg, err = NewMeshTrust(path).ClientTLSConfig()
	if err != nil {
		t.Fatalf("ClientTLSConfig on a two-CA bundle: %v", err)
	}
	for name, url := range map[string]string{"A": srvA.URL, "C": srvC.URL} {
		if err := tlstest.Get(cfg, url); err != nil {
			t.Errorf("two-CA bundle: server under %s refused: %v", name, err)
		}
	}
	if err := tlstest.Get(cfg, srvB.URL); !tlstest.IsUnknownAuthority(err) {
		t.Errorf("two-CA bundle: server under B: err = %v, want unknown authority", err)
	}
}

// TC-590-06: the bundle is read on every call, so a re-delivered CA is
// trusted by the next request and a removed bundle is refused by it.
func TestMeshTrust_ReReadsTheBundleOnEveryCall(t *testing.T) {
	a := tlstest.NewCA(t, "first")
	b := tlstest.NewCA(t, "second")
	srvA := a.NewServer(t, okHandler())
	srvB := b.NewServer(t, okHandler())
	path := filepath.Join(t.TempDir(), "tailscaled-ca.pem")
	trust := NewMeshTrust(path)

	writeBundle(t, path, a.PEM)
	cfg, err := trust.ClientTLSConfig()
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if err := tlstest.Get(cfg, srvA.URL); err != nil {
		t.Errorf("first call: server under A refused: %v", err)
	}

	writeBundle(t, path, b.PEM)
	cfg, err = trust.ClientTLSConfig()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if err := tlstest.Get(cfg, srvB.URL); err != nil {
		t.Errorf("second call: server under the replacement B refused: %v", err)
	}
	if err := tlstest.Get(cfg, srvA.URL); !tlstest.IsUnknownAuthority(err) {
		t.Errorf("second call: server under the replaced A: err = %v, want unknown authority", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	cfg, err = trust.ClientTLSConfig()
	if cfg != nil || err == nil || !strings.Contains(err.Error(), "this node trusts no mesh CA") {
		t.Errorf("third call after removal: cfg=%v err=%v, want the absent-bundle refusal", cfg, err)
	}
}
