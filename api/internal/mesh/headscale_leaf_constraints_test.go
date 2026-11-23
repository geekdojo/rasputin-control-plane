package mesh

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
)

// benchCA is a controlplane CA minted for cluster bench, so it is limited to
// bench's names (geekdojo/geekdojo-brain#258).
func benchCA(t *testing.T) *tlsca.CA {
	t.Helper()
	ca, err := tlsca.Ensure(tlsca.ControlplaneConfig().ForCluster("bench"), t.TempDir(), "test", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func benchSupervisor(t *testing.T, ca *tlsca.CA, serverURL, listenAddr string, extra []string) *DockerSupervisor {
	t.Helper()
	s, err := NewDockerSupervisor(DockerSupervisorConfig{StateDir: t.TempDir(), ServerURL: serverURL, ListenAddr: listenAddr,
		ExtraLeafDNSNames: extra, MeshCA: ca})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ipStrings(spec tlsca.LeafSpec) []string {
	out := []string{}
	for _, ip := range spec.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// TC-258-13: under bench's CA the Headscale leaf keeps only bench's names and
// private addresses, and the minted leaf verifies for bench.local and for
// loopback (the control plane's own enrolment).
func TestHeadscaleLeafSpec_FitsClusterCA(t *testing.T) {
	ca := benchCA(t)
	s := benchSupervisor(t, ca, "https://bench.local:18080", "192.168.1.10:18080", nil)
	spec, err := s.leafSpec()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(spec.DNSNames, []string{"bench.local"}) {
		t.Errorf("DNSNames = %v, want [bench.local] (no localhost)", spec.DNSNames)
	}
	if got := ipStrings(spec); !slices.Equal(got, []string{"127.0.0.1", "192.168.1.10"}) {
		t.Errorf("IPAddresses = %v, want [127.0.0.1 192.168.1.10]", got)
	}
	if err := s.ensureLeaf(); err != nil {
		t.Fatalf("ensureLeaf: %v", err)
	}
	certPEM, err := os.ReadFile(filepath.Join(s.cfg.StateDir, "certs", "leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	leaf := mustParseCert(t, certPEM)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	for _, name := range []string{"bench.local", "127.0.0.1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots}); err != nil {
			t.Errorf("Headscale leaf does not verify for %s: %v", name, err)
		}
	}

	// A public listen address is dropped.
	spec, err = benchSupervisor(t, ca, "https://bench.local:18080", "203.0.113.7:18080", nil).leafSpec()
	if err != nil {
		t.Fatal(err)
	}
	if got := ipStrings(spec); !slices.Equal(got, []string{"127.0.0.1"}) {
		t.Errorf("public ListenAddr: IPAddresses = %v, want [127.0.0.1]", got)
	}

	// Another cluster's server name is dropped.
	spec, err = benchSupervisor(t, ca, "https://home.local:18080", "192.168.1.10:18080", nil).leafSpec()
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.DNSNames) != 0 {
		t.Errorf("ServerURL home.local: DNSNames = %v, want none", spec.DNSNames)
	}

	// Of the extra names, only the one under bench's names is kept.
	spec, err = benchSupervisor(t, ca, "https://bench.local:18080", "192.168.1.10:18080",
		[]string{"x.example.com", "extra.local", "hs.bench.local"}).leafSpec()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(spec.DNSNames, []string{"bench.local", "hs.bench.local"}) {
		t.Errorf("ExtraLeafDNSNames: DNSNames = %v, want [bench.local hs.bench.local]", spec.DNSNames)
	}
}
