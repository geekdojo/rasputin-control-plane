package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
)

// The api leaf and the CA wiring under a controlplane CA limited to its
// cluster's names (geekdojo/geekdojo-brain#258).

func clusterCAForTest(t *testing.T, cid string) *tlsca.CA {
	t.Helper()
	ca, err := tlsca.Ensure(tlsca.ControlplaneConfig().ForCluster(cid), t.TempDir(), "test", tlscatest.Deps())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func specIPs(spec tlsca.LeafSpec) []string {
	out := []string{}
	for _, ip := range spec.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

func parseLeafFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("%s is not PEM", path)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TC-258-12: the api leaf keeps only the names the held CA permits.
func TestFittedAPILeafSpec_FitsClusterCA(t *testing.T) {
	bench := clusterCAForTest(t, "bench")
	lan := net.IPv4(192, 168, 1, 2)

	// (a)
	a := fittedAPILeafSpec(bench, "bench", lan)
	if !slices.Equal(a.DNSNames, []string{"bench.local"}) {
		t.Errorf("(a) DNSNames = %v, want [bench.local]", a.DNSNames)
	}
	if got := specIPs(a); !slices.Equal(got, []string{"127.0.0.1", "192.168.1.2"}) {
		t.Errorf("(a) IPAddresses = %v", got)
	}
	// (b)
	if got := specIPs(fittedAPILeafSpec(bench, "bench", net.IPv4(203, 0, 113, 7))); !slices.Equal(got, []string{"127.0.0.1"}) {
		t.Errorf("(b) IPAddresses = %v, want [127.0.0.1]", got)
	}
	// (c)
	if c := fittedAPILeafSpec(bench, "node.example.com", lan); len(c.DNSNames) != 0 {
		t.Errorf("(c) DNSNames = %v, want none", c.DNSNames)
	}
	// rasputin's CA keeps rasputin.local.
	if r := fittedAPILeafSpec(clusterCAForTest(t, "rasputin"), "rasputin", lan); !slices.Equal(r.DNSNames, []string{"rasputin.local"}) {
		t.Errorf("rasputin: DNSNames = %v, want [rasputin.local]", r.DNSNames)
	}

	// The leaf minted from (a) verifies for its name and both addresses.
	paths, err := bench.MintLeafToDisk(t.TempDir(), a)
	if err != nil {
		t.Fatal(err)
	}
	leaf := parseLeafFile(t, paths.CertPath)
	roots := x509.NewCertPool()
	roots.AddCert(bench.Cert)
	for _, name := range []string{"bench.local", "127.0.0.1", "192.168.1.2"} {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots}); err != nil {
			t.Errorf("api leaf does not verify for %s: %v", name, err)
		}
	}
}

// TC-258-14: on an existing cluster (an unconstrained CA) the fitted spec is
// apiLeafSpec's, and the sweep finds the leaf already on disk usable and
// leaves it alone.
func TestFittedAPILeafSpec_ExistingClusterNoReMint(t *testing.T) {
	ca := tlscatest.Controlplane(t, "")
	lan := net.IPv4(192, 168, 1, 2)
	old := apiLeafSpec("bench", lan)
	if !reflect.DeepEqual(fittedAPILeafSpec(ca, "bench", lan), old) {
		t.Fatalf("fitted spec %+v differs from apiLeafSpec %+v", fittedAPILeafSpec(ca, "bench", lan), old)
	}
	dir := t.TempDir()
	paths, err := ca.MintLeafToDisk(dir, old)
	if err != nil {
		t.Fatal(err)
	}
	before := parseLeafFile(t, paths.CertPath)
	if want := []string{"rasputin.local", "localhost", "bench", "bench.local"}; !slices.Equal(before.DNSNames, want) {
		t.Fatalf("old leaf DNSNames = %v, want %v", before.DNSNames, want)
	}
	st, err := os.Stat(paths.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.LeafUsable(paths, fittedAPILeafSpec(ca, "bench", lan)) {
		t.Error("the existing leaf is not usable for the fitted spec")
	}
	sweeper := tlsca.NewLeafSweeper(ca)
	if err := sweeper.Register(tlsca.LeafConsumer{Name: "api-https", Dir: dir,
		Spec: func() (tlsca.LeafSpec, error) { return fittedAPILeafSpec(ca, "bench", lan), nil }}); err != nil {
		t.Fatal(err)
	}
	if rep := sweeper.Sweep(context.Background(), nil); rep.Checked != 1 || len(rep.Renewed) != 0 {
		t.Errorf("sweep report = %+v, want the leaf checked and not renewed", rep)
	}
	after := parseLeafFile(t, filepath.Join(dir, filepath.Base(paths.CertPath)))
	st2, err := os.Stat(paths.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.SerialNumber.Cmp(before.SerialNumber) != 0 || !st2.ModTime().Equal(st.ModTime()) {
		t.Error("the existing api leaf was re-minted")
	}
}

// TC-258-21: ensureCAs mints the controlplane CA for the cluster id it is
// given, and the store and identity CAs unconstrained.
func TestEnsureCAs_ConstrainsControlplaneCAToCluster(t *testing.T) {
	exit := func(c int) { t.Fatalf("exit %d", c) }
	cp, store, identity := ensureCAs(context.Background(), slog.New(slog.DiscardHandler), exit, t.TempDir(), "home1", "bench",
		tlscatest.Deps(), "", false)
	if cp == nil || store == nil || identity == nil {
		t.Fatalf("CAs = %v %v %v, want all three", cp, store, identity)
	}
	got, want := cp.Constraints(), tlsca.ClusterConstraints("bench")
	if !reflect.DeepEqual(got.DNSDomains, want.DNSDomains) || !slices.Equal(netStrings(got.IPRanges), netStrings(want.IPRanges)) {
		t.Errorf("controlplane CA constraints = %v %v, want %v %v", got.DNSDomains, netStrings(got.IPRanges), want.DNSDomains, netStrings(want.IPRanges))
	}
	if !cp.Cert.PermittedDNSDomainsCritical {
		t.Error("controlplane CA constraint is not critical")
	}
	for _, c := range []*tlsca.CA{store, identity} {
		if !c.Constraints().IsZero() {
			t.Errorf("%s CA carries a constraint", c.Name())
		}
	}
}

func netStrings(rs []*net.IPNet) []string {
	out := []string{}
	for _, r := range rs {
		out = append(out, r.String())
	}
	return out
}
