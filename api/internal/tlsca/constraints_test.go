package tlsca_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/doors"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The tests of geekdojo/geekdojo-brain#258 (S4): a controlplane CA minted for
// cluster C is critically limited to C's names and the private addresses, and
// Go's verifier, the oracle here, agrees with PermitsDNS, PermitsIP and Fit.

var oidNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}

var wantRanges = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

// clusterCA is a controlplane CA created for cluster cid in a fresh dir.
func clusterCA(t *testing.T, cid string) *tlsca.CA {
	t.Helper()
	ca, err := tlsca.Ensure(tlsca.ControlplaneConfig().ForCluster(cid), t.TempDir(), "test", tlscatest.Deps())
	if err != nil {
		t.Fatalf("Ensure(ForCluster(%q)): %v", cid, err)
	}
	return ca
}

// verifyLeaf mints a server leaf under ca for dns and ips and verifies it
// against ca alone for name, a DNS name or an IP address.
func verifyLeaf(t *testing.T, ca *tlsca.CA, dns []string, ips []net.IP, name string) error {
	t.Helper()
	certPEM, key, err := ca.MintLeaf(tlsca.LeafSpec{Usage: tlsca.UsageServer, CommonName: "leaf", DNSNames: dns, IPAddresses: ips})
	if err != nil {
		t.Fatalf("MintLeaf(%v %v): %v", dns, ips, err)
	}
	key.Destroy()
	return verifyPEM(t, ca, certPEM, name)
}

func verifyPEM(t *testing.T, ca *tlsca.CA, certPEM []byte, name string) error {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("leaf is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	_, err = leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots})
	return err
}

// isConstraintError reports whether err is Go's name-constraint refusal.
func isConstraintError(err error) bool {
	var ie x509.CertificateInvalidError
	return errors.As(err, &ie) && ie.Reason == x509.CANotAuthorizedForThisName
}

func rangeStrings(rs []*net.IPNet) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.String())
	}
	return out
}

func readCert(t *testing.T, path string) *x509.Certificate {
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

func constraintExt(c *x509.Certificate) (critical, ok bool) {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidNameConstraints) {
			return e.Critical, true
		}
	}
	return false, false
}

func unconstrained(c *x509.Certificate) bool {
	_, has := constraintExt(c)
	return !has && len(c.PermittedDNSDomains)+len(c.ExcludedDNSDomains)+len(c.PermittedIPRanges)+len(c.ExcludedIPRanges)+
		len(c.PermittedEmailAddresses)+len(c.ExcludedEmailAddresses)+len(c.PermittedURIDomains)+len(c.ExcludedURIDomains) == 0
}

// TC-258-01: the CA minted for bench carries exactly bench's names and the
// four ranges, in a critical extension, as read back from mesh-ca.pem.
func TestForCluster_CreatedCACarriesCriticalClusterConstraints(t *testing.T) {
	dir := t.TempDir()
	if _, err := tlsca.Ensure(tlsca.ControlplaneConfig().ForCluster("bench"), dir, "test", tlscatest.Deps()); err != nil {
		t.Fatal(err)
	}
	c := readCert(t, filepath.Join(dir, tlsca.ControlplaneCertFile))
	wantDNS := []string{"bench.local", "sso-bench.local", "bench.internal", "relay.rasputin.internal"}
	if got := slices.Sorted(slices.Values(c.PermittedDNSDomains)); !slices.Equal(got, slices.Sorted(slices.Values(wantDNS))) {
		t.Errorf("PermittedDNSDomains = %v, want %v", c.PermittedDNSDomains, wantDNS)
	}
	if got := slices.Sorted(slices.Values(rangeStrings(c.PermittedIPRanges))); !slices.Equal(got, slices.Sorted(slices.Values(wantRanges))) {
		t.Errorf("PermittedIPRanges = %v, want %v", got, wantRanges)
	}
	if critical, ok := constraintExt(c); !ok || !critical {
		t.Errorf("name constraints extension present=%v critical=%v, want a critical one", ok, critical)
	}
	if !c.PermittedDNSDomainsCritical {
		t.Error("PermittedDNSDomainsCritical is false")
	}
}

// TC-258-02: the store and identity CAs, and ControlplaneConfig() with no
// ForCluster, carry no name constraint.
// TC-258-11 (second half): a CA from a Config with zero constraints carries
// no OID 2.5.29.30.
func TestUnconstrainedConfigs_CarryNoConstraint(t *testing.T) {
	for _, cfg := range []tlsca.Config{tlsca.StoreConfig(), tlsca.IdentityConfig(), tlsca.ControlplaneConfig()} {
		dir := t.TempDir()
		if _, err := tlsca.Ensure(cfg, dir, "test", tlscatest.Deps()); err != nil {
			t.Fatalf("%s: %v", cfg.Name, err)
		}
		if c := readCert(t, filepath.Join(dir, cfg.CertFile)); !unconstrained(c) {
			t.Errorf("%s CA carries a name constraint", cfg.Name)
		}
	}
}

// logRecords is a JSON slog sink.
type logRecords struct{ buf bytes.Buffer }

func (l *logRecords) deps() tlsca.Deps {
	d := tlscatest.Deps()
	d.Log = slog.New(slog.NewJSONHandler(&l.buf, nil))
	return d
}

func (l *logRecords) find(t *testing.T, msg string) map[string]any {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(l.buf.String()), "\n") {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("record %q: %v", line, err)
		}
		if r["msg"] == msg {
			return r
		}
	}
	t.Fatalf("no %q record in %s", msg, l.buf.String())
	return nil
}

// TC-258-03: an existing unconstrained CA loaded through ForCluster is
// unchanged and logged constrained=false; a fresh one is logged
// constrained=true.
func TestEnsure_ConstrainedField(t *testing.T) {
	dir := t.TempDir()
	if _, err := tlsca.Ensure(tlsca.ControlplaneConfig(), dir, "test", tlscatest.Deps()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, tlsca.ControlplaneCertFile))
	if err != nil {
		t.Fatal(err)
	}
	var loaded logRecords
	ca, err := tlsca.Ensure(tlsca.ControlplaneConfig().ForCluster("bench"), dir, "test", loaded.deps())
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(dir, tlsca.ControlplaneCertFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("loading through ForCluster rewrote the CA")
	}
	if !unconstrained(ca.Cert) || !ca.Constraints().IsZero() {
		t.Error("the loaded CA reports a constraint it was not minted with")
	}
	if r := loaded.find(t, "tls ca loaded"); r["constrained"] != false {
		t.Errorf("loaded record constrained = %v, want false", r["constrained"])
	}

	var created logRecords
	if _, err := tlsca.Ensure(tlsca.ControlplaneConfig().ForCluster("bench"), t.TempDir(), "test", created.deps()); err != nil {
		t.Fatal(err)
	}
	if r := created.find(t, "tls ca created"); r["constrained"] != true {
		t.Errorf("created record constrained = %v, want true", r["constrained"])
	}
}

// TC-258-04: each door's name, for rasputin, bench and a 59-character id, is
// permitted by and verifies under its own cluster's CA.
func TestDoorLeaves_FitTheirClustersCA(t *testing.T) {
	for _, cid := range []string{"rasputin", "bench", strings.Repeat("a", proto.ClusterIDMaxLen)} {
		table, err := doors.New(cid)
		if err != nil {
			t.Fatalf("doors.New(%q): %v", cid, err)
		}
		ca := clusterCA(t, cid)
		if want := []string{proto.SignInHomeFQDN(cid), proto.SignInFQDN(cid)}; !slices.Equal(table.Hosts(), want) {
			t.Fatalf("hosts = %v, want %v", table.Hosts(), want)
		}
		for _, d := range []doors.Door{table.Home, table.App} {
			if !ca.Constraints().PermitsDNS(d.Host) {
				t.Errorf("%s: PermitsDNS(%q) = false", cid, d.Host)
			}
			certPEM, key, err := ca.MintLeaf(d.LeafSpec())
			if err != nil {
				t.Fatalf("%s: MintLeaf(%s): %v", cid, d.Name, err)
			}
			key.Destroy()
			if err := verifyPEM(t, ca, certPEM, d.Host); err != nil {
				t.Errorf("%s: %s door leaf does not verify for %s: %v", cid, d.Name, d.Host, err)
			}
		}
	}
}

// TC-258-05: an app leaf verifies under bench's CA for both its names and
// for loopback.
func TestAppLeaf_FitsClusterCA(t *testing.T) {
	ca := clusterCA(t, "bench")
	dns := mesh.AppLeafDNSNames("bench", "jellyfin")
	ips := []net.IP{net.IPv4(127, 0, 0, 1)}
	for _, name := range []string{"jellyfin.bench.internal", "jellyfin.lan.bench.internal", "127.0.0.1"} {
		if err := verifyLeaf(t, ca, dns, ips, name); err != nil {
			t.Errorf("app leaf %v does not verify for %s: %v", dns, name, err)
		}
	}
}

// TC-258-06: the app relay leaf, signed over a fresh key, verifies under
// bench's CA for relay.rasputin.internal.
func TestRelayLeaf_FitsClusterCA(t *testing.T) {
	ca := clusterCA(t, "bench")
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := ca.SignLeaf(tlsca.LeafSpec{Usage: tlsca.UsageServer, CommonName: proto.AppRelayServerName,
		DNSNames: []string{proto.AppRelayServerName}}, &k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPEM(t, ca, certPEM, "relay.rasputin.internal"); err != nil {
		t.Errorf("relay leaf: %v", err)
	}
}

// TC-258-09: private and loopback addresses are permitted and verify; the
// rest are refused by both PermitsIP and Go's verifier.
func TestPermitsIP_AgreesWithVerify(t *testing.T) {
	ca := clusterCA(t, "bench")
	c := ca.Constraints()
	for _, s := range []string{"127.0.0.1", "192.168.1.2", "10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.50.7"} {
		ip := net.ParseIP(s)
		if !c.PermitsIP(ip) {
			t.Errorf("PermitsIP(%s) = false, want true", s)
		}
		if err := verifyLeaf(t, ca, nil, []net.IP{ip}, s); err != nil {
			t.Errorf("%s does not verify: %v", s, err)
		}
	}
	for _, s := range []string{"172.32.0.1", "8.8.8.8", "100.64.0.5", "169.254.1.1", "::1"} {
		ip := net.ParseIP(s)
		if c.PermitsIP(ip) {
			t.Errorf("PermitsIP(%s) = true, want false", s)
		}
		if err := verifyLeaf(t, ca, nil, []net.IP{ip}, s); !isConstraintError(err) {
			t.Errorf("%s: Verify = %v, want a name-constraint error", s, err)
		}
	}
}

// TC-258-10: PermitsDNS agrees with Go's verifier on names inside and
// outside bench's list.
func TestPermitsDNS_AgreesWithVerify(t *testing.T) {
	ca := clusterCA(t, "bench")
	c := ca.Constraints()
	inside := []string{"bench.local", "BENCH.LOCAL", "x.bench.local", "sso-bench.local", "bench.internal", "x.bench.internal", "relay.rasputin.internal"}
	outside := []string{"rasputin.local", "home.local", "sso-home.local", "x.local", "local", "signin.home.internal",
		"x-bench.local", "bench.local.evil.com", "localhost", "bench", "google.com"}
	for _, n := range inside {
		if !c.PermitsDNS(n) {
			t.Errorf("PermitsDNS(%q) = false, want true", n)
		}
		if err := verifyLeaf(t, ca, []string{n}, nil, n); err != nil {
			t.Errorf("%q does not verify: %v", n, err)
		}
	}
	for _, n := range outside {
		if c.PermitsDNS(n) {
			t.Errorf("PermitsDNS(%q) = true, want false", n)
		}
		if err := verifyLeaf(t, ca, []string{n}, nil, n); !isConstraintError(err) {
			t.Errorf("%q: Verify = %v, want a name-constraint error", n, err)
		}
	}
}

// TC-258-11 (first half): the zero NameConstraints permits every name.
func TestZeroNameConstraints_PermitAll(t *testing.T) {
	var z tlsca.NameConstraints
	if !z.IsZero() {
		t.Error("zero value is not IsZero")
	}
	for _, n := range []string{"google.com", "localhost", "rasputin.local"} {
		if !z.PermitsDNS(n) {
			t.Errorf("PermitsDNS(%q) = false", n)
		}
	}
	for _, s := range []string{"8.8.8.8", "::1", "10.0.0.1"} {
		if !z.PermitsIP(net.ParseIP(s)) {
			t.Errorf("PermitsIP(%s) = false", s)
		}
	}
}

// TC-258-15: a leaf for a public name or a public address is refused under
// bench's CA, even verified for that exact name.
func TestPublicNames_Refused(t *testing.T) {
	ca := clusterCA(t, "bench")
	if err := verifyLeaf(t, ca, []string{"google.com"}, nil, "google.com"); !isConstraintError(err) {
		t.Errorf("google.com: Verify = %v, want a name-constraint error", err)
	}
	if err := verifyLeaf(t, ca, nil, []net.IP{net.ParseIP("1.1.1.1")}, "1.1.1.1"); !isConstraintError(err) {
		t.Errorf("1.1.1.1: Verify = %v, want a name-constraint error", err)
	}
}

// TC-258-17: bench's CA refuses another cluster's names; home's CA accepts
// home's own, and refuses rasputin.local too.
func TestOtherClustersNames_Refused(t *testing.T) {
	bench, home := clusterCA(t, "bench"), clusterCA(t, "home")
	names := []string{"home.local", "sso-home.local", "signin.home.internal", "jellyfin.home.internal", "bmc-0123456789ab.home.internal", "rasputin.local"}
	for _, n := range names {
		if err := verifyLeaf(t, bench, []string{n}, nil, n); !isConstraintError(err) {
			t.Errorf("bench CA, %q: Verify = %v, want a name-constraint error", n, err)
		}
		err := verifyLeaf(t, home, []string{n}, nil, n)
		if n == "rasputin.local" {
			if !isConstraintError(err) {
				t.Errorf("home CA, rasputin.local: Verify = %v, want a name-constraint error", err)
			}
			continue
		}
		if err != nil {
			t.Errorf("home CA, %q: %v", n, err)
		}
	}
}

// TC-258-23: with no cluster id the list is rasputin's, and none of its
// entries is a bare or empty-label suffix.
func TestForCluster_EmptyIsRasputin(t *testing.T) {
	got, want := tlsca.ControlplaneConfig().ForCluster("").Constraints, tlsca.ControlplaneConfig().ForCluster("rasputin").Constraints
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ForCluster(\"\") = %+v, want ForCluster(\"rasputin\") = %+v", got, want)
	}
	for _, d := range got.DNSDomains {
		if d == "local" || d == ".local" || d == "sso-.local" || d == ".internal" {
			t.Errorf("entry %q is a bare suffix", d)
		}
	}
}

// Fit keeps only what the held CA permits, and replaces a CommonName it does
// not; under an unconstrained or nil CA the spec is unchanged.
func TestFit(t *testing.T) {
	spec := tlsca.LeafSpec{
		Usage:       tlsca.UsageServer,
		CommonName:  "rasputin.local",
		DNSNames:    []string{"rasputin.local", "localhost", "bench", "bench.local"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(203, 0, 113, 7), net.IPv4(192, 168, 1, 2)},
	}
	got := clusterCA(t, "bench").Fit(spec)
	if !slices.Equal(got.DNSNames, []string{"bench.local"}) {
		t.Errorf("DNSNames = %v, want [bench.local]", got.DNSNames)
	}
	if ips := fmtIPs(got.IPAddresses); !slices.Equal(ips, []string{"127.0.0.1", "192.168.1.2"}) {
		t.Errorf("IPAddresses = %v", ips)
	}
	if got.CommonName != "bench.local" {
		t.Errorf("CommonName = %q, want bench.local", got.CommonName)
	}
	if len(spec.DNSNames) != 4 || len(spec.IPAddresses) != 3 {
		t.Error("Fit changed its argument's slices")
	}
	if got := tlscatest.Controlplane(t, "").Fit(spec); !reflect.DeepEqual(got, spec) {
		t.Errorf("unconstrained CA: Fit = %+v, want the spec unchanged", got)
	}
	var nilCA *tlsca.CA
	if got := nilCA.Fit(spec); !reflect.DeepEqual(got, spec) {
		t.Errorf("nil CA: Fit = %+v, want the spec unchanged", got)
	}
}

// When the CA permits none of the spec's DNS names and not its CommonName
// either, Fit has no kept name to put in the CommonName: it drops every DNS
// name, keeps the CommonName as given and keeps the permitted addresses,
// without indexing an empty list (geekdojo/geekdojo-brain#258, F-258-29).
func TestFit_NoPermittedDNSName_KeepsCommonName(t *testing.T) {
	spec := tlsca.LeafSpec{
		Usage:       tlsca.UsageServer,
		CommonName:  "mesh.example.com",
		DNSNames:    []string{"mesh.example.com", "localhost", "other.local"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(203, 0, 113, 7)},
	}
	got := clusterCA(t, "bench").Fit(spec)
	if len(got.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want none", got.DNSNames)
	}
	if got.CommonName != "mesh.example.com" {
		t.Errorf("CommonName = %q, want mesh.example.com unchanged", got.CommonName)
	}
	if ips := fmtIPs(got.IPAddresses); !slices.Equal(ips, []string{"127.0.0.1"}) {
		t.Errorf("IPAddresses = %v, want [127.0.0.1]", ips)
	}
}

func fmtIPs(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
