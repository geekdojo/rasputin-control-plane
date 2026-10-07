package tlsca

import (
	"bytes"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func serverSpec(names ...string) LeafSpec {
	return LeafSpec{Usage: UsageServer, CommonName: names[0], DNSNames: names}
}

// ----- TC-741-05: exactly one explicit EKU per leaf -------------------------

// TC-741-05: every usage each instance allows mints a leaf whose ExtKeyUsage
// is exactly that usage's EKU; none is empty.
func TestMintLeaf_ExactlyOneExplicitEKU(t *testing.T) {
	for _, tc := range []struct {
		name string
		ca   *CA
		spec LeafSpec
		want x509.ExtKeyUsage
	}{
		{"store client", newStoreCAForTest(t), LeafSpec{Usage: UsageClient, CommonName: "api"}, x509.ExtKeyUsageClientAuth},
		{"store server", newStoreCAForTest(t), serverSpec("store.local"), x509.ExtKeyUsageServerAuth},
		{"controlplane server", newCAForTest(t), serverSpec("api.local"), x509.ExtKeyUsageServerAuth},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, key, err := tc.ca.MintLeaf(tc.spec)
			if err != nil {
				t.Fatalf("MintLeaf: %v", err)
			}
			defer key.Destroy()
			cert := mustParseCert(t, certPEM)
			if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{tc.want}) {
				t.Errorf("ExtKeyUsage %v, want exactly [%v]", cert.ExtKeyUsage, tc.want)
			}
			if err := cert.CheckSignatureFrom(tc.ca.Cert); err != nil {
				t.Errorf("not signed by its CA: %v", err)
			}
		})
	}
}

// ----- TC-741-06: MintLeaf refusals ----------------------------------------

// TC-741-06: a zero Usage, an unknown Usage, a client leaf from the
// controlplane CA, an empty CN and a server leaf with no SAN each fail with
// no certificate; a client leaf with a CN and no SAN mints.
func TestMintLeaf_Refusals(t *testing.T) {
	cp := newCAForTest(t)
	store := newStoreCAForTest(t)
	for _, tc := range []struct {
		name string
		ca   *CA
		spec LeafSpec
	}{
		{"zero usage", store, LeafSpec{CommonName: "x", DNSNames: []string{"x"}}},
		{"unknown usage", store, LeafSpec{Usage: Usage(99), CommonName: "x", DNSNames: []string{"x"}}},
		{"client leaf from the controlplane CA", cp, LeafSpec{Usage: UsageClient, CommonName: "x"}},
		{"empty CN", store, LeafSpec{Usage: UsageServer, DNSNames: []string{"x"}}},
		{"server leaf with no SAN", store, LeafSpec{Usage: UsageServer, CommonName: "x"}},
		{"nil CA", nil, serverSpec("x")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, key, err := tc.ca.MintLeaf(tc.spec)
			if err == nil || certPEM != nil || key.Len() != 0 {
				t.Errorf("err=%v cert=%d bytes key=%d bytes, want an error and nothing else", err, len(certPEM), key.Len())
			}
		})
	}
	certPEM, key, err := store.MintLeaf(LeafSpec{Usage: UsageClient, CommonName: "rasputin-api"})
	if err != nil {
		t.Fatalf("client leaf with no SAN: %v", err)
	}
	key.Destroy()
	if cert := mustParseCert(t, certPEM); cert.Subject.CommonName != "rasputin-api" {
		t.Errorf("CN %q", cert.Subject.CommonName)
	}
}

// ----- TC-741-07: the two CAs never chain to each other --------------------

// TC-741-07: x509.Verify against single-CA pools. A store client leaf verifies
// for ClientAuth against the store CA alone, and fails for ServerAuth and
// against the controlplane CA; a controlplane server leaf fails against the
// store CA; a store server leaf fails when presented for ClientAuth.
func TestTwoCAsNeverChain(t *testing.T) {
	cp := newCAForTest(t)
	store := newStoreCAForTest(t)
	pool := func(ca *CA) *x509.CertPool {
		p := x509.NewCertPool()
		p.AddCert(ca.Cert)
		return p
	}
	mint := func(ca *CA, spec LeafSpec) *x509.Certificate {
		certPEM, key, err := ca.MintLeaf(spec)
		if err != nil {
			t.Fatal(err)
		}
		key.Destroy()
		return mustParseCert(t, certPEM)
	}
	storeClient := mint(store, LeafSpec{Usage: UsageClient, CommonName: "rasputin-api"})
	storeServer := mint(store, serverSpec("store.local"))
	cpServer := mint(cp, serverSpec("api.local"))
	verify := func(leaf *x509.Certificate, roots *CA, usage x509.ExtKeyUsage) error {
		_, err := leaf.Verify(x509.VerifyOptions{Roots: pool(roots), KeyUsages: []x509.ExtKeyUsage{usage}})
		return err
	}
	for _, tc := range []struct {
		name  string
		err   error
		valid bool
	}{
		{"store client, store pool, ClientAuth", verify(storeClient, store, x509.ExtKeyUsageClientAuth), true},
		{"store client, store pool, ServerAuth", verify(storeClient, store, x509.ExtKeyUsageServerAuth), false},
		{"store client, controlplane pool", verify(storeClient, cp, x509.ExtKeyUsageClientAuth), false},
		{"controlplane server, store pool", verify(cpServer, store, x509.ExtKeyUsageServerAuth), false},
		{"store server, store pool, ClientAuth", verify(storeServer, store, x509.ExtKeyUsageClientAuth), false},
	} {
		if (tc.err == nil) != tc.valid {
			t.Errorf("%s: err=%v, want valid=%v", tc.name, tc.err, tc.valid)
		}
	}
}

// ----- TC-741-08: re-mint on EKU drift and near-expiry ---------------------

func fileBytes(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TC-741-08: a usable leaf of the other usage is re-minted (both directions);
// a leaf inside renewWindow under the injected clock is re-minted; a leaf that
// matches its spec and is outside the window is left byte-unchanged.
func TestMintLeafToDisk_ReMintsOnEKUDriftAndNearExpiry(t *testing.T) {
	store := newStoreCAForTest(t)
	client := LeafSpec{Usage: UsageClient, CommonName: "store.local", DNSNames: []string{"store.local"}}
	server := serverSpec("store.local")
	for _, tc := range []struct {
		name        string
		first, then LeafSpec
	}{
		{"server on disk, client wanted", server, client},
		{"client on disk, server wanted", client, server},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			paths, err := store.MintLeafToDisk(dir, tc.first)
			if err != nil {
				t.Fatal(err)
			}
			before := fileBytes(t, paths.CertPath)
			if _, err := store.MintLeafToDisk(dir, tc.then); err != nil {
				t.Fatal(err)
			}
			after := fileBytes(t, paths.CertPath)
			if bytes.Equal(before, after) {
				t.Fatal("a leaf of the other usage was reused")
			}
			want, _ := tc.then.Usage.extKeyUsage()
			if got := mustParseCert(t, after).ExtKeyUsage; !slices.Equal(got, []x509.ExtKeyUsage{want}) {
				t.Errorf("re-minted EKU %v, want [%v]", got, want)
			}
		})
	}

	t.Run("near expiry under the injected clock", func(t *testing.T) {
		now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
		d := testDeps()
		d.Now = func() time.Time { return now }
		ca := mustEnsure(t, StoreConfig(), t.TempDir(), d)
		dir := t.TempDir()
		spec := server
		spec.Lifetime = 100 * 24 * time.Hour
		paths, err := ca.MintLeafToDisk(dir, spec)
		if err != nil {
			t.Fatal(err)
		}
		first := fileBytes(t, paths.CertPath)
		now = now.Add(39 * 24 * time.Hour) // 61 days left: outside the window
		if _, err := ca.MintLeafToDisk(dir, spec); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, fileBytes(t, paths.CertPath)) {
			t.Fatal("a leaf outside the renew window was rewritten")
		}
		now = now.Add(24 * time.Hour) // exactly 60 days left: the window's edge, still reused
		if _, err := ca.MintLeafToDisk(dir, spec); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, fileBytes(t, paths.CertPath)) {
			t.Fatal("a leaf exactly at the renew window's edge was rewritten")
		}
		now = now.Add(24 * time.Hour) // 59 days left: inside it
		if _, err := ca.MintLeafToDisk(dir, spec); err != nil {
			t.Fatal(err)
		}
		renewed := fileBytes(t, paths.CertPath)
		if bytes.Equal(first, renewed) {
			t.Fatal("a leaf inside the renew window was not re-minted")
		}
		if nb := mustParseCert(t, renewed).NotBefore; !nb.Equal(now.Add(-time.Hour)) {
			t.Errorf("re-minted NotBefore %v, want the injected clock less an hour (%v)", nb, now.Add(-time.Hour))
		}
	})
}

// LeafUsable is false for a spec MintLeaf would refuse, so the sweep tries to
// mint and reports the refusal rather than calling a leaf usable.
func TestLeafUsable_FalseForAnUnmintableSpec(t *testing.T) {
	ca := newCAForTest(t)
	dir := t.TempDir()
	paths, err := ca.MintLeafToDisk(dir, serverSpec("x"))
	if err != nil {
		t.Fatal(err)
	}
	if !ca.LeafUsable(paths, serverSpec("x")) {
		t.Fatal("a matching leaf reads unusable")
	}
	if ca.LeafUsable(paths, LeafSpec{CommonName: "x", DNSNames: []string{"x"}}) {
		t.Error("a zero-usage spec read a leaf as usable")
	}
	var nilCA *CA
	if nilCA.LeafUsable(paths, serverSpec("x")) {
		t.Error("a nil CA read a leaf as usable")
	}
}

// ----- carried over from the mesh-era tests --------------------------------

func TestMintLeaf_HappyPath(t *testing.T) {
	ca := newCAForTest(t)
	certPEM, keyPEM, err := ca.MintLeaf(LeafSpec{
		Usage:       UsageServer,
		CommonName:  "headscale.rasputin.local",
		DNSNames:    []string{"headscale.rasputin.local", "rasputin.local"},
		IPAddresses: []net.IP{net.IPv4(192, 168, 50, 10), net.IPv4(127, 0, 0, 1)},
	})
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	if !strings.HasPrefix(string(certPEM), "-----BEGIN CERTIFICATE-----") {
		t.Error("cert PEM not well-formed")
	}
	if !strings.HasPrefix(string(keyPEM.Reveal()), "-----BEGIN EC PRIVATE KEY-----") {
		t.Error("key PEM not well-formed")
	}
	cert := mustParseCert(t, certPEM)
	if err := cert.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("leaf not signed by CA: %v", err)
	}
	if got := cert.DNSNames; len(got) != 2 || got[0] != "headscale.rasputin.local" {
		t.Errorf("DNSNames: %v", got)
	}
	if got := cert.IPAddresses; len(got) != 2 {
		t.Errorf("IPAddresses: %v", got)
	}
}

func TestMintLeaf_HonorsExplicitLifetime(t *testing.T) {
	ca := newCAForTest(t)
	spec := serverSpec("x")
	spec.Lifetime = 30 * 24 * time.Hour
	certPEM, _, err := ca.MintLeaf(spec)
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	cert := mustParseCert(t, certPEM)
	// NotBefore is shifted -1h for skew, so the span is lifetime + 1h.
	if got := cert.NotAfter.Sub(cert.NotBefore); got != spec.Lifetime+time.Hour {
		t.Errorf("lifetime: got %v, want %v", got, spec.Lifetime+time.Hour)
	}
}

func TestMintLeafToDisk_CreatesWhenMissing(t *testing.T) {
	ca := newCAForTest(t)
	paths, err := ca.MintLeafToDisk(t.TempDir(), serverSpec("headscale.local"))
	if err != nil {
		t.Fatalf("MintLeafToDisk: %v", err)
	}
	if got := mustPerm(t, paths.CertPath); got != 0o644 {
		t.Errorf("cert mode %o", got)
	}
	if got := mustPerm(t, paths.KeyPath); got != 0o600 {
		t.Errorf("key mode %o", got)
	}
}

func TestMintLeafToDisk_IdempotentOnFreshLeaf(t *testing.T) {
	ca := newCAForTest(t)
	outDir := t.TempDir()
	first, err := ca.MintLeafToDisk(outDir, serverSpec("x"))
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	before := fileBytes(t, first.CertPath)
	if _, err := ca.MintLeafToDisk(outDir, serverSpec("x")); err != nil {
		t.Fatalf("second mint: %v", err)
	}
	if !bytes.Equal(before, fileBytes(t, first.CertPath)) {
		t.Error("cert was rewritten on an idempotent re-mint")
	}
}

// SAN drift: a new hostname in the spec re-mints the leaf to cover it.
func TestMintLeafToDisk_ReMintsOnSANDrift(t *testing.T) {
	ca := newCAForTest(t)
	outDir := t.TempDir()
	if _, err := ca.MintLeafToDisk(outDir, serverSpec("old.local")); err != nil {
		t.Fatalf("first mint: %v", err)
	}
	if _, err := ca.MintLeafToDisk(outDir, serverSpec("old.local", "new.local")); err != nil {
		t.Fatalf("second mint: %v", err)
	}
	cert := mustParseCertFile(t, filepath.Join(outDir, "leaf.pem"))
	if !slices.Contains(cert.DNSNames, "new.local") {
		t.Errorf("re-mint did not include new SAN; have=%v", cert.DNSNames)
	}
}

// A leaf signed by a CA that has since been replaced is re-minted.
func TestMintLeafToDisk_ReMintsOnIssuerChange(t *testing.T) {
	caA := newCAForTest(t)
	caB := newCAForTest(t)
	outDir := t.TempDir()
	if _, err := caA.MintLeafToDisk(outDir, serverSpec("x")); err != nil {
		t.Fatalf("mint under caA: %v", err)
	}
	leafA := mustParseCertFile(t, filepath.Join(outDir, "leaf.pem"))
	if _, err := caB.MintLeafToDisk(outDir, serverSpec("x")); err != nil {
		t.Fatalf("mint under caB: %v", err)
	}
	leafB := mustParseCertFile(t, filepath.Join(outDir, "leaf.pem"))
	if leafA.SerialNumber.Cmp(leafB.SerialNumber) == 0 {
		t.Error("leaf was not re-minted under the new CA (same serial)")
	}
	if err := leafB.CheckSignatureFrom(caB.Cert); err != nil {
		t.Errorf("re-minted leaf is not signed by caB: %v", err)
	}
}

// A withdrawn name re-mints only when the spec asks for an exact SAN set.
func TestMintLeafToDisk_ExactDNSNames(t *testing.T) {
	ca := newCAForTest(t)
	outDir := t.TempDir()
	if _, err := ca.MintLeafToDisk(outDir, serverSpec("a.local", "b.local")); err != nil {
		t.Fatal(err)
	}
	before := fileBytes(t, filepath.Join(outDir, "leaf.pem"))
	tolerant := serverSpec("a.local")
	if _, err := ca.MintLeafToDisk(outDir, tolerant); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, fileBytes(t, filepath.Join(outDir, "leaf.pem"))) {
		t.Fatal("a tolerant spec re-minted on a withdrawn name")
	}
	exact := tolerant
	exact.ExactDNSNames = true
	if _, err := ca.MintLeafToDisk(outDir, exact); err != nil {
		t.Fatal(err)
	}
	if got := mustParseCertFile(t, filepath.Join(outDir, "leaf.pem")).DNSNames; !slices.Equal(got, []string{"a.local"}) {
		t.Errorf("exact spec left SANs %v", got)
	}
}

func TestUsage_String(t *testing.T) {
	for u, want := range map[Usage]string{UsageServer: "server", UsageClient: "client", Usage(0): "Usage(0)"} {
		if got := u.String(); got != want {
			t.Errorf("%d: %q, want %q", int(u), got, want)
		}
	}
}

// The leaf clock gate is consulted once per mint, and not by a re-use.
func TestMintLeaf_ConsultsTheClockGate(t *testing.T) {
	calls := 0
	d := testDeps()
	d.LeafClock = func() bool { calls++; return true }
	ca := mustEnsure(t, ControlplaneConfig(), t.TempDir(), d)
	dir := t.TempDir()
	if _, err := ca.MintLeafToDisk(dir, serverSpec("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.MintLeafToDisk(dir, serverSpec("x")); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("gate consulted %d times, want 1", calls)
	}
}
