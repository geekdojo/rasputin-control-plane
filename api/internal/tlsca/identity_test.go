package tlsca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The identity CA (geekdojo/geekdojo-brain#977): its config through Ensure,
// the PKCS-8 key form, chaining across three instances, and serialised
// sweeps.

func newIdentityCAForTest(t *testing.T) *CA {
	t.Helper()
	return mustEnsure(t, IdentityConfig(), t.TempDir(), testDeps())
}

func clientSpec(cn string) LeafSpec { return LeafSpec{Usage: UsageClient, CommonName: cn} }

func pk8Spec() LeafSpec { return LeafSpec{Usage: UsageClient, CommonName: "keycloak", KeyPKCS8: true} }

// assertLeafFilesMatch checks that dir's cert, PEM key and (when wantPK8) pk8
// all hold one key pair.
func assertLeafFilesMatch(t *testing.T, dir string, wantPK8 bool) {
	t.Helper()
	paths := LeafPathsIn(dir)
	if _, err := tls.LoadX509KeyPair(paths.CertPath, paths.KeyPath); err != nil {
		t.Errorf("%s: cert and key do not pair: %v", dir, err)
	}
	if !wantPK8 {
		return
	}
	cert := mustParseCertFile(t, paths.CertPath)
	if !pkcs8Matches(paths.PKCS8Path, cert) {
		t.Errorf("%s: leaf.pk8 does not hold the certificate's key", dir)
	}
}

// TC-977-05: IdentityConfig through Ensure writes identity-ca.pem 0644 and
// identity-ca.key 0600, subject "Rasputin Identity CA (<install>)", IsCA,
// NotAfter now+10y, logs created then loaded with ca=identity and the same
// sha256, and leaves the controlplane and store CAs in the same dir
// byte-identical.
func TestEnsure_IdentityConfig(t *testing.T) {
	dir := t.TempDir()
	mustEnsure(t, ControlplaneConfig(), dir, testDeps())
	mustEnsure(t, StoreConfig(), dir, testDeps())
	before := dirState(t, dir)

	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	rec := &records{}
	d := testDeps()
	d.Now = func() time.Time { return now }
	d.Log = slog.New(rec)
	ca := mustEnsure(t, IdentityConfig(), dir, d)
	if ca.Name() != "identity" {
		t.Errorf("Name = %q", ca.Name())
	}
	certPath, keyPath := filepath.Join(dir, "identity-ca.pem"), filepath.Join(dir, "identity-ca.key")
	if m := mustPerm(t, certPath); m != 0o644 {
		t.Errorf("identity-ca.pem mode %o, want 0644", m)
	}
	if m := mustPerm(t, keyPath); m != 0o600 {
		t.Errorf("identity-ca.key mode %o, want 0600", m)
	}
	cert := mustParseCertFile(t, certPath)
	if cert.Subject.CommonName != "Rasputin Identity CA (test-install)" || !cert.IsCA {
		t.Errorf("subject %q IsCA %v", cert.Subject.CommonName, cert.IsCA)
	}
	if !cert.NotAfter.Equal(now.Add(10 * 365 * 24 * time.Hour)) {
		t.Errorf("NotAfter %s, want now + 10 years", cert.NotAfter)
	}
	mustEnsure(t, IdentityConfig(), dir, d)
	var msgs, sums []string
	for _, r := range rec.recs {
		a := attrs(r)
		if a["ca"] != "identity" {
			t.Errorf("record %q carries ca=%q", r.Message, a["ca"])
		}
		msgs = append(msgs, r.Message)
		sums = append(sums, a["sha256"])
	}
	if !slices.Equal(msgs, []string{"tls ca created", "tls ca loaded"}) {
		t.Errorf("records %v, want created then loaded", msgs)
	}
	if len(sums) == 2 && (sums[0] == "" || sums[0] != sums[1]) {
		t.Errorf("sha256 %v, want one non-empty value twice", sums)
	}
	after := dirState(t, dir)
	for _, f := range []string{ControlplaneCertFile, ControlplaneKeyFile, StoreCertFile, StoreKeyFile} {
		if before[f] == "" || before[f] != after[f] {
			t.Errorf("%s changed beside the identity CA", f)
		}
	}
}

// TC-977-03: a KeyPKCS8 leaf's pk8 that is deleted, holds another key, or
// does not parse makes LeafUsable false, and MintLeafToDisk writes a fresh
// cert, key and pk8 that match. A leaf without KeyPKCS8 and with no pk8 stays
// usable and byte-identical. LeafPathsIn names leaf.pk8.
func TestLeafUsable_PKCS8(t *testing.T) {
	ca := newIdentityCAForTest(t)
	if got := LeafPathsIn("/d").PKCS8Path; got != filepath.Join("/d", "leaf.pk8") {
		t.Errorf("PKCS8Path = %q", got)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		damage func(path string) error
	}{
		{"(a) deleted", os.Remove},
		{"(b) another key", func(p string) error { return os.WriteFile(p, foreign, 0o600) }},
		{"(c) unparseable", func(p string) error { return os.WriteFile(p, []byte("not a key"), 0o600) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			paths, err := ca.MintLeafToDisk(dir, pk8Spec())
			if err != nil {
				t.Fatal(err)
			}
			if !ca.LeafUsable(paths, pk8Spec()) {
				t.Fatal("a fresh pk8 leaf is not usable")
			}
			if m := mustPerm(t, paths.PKCS8Path); m != 0o600 {
				t.Errorf("leaf.pk8 mode %o, want 0600", m)
			}
			oldCert := fileBytes(t, paths.CertPath)
			if err := tc.damage(paths.PKCS8Path); err != nil {
				t.Fatal(err)
			}
			if ca.LeafUsable(paths, pk8Spec()) {
				t.Fatal("LeafUsable is true with a damaged pk8")
			}
			if _, err := ca.MintLeafToDisk(dir, pk8Spec()); err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(oldCert, fileBytes(t, paths.CertPath)) {
				t.Error("the cert was not re-minted")
			}
			assertLeafFilesMatch(t, dir, true)
			if !ca.LeafUsable(paths, pk8Spec()) {
				t.Error("the re-minted leaf is not usable")
			}
		})
	}
	t.Run("(d) no KeyPKCS8, no pk8", func(t *testing.T) {
		dir := t.TempDir()
		spec := clientSpec("rasputin-api")
		paths, err := ca.MintLeafToDisk(dir, spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(paths.PKCS8Path); !os.IsNotExist(err) {
			t.Fatalf("a leaf without KeyPKCS8 wrote leaf.pk8 (stat %v)", err)
		}
		before := dirState(t, dir)
		if !ca.LeafUsable(paths, spec) {
			t.Fatal("a leaf without KeyPKCS8 is unusable without a pk8")
		}
		if _, err := ca.MintLeafToDisk(dir, spec); err != nil {
			t.Fatal(err)
		}
		if !sameState(before, dirState(t, dir)) {
			t.Error("MintLeafToDisk rewrote a usable leaf")
		}
	})
}

// TC-977-04: x509.Verify against single-CA pools across the three
// instances. Only the two positive rows verify.
func TestThreeCAsNeverChain(t *testing.T) {
	cp, store, id := newCAForTest(t), newStoreCAForTest(t), newIdentityCAForTest(t)
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
	loopback := LeafSpec{Usage: UsageServer, CommonName: "identity", IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	idClient := mint(id, clientSpec("rasputin-api"))
	idServer := mint(id, loopback)
	cpServer := mint(cp, serverSpec("api.local"))
	storeClient := mint(store, clientSpec("rasputin-api"))
	storeServer := mint(store, serverSpec("store.local"))
	verify := func(leaf *x509.Certificate, roots *CA, usage x509.ExtKeyUsage) error {
		_, err := leaf.Verify(x509.VerifyOptions{Roots: pool(roots), KeyUsages: []x509.ExtKeyUsage{usage}})
		return err
	}
	client, server := x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth
	rows := []struct {
		name  string
		err   error
		valid bool
	}{
		{"identity client, identity pool, ClientAuth", verify(idClient, id, client), true},
		{"identity server, identity pool, ServerAuth", verify(idServer, id, server), true},
		{"identity client, identity pool, ServerAuth", verify(idClient, id, server), false},
		{"store client, store pool, ClientAuth (pre-existing row)", verify(storeClient, store, client), true},
		{"store client, controlplane pool (pre-existing row)", verify(storeClient, cp, client), false},
		{"controlplane server, store pool (pre-existing row)", verify(cpServer, store, server), false},
	}
	for _, leaf := range []struct {
		name string
		c    *x509.Certificate
	}{{"identity client", idClient}, {"identity server", idServer}} {
		for _, other := range []struct {
			name string
			ca   *CA
		}{{"controlplane", cp}, {"store", store}} {
			for _, u := range []x509.ExtKeyUsage{client, server} {
				rows = append(rows, struct {
					name  string
					err   error
					valid bool
				}{leaf.name + ", " + other.name + " pool", verify(leaf.c, other.ca, u), false})
			}
		}
	}
	for _, leaf := range []struct {
		name string
		c    *x509.Certificate
	}{{"controlplane server", cpServer}, {"store client", storeClient}, {"store server", storeServer}} {
		for _, u := range []x509.ExtKeyUsage{client, server} {
			rows = append(rows, struct {
				name  string
				err   error
				valid bool
			}{leaf.name + ", identity pool", verify(leaf.c, id, u), false})
		}
	}
	for _, r := range rows {
		if (r.err == nil) != r.valid {
			t.Errorf("%s: err=%v, want valid=%v", r.name, r.err, r.valid)
		}
	}
}

// F-977-03 (Bryce's decision of 2026-11-15, recorded as TC-977-22 by the code
// reviewer): two concurrent Sweep calls on one sweeper run one after the
// other. The first is held inside its first mint (the clock gate); the second
// is then provably waiting — either it reached a mint too, which fails the
// test, or the runtime shows it parked on the sweep's lock. Once released,
// every missing leaf is minted and reloaded exactly once across both reports,
// and every cert matches its key (and its pk8).
func TestLeafSweep_ConcurrentSweepsMintEachLeafOnce(t *testing.T) {
	var (
		mu      sync.Mutex
		mints   int
		entered = make(chan struct{}, 16)
		release = make(chan struct{})
	)
	d := testDeps()
	d.LeafClock = func() bool {
		mu.Lock()
		mints++
		mu.Unlock()
		entered <- struct{}{}
		<-release
		return true
	}
	ca := mustEnsure(t, IdentityConfig(), t.TempDir(), d)
	s := NewLeafSweeper(ca)
	root := t.TempDir()
	reloads := map[string]int{}
	specs := map[string]LeafSpec{
		"server": {Usage: UsageServer, CommonName: "identity", IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}},
		"client": clientSpec("rasputin-api"),
		"pk8":    pk8Spec(),
	}
	names := []string{"server", "client", "pk8"}
	for _, n := range names {
		spec := specs[n]
		if err := s.Register(LeafConsumer{
			Name: n, Dir: filepath.Join(root, n),
			Spec: func() (LeafSpec, error) { return spec, nil },
			Reload: func(context.Context, LeafPaths) error {
				mu.Lock()
				reloads[n]++
				mu.Unlock()
				return nil
			},
		}); err != nil {
			t.Fatal(err)
		}
	}

	reports := make(chan LeafSweepReport, 2)
	go func() { reports <- s.Sweep(t.Context(), nil) }()
	<-entered // the first sweep is inside its first mint
	go func() { reports <- s.Sweep(t.Context(), nil) }()
	// Wait for a fact about the second sweep, never for a duration.
	for !sweepParkedOnLock() {
		select {
		case <-entered:
			t.Fatal("the second sweep reached a mint while the first was still minting")
		default:
		}
		runtime.Gosched()
	}
	close(release)
	a, b := <-reports, <-reports

	renewed := append(append([]string(nil), a.Renewed...), b.Renewed...)
	slices.Sort(renewed)
	want := slices.Clone(names)
	slices.Sort(want)
	if !slices.Equal(renewed, want) {
		t.Errorf("renewed across both sweeps = %v, want each leaf once: %v", renewed, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if mints != len(names) {
		t.Errorf("%d mints, want %d", mints, len(names))
	}
	for _, n := range names {
		if reloads[n] != 1 {
			t.Errorf("%s reloaded %d times, want 1", n, reloads[n])
		}
		assertLeafFilesMatch(t, filepath.Join(root, n), specs[n].KeyPKCS8)
	}
	if a.Checked != len(names) || b.Checked != len(names) {
		t.Errorf("checked %d and %d, want both sweeps to check all %d", a.Checked, b.Checked, len(names))
	}
}

// sweepParkedOnLock reports whether some goroutine is blocked acquiring a
// mutex inside LeafSweeper.Sweep, read from the runtime's goroutine dump.
func sweepParkedOnLock() bool {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "[sync.Mutex.Lock") && strings.Contains(g, "(*LeafSweeper).Sweep") {
			return true
		}
	}
	return false
}

// F-977-01 (TC-977-11's tlsca half): a nil sweeper, the one main holds when
// the identity CA did not load, has registered nothing and does not panic.
func TestLeafSweeper_RegisteredNamesNilSafe(t *testing.T) {
	var s *LeafSweeper
	if got := s.RegisteredNames(); got != nil {
		t.Errorf("nil sweeper RegisteredNames = %v, want nil", got)
	}
}
