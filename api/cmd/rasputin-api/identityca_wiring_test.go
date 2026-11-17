package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// The identity CA's wiring (geekdojo/geekdojo-brain#977): its six leaves,
// their reloads, its failure modes and its place beside the other two CAs.

const (
	identityResetBoth = "systemctl reset-failed keycloak-db.service keycloak.service"
	identityRestartDB = "systemctl restart keycloak-db.service"
	identityRestartKC = "systemctl restart keycloak.service"
	identityComponent = "identity"
)

// identityLeafOrder is the registration, and so the first-boot mint, order.
var identityLeafOrder = []string{identityDBServerLeafName, identityDBClientLeafName, identityServerLeafName,
	identityAPIClientLeafName, identityDoorClientLeafName, identityRepairCodeLeafName}

// scriptedRun is a runFunc that records each command and answers it with
// fail's error (nil for success).
type scriptedRun struct {
	mu    sync.Mutex
	calls []string
	fail  func(cmd string) error
}

func (r *scriptedRun) run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	r.mu.Lock()
	r.calls = append(r.calls, cmd)
	r.mu.Unlock()
	if r.fail != nil {
		return nil, r.fail(cmd)
	}
	return nil, nil
}

func (r *scriptedRun) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

func (r *scriptedRun) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = nil
}

func ensureIdentityCA(t *testing.T, trustDir string, d tlsca.Deps) *tlsca.CA {
	t.Helper()
	ca, err := tlsca.Ensure(tlsca.IdentityConfig(), trustDir, "test", d)
	if err != nil {
		t.Fatalf("identity CA: %v", err)
	}
	return ca
}

// wireIdentityCALeaves is wireIdentityLeaves for a CA that loaded.
func wireIdentityCALeaves(t *testing.T, ca *tlsca.CA, dataDir string, run runFunc) *tlsca.LeafSweeper {
	t.Helper()
	s, err := wireIdentityLeaves(ca, dataDir, run, nil)
	if err != nil || s == nil {
		t.Fatalf("wireIdentityLeaves = %v, %v", s, err)
	}
	return s
}

// identitySweep runs one startup sweep the way main starts it and returns its
// report.
func identitySweep(t *testing.T, s *tlsca.LeafSweeper, log *slog.Logger) tlsca.LeafSweepReport {
	t.Helper()
	return waitSweep(t, startLeafSweep(t.Context(), s, log, identityComponent))
}

func identityDir(dataDir, name string) string { return filepath.Join(dataDir, "tls", name) }

func fileSHA(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// leafState is every identity leaf file's hash, keyed by leaf/file.
func leafState(t *testing.T, dataDir string, names ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, n := range names {
		ents, err := os.ReadDir(identityDir(dataDir, n))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			out[n+"/"+e.Name()] = fileSHA(t, filepath.Join(identityDir(dataDir, n), e.Name()))
		}
	}
	return out
}

func withoutName(names []string, drop string) []string {
	return slices.DeleteFunc(slices.Clone(names), func(n string) bool { return n == drop })
}

// TC-977-01 and TC-977-02: the startup sweep on an empty data dir mints the
// six leaves, each verifying against the identity CA with exactly one EKU and
// the names its consumer needs; the db-client leaf alone has a leaf.pk8, DER
// PKCS-8 at 0600 holding the certificate's key.
func TestIdentityLeaves_StartupSweepMintsSix(t *testing.T) {
	ca := ensureIdentityCA(t, t.TempDir(), tlscatest.Deps())
	dataDir := t.TempDir()
	run := &scriptedRun{}
	rep := identitySweep(t, wireIdentityCALeaves(t, ca, dataDir, run.run), slog.New(slog.DiscardHandler))
	if !slices.Equal(rep.Renewed, identityLeafOrder) || len(rep.Failed) != 0 {
		t.Fatalf("report %+v, want all six renewed and none failed", rep)
	}
	loopback := []net.IP{net.IPv4(127, 0, 0, 1)}
	for _, tc := range []struct {
		name string
		eku  x509.ExtKeyUsage
		cn   string
		ips  []net.IP
		dns  []string
	}{
		{identityServerLeafName, x509.ExtKeyUsageServerAuth, "", loopback, nil},
		{identityDBServerLeafName, x509.ExtKeyUsageServerAuth, "", loopback, nil},
		{identityAPIClientLeafName, x509.ExtKeyUsageClientAuth, "rasputin-api", nil, nil},
		{identityDoorClientLeafName, x509.ExtKeyUsageClientAuth, "rasputin-door", nil, nil},
		{identityDBClientLeafName, x509.ExtKeyUsageClientAuth, "keycloak", nil, nil},
		{identityRepairCodeLeafName, x509.ExtKeyUsageServerAuth, "", nil, []string{"repair-code.rasputin.invalid"}},
	} {
		c := parseLeaf(t, filepath.Join(identityDir(dataDir, tc.name), "leaf.pem"))
		if !slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{tc.eku}) {
			t.Errorf("%s: EKU %v, want exactly [%v]", tc.name, c.ExtKeyUsage, tc.eku)
		}
		if err := verifyAgainst(c, ca.CertPEM, tc.eku); err != nil {
			t.Errorf("%s: does not verify against the identity CA: %v", tc.name, err)
		}
		if !bytes.Equal(c.RawIssuer, ca.Cert.RawSubject) {
			t.Errorf("%s: issuer is not the identity CA", tc.name)
		}
		if tc.cn != "" && c.Subject.CommonName != tc.cn {
			t.Errorf("%s: CN %q, want %q", tc.name, c.Subject.CommonName, tc.cn)
		}
		if len(c.IPAddresses) != len(tc.ips) || (len(tc.ips) == 1 && !c.IPAddresses[0].Equal(tc.ips[0])) {
			t.Errorf("%s: IP SANs %v, want %v", tc.name, c.IPAddresses, tc.ips)
		}
		if !slices.Equal(c.DNSNames, tc.dns) {
			t.Errorf("%s: DNS SANs %v, want %v", tc.name, c.DNSNames, tc.dns)
		}
	}

	// TC-977-02.
	pk8Path := filepath.Join(identityDir(dataDir, identityDBClientLeafName), "leaf.pk8")
	info, err := os.Stat(pk8Path)
	if err != nil {
		t.Fatalf("leaf.pk8: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("leaf.pk8 mode %o, want 0600", info.Mode().Perm())
	}
	der, err := os.ReadFile(pk8Path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(der, []byte("-----BEGIN")) {
		t.Error("leaf.pk8 is PEM, want DER")
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("leaf.pk8 does not parse as PKCS-8: %v", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	dbClient := parseLeaf(t, filepath.Join(identityDir(dataDir, identityDBClientLeafName), "leaf.pem"))
	if !ok || !ec.PublicKey.Equal(dbClient.PublicKey) {
		t.Error("leaf.pk8 does not hold the db-client certificate's ECDSA key")
	}
	for _, n := range withoutName(identityLeafOrder, identityDBClientLeafName) {
		if _, err := os.Stat(filepath.Join(identityDir(dataDir, n), "leaf.pk8")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s holds a leaf.pk8 (stat %v)", n, err)
		}
	}
}

// TC-977-06: a restore with identity data present and both identity CA files
// absent creates a new identity CA (no guard, no ERROR naming it), and one
// sweep re-mints all six leaves under it.
func TestIdentityCA_RestoreReMintsCAAndLeaves(t *testing.T) {
	trustDir, dataDir := t.TempDir(), t.TempDir()
	noExit := func(c int) { t.Fatalf("exit %d", c) }
	_, _, oldCA := ensureCAs(t.Context(), slog.New(slog.DiscardHandler), noExit, trustDir, "home1", tlscatest.Deps(), "", false)
	identitySweep(t, wireIdentityCALeaves(t, oldCA, dataDir, (&scriptedRun{}).run), slog.New(slog.DiscardHandler))
	for _, f := range []string{tlsca.IdentityCertFile, tlsca.IdentityKeyFile} {
		if err := os.Remove(filepath.Join(trustDir, f)); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"identity-db/data", "keycloak/data"} {
		if err := os.MkdirAll(filepath.Join(dataDir, d), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dataDir, d, "PG_VERSION"), []byte("18"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	log, rec := logkittest.New()
	d := tlscatest.Deps()
	d.Log = log
	cp, store, newCA := ensureCAs(t.Context(), log, noExit, trustDir, "home1", d, "", false)
	if cp == nil || store == nil || newCA == nil {
		t.Fatalf("cp=%v store=%v identity=%v, want all three", cp != nil, store != nil, newCA != nil)
	}
	if bytes.Equal(oldCA.Cert.Raw, newCA.Cert.Raw) {
		t.Fatal("the identity CA was not created afresh")
	}
	for _, r := range rec.AtLevel(slog.LevelError) {
		t.Errorf("ERROR record %q after a restore", r.Message)
	}
	rep := identitySweep(t, wireIdentityCALeaves(t, newCA, dataDir, (&scriptedRun{}).run), slog.New(slog.DiscardHandler))
	if !slices.Equal(rep.Renewed, identityLeafOrder) {
		t.Errorf("renewed %v, want all six", rep.Renewed)
	}
	for _, n := range identityLeafOrder {
		if err := parseLeaf(t, filepath.Join(identityDir(dataDir, n), "leaf.pem")).CheckSignatureFrom(newCA.Cert); err != nil {
			t.Errorf("%s does not verify against the new identity CA: %v", n, err)
		}
	}
}

// TC-977-07: each renewal fact renews exactly the leaf it touches, the
// renewed leaf verifies against the current CA, and the leaves that needed
// nothing keep their bytes.
func TestIdentityLeaves_RenewOnEachFact(t *testing.T) {
	// overwrite replaces name's leaf with one signer mints from spec.
	overwrite := func(t *testing.T, signer *tlsca.CA, dataDir, name string, spec tlsca.LeafSpec) {
		t.Helper()
		dir := identityDir(dataDir, name)
		for _, f := range []string{"leaf.pem", "leaf.key", "leaf.pk8"} {
			if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
		}
		if _, err := signer.MintLeafToDisk(dir, spec); err != nil {
			t.Fatal(err)
		}
	}
	const day = 24 * time.Hour
	for _, tc := range []struct {
		name string
		// prep changes one fact and returns the leaves the next sweep must renew.
		prep func(t *testing.T, ca *tlsca.CA, clock *testClock, dataDir string) []string
	}{
		{"(a) 61 days left: nothing renewed", func(_ *testing.T, _ *tlsca.CA, clock *testClock, _ string) []string {
			clock.advance((365 - 61) * day)
			return nil
		}},
		{"(a) 59 days left: all renewed", func(_ *testing.T, _ *tlsca.CA, clock *testClock, _ string) []string {
			clock.advance((365 - 59) * day)
			return identityLeafOrder
		}},
		{"(b) SAN drift", func(t *testing.T, ca *tlsca.CA, _ *testClock, dataDir string) []string {
			spec := identityServerLeafSpec()
			spec.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 2)}
			overwrite(t, ca, dataDir, identityServerLeafName, spec)
			return []string{identityServerLeafName}
		}},
		{"(c) EKU drift", func(t *testing.T, ca *tlsca.CA, _ *testClock, dataDir string) []string {
			overwrite(t, ca, dataDir, identityServerLeafName, tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin identity service"})
			return []string{identityServerLeafName}
		}},
		{"(d) signed by another identity CA with the same subject", func(t *testing.T, ca *tlsca.CA, _ *testClock, dataDir string) []string {
			other := ensureIdentityCA(t, t.TempDir(), tlscatest.Deps())
			if !bytes.Equal(other.Cert.RawSubject, ca.Cert.RawSubject) {
				t.Fatalf("subjects differ: %s / %s", other.Cert.Subject, ca.Cert.Subject)
			}
			overwrite(t, other, dataDir, identityServerLeafName, identityServerLeafSpec())
			return []string{identityServerLeafName}
		}},
		{"(e) a pk8 that does not match its cert", func(t *testing.T, ca *tlsca.CA, _ *testClock, dataDir string) []string {
			other := t.TempDir()
			if _, err := ca.MintLeafToDisk(other, identityDBClientLeafSpec()); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(filepath.Join(other, "leaf.pk8"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(identityDir(dataDir, identityDBClientLeafName), "leaf.pk8"), b, 0o600); err != nil {
				t.Fatal(err)
			}
			return []string{identityDBClientLeafName}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &testClock{now: time.Now()}
			ca := ensureIdentityCA(t, t.TempDir(), tlsca.Deps{Now: clock.Now, Rand: rand.Reader, Log: slog.New(slog.DiscardHandler)})
			dataDir := t.TempDir()
			run := &scriptedRun{}
			s := wireIdentityCALeaves(t, ca, dataDir, run.run)
			identitySweep(t, s, slog.New(slog.DiscardHandler))
			want := tc.prep(t, ca, clock, dataDir)
			before := leafState(t, dataDir, identityLeafOrder...)
			run.reset()
			rep := identitySweep(t, s, slog.New(slog.DiscardHandler))
			if !slices.Equal(rep.Renewed, want) {
				t.Errorf("renewed %v, want %v", rep.Renewed, want)
			}
			if len(want) == 0 && len(run.got()) != 0 {
				t.Errorf("a sweep that renewed nothing ran %v", run.got())
			}
			after := leafState(t, dataDir, identityLeafOrder...)
			for k, v := range before {
				if leaf := strings.SplitN(k, "/", 2)[0]; !slices.Contains(want, leaf) && after[k] != v {
					t.Errorf("%s changed, but %s needed nothing", k, leaf)
				}
			}
			for _, n := range want {
				c := parseLeaf(t, filepath.Join(identityDir(dataDir, n), "leaf.pem"))
				if err := c.CheckSignatureFrom(ca.Cert); err != nil {
					t.Errorf("%s: the renewed leaf does not verify against the current CA: %v", n, err)
				}
				if n == identityServerLeafName && (len(c.IPAddresses) != 1 || !c.IPAddresses[0].Equal(net.IPv4(127, 0, 0, 1)) ||
					!slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})) {
					t.Errorf("renewed identity-server: IPs %v EKU %v, want [127.0.0.1] and serverAuth", c.IPAddresses, c.ExtKeyUsage)
				}
			}
		})
	}
}

// TC-977-08: the first sweep on an empty data dir mints in registration order
// and runs the unit leaves' pairs in that order; then each leaf renewed alone
// runs exactly its own commands, and only the three unit-loaded leaves reload.
func TestIdentityLeaves_ReloadsAndOrder(t *testing.T) {
	ca := ensureIdentityCA(t, t.TempDir(), tlscatest.Deps())
	dataDir := t.TempDir()
	run := &scriptedRun{}
	s := wireIdentityCALeaves(t, ca, dataDir, run.run)
	rep := identitySweep(t, s, slog.New(slog.DiscardHandler))
	if !slices.Equal(rep.Renewed, identityLeafOrder) {
		t.Errorf("first sweep renewed %v, want %v", rep.Renewed, identityLeafOrder)
	}
	unitLeaves := []string{identityDBServerLeafName, identityDBClientLeafName, identityServerLeafName}
	if !slices.Equal(rep.Reloaded, unitLeaves) {
		t.Errorf("first sweep reloaded %v, want %v", rep.Reloaded, unitLeaves)
	}
	wantFirst := []string{identityResetBoth, identityRestartDB, identityResetBoth, identityRestartKC, identityResetBoth, identityRestartKC}
	if got := run.got(); !slices.Equal(got, wantFirst) {
		t.Errorf("first sweep ran %v, want %v", got, wantFirst)
	}
	for _, tc := range []struct {
		leaf string
		want []string
	}{
		{identityServerLeafName, []string{identityResetBoth, identityRestartKC}},
		{identityDBClientLeafName, []string{identityResetBoth, identityRestartKC}},
		{identityDBServerLeafName, []string{identityResetBoth, identityRestartDB}},
		{identityAPIClientLeafName, nil},
		{identityDoorClientLeafName, nil},
		{identityRepairCodeLeafName, nil},
	} {
		t.Run(tc.leaf, func(t *testing.T) {
			if err := os.Remove(filepath.Join(identityDir(dataDir, tc.leaf), "leaf.pem")); err != nil {
				t.Fatal(err)
			}
			run.reset()
			rep := identitySweep(t, s, slog.New(slog.DiscardHandler))
			if !slices.Equal(rep.Renewed, []string{tc.leaf}) {
				t.Errorf("renewed %v, want only %s", rep.Renewed, tc.leaf)
			}
			if got := run.got(); !slices.Equal(got, tc.want) {
				t.Errorf("ran %v, want %v", got, tc.want)
			}
			wantReloaded := []string(nil)
			if tc.want != nil {
				wantReloaded = []string{tc.leaf}
			}
			if !slices.Equal(rep.Reloaded, wantReloaded) {
				t.Errorf("reloaded %v, want %v", rep.Reloaded, wantReloaded)
			}
		})
	}
}

// TC-977-09: a failed reload is one WARN with component=identity naming the
// leaf, recorded in Failed with its fresh leaf on disk; the other leaves are
// still minted and their reloads attempted; nothing is logged at ERROR or
// FATAL, and a second sweep runs nothing and warns of nothing.
func TestIdentityLeaves_ReloadFailureIsAWarning(t *testing.T) {
	notFound := errors.New(`exec: "systemctl": executable file not found in $PATH`)
	for _, tc := range []struct {
		name       string
		fail       func(cmd string) error
		wantFailed []string
		wantCalls  []string
	}{
		{"restart keycloak-db.service fails",
			func(cmd string) error {
				if cmd == identityRestartDB {
					return errors.New("Job for keycloak-db.service failed")
				}
				return nil
			},
			[]string{identityDBServerLeafName},
			[]string{identityResetBoth, identityRestartDB, identityResetBoth, identityRestartKC, identityResetBoth, identityRestartKC}},
		{"systemctl not found",
			func(string) error { return notFound },
			[]string{identityDBServerLeafName, identityDBClientLeafName, identityServerLeafName},
			[]string{identityResetBoth, identityResetBoth, identityResetBoth}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := ensureIdentityCA(t, t.TempDir(), tlscatest.Deps())
			dataDir := t.TempDir()
			run := &scriptedRun{fail: tc.fail}
			log, rec := logkittest.New()
			s := wireIdentityCALeaves(t, ca, dataDir, run.run)
			rep := identitySweep(t, s, log)
			if !slices.Equal(rep.Failed, tc.wantFailed) {
				t.Errorf("failed %v, want %v", rep.Failed, tc.wantFailed)
			}
			if !slices.Equal(rep.Renewed, identityLeafOrder) {
				t.Errorf("renewed %v, want all six", rep.Renewed)
			}
			if got := run.got(); !slices.Equal(got, tc.wantCalls) {
				t.Errorf("ran %v, want %v", got, tc.wantCalls)
			}
			for _, n := range tc.wantFailed {
				if _, err := os.Stat(filepath.Join(identityDir(dataDir, n), "leaf.pem")); err != nil {
					t.Errorf("%s: the fresh leaf is not on disk after a failed reload: %v", n, err)
				}
			}
			warns := rec.AtLevel(slog.LevelWarn)
			if len(warns) != len(tc.wantFailed) {
				t.Fatalf("%d WARN records, want %d:\n%s", len(warns), len(tc.wantFailed), rec.Text())
			}
			for i, w := range warns {
				if c, _ := logkittest.Attr(w, "component"); c != identityComponent {
					t.Errorf("WARN %q has component=%q", w.Message, c)
				}
				if !strings.Contains(w.Message, tc.wantFailed[i]+": reload") {
					t.Errorf("WARN %q does not name %s's reload", w.Message, tc.wantFailed[i])
				}
			}
			if n := len(rec.AtLevel(slog.LevelError)) + len(rec.AtLevel(logkit.LevelFatal)); n != 0 {
				t.Errorf("%d ERROR or FATAL records:\n%s", n, rec.Text())
			}
			run.reset()
			log2, rec2 := logkittest.New()
			if rep := identitySweep(t, s, log2); len(rep.Renewed) != 0 || len(run.got()) != 0 || len(rec2.AtLevel(slog.LevelWarn)) != 0 {
				t.Errorf("second sweep renewed %v ran %v and warned %d times, want nothing", rep.Renewed, run.got(), len(rec2.AtLevel(slog.LevelWarn)))
			}
		})
	}
}

// identityFiles is which identity CA files exist in trustDir, with their
// hashes.
func identityFiles(t *testing.T, trustDir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, f := range []string{tlsca.IdentityCertFile, tlsca.IdentityKeyFile} {
		p := filepath.Join(trustDir, f)
		info, err := os.Stat(p)
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			t.Fatal(err)
		case info.IsDir():
			out[f] = "dir"
		default:
			out[f] = fileSHA(t, p)
		}
	}
	return out
}

// TC-977-10: an identity CA that will not load is one ERROR "identity CA
// unavailable" with ca=identity and err, no exit, the other two CAs loaded and
// a nil identity CA, and no identity file written or removed; and the store
// CA's refusals never skip the identity CA. No record carries PEM or key
// bytes.
func TestEnsureCAs_IdentityCAFailureIsNonFatalAndIndependent(t *testing.T) {
	cpPEM := tlscatest.Controlplane(t, "").CertPEM
	write := func(t *testing.T, dir, name string, b []byte) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name             string
		prep             func(t *testing.T, trustDir string)
		storeDataPresent bool
		identityLoads    bool
		storeLoads       bool
	}{
		{"(a) cert without key", func(t *testing.T, d string) { write(t, d, tlsca.IdentityCertFile, cpPEM) }, false, false, true},
		{"(b) unreadable key", func(t *testing.T, d string) {
			write(t, d, tlsca.IdentityCertFile, cpPEM)
			if err := os.MkdirAll(filepath.Join(d, tlsca.IdentityKeyFile), 0o700); err != nil {
				t.Fatal(err)
			}
		}, false, false, true},
		{"(b) cert not PEM", func(t *testing.T, d string) {
			write(t, d, tlsca.IdentityCertFile, []byte("not a certificate"))
			write(t, d, tlsca.IdentityKeyFile, []byte("not a key"))
		}, false, false, true},
		{"(c) store refused: store data present, store CA absent", func(*testing.T, string) {}, true, true, false},
		{"(d) partial store CA", func(t *testing.T, d string) { write(t, d, tlsca.StoreCertFile, cpPEM) }, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trustDir := filepath.Join(t.TempDir(), "trust")
			tc.prep(t, trustDir)
			before := identityFiles(t, trustDir)
			log, rec := logkittest.New()
			d := tlscatest.Deps()
			d.Log = log
			var exits []int
			cp, store, identity := ensureCAs(t.Context(), log, func(c int) { exits = append(exits, c) }, trustDir, "home1", d,
				filepath.Join(trustDir, "..", "openbao"), tc.storeDataPresent)
			if len(exits) != 0 || cp == nil {
				t.Fatalf("exits %v cp=%v, want no exit and a controlplane CA", exits, cp != nil)
			}
			if (store != nil) != tc.storeLoads || (identity != nil) != tc.identityLoads {
				t.Fatalf("store=%v identity=%v, want store=%v identity=%v", store != nil, identity != nil, tc.storeLoads, tc.identityLoads)
			}
			errs := rec.Matching(slog.LevelError, "identity CA unavailable")
			if tc.identityLoads {
				if len(errs) != 0 {
					t.Errorf("identity CA loaded but logged %d ERRORs", len(errs))
				}
				if identity.Name() != "identity" {
					t.Errorf("identity CA name %q", identity.Name())
				}
			} else {
				if len(errs) != 1 {
					t.Fatalf("%d ERROR identity CA records, want 1:\n%s", len(errs), rec.Text())
				}
				if ca, _ := logkittest.Attr(errs[0], "ca"); ca != "identity" {
					t.Errorf("ca=%q", ca)
				}
				if e, _ := logkittest.Attr(errs[0], "err"); e == "" {
					t.Error("no err attribute")
				}
				if after := identityFiles(t, trustDir); !maps.Equal(before, after) {
					t.Errorf("identity files %v became %v", before, after)
				}
			}
			text := rec.Text()
			if strings.Contains(text, "BEGIN") || strings.Contains(text, "PRIVATE KEY") {
				t.Errorf("a record carries PEM:\n%s", text)
			}
			if identity != nil {
				key, err := os.ReadFile(filepath.Join(trustDir, tlsca.IdentityKeyFile))
				if err != nil {
					t.Fatal(err)
				}
				for _, line := range strings.Split(string(key), "\n") {
					if len(line) > 16 && !strings.HasPrefix(line, "-----") && strings.Contains(text, line) {
						t.Error("a record carries identity CA key bytes")
					}
				}
			}
		})
	}
}

// TC-977-11 (F-977-01): with no identity CA, wireIdentityLeaves returns nil,
// nil without calling the runner or creating a directory; the startup leaf
// check built exactly as main builds it returns nil without panicking; and the
// leaf-sweep job with a nil identity sweeper reports the other two sweepers.
func TestIdentityLeaves_NilCAWiring(t *testing.T) {
	dataDir := t.TempDir()
	run := &scriptedRun{}
	identitySweeper, err := wireIdentityLeaves(nil, dataDir, run.run, nil)
	if identitySweeper != nil || err != nil {
		t.Fatalf("wireIdentityLeaves(nil) = %v, %v; want nil, nil", identitySweeper, err)
	}
	if len(run.got()) != 0 {
		t.Errorf("runner called: %v", run.got())
	}
	if matches, _ := filepath.Glob(filepath.Join(dataDir, "tls", "identity-*")); len(matches) != 0 {
		t.Errorf("identity directories created: %v", matches)
	}
	if done := startLeafSweep(t.Context(), identitySweeper, slog.New(slog.DiscardHandler), identityComponent); done != nil {
		t.Error("a nil identity sweeper started a sweep")
	}

	cp := tlscatest.Controlplane(t, "")
	leafSweeper := tlsca.NewLeafSweeper(cp)
	if err := leafSweeper.Register(tlsca.LeafConsumer{
		Name: "api-https", Dir: filepath.Join(dataDir, "tls", "api"),
		Spec: func() (tlsca.LeafSpec, error) { return apiLeafSpec("cp", net.IPv4(192, 0, 2, 1)), nil },
	}); err != nil {
		t.Fatal(err)
	}
	storeW, err := wireSecretStore(t.Context(), slog.New(slog.DiscardHandler), "openbao", defaultSecretStoreAddr,
		ensureStoreCA(t, t.TempDir(), tlscatest.Deps()), dataDir, (&recordedRun{}).run, noRestartHook)
	if err != nil {
		t.Fatal(err)
	}
	var identityCA *tlsca.CA
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("the startup leaf check panicked: %v", r)
			}
		}()
		// As main.go builds it.
		if err := verifyLeafConsumers(append(append(leafSweeper.RegisteredNames(), storeW.registeredNames()...), identitySweeper.RegisteredNames()...),
			append(requiredLeafConsumers(true, false, storeW.mode == storeModeOpenBao), identityLeafNames(identityCA != nil)...)); err != nil {
			t.Errorf("verifyLeafConsumers = %v, want nil", err)
		}
	}()

	step := tlsca.LeafSweepWorkflow(tlsca.LeafSweepDeps{Sweepers: []*tlsca.LeafSweeper{leafSweeper, storeW.sweeper, identitySweeper}}).Steps[0]
	raw, err := step.Do(&jobs.StepCtx{Ctx: t.Context(), Log: func(string, string) {}})
	if err != nil {
		t.Fatal(err)
	}
	var rep tlsca.LeafSweepReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	want := []string{"api-https", storeProvisionerLeafName, storeServerLeafName, storeClientLeafName, storeAppKeysLeafName}
	if !slices.Equal(rep.Renewed, want) || rep.Checked != len(want) {
		t.Errorf("job report %+v, want the controlplane and store leaves only: %v", rep, want)
	}
}

// TC-977-12: identityLeafNames is the six names or none, and the startup check
// refuses a configuration that registered five of the six.
func TestIdentityLeafNames_RequiredConsumers(t *testing.T) {
	all := identityLeafNames(true)
	if !slices.Equal(all, identityLeafOrder) {
		t.Errorf("identityLeafNames(true) = %v, want %v", all, identityLeafOrder)
	}
	if got := identityLeafNames(false); len(got) != 0 {
		t.Errorf("identityLeafNames(false) = %v, want none", got)
	}
	s := wireIdentityCALeaves(t, ensureIdentityCA(t, t.TempDir(), tlscatest.Deps()), t.TempDir(), (&scriptedRun{}).run)
	registered := s.RegisteredNames()
	five := withoutName(registered, identityRepairCodeLeafName)
	err := verifyLeafConsumers(five, all)
	if err == nil || !strings.Contains(err.Error(), identityRepairCodeLeafName) {
		t.Errorf("five of six registered: err %v, want one naming %s", err, identityRepairCodeLeafName)
	}
	if err := verifyLeafConsumers(registered, all); err != nil {
		t.Errorf("all six registered: %v", err)
	}
}

// TC-977-15 (the part the store's existing tests do not already pin):
// startLeafSweep's records carry the component it is given, and a nil sweeper
// starts nothing. restartStoreUnit's argv and its hook count are pinned,
// unedited, by TestStoreRestartHook's table in secretstore_wiring_test.go.
func TestStartLeafSweep_Component(t *testing.T) {
	if startLeafSweep(t.Context(), nil, slog.New(slog.DiscardHandler), "secretstore") != nil {
		t.Error("a nil sweeper started a sweep")
	}
	log, rec := logkittest.New()
	w, err := wireSecretStore(t.Context(), slog.New(slog.DiscardHandler), "openbao", defaultSecretStoreAddr,
		ensureStoreCA(t, t.TempDir(), tlscatest.Deps()), t.TempDir(), (&recordedRun{}).run, noRestartHook)
	if err != nil {
		t.Fatal(err)
	}
	waitSweep(t, startLeafSweep(t.Context(), w.sweeper, log, "secretstore"))
	recs := rec.Records()
	if len(recs) == 0 {
		t.Fatal("the store sweep logged nothing")
	}
	for _, r := range recs {
		if c, _ := logkittest.Attr(r, "component"); c != "secretstore" {
			t.Errorf("record %q has component=%q", r.Message, c)
		}
	}
}

// TC-977-20: upgrading from the previous release, which left the controlplane
// and store CAs and their leaves and no identity material, on a host without
// the identity units. The old files are byte-identical afterwards; the
// identity CA and six leaves exist; exactly three reload WARNs and no ERROR
// are logged; a second sweep runs nothing and warns of nothing.
func TestIdentityCA_UpgradeFromThePreviousRelease(t *testing.T) {
	trustDir, dataDir := t.TempDir(), t.TempDir()
	cp := tlscatest.ControlplaneWith(t, trustDir, tlscatest.Deps())
	store := ensureStoreCA(t, trustDir, tlscatest.Deps())
	old := map[string]tlsca.LeafSpec{
		"api":                    apiLeafSpec("home1", net.IPv4(192, 0, 2, 1)),
		storeServerLeafName:      storeServerLeafSpec(),
		storeClientLeafName:      storeClientLeafSpec(),
		storeProvisionerLeafName: storeProvisionerLeafSpec(),
	}
	for name, spec := range old {
		signer := store
		if name == "api" {
			signer = cp
		}
		if _, err := signer.MintLeafToDisk(filepath.Join(dataDir, "tls", name), spec); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := func() map[string]string {
		out := map[string]string{}
		for _, f := range []string{tlsca.ControlplaneCertFile, tlsca.ControlplaneKeyFile, tlsca.StoreCertFile, tlsca.StoreKeyFile} {
			out[f] = fileSHA(t, filepath.Join(trustDir, f))
		}
		for name := range old {
			for _, f := range []string{"leaf.pem", "leaf.key"} {
				out[name+"/"+f] = fileSHA(t, filepath.Join(dataDir, "tls", name, f))
			}
		}
		return out
	}
	before := snapshot()

	log, rec := logkittest.New()
	d := tlscatest.Deps()
	d.Log = log
	run := &scriptedRun{fail: func(string) error { return errors.New("Unit keycloak-db.service not found.") }}
	_, _, identityCA := ensureCAs(t.Context(), log, func(c int) { t.Fatalf("exit %d", c) }, trustDir, "home1", d,
		filepath.Join(dataDir, storeDataDirName), storeDataPresent(filepath.Join(dataDir, storeDataDirName)))
	if identityCA == nil {
		t.Fatal("no identity CA after an upgrade")
	}
	s := wireIdentityCALeaves(t, identityCA, dataDir, run.run)
	identitySweep(t, s, log)

	if !maps.Equal(before, snapshot()) {
		t.Error("the controlplane or store CA files or leaves changed")
	}
	for _, f := range []string{tlsca.IdentityCertFile, tlsca.IdentityKeyFile} {
		if _, err := os.Stat(filepath.Join(trustDir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	for _, n := range identityLeafOrder {
		if _, err := os.Stat(filepath.Join(identityDir(dataDir, n), "leaf.pem")); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	warns := rec.AtLevel(slog.LevelWarn)
	if len(warns) != 3 {
		t.Errorf("%d WARN records, want 3 (db-server, db-client, server):\n%s", len(warns), rec.Text())
	}
	if n := len(rec.AtLevel(slog.LevelError)); n != 0 {
		t.Errorf("%d ERROR records:\n%s", n, rec.Text())
	}
	run.reset()
	log2, rec2 := logkittest.New()
	if rep := identitySweep(t, s, log2); len(rep.Renewed) != 0 || len(run.got()) != 0 || len(rec2.AtLevel(slog.LevelWarn)) != 0 {
		t.Errorf("second sweep renewed %v ran %v warned %d times, want nothing", rep.Renewed, run.got(), len(rec2.AtLevel(slog.LevelWarn)))
	}
}
