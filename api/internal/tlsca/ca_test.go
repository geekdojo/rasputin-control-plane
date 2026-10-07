package tlsca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// ----- helpers ---------------------------------------------------------------

// testDeps is the production Deps with a discarding logger. (tlscatest has the
// same for other packages; it imports this one, so it cannot be used here.)
func testDeps() Deps {
	return Deps{Now: time.Now, Rand: rand.Reader, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func mustEnsure(t *testing.T, cfg Config, dir string, d Deps) *CA {
	t.Helper()
	ca, err := Ensure(cfg, dir, "test-install", d)
	if err != nil {
		t.Fatalf("Ensure(%s): %v", cfg.Name, err)
	}
	return ca
}

func newCAForTest(t *testing.T) *CA {
	t.Helper()
	return mustEnsure(t, ControlplaneConfig(), t.TempDir(), testDeps())
}

func newStoreCAForTest(t *testing.T) *CA {
	t.Helper()
	return mustEnsure(t, StoreConfig(), t.TempDir(), testDeps())
}

func mustParseCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("PEM block did not decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func mustParseCertFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return mustParseCert(t, b)
}

func mustPerm(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

// dirState is every file in dir with the SHA-256 of its bytes, so a test can
// say "nothing was written or rewritten".
func dirState(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out
		}
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			out[e.Name()] = "unreadable"
			continue
		}
		sum := sha256.Sum256(b)
		out[e.Name()] = hex.EncodeToString(sum[:])
	}
	return out
}

func sameState(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// records captures slog records for assertions.
type records struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (r *records) Enabled(context.Context, slog.Level) bool { return true }
func (r *records) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, rec.Clone())
	return nil
}
func (r *records) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *records) WithGroup(string) slog.Handler      { return r }

func attrs(rec slog.Record) map[string]string {
	out := map[string]string{}
	rec.Attrs(func(a slog.Attr) bool {
		out[a.Key] = a.Value.String()
		return true
	})
	return out
}

// ----- TC-741-01: one code path, config-only differences --------------------

// TC-741-01: the same assertions run over both instances. Each writes its own
// file names, subject and lifetime; both are CAs that sign certificates and
// CRLs only; the cert is 0644, the key 0600 and the dir 0700; a second Ensure
// reloads the same CA.
func TestEnsure_BothInstancesThroughOnePath(t *testing.T) {
	for _, tc := range []struct {
		cfg              Config
		cert, key, cnPre string
	}{
		{ControlplaneConfig(), "mesh-ca.pem", "mesh-ca.key", "Rasputin Mesh CA ("},
		{StoreConfig(), "store-ca.pem", "store-ca.key", "Rasputin Store CA ("},
	} {
		t.Run(tc.cfg.Name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "trust")
			ca, err := Ensure(tc.cfg, dir, "casa", testDeps())
			if err != nil {
				t.Fatalf("Ensure: %v", err)
			}
			if tc.cfg.CertFile != tc.cert || tc.cfg.KeyFile != tc.key {
				t.Errorf("file names %s/%s, want %s/%s", tc.cfg.CertFile, tc.cfg.KeyFile, tc.cert, tc.key)
			}
			if want := tc.cnPre + "casa)"; ca.Cert.Subject.CommonName != want {
				t.Errorf("subject %q, want %q", ca.Cert.Subject.CommonName, want)
			}
			if got := ca.Cert.NotAfter.Sub(ca.Cert.NotBefore); got != tc.cfg.Lifetime+time.Hour {
				t.Errorf("validity %v, want the config's lifetime plus the hour of skew (%v)", got, tc.cfg.Lifetime+time.Hour)
			}
			if tc.cfg.Lifetime != 10*365*24*time.Hour {
				t.Errorf("lifetime %v, want 10y", tc.cfg.Lifetime)
			}
			if !ca.Cert.IsCA || !ca.Cert.BasicConstraintsValid {
				t.Error("certificate is not a CA")
			}
			if ca.Cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
				t.Errorf("KeyUsage %v, want CertSign|CRLSign", ca.Cert.KeyUsage)
			}
			if ca.Name() != tc.cfg.Name {
				t.Errorf("Name() %q, want %q", ca.Name(), tc.cfg.Name)
			}
			if got := mustPerm(t, filepath.Join(dir, tc.cert)); got != 0o644 {
				t.Errorf("cert mode %o, want 644", got)
			}
			if got := mustPerm(t, filepath.Join(dir, tc.key)); got != 0o600 {
				t.Errorf("key mode %o, want 600", got)
			}
			if got := mustPerm(t, dir); got != 0o700 {
				t.Errorf("dir mode %o, want 700", got)
			}
			again, err := Ensure(tc.cfg, dir, "casa", testDeps())
			if err != nil {
				t.Fatalf("second Ensure: %v", err)
			}
			if !bytes.Equal(again.CertPEM, ca.CertPEM) || !again.key.Equal(ca.key) {
				t.Error("second Ensure did not reload the same CA")
			}
		})
	}
}

func TestEnsure_DefaultsInstallName(t *testing.T) {
	ca, err := Ensure(ControlplaneConfig(), t.TempDir(), "", testDeps())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if ca.Cert.Subject.CommonName != "Rasputin Mesh CA (rasputin)" {
		t.Errorf("subject %q", ca.Cert.Subject.CommonName)
	}
}

func TestEnsure_RefusesIncompleteConfigAndDeps(t *testing.T) {
	cfg := ControlplaneConfig()
	cfg.Usages = nil
	if _, err := Ensure(cfg, t.TempDir(), "x", testDeps()); err == nil {
		t.Error("a config with no usages was accepted")
	}
	cfg = ControlplaneConfig()
	cfg.Usages = []Usage{Usage(42)}
	if _, err := Ensure(cfg, t.TempDir(), "x", testDeps()); err == nil {
		t.Error("a config naming an unknown usage was accepted")
	}
	for name, d := range map[string]Deps{
		"no Now":  {Rand: rand.Reader, Log: testDeps().Log},
		"no Rand": {Now: time.Now, Log: testDeps().Log},
		"no Log":  {Now: time.Now, Rand: rand.Reader},
	} {
		dir := t.TempDir()
		if _, err := Ensure(ControlplaneConfig(), dir, "x", d); err == nil {
			t.Errorf("%s: Deps accepted", name)
		}
		if st := dirState(t, dir); len(st) != 0 {
			t.Errorf("%s: wrote %v", name, st)
		}
	}
}

// ----- TC-741-02: the existing CA is unchanged once the store CA exists -----

// writeLegacyControlplaneCA lays down mesh-ca.pem and mesh-ca.key the way the
// release before tlsca wrote them: a SEC1 "EC PRIVATE KEY" and a self-signed
// CERTIFICATE, under the old subject.
func writeLegacyControlplaneCA(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-48 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "Rasputin Mesh CA (legacy)", Organization: []string{"Rasputin"}},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mesh-ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mesh-ca.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-24 * time.Hour)
	for _, f := range []string{"mesh-ca.pem", "mesh-ca.key"} {
		if err := os.Chtimes(filepath.Join(dir, f), old, old); err != nil {
			t.Fatal(err)
		}
	}
}

// TC-741-02: an upgrade over an existing controlplane CA leaves both of its
// files byte- and mtime-identical after both Ensures and a mint, adds the
// store CA beside it, and the two CA keys differ.
func TestEnsure_ExistingControlplaneCAUnchangedBesideStoreCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "trust")
	writeLegacyControlplaneCA(t, dir)
	type snap struct {
		sum   [32]byte
		mtime time.Time
	}
	take := func() map[string]snap {
		out := map[string]snap{}
		for _, f := range []string{"mesh-ca.pem", "mesh-ca.key"} {
			p := filepath.Join(dir, f)
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			out[f] = snap{sha256.Sum256(b), info.ModTime()}
		}
		return out
	}
	before := take()

	cp := mustEnsure(t, ControlplaneConfig(), dir, testDeps())
	store := mustEnsure(t, StoreConfig(), dir, testDeps())
	if _, err := cp.MintLeafToDisk(filepath.Join(t.TempDir(), "leaf"), LeafSpec{Usage: UsageServer, CommonName: "api", DNSNames: []string{"api.local"}}); err != nil {
		t.Fatalf("mint: %v", err)
	}

	after := take()
	for f, b := range before {
		if after[f].sum != b.sum {
			t.Errorf("%s bytes changed", f)
		}
		if !after[f].mtime.Equal(b.mtime) {
			t.Errorf("%s mtime changed %v → %v", f, b.mtime, after[f].mtime)
		}
	}
	for _, f := range []string{"store-ca.pem", "store-ca.key"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s missing: %v", f, err)
		}
	}
	if cp.key.Equal(store.key) {
		t.Error("the controlplane and store CAs share a key")
	}
	if cp.Cert.Subject.CommonName != "Rasputin Mesh CA (legacy)" {
		t.Errorf("controlplane subject %q, want the fixture's", cp.Cert.Subject.CommonName)
	}
}

// ----- TC-741-03: partial state refused per instance ------------------------

// TC-741-03: a cert with no key (store), and a key with no cert
// (controlplane), each refuse with "tlsca <name>:" naming the partial state;
// nothing is re-issued and the other instance's files are byte-unchanged.
func TestEnsure_PartialStateRefusedPerInstance(t *testing.T) {
	for _, tc := range []struct {
		cfg, other Config
		lone       string
	}{
		{StoreConfig(), ControlplaneConfig(), "store-ca.pem"},
		{ControlplaneConfig(), StoreConfig(), "mesh-ca.key"},
	} {
		t.Run(tc.cfg.Name, func(t *testing.T) {
			dir := t.TempDir()
			mustEnsure(t, tc.other, dir, testDeps())
			if err := os.WriteFile(filepath.Join(dir, tc.lone), []byte("half"), 0o600); err != nil {
				t.Fatal(err)
			}
			before := dirState(t, dir)
			ca, err := Ensure(tc.cfg, dir, "x", testDeps())
			if err == nil || ca != nil {
				t.Fatalf("partial state accepted: ca=%v err=%v", ca, err)
			}
			if !strings.HasPrefix(err.Error(), "tlsca "+tc.cfg.Name+":") || !strings.Contains(err.Error(), "partial") {
				t.Errorf("error %q, want a tlsca %s: error naming the partial state", err, tc.cfg.Name)
			}
			if after := dirState(t, dir); !sameState(before, after) {
				t.Errorf("directory changed:\nbefore %v\nafter  %v", before, after)
			}
		})
	}
}

// ----- TC-741-04: malformed or unreadable inputs ----------------------------

// TC-741-04: for each instance, an empty dir argument, an unreadable cert, a
// non-PEM cert, a non-EC key and a key with the wrong PEM type each return a
// wrapped "tlsca <name>:" error and no CA, and write no file.
func TestEnsure_MalformedInputs(t *testing.T) {
	ecKeyPEM := func() []byte {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}
	rsaPKCS8 := func() []byte {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	for _, cfg := range []Config{ControlplaneConfig(), StoreConfig()} {
		t.Run(cfg.Name, func(t *testing.T) {
			if ca, err := Ensure(cfg, "", "x", testDeps()); err == nil || ca != nil || !strings.HasPrefix(err.Error(), "tlsca "+cfg.Name+":") {
				t.Errorf("empty dir: ca=%v err=%v", ca, err)
			}
			good := mustEnsure(t, cfg, t.TempDir(), testDeps())
			cases := []struct {
				name      string
				cert, key []byte
				certMode  os.FileMode
			}{
				{"non-PEM cert", []byte("not a certificate"), ecKeyPEM(), 0o644},
				{"non-EC key", good.CertPEM, rsaPKCS8(), 0o644},
				{"wrong key PEM type", good.CertPEM, pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("x")}), 0o644},
				{"unreadable cert", good.CertPEM, ecKeyPEM(), 0o000},
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					if c.certMode == 0 && os.Geteuid() == 0 {
						t.Skip("root reads a mode-0000 file")
					}
					dir := t.TempDir()
					if err := os.WriteFile(filepath.Join(dir, cfg.CertFile), c.cert, 0o644); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, cfg.KeyFile), c.key, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(filepath.Join(dir, cfg.CertFile), c.certMode); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, cfg.CertFile), 0o644) })
					before := dirState(t, dir)
					ca, err := Ensure(cfg, dir, "x", testDeps())
					if err == nil || ca != nil {
						t.Fatalf("accepted: ca=%v err=%v", ca, err)
					}
					if !strings.HasPrefix(err.Error(), "tlsca "+cfg.Name+":") {
						t.Errorf("error %q is not prefixed tlsca %s:", err, cfg.Name)
					}
					after := dirState(t, dir)
					names := func(m map[string]string) []string {
						var out []string
						for k := range m {
							out = append(out, k)
						}
						sort.Strings(out)
						return out
					}
					if strings.Join(names(before), ",") != strings.Join(names(after), ",") || !sameState(before, after) {
						t.Errorf("files changed:\nbefore %v\nafter  %v", before, after)
					}
				})
			}
		})
	}
}

// A failure creating the CA leaves no file behind: a key with no cert would be
// a partial state the next start must refuse.
func TestEnsure_CreateFailureWritesNoFile(t *testing.T) {
	dir := t.TempDir()
	// The cert's path is a directory, so writing the cert fails after the key.
	if err := os.Mkdir(filepath.Join(dir, "store-ca.pem"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(StoreConfig(), dir, "x", testDeps()); err == nil {
		t.Fatal("create succeeded over a directory")
	}
	if _, err := os.Stat(filepath.Join(dir, "store-ca.key")); !os.IsNotExist(err) {
		t.Errorf("the key was left behind: %v", err)
	}
}

// failingReader is a Rand that always errors.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// The injected Rand feeds the serial: a reader that fails fails the create,
// with no file written. (GenerateKey ignores its reader since Go 1.26.)
func TestEnsure_RandIsTheInjectedReader(t *testing.T) {
	dir := t.TempDir()
	d := testDeps()
	d.Rand = failingReader{}
	if _, err := Ensure(StoreConfig(), dir, "x", d); err == nil || !strings.Contains(err.Error(), "random serial") {
		t.Fatalf("err = %v, want the serial's read failure", err)
	}
	if st := dirState(t, dir); len(st) != 0 {
		t.Errorf("files written: %v", st)
	}
}

// ----- TC-741-13: load and create logging -----------------------------------

// TC-741-13: a create then a load each log one INFO record with ca, subject,
// not_after and sha256 (the certificate DER's digest), and no record carries
// key material.
func TestEnsure_LogsCreateThenLoad(t *testing.T) {
	h := &records{}
	d := testDeps()
	d.Log = slog.New(h)
	dir := t.TempDir()
	ca := mustEnsure(t, StoreConfig(), dir, d)
	mustEnsure(t, StoreConfig(), dir, d)

	if len(h.recs) != 2 {
		t.Fatalf("%d records, want 2", len(h.recs))
	}
	sum := sha256.Sum256(ca.Cert.Raw)
	keyFile, err := os.ReadFile(filepath.Join(dir, "store-ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"tls ca created", "tls ca loaded"} {
		rec := h.recs[i]
		if rec.Message != want || rec.Level != slog.LevelInfo {
			t.Errorf("record %d: %s %q, want INFO %q", i, rec.Level, rec.Message, want)
		}
		a := attrs(rec)
		if a["ca"] != "store" || a["subject"] != ca.Cert.Subject.CommonName ||
			a["not_after"] != ca.Cert.NotAfter.UTC().Format(time.RFC3339) || a["sha256"] != hex.EncodeToString(sum[:]) {
			t.Errorf("record %d attrs %v", i, a)
		}
		for k, v := range a {
			if strings.Contains(v, "PRIVATE KEY") || (len(v) > 20 && bytes.Contains(keyFile, []byte(v))) {
				t.Errorf("record %d attr %s carries key material", i, k)
			}
		}
	}
}
