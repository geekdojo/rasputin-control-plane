package bustls

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func ensureKeyIn(t *testing.T, dir string) *Key {
	t.Helper()
	k, _, err := EnsureKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The certificate is minted once and then REUSED, byte for byte, across every
// later start. That is the whole point of persisting it: a client may pin its
// bytes (geekdojo/geekdojo-brain#508).
func TestEnsureCert_PersistsAndReuses(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bus")
	key := ensureKeyIn(t, dir)

	cert, generated, err := EnsureCert(dir, key)
	if err != nil || !generated {
		t.Fatalf("first EnsureCert = (generated %t, %v), want a generated certificate", generated, err)
	}
	path := filepath.Join(dir, CertFileName)
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(EncodeCertPEM(cert)) {
		t.Fatal("the file does not hold the certificate that was returned")
	}

	again, generated, err := EnsureCert(dir, key)
	if err != nil || generated {
		t.Fatalf("second EnsureCert = (generated %t, %v), want the persisted certificate", generated, err)
	}
	if again.Leaf.SerialNumber.Cmp(cert.Leaf.SerialNumber) != 0 {
		t.Fatalf("serial changed on the second call: %s then %s", cert.Leaf.SerialNumber, again.Leaf.SerialNumber)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != string(first) {
		t.Fatal("the persisted bytes changed on a start that should have reused them")
	}
	// It serves the key, so a client that pins the key accepts it unchanged.
	if again.PrivateKey != key.Signer() {
		t.Fatal("the reused certificate does not carry the bus key")
	}
}

// The SAN is fixed, present, and what a name-verifying client matches. Go does
// not fall back to the CN, which is the finding that made this required rather
// than optional (geekdojo/geekdojo-brain#467).
func TestEnsureCert_CarriesTheFixedDNSName(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bus")
	key := ensureKeyIn(t, dir)
	cert, _, err := EnsureCert(dir, key)
	if err != nil {
		t.Fatal(err)
	}

	if got := cert.Leaf.DNSNames; len(got) != 1 || got[0] != BusDNSName {
		t.Fatalf("DNSNames = %v, want exactly [%q]", got, BusDNSName)
	}
	if err := cert.Leaf.VerifyHostname(BusDNSName); err != nil {
		t.Fatalf("VerifyHostname(%q): %v", BusDNSName, err)
	}
	// A full client-side verification against itself as the only root, the way
	// the collector will trust it as an exact-bytes ca_pem with
	// server_name = BusDNSName.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(EncodeCertPEM(cert)) {
		t.Fatal("the persisted PEM is not loadable as a trust root")
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		DNSName:     BusDNSName,
		Roots:       pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("a client verifying it by name against its own bytes: %v", err)
	}
	// And the name is the same on every cluster: a second, unrelated bus gets
	// the identical SAN.
	otherDir := filepath.Join(t.TempDir(), "bus")
	other, _, err := EnsureCert(otherDir, ensureKeyIn(t, otherDir))
	if err != nil {
		t.Fatal(err)
	}
	if other.Leaf.DNSNames[0] != cert.Leaf.DNSNames[0] {
		t.Fatalf("two clusters got different SANs: %q and %q", other.Leaf.DNSNames[0], cert.Leaf.DNSNames[0])
	}
	if other.Leaf.SerialNumber.Cmp(cert.Leaf.SerialNumber) == 0 {
		t.Fatal("two clusters got the same serial")
	}
}

// A persisted certificate that is not one this package would have written is
// replaced — with the reason — rather than served. The key beside it is the
// pin, so nothing is lost by re-minting.
func TestEnsureCert_ReplacesAnUnusableFile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		write   func(t *testing.T, dir string, key *Key)
		wantWhy string
	}{
		{"not a PEM certificate", func(t *testing.T, dir string, _ *Key) {
			write(t, filepath.Join(dir, CertFileName), []byte("nonsense\n"))
		}, "not a PEM CERTIFICATE"},
		{"a PEM block that does not parse", func(t *testing.T, dir string, _ *Key) {
			write(t, filepath.Join(dir, CertFileName), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}))
		}, "does not parse"},
		{"wraps a different key", func(t *testing.T, dir string, _ *Key) {
			otherDir := filepath.Join(t.TempDir(), "bus")
			otherCert, _, err := EnsureCert(otherDir, ensureKeyIn(t, otherDir))
			if err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(dir, CertFileName), EncodeCertPEM(otherCert))
		}, "was replaced or restored"},
		{"no DNS name", func(t *testing.T, dir string, key *Key) {
			write(t, filepath.Join(dir, CertFileName), EncodeCertPEM(noSANCert(t, key)))
		}, "carries no"},
		{"a bounded expiry", func(t *testing.T, dir string, key *Key) {
			c, err := SelfSignedCert(key.Signer(), certNotBefore, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
			if err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(dir, CertFileName), EncodeCertPEM(c))
		}, "expires at 2030-01-01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "bus")
			key := ensureKeyIn(t, dir)
			tc.write(t, dir, key)

			cert, generated, err := EnsureCert(dir, key)
			if !generated {
				t.Fatal("the unusable file was served rather than replaced")
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantWhy) {
				t.Fatalf("the replacement does not say why (%v), want it to mention %q", err, tc.wantWhy)
			}
			// Replaced with a good one, and the file now holds it.
			if len(cert.Certificate) == 0 || cert.Leaf.DNSNames[0] != BusDNSName {
				t.Fatalf("the replacement is not usable: %+v", cert.Leaf)
			}
			pin, perr := proto.BusPinForPublicKey(cert.Leaf.PublicKey)
			if perr != nil || pin != key.Pin() {
				t.Fatalf("the replacement wraps %q, want the bus key %q (%v)", pin, key.Pin(), perr)
			}
			on, _, err := EnsureCert(dir, key)
			if err != nil {
				t.Fatal(err)
			}
			if on.Leaf.SerialNumber.Cmp(cert.Leaf.SerialNumber) != 0 {
				t.Fatal("the replacement was not persisted: the next start minted another")
			}
		})
	}
}

// The file is public — it carries a public key and nothing else — and a
// container user reads it as the collector's ca_pem. The directory stays 0700.
func TestEnsureCert_FileIsPublicInAPrivateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bus")
	key := ensureKeyIn(t, dir)
	if _, _, err := EnsureCert(dir, key); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, CertFileName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("certificate mode = %v, want 0644", fi.Mode().Perm())
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("bus dir mode = %v, want 0700", di.Mode().Perm())
	}
}

func TestEnsureCert_NoKey(t *testing.T) {
	if _, _, err := EnsureCert(t.TempDir(), nil); err == nil {
		t.Fatal("EnsureCert(nil key) = nil, want an error")
	}
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// noSANCert is the shape the api minted before this change: a CN and no SAN.
// Go reports such a certificate as valid for no names at all.
func noSANCert(t *testing.T, key *Key) tls.Certificate {
	t.Helper()
	c, err := SelfSignedCert(key.Signer(), certNotBefore, certNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	leaf := *c.Leaf
	leaf.DNSNames = nil
	der, err := x509.CreateCertificate(rand.Reader, &leaf, &leaf, key.Signer().Public(), key.Signer())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.VerifyHostname(BusDNSName); err == nil {
		t.Fatal("a certificate with no SAN verified by name; the premise of the SAN is wrong")
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key.Signer(), Leaf: parsed}
}
