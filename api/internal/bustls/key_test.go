package bustls

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func TestEnsureKey_GeneratesOnceThenLoads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bus")
	k1, generated, err := EnsureKey(dir)
	if err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	if !generated {
		t.Fatal("first EnsureKey did not report generating a key")
	}
	if _, err := proto.ParseBusPin(k1.Pin()); err != nil {
		t.Fatalf("pin %q: %v", k1.Pin(), err)
	}

	path := filepath.Join(dir, KeyFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The one-line seed form: base64 and exactly one trailing newline.
	if strings.Count(string(raw), "\n") != 1 || !strings.HasSuffix(string(raw), "\n") {
		t.Errorf("key file is not one line: %q", raw)
	}

	k2, generated, err := EnsureKey(dir)
	if err != nil {
		t.Fatalf("second EnsureKey: %v", err)
	}
	if generated {
		t.Fatal("second EnsureKey generated a key over an existing one")
	}
	if k2.Pin() != k1.Pin() {
		t.Fatalf("pin changed across a reload: %s → %s", k1.Pin(), k2.Pin())
	}
}

// A key file that does not parse is an error, and the file is left alone:
// replacing a key every node pins would strand the fleet.
func TestEnsureKey_RefusesToReplaceAnUnusableKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, KeyFileName)
	if err := os.WriteFile(path, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := EnsureKey(dir); err == nil {
		t.Fatal("EnsureKey accepted a corrupt key file")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "not a key\n" {
		t.Fatalf("the unusable key file was overwritten: %q", got)
	}
}

// What a seed consumer writes, and what an operator might make with openssl,
// both load to the same pin; a world-readable file is tightened to 0600.
func TestEnsureKey_AcceptsSeedLineAndPEM(t *testing.T) {
	signer, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	wantPin, err := proto.BusPinForPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	line, err := EncodeKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(line, "\n\r \"'$`\\") {
		t.Fatalf("the seed form contains a character a sourced sh file would mangle: %q", line)
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	for name, content := range map[string][]byte{
		"seed line, no newline": []byte(line),
		"seed line, CRLF":       []byte(line + "\r\n"),
		"PKCS#8 PEM":            pemBytes,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, KeyFileName)
			if err := os.WriteFile(path, content, 0o644); err != nil { // G306: the test is that EnsureKey tightens it
				t.Fatal(err)
			}
			k, generated, err := EnsureKey(dir)
			if err != nil {
				t.Fatalf("EnsureKey: %v", err)
			}
			if generated || k.Pin() != wantPin {
				t.Fatalf("generated=%t pin=%s, want loaded %s", generated, k.Pin(), wantPin)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("key file mode = %o after load, want 600", perm)
			}
		})
	}
}

func TestParseKey_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	line, err := EncodeKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseKey([]byte(line))
	if err != nil {
		t.Fatalf("ParseKey(ed25519): %v", err)
	}
	if _, ok := got.(ed25519.PrivateKey); !ok {
		t.Fatalf("ParseKey returned %T", got)
	}
}

// The certificate is a wrapper: its public key is the bus key, whatever dates
// it was made with.
func TestServerTLSConfig_WrapsTheKey(t *testing.T) {
	k, _, err := EnsureKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := k.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("%d certificates, want 1", len(cfg.Certificates))
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := proto.BusPinForSPKI(leaf.RawSubjectPublicKeyInfo); got != k.Pin() {
		t.Fatalf("certificate key pin %s, bus key pin %s", got, k.Pin())
	}
	if cfg.MinVersion == 0 {
		t.Error("no minimum TLS version")
	}
	future, err := SelfSignedCert(k.Signer(), time.Now().AddDate(50, 0, 0), time.Now().AddDate(51, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got := proto.BusPinForSPKI(future.Leaf.RawSubjectPublicKeyInfo); got != k.Pin() {
		t.Fatalf("a not-yet-valid wrapper has pin %s, want %s", got, k.Pin())
	}
}
