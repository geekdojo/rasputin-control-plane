package mesh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"math/big"
	"strings"
	"testing"
	"time"
)

// freshSelfSignedCertPEM generates an in-memory self-signed CA cert so the
// test doesn't depend on any fixtures on disk. ECDSA-P256 keeps it fast.
func freshSelfSignedCertPEM(t *testing.T, commonName string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Rasputin"}},
		NotBefore:             time.Now().Add(-time.Hour).UTC(),
		NotAfter:              time.Now().Add(24 * time.Hour).UTC(),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestBuildIOSMobileConfig_RejectsNonCertInput(t *testing.T) {
	if _, err := BuildIOSMobileConfig(nil, "", ""); err == nil {
		t.Error("nil PEM should fail")
	}
	if _, err := BuildIOSMobileConfig([]byte("garbage"), "", ""); err == nil {
		t.Error("non-PEM input should fail")
	}
	// A PEM block of the wrong type (e.g. PRIVATE KEY) must be rejected.
	otherPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	if _, err := BuildIOSMobileConfig(otherPEM, "", ""); err == nil {
		t.Error("wrong PEM block type should fail")
	}
}

func TestBuildIOSMobileConfig_ProducesValidXML(t *testing.T) {
	certPEM := freshSelfSignedCertPEM(t, "Rasputin Test CA")
	body, err := BuildIOSMobileConfig(certPEM, "", "")
	if err != nil {
		t.Fatalf("BuildIOSMobileConfig: %v", err)
	}
	// Decoder parses the doc to confirm the XML is well-formed; we don't
	// validate against the plist schema (out of scope), but unparseable
	// XML would mean iOS rejects the profile.
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	for {
		_, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("invalid XML: %v", err)
		}
	}
	// Check the load-bearing strings appear.
	for _, want := range []string{
		`<key>PayloadType</key>`,
		`<string>com.apple.security.root</string>`,
		`<string>com.geekdojo.rasputin.trust</string>`,
		`<key>PayloadCertificateFileName</key>`,
		`<string>rasputin-ca.crt</string>`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestBuildIOSMobileConfig_RoundTripsCertBytes(t *testing.T) {
	certPEM := freshSelfSignedCertPEM(t, "Rasputin Round Trip")
	block, _ := pem.Decode(certPEM)
	origDER := block.Bytes

	body, err := BuildIOSMobileConfig(certPEM, "", "")
	if err != nil {
		t.Fatalf("BuildIOSMobileConfig: %v", err)
	}
	// Extract the base64 inside the <data>…</data> tag.
	const (
		start = "<data>"
		end   = "</data>"
	)
	i := strings.Index(string(body), start)
	j := strings.Index(string(body), end)
	if i < 0 || j < 0 || i >= j {
		t.Fatal("could not locate <data> body")
	}
	rawB64 := strings.Join(strings.Fields(string(body)[i+len(start):j]), "")
	der, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if string(der) != string(origDER) {
		t.Errorf("DER round-trip mismatch: got %d bytes, want %d", len(der), len(origDER))
	}
}

func TestBuildIOSMobileConfig_DeterministicUUIDs(t *testing.T) {
	certPEM := freshSelfSignedCertPEM(t, "Rasputin UUID Stability")
	a, err := BuildIOSMobileConfig(certPEM, "", "")
	if err != nil {
		t.Fatalf("BuildIOSMobileConfig a: %v", err)
	}
	b, err := BuildIOSMobileConfig(certPEM, "", "")
	if err != nil {
		t.Fatalf("BuildIOSMobileConfig b: %v", err)
	}
	if string(a) != string(b) {
		t.Error("two builds of the same cert should produce identical output (stable UUIDs)")
	}
	// And different cert → different output.
	other := freshSelfSignedCertPEM(t, "Rasputin Other")
	c, err := BuildIOSMobileConfig(other, "", "")
	if err != nil {
		t.Fatalf("BuildIOSMobileConfig other: %v", err)
	}
	if string(c) == string(a) {
		t.Error("different cert should produce different output")
	}
}

func TestBuildIOSMobileConfig_HonorsDisplayNameOverrides(t *testing.T) {
	certPEM := freshSelfSignedCertPEM(t, "x")
	body, err := BuildIOSMobileConfig(certPEM, "Casa Rasputin", "Geekdojo")
	if err != nil {
		t.Fatalf("BuildIOSMobileConfig: %v", err)
	}
	if !strings.Contains(string(body), "Casa Rasputin") {
		t.Error("display name override not present")
	}
	if !strings.Contains(string(body), "Geekdojo") {
		t.Error("organization override not present")
	}
}

func TestBuildIOSMobileConfig_EscapesAmpersand(t *testing.T) {
	certPEM := freshSelfSignedCertPEM(t, "x")
	body, err := BuildIOSMobileConfig(certPEM, "Tom & Jerry", "")
	if err != nil {
		t.Fatalf("BuildIOSMobileConfig: %v", err)
	}
	if strings.Contains(string(body), "Tom & Jerry") {
		t.Error("ampersand should be XML-escaped to &amp;")
	}
	if !strings.Contains(string(body), "Tom &amp; Jerry") {
		t.Error("escaped ampersand not present")
	}
}

func TestStableUUID_Format(t *testing.T) {
	id := stableUUID([]byte("p:"), []byte("x"))
	// RFC 4122 layout: 8-4-4-4-12 hex digits with dashes.
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Fatalf("uuid layout: got %d parts, want 5: %q", len(parts), id)
	}
	wantLens := []int{8, 4, 4, 4, 12}
	for i, p := range parts {
		if len(p) != wantLens[i] {
			t.Errorf("uuid part %d length: got %d want %d", i, len(p), wantLens[i])
		}
	}
	// Stable across calls.
	if stableUUID([]byte("p:"), []byte("x")) != id {
		t.Error("stableUUID should be deterministic")
	}
}
