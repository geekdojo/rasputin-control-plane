package bmccert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
)

const goodName = "rasputin-bmc-0123456789ab.local"

// countingIssuer wraps an Issuer and counts the calls that reach it.
type countingIssuer struct {
	next  Issuer
	err   error
	calls int
}

func (c *countingIssuer) SignLeaf(spec tlsca.LeafSpec, pub crypto.PublicKey) ([]byte, error) {
	c.calls++
	if c.err != nil {
		return nil, c.err
	}
	return c.next.SignLeaf(spec, pub)
}

// logCapture is a JSON log written to a buffer, read back as records.
type logCapture struct{ buf bytes.Buffer }

func (l *logCapture) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(&l.buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func (l *logCapture) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(l.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

type fixture struct {
	ca     *tlsca.CA
	issuer *countingIssuer
	log    *logCapture
	signer *Signer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ca := tlscatest.Controlplane(t, "")
	f := &fixture{ca: ca, issuer: &countingIssuer{next: ca}, log: &logCapture{}}
	s, err := New(f.issuer, ca.Cert, ca.CertPEM, f.log.logger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.signer = s
	return f
}

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// makeCSR builds and parses a CSR over key from tmpl. The subject CN is
// "evil" unless tmpl sets one, so a test can see it never reaches the leaf.
func makeCSR(t *testing.T, key crypto.Signer, tmpl x509.CertificateRequest) (*x509.CertificateRequest, []byte) {
	t.Helper()
	if tmpl.Subject.CommonName == "" {
		tmpl.Subject = pkix.Name{CommonName: "evil"}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	return csr, der
}

func goodCSR(t *testing.T) (*x509.CertificateRequest, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	k := p256(t)
	csr, der := makeCSR(t, k, x509.CertificateRequest{DNSNames: []string{goodName}})
	return csr, k, der
}

func mustExt(t *testing.T, id asn1.ObjectIdentifier, v any) pkix.Extension {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: id, Critical: true, Value: b}
}

// TC-1065-05: a valid request is signed as a server leaf for its one name,
// over its own key, expiring with the CA; the request's subject is ignored.
// TC-1065-13: that signing writes exactly one INFO record, with no
// certificate material in any record.
func TestSign_HappyPathAndRecord(t *testing.T) {
	f := newFixture(t)
	csr, key, der := goodCSR(t)

	got, err := f.signer.Sign(context.Background(), "bryce", csr)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got.Name != goodName {
		t.Errorf("Name = %q, want %q", got.Name, goodName)
	}
	block, _ := pem.Decode(got.LeafPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("LeafPEM is not a PEM certificate: %q", got.LeafPEM)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != goodName {
		t.Errorf("CN = %q, want %q (the request's subject must be ignored)", leaf.Subject.CommonName, goodName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != goodName {
		t.Errorf("DNSNames = %v", leaf.DNSNames)
	}
	if len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) != 0 {
		t.Errorf("extra SANs: %v %v %v", leaf.IPAddresses, leaf.EmailAddresses, leaf.URIs)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage = %v", leaf.ExtKeyUsage)
	}
	if leaf.IsCA {
		t.Error("leaf is a CA")
	}
	if !key.PublicKey.Equal(leaf.PublicKey) {
		t.Error("leaf key is not the request's key")
	}
	if !leaf.NotAfter.Equal(f.ca.Cert.NotAfter) {
		t.Errorf("leaf NotAfter = %v, want the CA's %v", leaf.NotAfter, f.ca.Cert.NotAfter)
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: goodName, Roots: roots}); err != nil {
		t.Errorf("Verify: %v", err)
	}
	if !bytes.Equal(got.CAPEM, f.ca.CertPEM) {
		t.Error("CAPEM is not the CA's PEM")
	}
	if !got.NotAfter.Equal(f.ca.Cert.NotAfter) {
		t.Errorf("Signed.NotAfter = %v, want %v", got.NotAfter, f.ca.Cert.NotAfter)
	}

	// TC-1065-13
	recs := f.log.records(t)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1: %s", len(recs), f.log.buf.String())
	}
	r := recs[0]
	want := map[string]string{
		"level":  "INFO",
		"msg":    "bmc server leaf signed",
		"event":  "bmccert.signed",
		"name":   goodName,
		"serial": leaf.SerialNumber.Text(16),
		"user":   "bryce",
	}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("record %s = %v, want %q", k, r[k], v)
		}
	}
	if _, ok := r["not_after"]; !ok {
		t.Error("record has no not_after")
	}
	raw := f.log.buf.String()
	if strings.Contains(raw, "BEGIN") || strings.Contains(raw, base64.StdEncoding.EncodeToString(der)[:40]) {
		t.Errorf("log carries certificate material: %s", raw)
	}
}

// TC-1065-06: a request whose signature was altered is refused before the
// issuer is reached.
func TestSign_BadSignature(t *testing.T) {
	f := newFixture(t)
	csr, _, _ := goodCSR(t)
	sig := append([]byte(nil), csr.Signature...)
	sig[len(sig)-1] ^= 0xff
	csr.Signature = sig

	if _, err := f.signer.Sign(context.Background(), "bryce", csr); !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
	if f.issuer.calls != 0 {
		t.Errorf("issuer called %d times", f.issuer.calls)
	}
}

// TC-1065-07: a CA flag, a requested EKU or a keyUsage is refused.
func TestSign_ExtensionsRefused(t *testing.T) {
	f := newFixture(t)
	type basicConstraints struct {
		IsCA bool `asn1:"optional"`
	}
	cases := map[string]pkix.Extension{
		"basicConstraints CA:TRUE": mustExt(t, asn1.ObjectIdentifier{2, 5, 29, 19}, basicConstraints{IsCA: true}),
		"extKeyUsage clientAuth":   mustExt(t, asn1.ObjectIdentifier{2, 5, 29, 37}, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 2}}),
		"keyUsage":                 mustExt(t, asn1.ObjectIdentifier{2, 5, 29, 15}, asn1.BitString{Bytes: []byte{0x84}, BitLength: 6}),
	}
	for name, ext := range cases {
		t.Run(name, func(t *testing.T) {
			csr, _ := makeCSR(t, p256(t), x509.CertificateRequest{
				DNSNames:        []string{goodName},
				ExtraExtensions: []pkix.Extension{ext},
			})
			if _, err := f.signer.Sign(context.Background(), "bryce", csr); !errors.Is(err, ErrExtension) {
				t.Fatalf("err = %v, want ErrExtension", err)
			}
		})
	}
	if f.issuer.calls != 0 {
		t.Errorf("issuer called %d times", f.issuer.calls)
	}
}

// TC-1065-08: only an ECDSA P-256 key is accepted.
func TestSign_KeyType(t *testing.T) {
	f := newFixture(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]crypto.Signer{"RSA-2048": rsaKey, "P-384": p384} {
		t.Run(name, func(t *testing.T) {
			csr, _ := makeCSR(t, key, x509.CertificateRequest{DNSNames: []string{goodName}})
			if _, err := f.signer.Sign(context.Background(), "bryce", csr); !errors.Is(err, ErrKeyType) {
				t.Fatalf("err = %v, want ErrKeyType", err)
			}
		})
	}
	if f.issuer.calls != 0 {
		t.Errorf("issuer called %d times", f.issuer.calls)
	}
}

// TC-1065-09: the request names exactly one rasputin-bmc-<12 lowercase
// hex>.local host and nothing else.
func TestSign_NameRefused(t *testing.T) {
	f := newFixture(t)
	uri, _ := url.Parse("https://rasputin-bmc-0123456789ab.local/")
	cases := map[string]x509.CertificateRequest{
		"uppercase hex":  {DNSNames: []string{"rasputin-bmc-0123456789AB.local"}},
		"11 hex digits":  {DNSNames: []string{"rasputin-bmc-0123456789a.local"}},
		"13 hex digits":  {DNSNames: []string{"rasputin-bmc-0123456789abc.local"}},
		"another domain": {DNSNames: []string{"rasputin-bmc-0123456789ab.example.com"}},
		"no .local":      {DNSNames: []string{"rasputin-bmc-0123456789ab"}},
		"prefixed":       {DNSNames: []string{"xrasputin-bmc-0123456789ab.local"}},
		"trailing dot":   {DNSNames: []string{"rasputin-bmc-0123456789ab.local."}},
		"two DNS names":  {DNSNames: []string{goodName, "rasputin-bmc-0123456789ac.local"}},
		"plus an IP":     {DNSNames: []string{goodName}, IPAddresses: []net.IP{net.IPv4(192, 168, 1, 2)}},
		"plus an email":  {DNSNames: []string{goodName}, EmailAddresses: []string{"a@b.c"}},
		"plus a URI":     {DNSNames: []string{goodName}, URIs: []*url.URL{uri}},
		"no SAN":         {},
	}
	for name, tmpl := range cases {
		t.Run(name, func(t *testing.T) {
			csr, _ := makeCSR(t, p256(t), tmpl)
			if _, err := f.signer.Sign(context.Background(), "bryce", csr); !errors.Is(err, ErrName) {
				t.Fatalf("err = %v, want ErrName", err)
			}
		})
	}
	if f.issuer.calls != 0 {
		t.Errorf("issuer called %d times", f.issuer.calls)
	}
}

// TC-1065-10: an empty user is refused and nothing is signed.
func TestSign_NoUser(t *testing.T) {
	f := newFixture(t)
	csr, _, _ := goodCSR(t)
	if _, err := f.signer.Sign(context.Background(), "", csr); !errors.Is(err, ErrNoUser) {
		t.Fatalf("err = %v, want ErrNoUser", err)
	}
	if f.issuer.calls != 0 {
		t.Errorf("issuer called %d times", f.issuer.calls)
	}
}

// TC-1065-11: an issuer failure is returned wrapped, matches no policy
// sentinel, returns the zero Signed, and writes one ERROR record naming the
// request's name.
func TestSign_IssuerFailure(t *testing.T) {
	f := newFixture(t)
	errSentinel := errors.New("ca fault")
	f.issuer.err = errSentinel
	csr, _, _ := goodCSR(t)

	got, err := f.signer.Sign(context.Background(), "bryce", csr)
	if !errors.Is(err, errSentinel) {
		t.Fatalf("err = %v, want the issuer's error", err)
	}
	for _, s := range []error{ErrNoUser, ErrSignature, ErrKeyType, ErrExtension, ErrName} {
		if errors.Is(err, s) {
			t.Errorf("issuer error matches policy sentinel %v", s)
		}
	}
	if got.Name != "" || got.LeafPEM != nil || got.CAPEM != nil || !got.NotAfter.IsZero() {
		t.Errorf("Signed is not the zero value: %+v", got)
	}
	recs := f.log.records(t)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1: %s", len(recs), f.log.buf.String())
	}
	if recs[0]["level"] != "ERROR" || recs[0]["name"] != goodName {
		t.Errorf("record = %v, want one ERROR naming %s", recs[0], goodName)
	}
}

// TC-1065-11 (the issuer's own output): a leaf that does not read back is the
// same failure, logged at ERROR.
func TestSign_IssuerReturnsNoCertificate(t *testing.T) {
	ca := tlscatest.Controlplane(t, "")
	lc := &logCapture{}
	s, err := New(issuerFunc(func(tlsca.LeafSpec, crypto.PublicKey) ([]byte, error) { return []byte("junk"), nil }),
		ca.Cert, ca.CertPEM, lc.logger())
	if err != nil {
		t.Fatal(err)
	}
	csr, _, _ := goodCSR(t)
	if _, err := s.Sign(context.Background(), "bryce", csr); err == nil {
		t.Fatal("Sign accepted an unreadable leaf")
	}
	if recs := lc.records(t); len(recs) != 1 || recs[0]["level"] != "ERROR" {
		t.Errorf("records = %v, want one ERROR", recs)
	}
}

type issuerFunc func(tlsca.LeafSpec, crypto.PublicKey) ([]byte, error)

func (f issuerFunc) SignLeaf(s tlsca.LeafSpec, p crypto.PublicKey) ([]byte, error) { return f(s, p) }

// TC-1065-12: New refuses each missing collaborator.
func TestNew_RefusesMissingCollaborators(t *testing.T) {
	ca := tlscatest.Controlplane(t, "")
	log := slog.New(slog.DiscardHandler)
	cases := map[string]func() (*Signer, error){
		"nil issuer":  func() (*Signer, error) { return New(nil, ca.Cert, ca.CertPEM, log) },
		"nil caCert":  func() (*Signer, error) { return New(ca, nil, ca.CertPEM, log) },
		"empty caPEM": func() (*Signer, error) { return New(ca, ca.Cert, nil, log) },
		"nil logger":  func() (*Signer, error) { return New(ca, ca.Cert, ca.CertPEM, nil) },
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := build()
			if err == nil {
				t.Error("New accepted it")
			}
			if s != nil {
				t.Error("New returned a Signer with its error")
			}
		})
	}
}
