package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/bmccert"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

const (
	bmcCSRPath = "/api/bmc/csr"
	bmcCSRName = "rasputin-bmc-0123456789ab.local"
)

// fakeBMCSigner counts calls and returns err.
type fakeBMCSigner struct {
	err   error
	calls int
}

func (f *fakeBMCSigner) Sign(context.Context, string, *x509.CertificateRequest) (bmccert.Signed, error) {
	f.calls++
	return bmccert.Signed{}, f.err
}

// csrPEM is a Go-made P-256 certificate request naming names.
func csrPEM(t *testing.T, names ...string) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "evil"}, DNSNames: names,
	}, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func csrBody(t *testing.T, pemText string) string {
	t.Helper()
	b, err := json.Marshal(bmcCSRRequest{CSR: pemText})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// bmcCSRServer is the fixture's server rebuilt around signer, with its own
// log recorder.
func bmcCSRServer(t *testing.T, f *apiFixture, signer bmcCSRSigner) (func(body string, c *http.Cookie) *httptest.ResponseRecorder, *logkittest.Recorder) {
	t.Helper()
	log, rec := logkittest.New()
	srv, err := NewServer(f.jobsStore, f.runner, f.inv, inventory.NewService(f.inv, f.nc, slog.New(slog.DiscardHandler)),
		f.fw, f.fwSvc, f.appsStore, f.metricsStore, f.updStore, f.verifier, f.bundleDir, f.srv.trustDir,
		f.mesh, f.bmcSvc, f.setupSvc, f.authSvc, nil, f.srv.busTokens, f.nc,
		f.srv.bus, f.srv.operatorSecrets, f.srv.nodeApps, signer, log, sequentialIDs())
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	return func(body string, c *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, bmcCSRPath, strings.NewReader(body))
		if c != nil {
			req.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}, rec
}

// TC-1065-14: a signed-in operator posts a valid request and gets the leaf,
// the CA and the expiry, through the real signer over a real CA.
func TestBMCSignCSR_Success(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, bmcCSRPath, csrBody(t, csrPEM(t, bmcCSRName)), c)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 4 {
		t.Errorf("body keys = %v, want name, leafPem, caPem, notAfter", raw)
	}
	var got bmcCSRResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != bmcCSRName {
		t.Errorf("name = %q", got.Name)
	}
	block, _ := pem.Decode([]byte(got.LeafPEM))
	if block == nil {
		t.Fatalf("leafPem is not PEM: %q", got.LeafPEM)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != bmcCSRName || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != bmcCSRName {
		t.Errorf("leaf CN %q, SANs %v", leaf.Subject.CommonName, leaf.DNSNames)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("EKU = %v", leaf.ExtKeyUsage)
	}
	if got.CAPEM != string(f.bmcCA.CertPEM) {
		t.Error("caPem is not the CA's PEM")
	}
	wantNotAfter, _ := json.Marshal(f.bmcCA.Cert.NotAfter)
	if string(raw["notAfter"]) != string(wantNotAfter) {
		t.Errorf("notAfter = %s, want %s", raw["notAfter"], wantNotAfter)
	}
}

// TC-1065-15: a body that is not one parseable PEM certificate request is
// refused at the endpoint, coded, logged without the PEM, and never reaches
// the signer.
func TestBMCSignCSR_MalformedInput(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	signer := &fakeBMCSigner{}
	do, rec := bmcCSRServer(t, f, signer)
	good := csrPEM(t, bmcCSRName)
	garbage := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("not DER")}))
	cases := map[string]string{
		"not JSON":              "csr=" + good,
		"empty object":          `{}`,
		"empty csr":             `{"csr":""}`,
		"CERTIFICATE block":     csrBody(t, strings.ReplaceAll(good, "CERTIFICATE REQUEST", "CERTIFICATE")),
		"two request blocks":    csrBody(t, good+good),
		"garbage DER":           csrBody(t, garbage),
		"body over 8 KiB bound": csrBody(t, good+strings.Repeat(" ", bmcCSRMaxBody)),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			before := len(rec.Records())
			w := do(body, c)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status %d, body %s", w.Code, w.Body)
			}
			ce := decodeCoded(t, w.Body.Bytes())
			if ce.Code != codeBMCCSRInvalid || ce.Error != msgBMCCSRInvalid || ce.CorrelationID == "" {
				t.Errorf("body = %+v", ce)
			}
			recs := rec.Records()[before:]
			if len(recs) != 1 || recs[0].Level != slog.LevelWarn || recs[0].Message != "api: request refused" {
				t.Fatalf("records = %v, want one WARN api: request refused", recs)
			}
			for k, v := range map[string]string{"route": "POST " + bmcCSRPath, "code": codeBMCCSRInvalid, "correlation_id": ce.CorrelationID} {
				if got, _ := logkittest.Attr(recs[0], k); got != v {
					t.Errorf("record %s = %q, want %q", k, got, v)
				}
			}
		})
	}
	if signer.calls != 0 {
		t.Errorf("signer called %d times", signer.calls)
	}
	if strings.Contains(rec.Text(), "BEGIN") {
		t.Errorf("a record carries PEM text:\n%s", rec.Text())
	}
}

// TC-1065-16: each policy refusal maps to its status, code and sentence; a
// signing failure is a 500 that does not echo the internal error.
func TestBMCSignCSR_RefusalsMapToCodedResponses(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	signer := &fakeBMCSigner{}
	do, _ := bmcCSRServer(t, f, signer)
	body := csrBody(t, csrPEM(t, bmcCSRName))
	const internal = "rand reader exploded"
	cases := []struct {
		err    error
		status int
		code   string
		msg    string
	}{
		{fmt.Errorf("wrapped: %w", bmccert.ErrSignature), http.StatusBadRequest, codeBMCCSRRefused, msgBMCCSRSignature},
		{fmt.Errorf("wrapped: %w", bmccert.ErrKeyType), http.StatusBadRequest, codeBMCCSRRefused, msgBMCCSRKeyType},
		{fmt.Errorf("wrapped: %w", bmccert.ErrExtension), http.StatusBadRequest, codeBMCCSRRefused, msgBMCCSRExtension},
		{fmt.Errorf("wrapped: %w", bmccert.ErrName), http.StatusBadRequest, codeBMCCSRRefused, msgBMCCSRName},
		{fmt.Errorf("wrapped: %w", bmccert.ErrNoUser), http.StatusForbidden, codeBMCCSRRefused, msgBMCCSRNoUser},
		{errors.New(internal), http.StatusInternalServerError, codeBMCCSRSignFailed, "The control plane could not sign the certificate request."},
	}
	for _, tc := range cases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			signer.err = tc.err
			w := do(body, c)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
			ce := decodeCoded(t, w.Body.Bytes())
			if ce.Code != tc.code || ce.Error != tc.msg {
				t.Errorf("body = %+v, want %s %q", ce, tc.code, tc.msg)
			}
			if strings.Contains(w.Body.String(), internal) {
				t.Errorf("body carries the internal error: %s", w.Body)
			}
		})
	}

	// The real signer refuses a name outside the BMC pattern with ErrName's
	// sentence.
	w := f.do(t, http.MethodPost, bmcCSRPath, csrBody(t, csrPEM(t, "host.example.com")), c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("real signer: status %d, body %s", w.Code, w.Body)
	}
	if ce := decodeCoded(t, w.Body.Bytes()); ce.Code != codeBMCCSRRefused || ce.Error != msgBMCCSRName {
		t.Errorf("real signer: body = %+v", ce)
	}
}
