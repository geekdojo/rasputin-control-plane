package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// ============================================================================
// Bundle upload — round-trip through verifier + GET-by-sha
// ============================================================================

// buildBundleFixture sets up the verifier with a fresh root CA stashed under
// the api fixture dir and returns the bundle bytes + expected sha.
func buildBundleFixture(t *testing.T, f *apiFixture) ([]byte, string) {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen root: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TestRoot"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "TestSigner"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	leafCert, _ := x509.ParseCertificate(leafDER)
	_ = leafCert
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	// Overwrite the verifier dir with a real root CA.
	if err := os.WriteFile(filepath.Join(f.dir, "root-ca.pem"), rootPEM, 0o600); err != nil {
		t.Fatalf("write root: %v", err)
	}
	// Re-init the verifier on the server.
	v, err := updater.NewVerifier(f.dir)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	f.srv.updaterVerifier = v

	manifest := proto.BundleManifest{
		Version: "test-1.0", Compatible: "rasputin-pi5-cm5", Architecture: "arm64",
	}
	payload := []byte("hello payload")
	hashed := sha256.Sum256(payload)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, leafKey, crypto.SHA256, hashed[:])

	env := map[string]any{
		"manifest":  manifest,
		"payload":   hex.EncodeToString(payload),
		"signature": hex.EncodeToString(sig),
		"certPem":   string(leafPEM),
	}
	buf, _ := json.Marshal(env)
	sum := sha256.Sum256(buf)
	return buf, hex.EncodeToString(sum[:])
}

func TestHandleUploadAndGetBundle_RoundTrip(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	buf, sha := buildBundleFixture(t, f)

	if err := os.MkdirAll(f.bundleDir, 0o755); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}

	// Upload via raw body.
	req := httptest.NewRequest(http.MethodPost, "/api/bundles", strings.NewReader(string(buf)))
	req.ContentLength = int64(len(buf))
	req.AddCookie(c)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("upload want 201, got %d body=%s", w.Code, w.Body.String())
	}

	// Duplicate upload → 409.
	req2 := httptest.NewRequest(http.MethodPost, "/api/bundles", strings.NewReader(string(buf)))
	req2.ContentLength = int64(len(buf))
	req2.AddCookie(c)
	w2 := httptest.NewRecorder()
	f.handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Errorf("dup upload want 409, got %d", w2.Code)
	}

	// List: bundle now present.
	w3 := f.do(t, http.MethodGet, "/api/bundles", "", c)
	if w3.Code != http.StatusOK {
		t.Errorf("list want 200, got %d", w3.Code)
	}
	if !strings.Contains(w3.Body.String(), sha) {
		t.Errorf("list missing sha; body=%s", w3.Body.String())
	}

	// GET bytes (open endpoint).
	wb := f.do(t, http.MethodGet, "/api/bundles/"+sha, "", nil)
	if wb.Code != http.StatusOK {
		t.Errorf("get bytes want 200, got %d", wb.Code)
	}

	// Delete: 204.
	wd := f.do(t, http.MethodDelete, "/api/bundles/"+sha, "", c)
	if wd.Code != http.StatusNoContent {
		t.Errorf("delete want 204, got %d", wd.Code)
	}
}

func TestHandleUploadBundle_VerificationFails(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	// Garbage body: still gets accepted by verifier in dev-permissive mode
	// (no root pem set), so this test only verifies the "looks like JSON"
	// branch when it's NOT a real bundle.
	buf := []byte(`{not a valid envelope`)
	req := httptest.NewRequest(http.MethodPost, "/api/bundles", strings.NewReader(string(buf)))
	req.ContentLength = int64(len(buf))
	req.AddCookie(c)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
}

// ============================================================================
// PATCH intent: update Name, Enabled, and Spec
// ============================================================================

func TestHandleUpdateIntent_PatchesFields(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	// Seed an intent directly.
	now := time.Now().UTC()
	intent := &firewall.Intent{
		ID:        "i1",
		Kind:      string(proto.IntentPortForward),
		Name:      "old",
		Enabled:   true,
		Spec:      json.RawMessage(`{"wanPort":80,"lanPort":80,"lanHost":"h","protocol":"tcp"}`),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := f.fw.CreateIntent(f.ctx, intent); err != nil {
		t.Fatalf("CreateIntent: %v", err)
	}

	body := `{"name":"new","enabled":false,"spec":{"wanPort":81,"lanPort":81,"lanHost":"h","protocol":"tcp"}}`
	w := f.do(t, http.MethodPatch, "/api/firewall/intents/i1", body, c)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	got, _ := f.fw.GetIntent(f.ctx, "i1")
	if got.Name != "new" || got.Enabled != false {
		t.Errorf("patch did not stick: %+v", got)
	}
}

func TestHandleUpdateIntent_BadSpec(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	now := time.Now().UTC()
	intent := &firewall.Intent{
		ID: "i1", Kind: string(proto.IntentPortForward), Name: "x", Enabled: true,
		Spec:      json.RawMessage(`{"wanPort":80,"lanPort":80,"lanHost":"h","protocol":"tcp"}`),
		CreatedAt: now, UpdatedAt: now,
	}
	_ = f.fw.CreateIntent(f.ctx, intent)

	body := `{"spec":{"wanPort":0,"lanPort":1,"lanHost":"h"}}`
	w := f.do(t, http.MethodPatch, "/api/firewall/intents/i1", body, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleUpdateIntent_BadJSON(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	now := time.Now().UTC()
	intent := &firewall.Intent{
		ID: "i1", Kind: string(proto.IntentPortForward), Name: "x", Enabled: true,
		Spec:      json.RawMessage(`{"wanPort":80,"lanPort":80,"lanHost":"h","protocol":"tcp"}`),
		CreatedAt: now, UpdatedAt: now,
	}
	_ = f.fw.CreateIntent(f.ctx, intent)
	w := f.do(t, http.MethodPatch, "/api/firewall/intents/i1", "{bad", c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// ============================================================================
// handleGetFirewallState with a firewall node present
// ============================================================================

func TestHandleGetFirewallState_WithFirewallNode(t *testing.T) {
	f := newAPIFixture(t)
	_ = f.inv.Insert(f.ctx, &proto.Node{
		ID: "fw-1", Role: proto.RoleFirewall, Hostname: "fw",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	})
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/firewall/state", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var got []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if len(got) != 1 {
		t.Errorf("want 1 firewall state, got %d", len(got))
	}
}

// ============================================================================
// publishMeshKeyCreated direct test
// ============================================================================

func TestPublishMeshKeyCreated_Direct(t *testing.T) {
	f := newAPIFixture(t)
	sub, err := f.nc.SubscribeSync(proto.MeshChangeSubject("global", proto.MeshKeyCreated))
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()
	publishMeshKeyCreated(f.srv, "intent-1", "hsid-1")
	if _, err := sub.NextMsg(time.Second); err != nil {
		t.Errorf("publish didn't land: %v", err)
	}
}

// ============================================================================
// withCORS specifically for non-OPTIONS that returns the configured headers.
// ============================================================================

func TestCORS_NonOptionsSetsHeaders(t *testing.T) {
	f := newAPIFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("ACAC: %q", got)
	}
}
