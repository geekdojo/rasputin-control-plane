package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// ============================================================================
// Bundle upload — round-trip through verifier + GET-by-sha
// ============================================================================

// artifactFixture is the artifact / detached-signature / trust-root triple the
// bundle routes now take. It is the CMS pair artifactsig's fixtures hold —
// produced by a verbatim copy of the release pipeline's own `openssl cms
// -sign` command — rather than anything invented here, because a verifier
// proven against signatures the test made up proves nothing about the ones the
// pipeline emits.
type artifactFixture struct {
	artifact []byte
	sig      []byte
	sha      string
}

func artifactsigFixture(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "artifactsig", "testdata", name)
}

// buildBundleFixture installs the fixture root CA under f.dir, re-inits the
// server's verifier so trust is ENFORCED, and returns the artifact bytes plus
// their sha256. Callers that also need the detached signature use
// buildSignedArtifactFixture.
func buildBundleFixture(t *testing.T, f *apiFixture) ([]byte, string) {
	af := buildSignedArtifactFixture(t, f)
	return af.artifact, af.sha
}

func buildSignedArtifactFixture(t *testing.T, f *apiFixture) artifactFixture {
	t.Helper()
	rootPEM, err := os.ReadFile(artifactsigFixture(t, "root-ca.pem"))
	if err != nil {
		t.Fatalf("read fixture root CA: %v", err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "root-ca.pem"), rootPEM, 0o600); err != nil {
		t.Fatalf("write root: %v", err)
	}
	v := updater.NewVerifier(f.dir)
	if !v.TrustConfigured() {
		t.Fatalf("fixture root CA did not load from %s", f.dir)
	}
	f.srv.updaterVerifier = v

	artifact, err := os.ReadFile(artifactsigFixture(t, "payload.bin"))
	if err != nil {
		t.Fatalf("read fixture artifact: %v", err)
	}
	sig, err := os.ReadFile(artifactsigFixture(t, "payload.bin.sig"))
	if err != nil {
		t.Fatalf("read fixture signature: %v", err)
	}
	sum := sha256.Sum256(artifact)
	return artifactFixture{artifact: artifact, sig: sig, sha: hex.EncodeToString(sum[:])}
}

// uploadBody builds the multipart body POST /api/bundles takes, in the order
// the route requires: signature first, artifact last.
func uploadBody(t *testing.T, sig, artifact []byte, fields map[string]string) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if sig != nil {
		part, err := mw.CreateFormFile("signature", "artifact.sig")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(sig); err != nil {
			t.Fatal(err)
		}
	}
	for k, val := range fields {
		if err := mw.WriteField(k, val); err != nil {
			t.Fatal(err)
		}
	}
	if artifact != nil {
		part, err := mw.CreateFormFile("artifact", "artifact")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(artifact); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, mw.FormDataContentType()
}

func defaultUploadFields() map[string]string {
	return map[string]string{
		"version": "test-1.0", "architecture": "arm64", "compatible": "rasputin-rpi-arm64",
	}
}

// uploadArtifact POSTs the multipart upload and returns the recorder.
func uploadArtifact(t *testing.T, f *apiFixture, c *http.Cookie,
	sig, artifact []byte, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, contentType := uploadBody(t, sig, artifact, fields)
	req := httptest.NewRequest(http.MethodPost, "/api/bundles", body)
	req.Header.Set("Content-Type", contentType)
	if c != nil {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	return w
}

func TestHandleUploadAndGetBundle_RoundTrip(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	af := buildSignedArtifactFixture(t, f)

	if err := os.MkdirAll(f.bundleDir, 0o755); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}

	w := uploadArtifact(t, f, c, af.sig, af.artifact, defaultUploadFields())
	if w.Code != http.StatusCreated {
		t.Fatalf("upload want 201, got %d body=%s", w.Code, w.Body.String())
	}
	// SignedBy is the VERIFIED leaf's CN, not a string the upload supplied.
	if body := w.Body.String(); !strings.Contains(body, "Rasputin Test Release Leaf") {
		t.Errorf("the stored bundle must be attributed to the verified signer; got %s", body)
	}

	// The detached signature is staged beside the blob, which is where the
	// agent fetches it from before it moves the artifact.
	ws := f.do(t, http.MethodGet, "/api/bundles/"+af.sha+"/sig", "", nil)
	if ws.Code != http.StatusOK {
		t.Errorf("get sig want 200, got %d body=%s", ws.Code, ws.Body.String())
	}
	if !bytes.Equal(ws.Body.Bytes(), af.sig) {
		t.Error("the served signature is not the one that was uploaded")
	}

	// Duplicate upload → 409.
	w2 := uploadArtifact(t, f, c, af.sig, af.artifact, defaultUploadFields())
	if w2.Code != http.StatusConflict {
		t.Errorf("dup upload want 409, got %d body=%s", w2.Code, w2.Body.String())
	}

	// List: bundle now present.
	w3 := f.do(t, http.MethodGet, "/api/bundles", "", c)
	if w3.Code != http.StatusOK {
		t.Errorf("list want 200, got %d", w3.Code)
	}
	if !strings.Contains(w3.Body.String(), af.sha) {
		t.Errorf("list missing sha; body=%s", w3.Body.String())
	}

	// GET bytes (open endpoint).
	wb := f.do(t, http.MethodGet, "/api/bundles/"+af.sha, "", nil)
	if wb.Code != http.StatusOK {
		t.Errorf("get bytes want 200, got %d", wb.Code)
	}

	// Delete: 204.
	wd := f.do(t, http.MethodDelete, "/api/bundles/"+af.sha, "", c)
	if wd.Code != http.StatusNoContent {
		t.Errorf("delete want 204, got %d", wd.Code)
	}
}

// THE GATE. A real artifact and a real, well-formed signature — over DIFFERENT
// bytes. Chain-to-root passes; the content binding does not. This is the case
// the retired envelope could not even express, because its signature travelled
// inside the thing it signed.
func TestHandleUploadBundle_SignatureOverOtherBytesIsRefused(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	af := buildSignedArtifactFixture(t, f)

	tampered := slices.Clone(af.artifact)
	tampered[len(tampered)/2] ^= 0xFF

	w := uploadArtifact(t, f, c, af.sig, tampered, defaultUploadFields())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
	sum := sha256.Sum256(tampered)
	if g := f.do(t, http.MethodGet, "/api/bundles/"+hex.EncodeToString(sum[:]), "", nil); g.Code == http.StatusOK {
		t.Error("an artifact whose signature does not cover it must not be stored")
	}
}

// THE PURPOSE SPLIT at the HTTP boundary: a catalog-signed bundle is a valid
// signature under the same root, and the update route must still refuse it.
func TestHandleUploadBundle_CatalogPurposeSignatureIsRefused(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	af := buildSignedArtifactFixture(t, f)
	catalogSig, err := os.ReadFile(artifactsigFixture(t, "payload.bin.catalog.sig"))
	if err != nil {
		t.Fatal(err)
	}

	w := uploadArtifact(t, f, c, catalogSig, af.artifact, defaultUploadFields())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
	if g := f.do(t, http.MethodGet, "/api/bundles/"+af.sha, "", nil); g.Code == http.StatusOK {
		t.Error("an artifact signed by a catalog leaf must not be stored as an OS update")
	}
}

// Each required part named on its own, because "400" on a six-part form tells
// an operator nothing about which one they left out.
func TestHandleUploadBundle_MissingPartsAreNamed(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	af := buildSignedArtifactFixture(t, f)

	fieldsWithout := func(drop string) map[string]string {
		m := defaultUploadFields()
		delete(m, drop)
		return m
	}
	for _, tc := range []struct {
		name   string
		sig    []byte
		fields map[string]string
		want   string
	}{
		{"no signature", nil, defaultUploadFields(), "`signature` part"},
		{"no version", af.sig, fieldsWithout("version"), "`version` field"},
		{"no architecture", af.sig, fieldsWithout("architecture"), "`architecture` field"},
		{"no compatible", af.sig, fieldsWithout("compatible"), "`compatible` field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := uploadArtifact(t, f, c, tc.sig, af.artifact, tc.fields)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.want) {
				t.Errorf("the refusal must name %s; got %s", tc.want, w.Body.String())
			}
		})
	}
}

// The retired format must not still be accepted by the route that used to take
// it. A raspbundle envelope is now just a JSON file with no detached
// signature, and the api refuses it as such rather than parsing it.
func TestHandleUploadBundle_RaspbundleEnvelopeIsNoLongerAccepted(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	buildSignedArtifactFixture(t, f) // trust enforced

	envelope := []byte(`{"manifest":{"version":"1.0"},"payload":"00","signature":"00","certPem":""}`)
	req := httptest.NewRequest(http.MethodPost, "/api/bundles", bytes.NewReader(envelope))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(envelope))
	req.AddCookie(c)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "multipart/form-data") {
		t.Errorf("the refusal must say what the route takes now; got %s", w.Body.String())
	}
}

func TestHandleUploadBundle_VerificationFails(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	af := buildSignedArtifactFixture(t, f) // installs a real root CA, so trust is enforced
	// Garbage where the detached signature should be, WITH trust configured:
	// rejected on its own merits as a bad artifact (400), not because the api
	// cannot verify anything.
	w := uploadArtifact(t, f, c, []byte("not a CMS object"), af.artifact, defaultUploadFields())
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
}

// The fail-closed contract at the HTTP boundary. The fixture has no root CA,
// which is exactly the state a box is in before scripts/pki-init.sh has run or
// after root-ca.pem goes missing — and the pair below is perfectly valid. A
// well-formed bundle used to be ingested and stored, SignedBy "<unverified>",
// and was then installable on every node in the fleet.
func TestHandleUploadBundle_NoTrustRootRefusesAndStoresNothing(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)

	// Build a valid pair, then take the api's trust root back away so the
	// upload meets an unavailable verifier.
	af := buildSignedArtifactFixture(t, f)
	if err := os.Remove(filepath.Join(f.dir, "root-ca.pem")); err != nil {
		t.Fatalf("remove root: %v", err)
	}
	f.srv.updaterVerifier = updater.NewVerifier(f.dir)

	w := uploadArtifact(t, f, c, af.sig, af.artifact, defaultUploadFields())

	// 503, not 400: the artifact is fine, the api's trust root is missing.
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("want 503, got %d body=%s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "root-ca.pem") {
		t.Errorf("the refusal must name the missing trust root; got %s", body)
	}
	// And nothing was persisted — a refused bundle must not be stageable.
	if g := f.do(t, http.MethodGet, "/api/bundles/"+af.sha, "", nil); g.Code == http.StatusOK {
		t.Error("a bundle refused for want of a trust root must not be stored")
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

// ============================================================================
// firewall.dns_forward is re-run by facts, not a timer (#431)
// ============================================================================

// registerDNSForwardStub gives the fixture runner a no-op firewall.dns_forward
// so submissions persist as jobs the test can count.
func registerDNSForwardStub(f *apiFixture) {
	f.runner.Register(jobs.Workflow{Kind: "firewall.dns_forward", Steps: []jobs.WorkflowStep{{
		Name: "noop", Timeout: time.Second,
		Do: func(*jobs.StepCtx) (json.RawMessage, error) { return nil, nil },
	}}})
}

func dnsForwardJobs(t *testing.T, f *apiFixture) []string {
	t.Helper()
	js, err := f.jobsStore.ListJobsByKind(f.ctx, "firewall.dns_forward", 100)
	if err != nil {
		t.Fatal(err)
	}
	var by []string
	for _, j := range js {
		by = append(by, j.CreatedBy)
	}
	return by
}

func TestHandleSetupMode_SubmitsDNSForward(t *testing.T) {
	f := newAPIFixture(t)
	registerDNSForwardStub(f)
	c := f.authenticate(t)
	if w := f.do(t, http.MethodPost, "/api/setup/mode", `{"mode":"lan_peer"}`, c); w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	if got := dnsForwardJobs(t, f); len(got) != 1 || got[0] != "setup-mode-change" {
		t.Fatalf("dns_forward jobs = %v, want one from the mode change", got)
	}
	// A rejected mode write changes nothing, so it re-runs nothing.
	f.do(t, http.MethodPost, "/api/setup/mode", `{"mode":"nope"}`, c)
	if got := dnsForwardJobs(t, f); len(got) != 1 {
		t.Fatalf("dns_forward jobs after a rejected mode = %v, want still one", got)
	}
}

func TestHandleIntent_DNSForwardEditOrDeleteResubmits(t *testing.T) {
	f := newAPIFixture(t)
	registerDNSForwardStub(f)
	c := f.authenticate(t)
	now := time.Now().UTC()
	for _, in := range []*firewall.Intent{
		{ID: "fwd", Kind: string(proto.IntentDNSForward), Name: "DNS-Forward-Internal", Enabled: true,
			Spec: json.RawMessage(`{"zone":"test1.internal","target":"192.168.1.2"}`), CreatedAt: now, UpdatedAt: now},
		{ID: "pf", Kind: string(proto.IntentPortForward), Name: "pf", Enabled: true,
			Spec: json.RawMessage(`{"wanPort":80,"lanPort":80,"lanHost":"h","protocol":"tcp"}`), CreatedAt: now, UpdatedAt: now},
	} {
		if err := f.fw.CreateIntent(f.ctx, in); err != nil {
			t.Fatal(err)
		}
	}

	// Operator intents never trigger it.
	f.do(t, http.MethodPatch, "/api/firewall/intents/pf", `{"enabled":false}`, c)
	f.do(t, http.MethodDelete, "/api/firewall/intents/pf", "", c)
	if got := dnsForwardJobs(t, f); len(got) != 0 {
		t.Fatalf("operator intent edits submitted dns_forward: %v", got)
	}

	if w := f.do(t, http.MethodPatch, "/api/firewall/intents/fwd", `{"enabled":false}`, c); w.Code != http.StatusOK {
		t.Fatalf("patch forward: %d %s", w.Code, w.Body.String())
	}
	if w := f.do(t, http.MethodDelete, "/api/firewall/intents/fwd", "", c); w.Code != http.StatusNoContent {
		t.Fatalf("delete forward: %d %s", w.Code, w.Body.String())
	}
	got := dnsForwardJobs(t, f)
	slices.Sort(got)
	if !slices.Equal(got, []string{"dns-forward-deleted", "dns-forward-edited"}) {
		t.Fatalf("dns_forward jobs = %v, want one per edit and delete of the forward", got)
	}
}
