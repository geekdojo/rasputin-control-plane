package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The api serves /api/bundles/{sha} over its Mesh-CA HTTPS leaf, which the
// system roots don't cover. Download must trust the configured CA bundle, or
// every real update stalls at the download step with a TLS "bad certificate"
// — the bug that wedged the first control-plane self-update on hardware
// (agent rejected the api's mesh-CA cert because its client used system roots
// only). Mock-backend tests never caught it since they don't do real TLS.
func TestRAUCBackend_Download_TrustsMeshCA(t *testing.T) {
	body := []byte("pretend-raucb-bytes")
	sum := sha256.Sum256(body)
	wantSHA := hex.EncodeToString(sum[:])

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	// Write the server's self-signed cert as the CA the client should trust —
	// stands in for the per-installation Mesh CA at tailscale.CABundlePath().
	caPath := filepath.Join(t.TempDir(), "mesh-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	newBackend := func() *RAUCBackend {
		b, err := newRAUCBackend(t.TempDir(), "/bin/true")
		if err != nil {
			t.Fatalf("newRAUCBackend: %v", err)
		}
		return b
	}
	url := srv.URL + "/api/bundles/" + wantSHA

	// Without the CA: system roots don't cover the server cert → TLS failure,
	// not a silent success.
	b := newBackend()
	if _, _, err := b.Download(context.Background(), "b1", url, wantSHA, int64(len(body)), nil); err == nil {
		t.Fatal("expected a TLS failure without the mesh CA, got nil")
	}

	// With the CA trusted: download succeeds and the sha matches.
	b = newBackend()
	b.SetCABundle(caPath)
	path, observed, err := b.Download(context.Background(), "b1", url, wantSHA, int64(len(body)), nil)
	if err != nil {
		t.Fatalf("Download with mesh CA trusted: %v", err)
	}
	if observed != wantSHA {
		t.Errorf("observed sha = %s, want %s", observed, wantSHA)
	}
	if got, _ := os.ReadFile(path); string(got) != string(body) {
		t.Errorf("downloaded bytes mismatch")
	}
}
