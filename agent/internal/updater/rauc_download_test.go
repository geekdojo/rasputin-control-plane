package updater

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/proto/tlstest"
)

// The bundle download trusts exactly the node's controlplane CA bundle
// (geekdojo/geekdojo-brain#590). The api serves /api/bundles/{sha} over its
// controlplane-CA HTTPS leaf; a system root can never legitimately verify it, so the
// client carries none, and a node with no usable bundle refuses before it
// asks for anything.

// trusting is a TrustSource over ca alone, built the way the agent builds it.
func trusting(t *testing.T, ca *tlstest.CA) TrustSource {
	t.Helper()
	return func() (*tls.Config, error) { return proto.CATLSConfig(ca.PEM, "test CA") }
}

// countingServer serves body under ca and counts every request it receives.
func countingServer(t *testing.T, ca *tlstest.CA, body []byte) (url string, hits *atomic.Int32) {
	t.Helper()
	hits = &atomic.Int32{}
	srv := ca.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(body)
	}))
	return srv.URL, hits
}

func shaOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// assertNoBundleFiles checks the bundle store holds no bundle and no partial.
func assertNoBundleFiles(t *testing.T, stateDir string) {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(stateDir, "bundles"))
	if err != nil {
		t.Fatalf("read bundle store: %v", err)
	}
	for _, e := range ents {
		t.Errorf("bundle store holds %s after a refused download", e.Name())
	}
}

// TC-590-07: over TLS the bundle's CA signs, the download succeeds, reports
// the observed sha, and the file on disk hashes to it.
func TestRAUCBackend_Download_TrustsMeshCA(t *testing.T) {
	ca := tlstest.NewCA(t, "mesh")
	body := []byte("pretend-raucb-bytes")
	want := shaOf(body)
	url, _ := countingServer(t, ca, body)

	b, err := newRAUCBackend(t.TempDir(), "/bin/true", trusting(t, ca))
	if err != nil {
		t.Fatalf("newRAUCBackend: %v", err)
	}
	path, observed, err := b.Download(context.Background(), "b1", url+"/api/bundles/"+want, "", want, int64(len(body)), nil)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if observed != want {
		t.Errorf("observed sha = %s, want %s", observed, want)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read downloaded bundle: %v", err)
	}
	if shaOf(got) != want {
		t.Errorf("file on disk hashes to %s, want %s", shaOf(got), want)
	}
}

// TC-590-08: a server whose leaf the trusted CA did not sign is refused with
// the X.509 verdict, and nothing — no bundle, no partial — is left behind.
func TestRAUCBackend_Download_RefusesAnUntrustedServer(t *testing.T) {
	serverCA := tlstest.NewCA(t, "server")
	unrelated := tlstest.NewCA(t, "unrelated")
	body := []byte("pretend-raucb-bytes")
	url, _ := countingServer(t, serverCA, body)

	stateDir := t.TempDir()
	b, err := newRAUCBackend(stateDir, "/bin/true", trusting(t, unrelated))
	if err != nil {
		t.Fatalf("newRAUCBackend: %v", err)
	}
	_, _, err = b.Download(context.Background(), "b1", url, "", shaOf(body), int64(len(body)), nil)
	if !tlstest.IsUnknownAuthority(err) {
		t.Fatalf("err = %v, want an unknown-authority failure", err)
	}
	assertNoBundleFiles(t, stateDir)
}

// TC-590-09: a trust failure refuses the download before any request, with
// the trust error wrapped under "rauc download:".
func TestRAUCBackend_Download_TrustFailureRefusesBeforeAnyRequest(t *testing.T) {
	ca := tlstest.NewCA(t, "mesh")
	body := []byte("pretend-raucb-bytes")
	url, hits := countingServer(t, ca, body)
	errTrust := errors.New("controlplane CA bundle /x/tailscaled-ca.pem: no such file")

	b, err := newRAUCBackend(t.TempDir(), "/bin/true", func() (*tls.Config, error) { return nil, errTrust })
	if err != nil {
		t.Fatalf("newRAUCBackend: %v", err)
	}
	_, _, err = b.Download(context.Background(), "b1", url, "", shaOf(body), int64(len(body)), nil)
	if err == nil || !strings.HasPrefix(err.Error(), "rauc download:") {
		t.Fatalf("err = %v, want it to start %q", err, "rauc download:")
	}
	if !errors.Is(err, errTrust) {
		t.Errorf("err = %v, want it to wrap the trust error", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("server received %d request(s), want 0", n)
	}
}

// TC-590-11 (RAUC): a backend with no trust source cannot be built.
func TestNewRAUCBackend_RefusesANilTrustSource(t *testing.T) {
	b, err := newRAUCBackend(t.TempDir(), "/bin/true", nil)
	if b != nil || err == nil {
		t.Errorf("newRAUCBackend(nil trust) = (%v, %v), want (nil, error)", b, err)
	}
}
