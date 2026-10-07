package updater

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto/tlstest"
)

// tlsArtifactServer serves an artifact and its .sig under ca, counting every
// request, the .sig included.
func tlsArtifactServer(t *testing.T, ca *tlstest.CA, body, sig []byte) (bundleURL, sigURL string, hits *atomic.Int32) {
	t.Helper()
	hits = &atomic.Int32{}
	mux := http.NewServeMux()
	mux.HandleFunc("/bundle/sig", func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(sig)
	})
	mux.HandleFunc("/bundle", func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(body)
	})
	srv := ca.NewServer(t, mux)
	return srv.URL + "/bundle", srv.URL + "/bundle/sig", hits
}

// countCalls wraps a TrustSource and counts its calls.
func countCalls(src TrustSource) (TrustSource, *atomic.Int32) {
	n := &atomic.Int32{}
	return func() (*tls.Config, error) {
		n.Add(1)
		return src()
	}, n
}

// TC-590-10: the firewall's .sig and artifact both come through one client
// built from one trust call, and every trust failure refuses with nothing on
// disk.
func TestOpenWrtDownload_SigAndArtifactThroughOneTrustedClient(t *testing.T) {
	serverCA := tlstest.NewCA(t, "mesh")
	body := []byte("SQUASHFS-BYTES")
	sig := []byte("detached-cms-bytes")

	t.Run("(a) trusting the server: both fetched, one trust call", func(t *testing.T) {
		bundleURL, sigURL, hits := tlsArtifactServer(t, serverCA, body, sig)
		trust, calls := countCalls(trusting(t, serverCA))
		b, err := NewOpenWrtABBackend(t.TempDir(), trust)
		if err != nil {
			t.Fatal(err)
		}
		_, observed, err := b.Download(context.Background(), "b1", bundleURL, sigURL, shaOf(body), int64(len(body)), nil)
		if err != nil {
			t.Fatalf("Download: %v", err)
		}
		if observed != shaOf(body) {
			t.Errorf("observed sha = %s, want %s", observed, shaOf(body))
		}
		if n := hits.Load(); n != 2 {
			t.Errorf("server received %d request(s), want 2 (.sig and artifact)", n)
		}
		if n := calls.Load(); n != 1 {
			t.Errorf("trust source called %d times for one Download, want 1", n)
		}
	})

	t.Run("(b) trusting an unrelated CA: refused at the signature fetch", func(t *testing.T) {
		bundleURL, sigURL, _ := tlsArtifactServer(t, serverCA, body, sig)
		stateDir := t.TempDir()
		b, err := NewOpenWrtABBackend(stateDir, trusting(t, tlstest.NewCA(t, "unrelated")))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = b.Download(context.Background(), "b1", bundleURL, sigURL, shaOf(body), int64(len(body)), nil)
		if !tlstest.IsUnknownAuthority(err) {
			t.Fatalf("err = %v, want an unknown-authority failure", err)
		}
		if !strings.Contains(err.Error(), "fetch signature") {
			t.Errorf("err = %v, want it to fail at the signature fetch", err)
		}
		assertNoBundleFiles(t, stateDir)
	})

	t.Run("(c) trust error: refused before any request", func(t *testing.T) {
		bundleURL, sigURL, hits := tlsArtifactServer(t, serverCA, body, sig)
		errTrust := errors.New("controlplane CA bundle /etc/rasputin/mesh/tailscaled-ca.pem: no such file")
		stateDir := t.TempDir()
		b, err := NewOpenWrtABBackend(stateDir, func() (*tls.Config, error) { return nil, errTrust })
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = b.Download(context.Background(), "b1", bundleURL, sigURL, shaOf(body), int64(len(body)), nil)
		if err == nil || !strings.HasPrefix(err.Error(), "openwrt-ab download:") {
			t.Fatalf("err = %v, want it to start %q", err, "openwrt-ab download:")
		}
		if !errors.Is(err, errTrust) {
			t.Errorf("err = %v, want it to wrap the trust error", err)
		}
		if n := hits.Load(); n != 0 {
			t.Errorf("server received %d request(s), .sig included, want 0", n)
		}
		assertNoBundleFiles(t, stateDir)
	})
}

// TC-590-11 (openwrt-ab): a backend with no trust source cannot be built.
func TestNewOpenWrtABBackend_RefusesANilTrustSource(t *testing.T) {
	b, err := NewOpenWrtABBackend(t.TempDir(), nil)
	if b != nil || err == nil {
		t.Errorf("NewOpenWrtABBackend(nil trust) = (%v, %v), want (nil, error)", b, err)
	}
}
