package idclient

import (
	"crypto/tls"
	"io"
	"net/http"
	"path/filepath"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/looptls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// TC-985-33: two pools from NewTransport, one presenting rasputin-api and one
// rasputin-door, interleaved concurrently against one server that echoes the
// peer's CN: every answer names its own transport's leaf, so a connection
// opened with one leaf never carries the other's request. Both have no proxy
// and TLS 1.3 at least.
func TestNewTransport_TwoPoolsNeverShareAConnection(t *testing.T) {
	p := newPKI(t)
	door, err := p.ca.MintLeafToDisk(filepath.Join(t.TempDir(), "door"), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-door"})
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(t, p, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}, nil)
	transport := func(leaf tlsca.LeafPaths) *http.Transport {
		cfg, err := looptls.NewClientTLS(p.ca.CertPEM, leaf.CertPath, leaf.KeyPath)
		if err != nil {
			t.Fatal(err)
		}
		cfg.MinVersion = tls.VersionTLS12
		tr := NewTransport(cfg)
		t.Cleanup(tr.CloseIdleConnections)
		if tr.Proxy != nil {
			t.Error("the transport consults a proxy")
		}
		if tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
			t.Errorf("minimum TLS version %x, want TLS 1.3", tr.TLSClientConfig.MinVersion)
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Error("NewTransport changed the caller's config")
		}
		return tr
	}
	pools := map[string]*http.Transport{"rasputin-api": transport(p.clientLeaf), "rasputin-door": transport(door)}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var wrong []string
	for range 64 {
		for cn, tr := range pools {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
				resp, err := tr.RoundTrip(req)
				if err != nil {
					mu.Lock()
					wrong = append(wrong, err.Error())
					mu.Unlock()
					return
				}
				b, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if string(b) != cn {
					mu.Lock()
					wrong = append(wrong, cn+" answered as "+string(b))
					mu.Unlock()
				}
			}()
		}
	}
	wg.Wait()
	if len(wrong) > 0 {
		t.Fatalf("%d requests went wrong: %v", len(wrong), wrong[:min(len(wrong), 5)])
	}
}
