package updater

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto/tlstest"
)

// F-590-05: a trust source that answers without an error but with no root
// pool — a nil config, or a config whose RootCAs is nil — would make net/http
// verify against the system roots. Both backends refuse it before any
// request, the .sig included, and leave nothing in the bundle store.
func TestDownload_RefusesATrustConfigWithNoRoots(t *testing.T) {
	ca := tlstest.NewCA(t, "mesh")
	body := []byte("pretend-bundle-bytes")
	sources := []struct {
		name  string
		trust TrustSource
	}{
		{"nil config, nil error", func() (*tls.Config, error) { return nil, nil }},
		{"config with nil RootCAs", func() (*tls.Config, error) { return &tls.Config{MinVersion: tls.VersionTLS12}, nil }},
	}
	for _, src := range sources {
		t.Run("rauc: "+src.name, func(t *testing.T) {
			url, hits := countingServer(t, ca, body)
			stateDir := t.TempDir()
			b, err := newRAUCBackend(stateDir, "/bin/true", src.trust)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = b.Download(context.Background(), "b1", url, "", shaOf(body), int64(len(body)), nil)
			if !errors.Is(err, errNoTrustRoots) {
				t.Fatalf("err = %v, want errNoTrustRoots", err)
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("server received %d request(s), want 0", n)
			}
			assertNoBundleFiles(t, stateDir)
		})
		t.Run("openwrt-ab: "+src.name, func(t *testing.T) {
			bundleURL, sigURL, hits := tlsArtifactServer(t, ca, body, []byte("sig"))
			stateDir := t.TempDir()
			b, err := NewOpenWrtABBackend(stateDir, src.trust)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = b.Download(context.Background(), "b1", bundleURL, sigURL, shaOf(body), int64(len(body)), nil)
			if !errors.Is(err, errNoTrustRoots) {
				t.Fatalf("err = %v, want errNoTrustRoots", err)
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("server received %d request(s), .sig included, want 0", n)
			}
			assertNoBundleFiles(t, stateDir)
		})
	}
}
