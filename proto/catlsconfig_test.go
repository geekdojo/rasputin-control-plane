package proto

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto/tlstest"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
}

// TC-590-01: CATLSConfig trusts exactly the PEM it is handed — its pool is
// that CA alone, at TLS 1.2 or better — and a server under any other CA is
// refused.
func TestCATLSConfig_TrustsExactlyItsInput(t *testing.T) {
	mine := tlstest.NewCA(t, "mine")
	other := tlstest.NewCA(t, "other")

	cfg, err := CATLSConfig(mine.PEM, "src")
	if err != nil {
		t.Fatalf("CATLSConfig: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs is nil, which means the system roots")
	}
	if !cfg.RootCAs.Equal(mine.Pool()) {
		t.Error("RootCAs is not a pool of the input CA alone")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2 (%#x)", cfg.MinVersion, tls.VersionTLS12)
	}

	if err := tlstest.Get(cfg, mine.NewServer(t, okHandler()).URL); err != nil {
		t.Errorf("a server under the trusted CA was refused: %v", err)
	}
	err = tlstest.Get(cfg, other.NewServer(t, okHandler()).URL)
	if !tlstest.IsUnknownAuthority(err) {
		t.Errorf("a server under an unrelated CA: err = %v, want an unknown-authority failure", err)
	}
}

// TC-590-02: every unusable input is refused with a nil config and an error
// naming the source, never a config that falls back to the system pool.
func TestCATLSConfig_RefusesUnusableInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		pem  []byte
	}{
		{"empty", nil},
		{"whitespace only", []byte(" \n\t \n")},
		{"not PEM", []byte("this is not a certificate")},
		{"a PEM holding only a private key", tlstest.KeyOnlyPEM(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CATLSConfig(tc.pem, "the-source-name")
			if cfg != nil {
				t.Errorf("config = %+v, want nil", cfg)
			}
			if err == nil || !strings.Contains(err.Error(), "the-source-name") {
				t.Errorf("err = %v, want an error naming the source", err)
			}
		})
	}
}
