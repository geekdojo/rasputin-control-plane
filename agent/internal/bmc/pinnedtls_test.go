package bmc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The one TLS config every device client is built from. These are handshakes
// against a real server, not assertions about struct fields: the property that
// matters is which connections complete and which do not.
func TestPinnedTLSConfig(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	leaf := srv.Certificate()

	get := func(t *testing.T, pin string) error {
		t.Helper()
		cfg, err := pinnedTLSConfig(pin)
		if err != nil {
			return err
		}
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}

	// The pinned key connects — even though the certificate chains to nothing
	// this machine trusts, which is the whole point: the board's own
	// certificate is self-signed and permanently expired.
	if err := get(t, proto.DevicePinForCert(leaf)); err != nil {
		t.Fatalf("the pinned key must connect: %v", err)
	}

	// Any other key does not, and the failure says it was the pin — the most
	// likely misconfiguration of the whole driver must not read as an
	// unplugged cable.
	err := get(t, proto.DevicePinForSPKI([]byte("a-different-key")))
	if err == nil {
		t.Fatal("a different key must fail the handshake")
	}
	if !strings.Contains(err.Error(), "does not match the pin") {
		t.Errorf("the error must name the pin; got %v", err)
	}
	// Both values belong in it: the operator needs the presented one after a
	// firmware reinstall regenerates the board's key.
	if !strings.Contains(err.Error(), proto.DevicePinForCert(leaf)) {
		t.Errorf("the error must report the presented pin; got %v", err)
	}

	// A pin that is not a pin is refused at construction, not at connect
	// time, and the malformed value is not echoed back at full length.
	for _, bad := range []string{"", "41:7C:1E:EA", "sha256/not-base64", strings.Repeat("x", 200)} {
		if _, err := pinnedTLSConfig(bad); err == nil {
			t.Errorf("pinnedTLSConfig(%.20q) should have been refused", bad)
		} else if len(err.Error()) > 400 {
			t.Errorf("a refusal must not echo the whole value back: %v", err)
		}
	}
}

// requireHTTPSEndpoint is the other half of the helper: no device endpoint may
// carry credentials over anything but TLS.
func TestRequireHTTPSEndpoint(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"turingpi.local", "https://turingpi.local"},
		{"192.168.1.5:8443", "https://192.168.1.5:8443"},
		{"https://turingpi.local:8443", "https://turingpi.local:8443"},
	} {
		got, err := requireHTTPSEndpoint(tc.in)
		if err != nil {
			t.Errorf("requireHTTPSEndpoint(%q): %v", tc.in, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("requireHTTPSEndpoint(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "   ", "http://turingpi.local", "ftp://turingpi.local", "https://"} {
		if _, err := requireHTTPSEndpoint(bad); err == nil {
			t.Errorf("requireHTTPSEndpoint(%q) should fail", bad)
		}
	}
}
