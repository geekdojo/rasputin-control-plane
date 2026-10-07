package tlsca

import (
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-590-03: tlsca.CATLSConfig is proto.CATLSConfig — the api's Headscale
// clients and the agent's HTTPS clients build trust the same way. For every
// input, the two return equal pools and identical error text.
func TestCATLSConfig_DelegatesToProto(t *testing.T) {
	ca := newCA(t, "mesh")
	for _, tc := range []struct {
		name string
		pem  []byte
	}{
		{"a CA", ca.CertPEM},
		{"empty", nil},
		{"not PEM", []byte("garbage")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, gotErr := CATLSConfig(tc.pem, "src")
			want, wantErr := proto.CATLSConfig(tc.pem, "src")
			if (gotErr == nil) != (wantErr == nil) {
				t.Fatalf("errors differ: mesh %v, proto %v", gotErr, wantErr)
			}
			if gotErr != nil {
				if gotErr.Error() != wantErr.Error() {
					t.Errorf("error text: mesh %q, proto %q", gotErr, wantErr)
				}
				if got != nil {
					t.Errorf("mesh returned a config beside its error")
				}
				return
			}
			if !got.RootCAs.Equal(want.RootCAs) {
				t.Error("pools differ")
			}
			if got.MinVersion != want.MinVersion {
				t.Errorf("MinVersion: mesh %#x, proto %#x", got.MinVersion, want.MinVersion)
			}
		})
	}
}
