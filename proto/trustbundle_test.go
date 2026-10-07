package proto

import (
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto/tlstest"
)

// ValidateTrustBundle accepts a bundle of CA certificates and refuses every
// other shape, saying which. The agent refuses trust.install on it; the api's
// node bundle is built to pass it (TC-741-32).
func TestValidateTrustBundle(t *testing.T) {
	a, b := tlstest.NewCA(t, "a").PEM, tlstest.NewCA(t, "b").PEM
	for name, in := range map[string][]byte{
		"one certificate":        a,
		"two, blank-line spaced": []byte(string(a) + "\n\n" + string(b)),
		"surrounding whitespace": []byte(" \n" + string(a) + "\t\n"),
	} {
		if err := ValidateTrustBundle(in); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	for name, tc := range map[string]struct {
		in   []byte
		want string
	}{
		"empty":                     {nil, "no certificate"},
		"whitespace only":           {[]byte(" \n\t"), "no certificate"},
		"text before a block":       {[]byte("Bag Attributes\n" + string(a)), "outside a PEM block"},
		"text after the last block": {[]byte(string(a) + "subject=/CN=a\n"), "outside a PEM block"},
		"a private key":             {tlstest.KeyOnlyPEM(t), `"PRIVATE KEY" block`},
		"a malformed block":         {[]byte("-----BEGIN CERTIFICATE-----\nnot base64 at all\n"), "malformed PEM block"},
		"an unparseable cert":       {[]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), "does not parse"},
	} {
		err := ValidateTrustBundle(tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want it to say %q", name, err, tc.want)
		}
	}
}
