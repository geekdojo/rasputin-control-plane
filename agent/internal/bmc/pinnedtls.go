package bmc

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// One pinned-TLS helper for every external device this agent talks to.
//
// There used to be three ways to configure that TLS, per driver: a cert-DER
// fingerprint, `insecure_skip_verify` (accept anything), and an `http://`
// endpoint (no TLS at all). The last two send the operator's device password —
// an account that on a chassis BMC also serves SSH and controls power for
// every node in it — to whatever answers. Both are gone, and this file is the
// only way a device client is built (geekdojo/geekdojo-brain#548).
//
// What is left is one typed pin, in the same encoding as the bus pin
// (proto.DevicePinForCert), checked in VerifyConnection.

// pinError is a trust failure raised by our own verifier. A named type so a
// driver can tell it apart from every other transport error and let its
// message through: drivers otherwise collapse transport failures to "request
// failed" to keep the URL — which on this BMC's API carries its arguments —
// out of the text, and that would hide the single most likely
// misconfiguration behind the least actionable message (bench 2026-07-28, a
// deliberately wrong pin reported only "get power: request failed").
//
// Built from the pins alone, so it carries no credentials.
type pinError struct{ msg string }

func (e *pinError) Error() string { return e.msg }

// pinnedTLSConfig returns the TLS config for talking to a device pinned to
// pin. It is the ONLY TLS config the device drivers use.
//
// InsecureSkipVerify is on and VerifyConnection does the work. That is
// STRICTER than the chain validation being skipped, not weaker: chain
// validation accepts any certificate some trusted issuer signed, for a
// matching name, within its validity window; this accepts exactly one public
// key and nothing else. It is also the only thing that CAN work here — the
// board mints a self-signed certificate at the epoch (it has no clock), so it
// is permanently expired and no chain check can ever pass.
//
// VerifyConnection rather than VerifyPeerCertificate: it runs on resumed
// connections too. VerifyPeerCertificate does not, so a pin checked that way
// silently stops being checked the moment anything hands the client a
// ClientSessionCache — a property of a struct field far from this file, which
// is not where a trust decision should live.
//
// TRIP-WIRE: the safety of the InsecureSkipVerify line lives in the
// VerifyConnection function below it. If that function is removed, made
// conditional, or changed to compare anything less than the full digest, this
// becomes "accept any certificate" and the verdicts recorded for this file in
// .github/sast-register.tsv and .github/codeql-register.tsv are void.
func pinnedTLSConfig(pin string) (*tls.Config, error) {
	want, err := proto.ParseDevicePin(pin)
	if err != nil {
		return nil, fmt.Errorf("device pin %q is not usable: %w", redactPin(pin), err)
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // verified by pin in VerifyConnection, below — see the doc comment
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return &pinError{"the device presented no certificate"}
			}
			leaf := cs.PeerCertificates[0]
			if !proto.DevicePinMatchesSPKI(want, leaf.RawSubjectPublicKeyInfo) {
				return &pinError{fmt.Sprintf(
					"the device's certificate does not match the pin (presented %s, pinned %s) — if its firmware was reinstalled its key was regenerated and the device needs detecting again; otherwise treat this as a trust failure",
					proto.DevicePinForCert(leaf), pin)}
			}
			return nil
		},
	}, nil
}

// redactPin keeps a malformed pin out of an error message at full length: it
// is operator-supplied text, and a paste accident could put something else
// there. Enough is kept to recognise which value was meant.
func redactPin(pin string) string {
	pin = strings.TrimSpace(pin)
	if len(pin) <= 16 {
		return pin
	}
	return pin[:16] + "…"
}

// requireHTTPSEndpoint parses a device endpoint and refuses anything that is
// not https. A bare host gets https:// — the form the operator is told to use,
// since these devices take DHCP and are addressed by name.
//
// `http://` used to be honoured "so a lab board with TLS disabled still
// works". What it actually did was put the device password on the wire in
// clear, in a Basic header, on the operator's LAN, with nothing in the UI
// saying so. A lab board with TLS off is not a case worth that.
func requireHTTPSEndpoint(raw string) (*url.URL, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("endpoint is required")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("endpoint %q: %w", raw, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("endpoint %q: %s is not supported — the device's credentials would go over the network in clear. Use https (a bare host or name is taken as https)", raw, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("endpoint %q has no host", raw)
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}
