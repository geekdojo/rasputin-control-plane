package bmc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/mdns"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Probe answers "is there a board there, and what certificate does it
// present" — the two questions an operator would otherwise have to
// answer by hand with an IP scan and an `openssl s_client` incantation
// (bmc-settings §7a).
//
// It deliberately runs on the BMC-host agent rather than in the api or
// the browser: mDNS is link-local, so `turingpi.local` only resolves
// from a machine on the chassis's segment. The host agent is by
// definition such a machine; the operator's laptop may not be.
//
// It runs with NO credentials and never needs any. That is the point —
// an unauthenticated request to a Turing Pi BMC returns 401 with a
// recognisable body, so the board identifies itself before a password
// exists. This ordering is what lets the UI say "found a Turing Pi, here
// is its certificate, confirm and then enter credentials" rather than
// demanding all three up front.
const (
	turingpiMDNSName    = "turingpi.local"
	probeDialTimeout    = 5 * time.Second
	probeRequestTimeout = 8 * time.Second
	probeMDNSTimeout    = 3 * time.Second
	// The vendor's unauthenticated-response marker. Matched loosely
	// (lowercased, substring) because firmware wording may drift; the
	// 401 status is the primary signal and this only corroborates it.
	turingpiAuthMarker = "no authorization header"
)

// Probe performs an unauthenticated reachability + certificate probe.
// It never returns an error for "board not found" — that is a result the
// operator needs to see, not a transport failure.
func Probe(ctx context.Context, cmd proto.BMCProbeCmd) proto.BMCProbeResult {
	kind := cmd.Kind
	if kind == "" {
		kind = "turingpi"
	}
	if kind != "turingpi" {
		return proto.BMCProbeResult{Detail: fmt.Sprintf("backend %q is not probeable", kind)}
	}

	endpoint := strings.TrimSpace(cmd.Endpoint)
	discovered := false
	if endpoint == "" {
		// Discovery: resolve the well-known name from where the agent
		// sits. Report the NAME as the endpoint rather than the resolved
		// address — a DHCP lease is not an identity, and pinning the
		// address here would break the first time the board renews.
		if _, err := mdns.Resolve(turingpiMDNSName, probeMDNSTimeout); err != nil {
			return proto.BMCProbeResult{
				Detail: fmt.Sprintf("no board found: %s did not resolve from this node (%v). Enter the address manually, or check the controlplane is on the same network segment as the BMC.", turingpiMDNSName, err),
			}
		}
		endpoint = turingpiMDNSName
		discovered = true
	}

	base, err := parseTuringPiEndpoint(endpoint)
	if err != nil {
		return proto.BMCProbeResult{Detail: err.Error()}
	}

	// Capture the leaf without judging it. Verification is explicitly
	// disabled: the board's certificate is self-signed and minted at the
	// epoch, so every check would fail and we would learn nothing. The
	// operator does the trusting, once, on what we show them.
	var (
		fingerprint string
		subject     string
	)
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // TOFU capture; the operator confirms the digest
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) > 0 {
				fingerprint = displayFingerprint(certFingerprint(rawCerts[0]))
				subject = leafSubject(rawCerts[0])
			}
			return nil
		},
	}

	client := &http.Client{
		Timeout: probeRequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			TLSHandshakeTimeout: probeDialTimeout,
			DialContext:         mdnsDialContext(probeMDNSTimeout, probeDialTimeout),
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base.String()+"/api/bmc?opt=get&type=about", nil)
	if err != nil {
		return proto.BMCProbeResult{Detail: err.Error()}
	}
	resp, err := client.Do(req)
	if err != nil {
		// Keep the URL out of the message for the same reason the driver
		// does — this API carries its arguments in the query string.
		return proto.BMCProbeResult{
			Endpoint: endpoint,
			Detail:   fmt.Sprintf("could not reach a BMC at %s — check the address and that the board is powered", endpoint),
		}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	res := proto.BMCProbeResult{
		OK:          true,
		Endpoint:    endpoint,
		Fingerprint: fingerprint,
		CertSubject: subject,
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized &&
		strings.Contains(strings.ToLower(string(body)), turingpiAuthMarker):
		res.Identified = true
		res.Detail = "Turing Pi BMC — responded 401 as expected before credentials."
	case resp.StatusCode == http.StatusUnauthorized:
		res.Identified = true
		res.Detail = "A BMC requiring authentication answered. Treated as the board."
	default:
		// Something answered but not the way this board does. Surface it
		// rather than pinning whatever certificate happened to arrive.
		res.Detail = fmt.Sprintf("something answered at %s with HTTP %d, which is not how a Turing Pi BMC responds unauthenticated. Confirm the address before trusting this certificate.", endpoint, resp.StatusCode)
	}
	if discovered {
		// Two boards on one LAN both claim the name; say "a board".
		res.Detail += fmt.Sprintf(" Found by resolving %s from this node.", turingpiMDNSName)
	}
	if res.Fingerprint == "" {
		res.OK = false
		res.Detail = "connected but no certificate was presented — nothing to pin"
		return res
	}

	// Second half: which node is in which slot. Needs credentials, so it
	// runs only once the operator has supplied them — and only against a
	// board we just identified, so we are never reading consoles from
	// something we could not name.
	if res.Identified && strings.TrimSpace(cmd.User) != "" {
		b, berr := NewTuringPiBackend(TuringPiOptions{
			Endpoint:    endpoint,
			User:        cmd.User,
			Pass:        cmd.Pass,
			Targets:     map[string]int{"probe-placeholder": 1},
			Fingerprint: res.Fingerprint,
		})
		if berr != nil {
			res.Detail += " Slot detection unavailable: " + berr.Error()
		} else {
			res.Slots = detectSlots(ctx, b)
		}
	}
	return res
}

// leafSubject parses just enough of the presented certificate to show
// the operator something human next to the digest.
func leafSubject(der []byte) string {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	return c.Subject.String()
}

// displayFingerprint renders a hex digest as colon-separated uppercase
// pairs — the form `openssl x509 -fingerprint` prints, so an operator
// comparing the two sees the same string rather than having to squint.
func displayFingerprint(hexDigest string) string {
	if hexDigest == "" {
		return ""
	}
	up := strings.ToUpper(hexDigest)
	var b strings.Builder
	for i := 0; i < len(up); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(up[i : i+2])
	}
	return b.String()
}

// loginBannerHost matches the hostname a getty prints before its login
// prompt — `tp-n1 login:`. That string is the node's own idea of who it
// is, which for an enrolled Rasputin node is its node-id, so it is the
// cheapest possible way to learn which node sits in which slot.
//
// Deliberately anchored on ` login:` rather than parsing the whole
// banner: the ring buffer may have wrapped mid-boot, so the only thing
// that can be relied on is the repeating prompt at the tail.
var loginBannerHost = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s+login:`)

// detectSlots reads each slot's console and reports what it finds. It is
// non-destructive — the UART endpoint returns the ring buffer's current
// contents and consumes nothing — so this is safe to run against a
// working cluster.
//
// Requires credentials: unlike identification and certificate capture,
// the UART endpoint is authenticated. That is why it is a separate half
// of the probe rather than part of the first pass.
//
// Slots that report nothing are reported AS nothing rather than skipped.
// An unpowered slot, a slot whose buffer wrapped past its last prompt,
// and a slot running something that is not Rasputin are all legitimate
// states an operator needs to see, and all of them mean "you fill this
// row in yourself".
func detectSlots(ctx context.Context, t *TuringPiBackend) []proto.BMCProbeSlot {
	out := make([]proto.BMCProbeSlot, 0, turingpiMaxSlot)
	power, perr := t.readPower(ctx)
	for slot := turingpiMinSlot; slot <= turingpiMaxSlot; slot++ {
		s := proto.BMCProbeSlot{Slot: slot}
		if perr == nil {
			s.Powered = power[slot] == proto.BMCStateOn
		}
		if perr == nil && !s.Powered {
			s.Detail = "slot is powered off — power it on to identify it, or choose the node yourself"
			out = append(out, s)
			continue
		}
		body, err := t.get(ctx, url.Values{
			"opt": {"get"}, "type": {"uart"}, "node": {zeroBasedNode(slot)},
		})
		if err != nil {
			s.Detail = "could not read this slot's console"
			out = append(out, s)
			continue
		}
		var env struct {
			Response []struct {
				UART string `json:"uart"`
			} `json:"response"`
		}
		if json.Unmarshal(body, &env) != nil || len(env.Response) == 0 {
			s.Detail = "console returned nothing readable"
			out = append(out, s)
			continue
		}
		text := env.Response[0].UART
		if m := loginBannerHost.FindAllStringSubmatch(strings.ReplaceAll(text, "\r", "\n"), -1); len(m) > 0 {
			// Last match wins — the most recent prompt is the most
			// current identity, and a node that was renamed or re-seeded
			// will have printed the old one earlier in the same buffer.
			s.Hostname = m[len(m)-1][1]
		} else if strings.TrimSpace(text) == "" {
			s.Detail = "console buffer is empty — the node may still be booting"
		} else {
			s.Detail = "no login prompt in this slot's console — choose the node yourself"
		}
		out = append(out, s)
	}
	return out
}
