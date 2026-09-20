package bmc

import (
	"context"
	"crypto/tls"
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

	// Capture the board's key without judging it. Verification is explicitly
	// disabled: the board's certificate is self-signed and minted at the
	// epoch, so every check would fail and we would learn nothing. The
	// operator does the trusting, once, on what we show them.
	//
	// CodeQL flags this as go/disabled-certificate-check (HIGH), and gosec as
	// G402. Accepted as deliberate rather than a false positive: verification
	// really is off and this really is trust-on-first-use, with TOFU's usual
	// weakness that an attacker present at probe time gets their pin recorded
	// instead of the board's. What makes it safe to ship is what this
	// connection does NOT do:
	//
	//   * it sends no credentials — the request is an unauthenticated
	//     GET /api/bmc?opt=get&type=about, so a hostile endpoint learns
	//     nothing and captures nothing;
	//   * it grants no trust — the VerifyConnection hook below only RECORDS
	//     the pin and the subject and always returns nil. Nothing downstream
	//     acts on this connection;
	//   * the pin it captures is shown to the operator, who accepts it before
	//     it ever becomes the pin NewTuringPiBackend enforces.
	//
	// TRIP-WIRE: this verdict rests on the connection carrying no secrets and
	// conferring no trust. If this probe ever sends credentials, or its result
	// is used to configure anything without the operator accepting the pin,
	// re-open .github/codeql-register.tsv and .github/sast-register.tsv — it
	// becomes a real finding.
	var (
		pin     string
		subject string
	)
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // TOFU capture; the operator accepts the pin
		MinVersion:         tls.VersionTLS12,
		// VerifyConnection, not VerifyPeerCertificate, for the same reason
		// pinnedtls.go gives: it runs on resumed connections too, so what is
		// recorded here is always the key of the connection actually in use.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 {
				pin = proto.DevicePinForCert(cs.PeerCertificates[0])
				subject = cs.PeerCertificates[0].Subject.String()
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
		Pin:         pin,
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
		// rather than pinning whatever key happened to arrive.
		res.Detail = fmt.Sprintf("something answered at %s with HTTP %d, which is not how a Turing Pi BMC responds unauthenticated. Confirm the address before trusting this device.", endpoint, resp.StatusCode)
	}
	if discovered {
		// Two boards on one LAN both claim the name; say "a board".
		res.Detail += fmt.Sprintf(" Found by resolving %s from this node.", turingpiMDNSName)
	}
	if res.Pin == "" {
		res.OK = false
		res.Detail = "connected but no certificate was presented — nothing to pin"
		return res
	}

	// Second half: which node is in which slot. This sends the operator's
	// BMC credentials, so it is gated on a certificate they have ALREADY
	// accepted — never on the one just captured.
	//
	// Pinning to res.Pin here would be circular: that pin came from this very
	// handshake, made with verification disabled, so it would authorise
	// whatever answered. Anyone able to answer for the board's mDNS name could
	// then present any certificate, return the 401 marker to look identified,
	// and collect an account that also serves SSH and controls power for the
	// whole chassis.
	//
	// So credentials require cmd.Pin — carried back from the operator's form
	// after the first, uncredentialed probe showed it to them — AND the board
	// must still be presenting exactly that key now. A mismatch is refused
	// loudly rather than re-pinned, because at that point either the firmware
	// was reinstalled or someone is answering in the board's place, and only
	// the operator can tell those apart.
	if !res.Identified || strings.TrimSpace(cmd.User) == "" {
		return res
	}
	if strings.TrimSpace(cmd.Pin) == "" {
		res.Detail += " Slot detection skipped: accept the pin above first — credentials are never sent to a device whose key has not been accepted."
		return res
	}
	wantPin, ferr := proto.ParseDevicePin(cmd.Pin)
	gotPin, gerr := proto.ParseDevicePin(res.Pin)
	if ferr != nil || gerr != nil || wantPin != gotPin {
		res.Detail += " Slot detection refused: this device is presenting a different key than the one you accepted. No credentials were sent. If the BMC firmware was reinstalled, clear the pin and detect again; otherwise treat this as a trust failure."
		return res
	}
	b, berr := NewTuringPiBackend(TuringPiOptions{
		Endpoint: endpoint,
		User:     cmd.User,
		Pass:     cmd.Pass,
		Targets:  map[string]int{"probe-placeholder": 1},
		Pin:      res.Pin,
	})
	if berr != nil {
		res.Detail += " Slot detection unavailable: " + berr.Error()
		return res
	}
	res.Slots = detectSlots(ctx, b)
	return res
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
