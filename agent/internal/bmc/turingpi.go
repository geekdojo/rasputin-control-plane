package bmc

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TuringPiBackend drives a Turing Pi 2/2.5 cluster board's BMC over its
// REST API. It is the first *networked* Backend — the host agent reaches
// the chassis BMC over HTTPS instead of owning a local bus — so it is
// also the test that the Backend seam generalizes past the
// local-bus model the serial drivers assume (design/control-plane/bmc.md §2).
//
// Addressing stays per-chassis, never per-target: one endpoint for the
// whole board, with individual nodes addressed by *slot* inside this
// driver, exactly as the serial backends address them by bus position.
type TuringPiBackend struct {
	client  *http.Client
	base    *url.URL // scheme://host (no path)
	user    string
	pass    string
	settle  time.Duration
	targets map[string]int // node-id -> slot (1..4)
	mu      sync.Mutex
}

const (
	sha256HexLen           = 64
	turingpiDefaultSettle  = 3 * time.Second
	turingpiDefaultTimeout = 20 * time.Second
	turingpiMinSlot        = 1
	turingpiMaxSlot        = 4
)

// ── Node indexing ────────────────────────────────────────────────────────
//
// The BMC API is inconsistent about node indexing and it is the easiest
// way to drive the wrong slot (confirmed on hardware 2026-07-27/28):
//
//	power  -> 1-based, in the parameter NAME:  node1=1
//	usb    -> 0-based, as the `node` VALUE:    node=0
//	uart   -> 0-based, as the `node` VALUE:    node=0
//	flash  -> 0-based, as the `node` VALUE:    node=0
//
// Reading slot 1's console as node=1 silently returns slot 2's empty
// buffer with no error. Both conversions live here so no caller has to
// remember which convention an endpoint uses.

// powerParam renders the power endpoint's 1-based parameter name.
func powerParam(slot int) string { return "node" + strconv.Itoa(slot) }

// zeroBasedNode renders the 0-based `node` value used by usb/uart/flash.
func zeroBasedNode(slot int) string { return strconv.Itoa(slot - 1) }

// ── Construction ─────────────────────────────────────────────────────────

// TuringPiOptions carries everything the driver needs. Endpoint may be a
// bare host ("turingpi.local"), which is the form to prefer: the BMC
// takes DHCP, and on this bench its lease moved repeatedly while mDNS
// followed correctly.
type TuringPiOptions struct {
	Endpoint string         // host, host:port, or full URL
	User     string         //
	Pass     string         //
	Targets  map[string]int // node-id -> slot
	Settle   time.Duration  // off->on gap when synthesizing `cycle`

	// TLS against the chassis BMC.
	//
	// The board presents a self-signed certificate that is ALREADY
	// EXPIRED — it is minted at epoch because the BMC has no clock:
	//
	//	subject=CN=Turing-Pi self signed  issuer=CN=Turing-Pi self signed
	//	notBefore=Jan 1 1970  notAfter=Jan 31 1970  BasicConstraints: CA:TRUE
	//
	// So trusting it as a CA cannot work: Go checks validity independently
	// of trust and the chain fails on expiry no matter what is in the pool.
	// The mechanism that does work is pinning the exact certificate:
	//
	//	Fingerprint        — SHA-256 of the leaf, hex (colons optional)
	//	InsecureSkipVerify — accept any certificate (explicit opt-in only)
	//
	// Fingerprint pinning reads alarming because it rides on
	// InsecureSkipVerify, but it is STRICTER than CA trust here — it
	// accepts exactly one certificate rather than anything chaining to an
	// anchor. Neither is defaulted on: a driver that silently disabled
	// verification would be out of step with the rest of the platform
	// (mesh CA, bus-auth enforce), so the operator has to choose.
	Fingerprint        string
	InsecureSkipVerify bool
}

// NewTuringPiBackend builds the driver. It performs no I/O — the first
// request happens on the first verb, so a misconfigured endpoint surfaces
// as a failed operation rather than a failed agent start.
func NewTuringPiBackend(opts TuringPiOptions) (*TuringPiBackend, error) {
	if opts.Endpoint == "" {
		return nil, fmt.Errorf("turingpi: endpoint is required")
	}
	base, err := parseTuringPiEndpoint(opts.Endpoint)
	if err != nil {
		return nil, err
	}
	if opts.User == "" {
		return nil, fmt.Errorf("turingpi: user is required (BMC auth is mandatory since firmware v2.0.0)")
	}
	if len(opts.Targets) == 0 {
		return nil, fmt.Errorf("turingpi: no targets configured — nothing would be advertised, which is indistinguishable from BMC-off")
	}
	for id, slot := range opts.Targets {
		if slot < turingpiMinSlot || slot > turingpiMaxSlot {
			return nil, fmt.Errorf("turingpi: node %q has slot %d, want %d..%d", id, slot, turingpiMinSlot, turingpiMaxSlot)
		}
	}
	if err := assertDistinctSlots(opts.Targets); err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case opts.Fingerprint != "":
		want, err := normalizeFingerprint(opts.Fingerprint)
		if err != nil {
			return nil, err
		}
		// Go's own verification is disabled so the expired-at-epoch cert
		// gets past it; VerifyPeerCertificate then applies the stricter
		// exact-match check.
		//
		// CodeQL flags the next line as go/disabled-certificate-check (HIGH)
		// and it is a false positive: certificate pinning is STRICTER than the
		// CA trust being skipped. CA trust accepts any cert a trusted issuer
		// signed; pinnedCertVerifier accepts exactly one SHA-256 fingerprint
		// and nothing else. Skipping is not optional either — the board mints
		// a self-signed cert at the epoch, so it is permanently expired and no
		// chain check can ever pass.
		//
		// TRIP-WIRE: the safety of this line lives on the line AFTER it. If
		// the VerifyPeerCertificate assignment is removed, moved behind a
		// condition, or replaced with a verifier that does not compare the
		// full fingerprint, this becomes "accept any certificate" and the
		// verdict in .github/codeql-register.tsv is void. The register's
		// fingerprint covers only the flagged line and will NOT catch that.
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyPeerCertificate = pinnedCertVerifier(want)
	case opts.InsecureSkipVerify:
		tlsCfg.InsecureSkipVerify = true
	default:
		return nil, fmt.Errorf("turingpi: TLS not configured — pin the board's certificate with its SHA-256 fingerprint, or set insecure_skip_verify to accept any (the board's self-signed cert is minted at epoch and permanently expired, so CA trust cannot work)")
	}

	settle := opts.Settle
	if settle <= 0 {
		settle = turingpiDefaultSettle
	}
	targets := make(map[string]int, len(opts.Targets))
	for id, slot := range opts.Targets {
		targets[id] = slot
	}

	return &TuringPiBackend{
		client: &http.Client{
			Timeout: turingpiDefaultTimeout,
			// .local endpoints resolve over mDNS — see dial.go. The
			// operator is told everywhere to address the board by name.
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
				DialContext:     mdnsDialContext(3*time.Second, 5*time.Second),
			},
		},
		base:    base,
		user:    opts.User,
		pass:    opts.Pass,
		settle:  settle,
		targets: targets,
	}, nil
}

// parseTuringPiEndpoint accepts "turingpi.local", "turingpi.local:8443",
// or a full URL, and normalises to an https base. Plain http is honoured
// when explicitly asked for so a lab board with TLS disabled still works.
func parseTuringPiEndpoint(raw string) (*url.URL, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("turingpi: endpoint is required")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("turingpi: endpoint %q: %w", raw, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("turingpi: endpoint %q: unsupported scheme %q", raw, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("turingpi: endpoint %q has no host", raw)
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

func assertDistinctSlots(targets map[string]int) error {
	seen := make(map[int]string, len(targets))
	ids := make([]string, 0, len(targets))
	for id := range targets {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic error text
	for _, id := range ids {
		slot := targets[id]
		if prev, dup := seen[slot]; dup {
			return fmt.Errorf("turingpi: nodes %q and %q both claim slot %d", prev, id, slot)
		}
		seen[slot] = id
	}
	return nil
}

// ── Backend ──────────────────────────────────────────────────────────────

func (t *TuringPiBackend) Name() string { return "turingpi" }

// Targets returns the configured node-ids. Unlike a bus scan this is
// operator-declared: the BMC knows its slots but not what Rasputin calls
// the module in each one.
func (t *TuringPiBackend) Targets() []proto.BMCTarget {
	ids := make([]string, 0, len(t.targets))
	for id := range t.targets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]proto.BMCTarget, 0, len(ids))
	for _, id := range ids {
		// Power and reset only. The BMC's UART is a polled ~16 KB ring
		// with a command-granular write side, so OpenSOL refuses — and
		// advertising a console capability we cannot honour would put a
		// CONSOLE button on screen that fails on click. When a polled
		// SoL lands this becomes BMCCapConsole with
		// {Mode: line, Lossy: true}, which the UI can label honestly.
		out = append(out, proto.BMCTarget{
			NodeID: id,
			Caps:   []string{proto.BMCCapPower, proto.BMCCapReset},
		})
	}
	return out
}

func (t *TuringPiBackend) Power(ctx context.Context, target string, verb proto.BMCPowerVerb) (proto.BMCPowerState, string, error) {
	slot, ok := t.targets[target]
	if !ok {
		return proto.BMCStateUnknown, "", fmt.Errorf("turingpi: node %q not in the address map", target)
	}

	// One board, one in-flight verb. The BMC multiplexes a single USB
	// bus and its own state machine across all four slots; concurrent
	// verbs are not worth the risk for the rare parallel case.
	t.mu.Lock()
	defer t.mu.Unlock()

	var detail string
	switch verb {
	case proto.BMCPowerOn:
		if err := t.setPower(ctx, slot, true); err != nil {
			return proto.BMCStateUnknown, "", err
		}
		detail = "powered on"
	case proto.BMCPowerOff:
		if err := t.setPower(ctx, slot, false); err != nil {
			return proto.BMCStateUnknown, "", err
		}
		detail = "powered off (hard cut)"
	case proto.BMCPowerReset:
		// The BMC has a real reset verb, unlike the CB04B.
		if err := t.call(ctx, url.Values{"opt": {"set"}, "type": {"reset"}, "node": {zeroBasedNode(slot)}}); err != nil {
			return proto.BMCStateUnknown, "", err
		}
		detail = "reset"
	case proto.BMCPowerCycle:
		// No `cycle` verb on this BMC — synthesize it. The api accepts
		// `cycle`, so dropping it would be a silent capability hole.
		if err := t.setPower(ctx, slot, false); err != nil {
			return proto.BMCStateUnknown, "", err
		}
		select {
		case <-time.After(t.settle):
		case <-ctx.Done():
			return proto.BMCStateUnknown, "", ctx.Err()
		}
		if err := t.setPower(ctx, slot, true); err != nil {
			return proto.BMCStateUnknown, "", err
		}
		detail = "hard power-cycled"
	case proto.BMCPowerQuery:
		detail = "queried"
	default:
		return proto.BMCStateUnknown, "", fmt.Errorf("turingpi: unsupported verb %q", verb)
	}

	// The ack reports post-op reality, not the verb's intent (§3 step 3).
	states, err := t.readPower(ctx)
	if err != nil {
		return proto.BMCStateUnknown, "", err
	}
	state, ok := states[slot]
	if !ok {
		return proto.BMCStateUnknown, detail, fmt.Errorf("turingpi: BMC did not report slot %d", slot)
	}
	return state, detail, nil
}

// OpenSOL is not implemented yet. The BMC's UART is a polled,
// non-destructive ~16 KB ring (≈1.4 s of output at 115200) with a
// command-granular write side, so a faithful SOL needs offset tracking
// and cannot honour §1's boot-capture use case. Refusing is better than
// shipping a console that silently drops the bytes an operator opened it
// to read.
func (t *TuringPiBackend) OpenSOL(ctx context.Context, target, sessionID string) (SOL, error) {
	if _, ok := t.targets[target]; !ok {
		return nil, fmt.Errorf("turingpi: node %q not in the address map", target)
	}
	return nil, fmt.Errorf("turingpi: serial console not implemented for this backend yet")
}

// ── Wire ─────────────────────────────────────────────────────────────────

func (t *TuringPiBackend) setPower(ctx context.Context, slot int, on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	// Power values are strings on this API, and the node index rides in
	// the parameter NAME rather than a `node` value.
	return t.call(ctx, url.Values{"opt": {"set"}, "type": {"power"}, powerParam(slot): {v}})
}

// readPower returns every slot's state from one call — the BMC reports
// all four together, which is also what makes the bmc-targets
// advertisement a single request.
func (t *TuringPiBackend) readPower(ctx context.Context) (map[int]proto.BMCPowerState, error) {
	body, err := t.get(ctx, url.Values{"opt": {"get"}, "type": {"power"}})
	if err != nil {
		return nil, err
	}
	var env struct {
		Response []struct {
			Result []map[string]string `json:"result"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("turingpi: decode power status: %w", err)
	}
	if len(env.Response) == 0 || len(env.Response[0].Result) == 0 {
		return nil, fmt.Errorf("turingpi: power status returned no result")
	}
	out := make(map[int]proto.BMCPowerState, turingpiMaxSlot)
	for key, raw := range env.Response[0].Result[0] {
		slot, err := strconv.Atoi(strings.TrimPrefix(key, "node"))
		if err != nil {
			continue
		}
		switch raw {
		case "1":
			out[slot] = proto.BMCStateOn
		case "0":
			out[slot] = proto.BMCStateOff
		default:
			out[slot] = proto.BMCStateUnknown
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("turingpi: power status had no node fields")
	}
	return out, nil
}

// call issues a request and discards the payload, surfacing only errors.
func (t *TuringPiBackend) call(ctx context.Context, q url.Values) error {
	_, err := t.get(ctx, q)
	return err
}

// get performs one BMC request and returns the raw body.
//
// Two traps are handled here rather than at each call site:
//   - the documented response envelope is wrong. The API reference says
//     `[{"response": …}]`; the wire shape is `{"response":[{…}]}`.
//   - logical failures come back as HTTP 200 with a "Failed to …" string
//     in the result, so status codes alone will happily report success
//     for an operation that did not happen.
func (t *TuringPiBackend) get(ctx context.Context, q url.Values) ([]byte, error) {
	u := *t.base
	u.Path = "/api/bmc"
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("turingpi: build request: %w", err)
	}
	req.SetBasicAuth(t.user, t.pass)

	resp, err := t.client.Do(req)
	if err != nil {
		// Keep credentials out of the error: url.Error embeds the URL,
		// and the query string is where this API carries its arguments.
		// Our own trust failure: the message is ours, names only
		// fingerprints, and is the one an operator can actually act on.
		var pe *pinError
		if errors.As(err, &pe) {
			return nil, fmt.Errorf("turingpi: %s %s: %w", q.Get("opt"), q.Get("type"), pe)
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, fmt.Errorf("turingpi: %s %s: timeout", q.Get("opt"), q.Get("type"))
		}
		return nil, fmt.Errorf("turingpi: %s %s: request failed", q.Get("opt"), q.Get("type"))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("turingpi: read response: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("turingpi: unauthorized — check the BMC username/password (auth is mandatory since firmware v2.0.0)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("turingpi: %s %s: HTTP %d: %s", q.Get("opt"), q.Get("type"), resp.StatusCode, strings.TrimSpace(truncate(string(body), 200)))
	}
	if msg, failed := turingpiResultFailure(body); failed {
		return nil, fmt.Errorf("turingpi: %s %s: %s", q.Get("opt"), q.Get("type"), msg)
	}
	return body, nil
}

// turingpiResultFailure detects the 200-with-an-error-string case.
func turingpiResultFailure(body []byte) (string, bool) {
	var env struct {
		Response []struct {
			Result json.RawMessage `json:"result"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "", false
	}
	if len(env.Response) == 0 {
		return "", false
	}
	var s string
	if err := json.Unmarshal(env.Response[0].Result, &s); err != nil {
		return "", false // result was an object/array, not a status string
	}
	if strings.HasPrefix(s, "Failed to") {
		return s, true
	}
	return "", false
}

// normalizeFingerprint accepts the shapes an operator will actually
// paste — "41:7C:1E:…" from openssl, or bare hex, in either case.
func normalizeFingerprint(raw string) (string, error) {
	clean := strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(raw)))
	clean = strings.TrimPrefix(clean, "sha256")
	if len(clean) != sha256HexLen {
		return "", fmt.Errorf("turingpi: fingerprint must be a SHA-256 hex digest (%d hex chars, colons optional), got %d chars", sha256HexLen, len(clean))
	}
	if _, err := hex.DecodeString(clean); err != nil {
		return "", fmt.Errorf("turingpi: fingerprint is not valid hex: %w", err)
	}
	return clean, nil
}

// certFingerprint returns the lowercase hex SHA-256 of a certificate's DER.
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// pinError is a trust failure raised by our own verifier. It is a named
// type so get() can tell it apart from every other transport error and
// let its message through: get() otherwise collapses transport failures
// to "request failed" to keep the URL out of the text, which would hide
// the single most likely misconfiguration behind the single least
// actionable message (bench 2026-07-28 — a deliberately wrong pin
// reported only "get power: request failed"). This error is built here
// from the fingerprints alone, so it carries no credentials.
type pinError struct{ msg string }

func (e *pinError) Error() string { return e.msg }

// pinnedCertVerifier matches the presented leaf against a pinned digest.
// Deliberately ignores chain and validity: this board's certificate is
// permanently expired by construction, so those checks can only ever fail.
func pinnedCertVerifier(want string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return &pinError{"BMC presented no certificate"}
		}
		got := certFingerprint(rawCerts[0])
		if got != want {
			return &pinError{fmt.Sprintf("BMC certificate does not match the pinned fingerprint (got %s, pinned %s) — if the BMC firmware was updated its certificate was regenerated and needs re-pinning; otherwise treat this as a trust failure", got, want)}
		}
		return nil
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// parseTuringPiMap parses the env-var address map: comma-separated
// "<node-id>:<slot>" pairs, e.g. "tp-cp1:1,tp-n1:2". The settings path
// carries the same mapping as structured JSON instead.
func parseTuringPiMap(raw string) (map[string]int, error) {
	out := map[string]int{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, slotStr, ok := strings.Cut(part, ":")
		id = strings.TrimSpace(id)
		if !ok || id == "" {
			return nil, fmt.Errorf("turingpi: address map entry %q: want <node-id>:<slot>", part)
		}
		slot, err := strconv.Atoi(strings.TrimSpace(slotStr))
		if err != nil {
			return nil, fmt.Errorf("turingpi: address map entry %q: slot is not a number", part)
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("turingpi: address map lists node %q twice", id)
		}
		out[id] = slot
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("turingpi: address map is empty (want e.g. \"tp-cp1:1,tp-n1:2\")")
	}
	return out, nil
}
