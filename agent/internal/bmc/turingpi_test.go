package bmc

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// fakeBMC stands in for the board. It records every query it is asked
// and replies with the *real* wire shapes captured from a Turing Pi 2.5
// (board rev 2.5.1, BMC firmware 2.3.2) on 2026-07-27/28 — including the
// quirks the vendor docs get wrong.
type fakeBMC struct {
	mu      sync.Mutex
	queries []url.Values
	power   map[int]string // slot -> "0"/"1"
	// failNext makes the next call return the 200-with-"Failed to…"
	// shape this BMC uses for logical errors.
	failNext string
}

func newFakeBMC(t *testing.T, power map[int]string) (*fakeBMC, *httptest.Server) {
	t.Helper()
	f := &fakeBMC{power: power}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.queries = append(f.queries, q)
		fail := f.failNext
		f.failNext = ""
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if fail != "" {
			// Note the status code: logical failures are HTTP 200.
			_, _ = w.Write([]byte(`{"response":[{"result":"Failed to ` + fail + `: ` + fail + `"}]}`))
			return
		}
		switch {
		case q.Get("opt") == "get" && q.Get("type") == "power":
			f.mu.Lock()
			var sb strings.Builder
			sb.WriteString(`{"response":[{"result":[{`)
			for slot := 1; slot <= 4; slot++ {
				if slot > 1 {
					sb.WriteString(",")
				}
				v := f.power[slot]
				if v == "" {
					v = "0"
				}
				sb.WriteString(`"node` + itoa(slot) + `":"` + v + `"`)
			}
			sb.WriteString(`}]}]}`)
			f.mu.Unlock()
			_, _ = w.Write([]byte(sb.String()))
		case q.Get("opt") == "set" && q.Get("type") == "power":
			f.mu.Lock()
			for slot := 1; slot <= 4; slot++ {
				if v := q.Get("node" + itoa(slot)); v != "" {
					f.power[slot] = v
				}
			}
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"response":[{"result":"ok"}]}`))
		default:
			_, _ = w.Write([]byte(`{"response":[{"result":"ok"}]}`))
		}
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

func itoa(i int) string { return string(rune('0' + i)) }

func (f *fakeBMC) lastQuery() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queries) == 0 {
		return nil
	}
	return f.queries[len(f.queries)-1]
}

func (f *fakeBMC) allQueries() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]url.Values, len(f.queries))
	copy(out, f.queries)
	return out
}

func testBackend(t *testing.T, srv *httptest.Server, targets map[string]int) *TuringPiBackend {
	t.Helper()
	b, err := NewTuringPiBackend(TuringPiOptions{
		Endpoint:           srv.URL,
		User:               "root",
		Pass:               "turing",
		Targets:            targets,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("NewTuringPiBackend: %v", err)
	}
	// httptest's TLS cert isn't the board's; trust the test server.
	b.client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return b
}

// The indexing split is the single easiest way to drive the wrong slot,
// so it gets a dedicated test: power is 1-based in the parameter NAME,
// everything else is a 0-based `node` VALUE.
func TestTuringPiNodeIndexing(t *testing.T) {
	if got := powerParam(1); got != "node1" {
		t.Errorf("powerParam(1) = %q, want node1", got)
	}
	if got := powerParam(4); got != "node4" {
		t.Errorf("powerParam(4) = %q, want node4", got)
	}
	if got := zeroBasedNode(1); got != "0" {
		t.Errorf("zeroBasedNode(1) = %q, want 0 — slot 1 is node=0", got)
	}
	if got := zeroBasedNode(4); got != "3" {
		t.Errorf("zeroBasedNode(4) = %q, want 3", got)
	}
}

func TestTuringPiPowerOnUsesOneBasedParamName(t *testing.T) {
	f, srv := newFakeBMC(t, map[int]string{1: "0"})
	b := testBackend(t, srv, map[string]int{"tp-cp1": 1})

	state, detail, err := b.Power(context.Background(), "tp-cp1", proto.BMCPowerOn)
	if err != nil {
		t.Fatalf("Power(on): %v", err)
	}
	if state != proto.BMCStateOn {
		t.Errorf("state = %q, want on", state)
	}
	if detail == "" {
		t.Error("detail should describe the operation")
	}
	// The set call must carry node1=1, not node=0/node=1.
	var setQ url.Values
	for _, q := range f.allQueries() {
		if q.Get("opt") == "set" && q.Get("type") == "power" {
			setQ = q
		}
	}
	if setQ == nil {
		t.Fatal("no power set call was made")
	}
	if setQ.Get("node1") != "1" {
		t.Errorf("power set query = %v, want node1=1", setQ)
	}
	if setQ.Get("node") != "" {
		t.Errorf("power set must not use a bare `node` value: %v", setQ)
	}
}

func TestTuringPiResetUsesZeroBasedNodeValue(t *testing.T) {
	f, srv := newFakeBMC(t, map[int]string{2: "1"})
	b := testBackend(t, srv, map[string]int{"tp-n1": 2})

	if _, _, err := b.Power(context.Background(), "tp-n1", proto.BMCPowerReset); err != nil {
		t.Fatalf("Power(reset): %v", err)
	}
	var resetQ url.Values
	for _, q := range f.allQueries() {
		if q.Get("type") == "reset" {
			resetQ = q
		}
	}
	if resetQ == nil {
		t.Fatal("no reset call was made")
	}
	// slot 2 -> node=1
	if got := resetQ.Get("node"); got != "1" {
		t.Errorf("reset node = %q, want 1 (slot 2 is 0-based node=1)", got)
	}
}

// A 200 carrying "Failed to …" is a failure. Trusting the status code
// alone reports success for an operation that never happened.
func TestTuringPiTreats200FailureAsError(t *testing.T) {
	f, srv := newFakeBMC(t, map[int]string{1: "0"})
	b := testBackend(t, srv, map[string]int{"tp-cp1": 1})

	f.mu.Lock()
	f.failNext = "Compute module's USB interface not found or supported"
	f.mu.Unlock()

	_, _, err := b.Power(context.Background(), "tp-cp1", proto.BMCPowerOn)
	if err == nil {
		t.Fatal("expected an error for a 200 response carrying \"Failed to …\"")
	}
	if !strings.Contains(err.Error(), "USB interface not found") {
		t.Errorf("error should surface the BMC's message, got: %v", err)
	}
}

// cycle has no BMC verb and must be synthesized, because the api accepts
// it — dropping it would be a silent capability hole.
func TestTuringPiCycleIsSynthesized(t *testing.T) {
	f, srv := newFakeBMC(t, map[int]string{1: "1"})
	b := testBackend(t, srv, map[string]int{"tp-cp1": 1})
	b.settle = 0 // keep the test fast

	if _, _, err := b.Power(context.Background(), "tp-cp1", proto.BMCPowerCycle); err != nil {
		t.Fatalf("Power(cycle): %v", err)
	}
	var sets []string
	for _, q := range f.allQueries() {
		if q.Get("opt") == "set" && q.Get("type") == "power" {
			sets = append(sets, q.Get("node1"))
		}
	}
	if len(sets) != 2 || sets[0] != "0" || sets[1] != "1" {
		t.Errorf("cycle should be off then on, got node1 sets %v", sets)
	}
}

// The ack reports post-op reality, not the verb's intent.
func TestTuringPiReportsPostOpStateNotIntent(t *testing.T) {
	// The board refuses to come up: it stays off despite an `on`.
	f, srv := newFakeBMC(t, map[int]string{1: "0"})
	b := testBackend(t, srv, map[string]int{"tp-cp1": 1})

	// Freeze the reported state by ignoring writes.
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.queries = append(f.queries, q)
		f.mu.Unlock()
		if q.Get("opt") == "get" {
			_, _ = w.Write([]byte(`{"response":[{"result":[{"node1":"0","node2":"0","node3":"0","node4":"0"}]}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"response":[{"result":"ok"}]}`))
	})

	state, _, err := b.Power(context.Background(), "tp-cp1", proto.BMCPowerOn)
	if err != nil {
		t.Fatalf("Power(on): %v", err)
	}
	if state != proto.BMCStateOff {
		t.Errorf("state = %q, want off — the ack must report what the BMC says, not the verb's intent", state)
	}
}

func TestTuringPiOneCallEnumeratesAllSlots(t *testing.T) {
	f, srv := newFakeBMC(t, map[int]string{1: "1", 2: "0"})
	b := testBackend(t, srv, map[string]int{"tp-cp1": 1, "tp-n1": 2})

	if _, _, err := b.Power(context.Background(), "tp-cp1", proto.BMCPowerQuery); err != nil {
		t.Fatalf("Power(status): %v", err)
	}
	// A status query must not issue a set at all.
	for _, q := range f.allQueries() {
		if q.Get("opt") == "set" {
			t.Errorf("status query must be read-only, saw a set: %v", q)
		}
	}
	if got := f.lastQuery().Get("type"); got != "power" {
		t.Errorf("last query type = %q, want power", got)
	}
}

func TestTuringPiTargetsSorted(t *testing.T) {
	_, srv := newFakeBMC(t, nil)
	b := testBackend(t, srv, map[string]int{"tp-n1": 2, "tp-cp1": 1})
	got := b.Targets()
	if len(got) != 2 || got[0].NodeID != "tp-cp1" || got[1].NodeID != "tp-n1" {
		t.Errorf("Targets() = %v, want sorted [tp-cp1 tp-n1]", got)
	}
}

// The whole point of per-target capabilities: this backend drives power
// and reset but must NOT claim a console, because OpenSOL refuses and a
// CONSOLE button would fail on click.
func TestTuringPiAdvertisesNoConsoleCapability(t *testing.T) {
	_, srv := newFakeBMC(t, nil)
	b := testBackend(t, srv, map[string]int{"tp-cp1": 1})
	tgts := b.Targets()
	if len(tgts) != 1 {
		t.Fatalf("Targets() = %v", tgts)
	}
	tgt := tgts[0]
	if !tgt.HasCap(proto.BMCCapPower) || !tgt.HasCap(proto.BMCCapReset) {
		t.Errorf("want power+reset, got caps=%v", tgt.Caps)
	}
	if tgt.HasCap(proto.BMCCapConsole) {
		t.Error("must not advertise console: OpenSOL refuses, so the button would fail on click")
	}
	if tgt.Console != nil {
		t.Errorf("console info should be nil without the capability, got %+v", tgt.Console)
	}
}

func TestTuringPiUnknownTargetRefused(t *testing.T) {
	_, srv := newFakeBMC(t, nil)
	b := testBackend(t, srv, map[string]int{"tp-cp1": 1})
	if _, _, err := b.Power(context.Background(), "nope", proto.BMCPowerOn); err == nil {
		t.Fatal("expected a refusal for a node outside the address map")
	}
}

// TLS has to be an explicit choice — a driver that silently skipped
// verification would be out of step with the rest of the platform.
func TestTuringPiRequiresExplicitTLSChoice(t *testing.T) {
	_, err := NewTuringPiBackend(TuringPiOptions{
		Endpoint: "turingpi.local",
		User:     "root",
		Targets:  map[string]int{"tp-cp1": 1},
	})
	if err == nil {
		t.Fatal("expected construction to fail without a TLS choice")
	}
	if !strings.Contains(err.Error(), "TLS not configured") {
		t.Errorf("error should name the TLS decision, got: %v", err)
	}
}

// Operators paste fingerprints in whatever shape their tool emitted.
func TestNormalizeFingerprint(t *testing.T) {
	const want = "417c1eeab9427f1033634c7af2d2ddf1e8758a9226ce1f633fe1ffd5110fb9e1"
	for _, in := range []string{
		"41:7C:1E:EA:B9:42:7F:10:33:63:4C:7A:F2:D2:DD:F1:E8:75:8A:92:26:CE:1F:63:3F:E1:FF:D5:11:0F:B9:E1",
		"417C1EEAB9427F1033634C7AF2D2DDF1E8758A9226CE1F633FE1FFD5110FB9E1",
		"  417c1eeab9427f1033634c7af2d2ddf1e8758a9226ce1f633fe1ffd5110fb9e1  ",
	} {
		got, err := normalizeFingerprint(in)
		if err != nil {
			t.Errorf("normalizeFingerprint(%.20s…): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("normalizeFingerprint(%.20s…) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "abc", "zz7c1eeab9427f1033634c7af2d2ddf1e8758a9226ce1f633fe1ffd5110fb9e1"} {
		if _, err := normalizeFingerprint(bad); err == nil {
			t.Errorf("normalizeFingerprint(%q) should fail", bad)
		}
	}
}

// The pinned verifier must accept exactly one certificate and reject any
// other — including a valid-but-different one.
func TestPinnedCertVerifier(t *testing.T) {
	der := []byte("pretend-DER-bytes")
	pin := certFingerprint(der)

	if err := pinnedCertVerifier(pin)([][]byte{der}, nil); err != nil {
		t.Errorf("matching certificate should verify: %v", err)
	}
	err := pinnedCertVerifier(pin)([][]byte{[]byte("a-different-cert")}, nil)
	if err == nil {
		t.Fatal("a different certificate must be rejected")
	}
	// The message has to point at the likely cause, since a firmware
	// update regenerating the cert is a normal-operation path here.
	if !strings.Contains(err.Error(), "re-pin") {
		t.Errorf("mismatch error should mention re-pinning, got: %v", err)
	}
	if err := pinnedCertVerifier(pin)(nil, nil); err == nil {
		t.Error("an empty chain must be rejected")
	}
}

// An expired self-signed cert is what this board actually presents, so
// pinning has to work against one. A CA-trust approach cannot.
func TestTuringPiPinnedCertWorksAgainstExpiredSelfSignedBoard(t *testing.T) {
	_, srv := newFakeBMC(t, map[int]string{1: "1"})
	leaf := srv.Certificate()

	b, err := NewTuringPiBackend(TuringPiOptions{
		Endpoint:    srv.URL,
		User:        "root",
		Pass:        "turing",
		Targets:     map[string]int{"tp-cp1": 1},
		Fingerprint: certFingerprint(leaf.Raw),
	})
	if err != nil {
		t.Fatalf("NewTuringPiBackend with a pinned fingerprint: %v", err)
	}
	if _, _, err := b.Power(context.Background(), "tp-cp1", proto.BMCPowerQuery); err != nil {
		t.Fatalf("pinned request should succeed: %v", err)
	}

	// A wrong pin must fail the handshake rather than fall through.
	bad, err := NewTuringPiBackend(TuringPiOptions{
		Endpoint:    srv.URL,
		User:        "root",
		Pass:        "turing",
		Targets:     map[string]int{"tp-cp1": 1},
		Fingerprint: certFingerprint([]byte("not-this-board")),
	})
	if err != nil {
		t.Fatalf("construction with a wrong pin should still build: %v", err)
	}
	_, _, err = bad.Power(context.Background(), "tp-cp1", proto.BMCPowerQuery)
	if err == nil {
		t.Fatal("a mismatched pin must fail the connection")
	}
	// ...and must SAY it was the pin. This assertion used to stop at
	// err != nil, so the driver shipped collapsing a pin mismatch into
	// "request failed" — indistinguishable from an unplugged cable, for
	// what is the most likely misconfiguration of the whole driver
	// (caught on the bench 2026-07-28 with a deliberately wrong pin).
	if !strings.Contains(err.Error(), "pinned fingerprint") {
		t.Errorf("a pin mismatch must name itself; got %q", err)
	}
	// The pinned and presented digests both belong in the message: the
	// operator needs the value to re-pin after a firmware update.
	if !strings.Contains(err.Error(), certFingerprint(leaf.Raw)) {
		t.Errorf("pin-mismatch error should report the presented fingerprint; got %q", err)
	}
}

func TestTuringPiRejectsBadConfig(t *testing.T) {
	base := func() TuringPiOptions {
		return TuringPiOptions{
			Endpoint:           "turingpi.local",
			User:               "root",
			Targets:            map[string]int{"tp-cp1": 1},
			InsecureSkipVerify: true,
		}
	}
	t.Run("slot out of range", func(t *testing.T) {
		o := base()
		o.Targets = map[string]int{"tp-cp1": 5}
		if _, err := NewTuringPiBackend(o); err == nil {
			t.Fatal("expected slot 5 to be rejected")
		}
	})
	t.Run("duplicate slots", func(t *testing.T) {
		o := base()
		o.Targets = map[string]int{"a": 1, "b": 1}
		if _, err := NewTuringPiBackend(o); err == nil {
			t.Fatal("expected duplicate slot assignment to be rejected")
		}
	})
	t.Run("no targets", func(t *testing.T) {
		o := base()
		o.Targets = nil
		if _, err := NewTuringPiBackend(o); err == nil {
			t.Fatal("expected an empty address map to be rejected")
		}
	})
	t.Run("no user", func(t *testing.T) {
		o := base()
		o.User = ""
		if _, err := NewTuringPiBackend(o); err == nil {
			t.Fatal("expected a missing user to be rejected")
		}
	})
}

func TestParseTuringPiEndpoint(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"turingpi.local", "https://turingpi.local"},
		{"192.168.1.5", "https://192.168.1.5"},
		{"https://turingpi.local:8443", "https://turingpi.local:8443"},
		{"http://turingpi.local", "http://turingpi.local"},
	} {
		got, err := parseTuringPiEndpoint(tc.in)
		if err != nil {
			t.Errorf("parseTuringPiEndpoint(%q): %v", tc.in, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("parseTuringPiEndpoint(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "ftp://turingpi.local"} {
		if _, err := parseTuringPiEndpoint(bad); err == nil {
			t.Errorf("parseTuringPiEndpoint(%q) should fail", bad)
		}
	}
}

func TestParseTuringPiMap(t *testing.T) {
	got, err := parseTuringPiMap("tp-cp1:1, tp-n1:2")
	if err != nil {
		t.Fatalf("parseTuringPiMap: %v", err)
	}
	if got["tp-cp1"] != 1 || got["tp-n1"] != 2 {
		t.Errorf("parseTuringPiMap = %v", got)
	}
	for _, bad := range []string{"", "tp-cp1", "tp-cp1:x", "a:1,a:2"} {
		if _, err := parseTuringPiMap(bad); err == nil {
			t.Errorf("parseTuringPiMap(%q) should fail", bad)
		}
	}
}

// SOL is refused rather than half-implemented: the BMC's UART is a
// polled ~16 KB ring that cannot honour the boot-capture use case.
func TestTuringPiSOLRefused(t *testing.T) {
	_, srv := newFakeBMC(t, nil)
	b := testBackend(t, srv, map[string]int{"tp-cp1": 1})
	if _, err := b.OpenSOL(context.Background(), "tp-cp1", "sess"); err == nil {
		t.Fatal("expected OpenSOL to refuse until it is implemented")
	}
}

func TestTuringPiRegisteredInBothPaths(t *testing.T) {
	found := false
	for _, n := range Names() {
		if n == "turingpi" {
			found = true
		}
	}
	if !found {
		t.Errorf("turingpi missing from the env-path registry: %v", Names())
	}
	// The settings path must recognise the kind (construction fails on
	// config, which is fine — the error must not be "unknown backend").
	_, err := NewFromSelection("turingpi", []byte(`{"endpoint":"","user":""}`), t.TempDir())
	if err == nil {
		t.Fatal("expected empty selection to fail validation")
	}
	if strings.Contains(err.Error(), "unknown backend") {
		t.Errorf("settings path does not know turingpi: %v", err)
	}
}

// A .local endpoint must not be handed straight to the OS resolver. The
// BMC is addressed by name everywhere — the Settings placeholder, the
// public guide, and the design doc all say to use `turingpi.local`,
// because the board takes DHCP and a lease is not an identity. The
// driver nonetheless used a plain transport until 2026-07-28, so the one
// address form we recommend was the one that could not connect; it went
// unnoticed because every bench run used a literal IP. This pins that
// the driver dials through the mDNS-aware path.
func TestTuringPiDialsLocalNamesViaMDNS(t *testing.T) {
	b, err := NewTuringPiBackend(TuringPiOptions{
		Endpoint:           "turingpi.local",
		User:               "root",
		Targets:            map[string]int{"cp-1": 1},
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	tr, ok := b.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected an *http.Transport")
	}
	if tr.DialContext == nil {
		t.Fatal("no DialContext — .local endpoints would go to the OS resolver, which cannot resolve them on the appliance")
	}
}

// The probe renders digests the way `openssl x509 -fingerprint` does, so
// an operator comparing what the UI shows against what they ran by hand
// sees the same string rather than having to squint at case and colons.
func TestDisplayFingerprintMatchesOpensslForm(t *testing.T) {
	got := displayFingerprint("417c1eeab9427f10")
	want := "41:7C:1E:EA:B9:42:7F:10"
	if got != want {
		t.Errorf("displayFingerprint = %q, want %q", got, want)
	}
	if displayFingerprint("") != "" {
		t.Error("empty digest should render empty, not a stray colon")
	}
}
