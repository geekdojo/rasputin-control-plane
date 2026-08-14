package bmc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// slotConsoleBoard fakes a Turing Pi for detectSlots: it reports the given
// per-slot power ("0"/"1") and, for a slot's authenticated UART read, returns
// the console text keyed by 0-based node value. detectSlots drives it via the
// low-level readPower/get, so this is the whole board it needs.
func slotConsoleBoard(t *testing.T, power map[int]string, uartByNode map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case q.Get("type") == "power":
			var sb strings.Builder
			sb.WriteString(`{"response":[{"result":[{`)
			for slot := 1; slot <= 4; slot++ {
				if slot > 1 {
					sb.WriteString(",")
				}
				v := power[slot]
				if v == "" {
					v = "0"
				}
				sb.WriteString(`"node` + itoa(slot) + `":"` + v + `"`)
			}
			sb.WriteString(`}]}]}`)
			_, _ = w.Write([]byte(sb.String()))
		case q.Get("type") == "uart":
			txt := uartByNode[q.Get("node")]
			// json-escape the minimum we use (\r, \n, ").
			esc := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\r", "\\r", "\n", "\\n").Replace(txt)
			_, _ = w.Write([]byte(`{"response":[{"uart":"` + esc + `"}]}`))
		default:
			_, _ = w.Write([]byte(`{"response":[{"result":"ok"}]}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// detectSlots is what turns "there is a board here" into "node tp-cp1 is in
// slot 1" — the identification the whole probe exists for. Its every branch was
// NOT COVERED. This drives all four slots through the states an operator sees:
// a powered slot whose console shows the current login prompt (after a stale
// one — last prompt wins), a booting slot (empty console), a running-but-not-
// Rasputin slot (no prompt), and a powered-off slot (never read).
//
// Kills the following survivors in probe.go detectSlots:
//   - 255:36 CONDITIONALS_BOUNDARY (`slot <= max` → `<`) and CONDITIONALS_NEGATION
//     (`<=` → `>`): both change the slot count away from 4.
//   - 257:11 CONDITIONALS_NEGATION (`perr == nil` → `!=`): Powered would never be set.
//   - 258:28 CONDITIONALS_NEGATION (`power[slot] == On` → `!=`): a powered slot reads as off.
//   - 260:11 CONDITIONALS_NEGATION (`perr == nil && !Powered` → `perr != nil`): a
//     powered-off slot would be UART-read and mislabeled instead of reported off.
//   - 284:99 CONDITIONALS_BOUNDARY (`len(m) > 0` → `>= 0`, panics on the no-prompt
//     slot) and CONDITIONALS_NEGATION (`> 0` → `<= 0`, drops a real prompt).
//   - 288:25 ARITHMETIC_BASE (`m[len(m)-1]` → `m[len(m)+1]`, panics on two prompts).
//   - 289:37 CONDITIONALS_NEGATION (`TrimSpace(text) == ""` → `!=`): a booting slot
//     is mislabeled "no login prompt".
func TestDetectSlots_ReportsPerSlotIdentity(t *testing.T) {
	srv := slotConsoleBoard(t,
		map[int]string{1: "1", 2: "1", 3: "1", 4: "0"},
		map[string]string{
			"0": "tp-old login:\r\ntp-cp1 login: ", // slot 1: two prompts, last wins
			"1": "   ",                             // slot 2: empty → still booting
			"2": "panic: not a rasputin node here", // slot 3: no login prompt
			"3": "tp-n3 login: ",                   // slot 4: powered off — must NOT be read
		})
	b := testBackend(t, srv, map[string]int{"tp-cp1": 1})

	slots := detectSlots(context.Background(), b)

	if len(slots) != 4 {
		t.Fatalf("detectSlots returned %d slots, want 4 (one per node)", len(slots))
	}
	// Slot 1: powered, current login prompt wins over the stale one.
	if !slots[0].Powered {
		t.Errorf("slot 1 Powered = false, want true")
	}
	if slots[0].Hostname != "tp-cp1" {
		t.Errorf("slot 1 Hostname = %q, want tp-cp1 (the most recent login prompt)", slots[0].Hostname)
	}
	// Slot 2: powered, empty console → booting, no hostname.
	if !slots[1].Powered || slots[1].Hostname != "" {
		t.Errorf("slot 2 = %+v, want powered with no hostname", slots[1])
	}
	if !strings.Contains(slots[1].Detail, "booting") {
		t.Errorf("slot 2 Detail = %q, want it to mention still booting", slots[1].Detail)
	}
	// Slot 3: powered, non-Rasputin console → no prompt, no hostname.
	if slots[2].Hostname != "" || !strings.Contains(slots[2].Detail, "no login prompt") {
		t.Errorf("slot 3 = %+v, want no hostname and a 'no login prompt' detail", slots[2])
	}
	// Slot 4: powered off → reported off, never UART-read, no hostname.
	if slots[3].Powered {
		t.Errorf("slot 4 Powered = true, want false")
	}
	if slots[3].Hostname != "" || !strings.Contains(slots[3].Detail, "powered off") {
		t.Errorf("slot 4 = %+v, want a powered-off detail and no hostname", slots[3])
	}
}

// unauthedBoard behaves the way a real Turing Pi BMC does before
// credentials exist: 401 with the marker the probe identifies on. That
// is exactly what an attacker would imitate to be flagged Identified, so
// it is the right shape to test the credential gate against.
func unauthedBoard(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("credentials were sent to an unaccepted board: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("no authorization header provided"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Credentials must never ride on a first-contact handshake.
//
// The credentialed half of the probe originally pinned to the digest
// captured moments earlier in the same call — a handshake made with
// verification disabled. That pin authorises whatever answered, so
// anyone able to answer for the board's mDNS name could present any
// certificate, return the 401 marker to look identified, and collect the
// operator's BMC account — which also serves SSH and controls power for
// every node in the chassis. Caught by the automated security review on
// CP #51 before any build shipped.
//
// These pin the gate rather than the plumbing: no accepted fingerprint,
// or one that does not match what the board is presenting now, means no
// credential leaves the node.
func TestProbeRefusesCredentialsWithoutAnAcceptedFingerprint(t *testing.T) {
	srv := unauthedBoard(t)

	res := Probe(context.Background(), proto.BMCProbeCmd{
		Kind:     "turingpi",
		Endpoint: srv.URL,
		User:     "root",
		Pass:     "hunter2",
		// Fingerprint deliberately absent — the operator has not
		// accepted anything yet.
	})
	if len(res.Slots) != 0 {
		t.Error("slot detection ran without an accepted certificate — that sends credentials to an unverified host")
	}
	if !strings.Contains(res.Detail, "confirm the certificate") {
		t.Errorf("detail should tell the operator what to do; got %q", res.Detail)
	}
}

func TestProbeRefusesCredentialsOnFingerprintMismatch(t *testing.T) {
	srv := unauthedBoard(t)

	res := Probe(context.Background(), proto.BMCProbeCmd{
		Kind:     "turingpi",
		Endpoint: srv.URL,
		User:     "root",
		Pass:     "hunter2",
		// An accepted fingerprint that is NOT what this host presents —
		// i.e. something else is answering for the board.
		Fingerprint: strings.Repeat("ab", 32),
	})
	if len(res.Slots) != 0 {
		t.Error("slot detection ran against a certificate the operator never accepted")
	}
	if !strings.Contains(res.Detail, "different certificate") {
		t.Errorf("a mismatch must be named as a trust failure; got %q", res.Detail)
	}
	if !strings.Contains(res.Detail, "No credentials were sent") {
		t.Errorf("the operator needs to know their password was not disclosed; got %q", res.Detail)
	}
}

// A 401 carrying the vendor marker must be reported as the recognised board
// with the "as expected" wording — the strongest identification the probe can
// make before credentials exist. Kills probe.go:132 CONDITIONALS_NEGATION
// (`StatusCode == StatusUnauthorized` → `!=`): under the mutation a 401+marker
// falls through to the plainer 401 case, so the detail changes from
// "responded 401 as expected" to "requiring authentication".
func TestProbeIdentifiesMarkedUnauthorizedAsExpected(t *testing.T) {
	srv := unauthedBoard(t) // 401 + "no authorization header provided"

	res := Probe(context.Background(), proto.BMCProbeCmd{
		Kind:     "turingpi",
		Endpoint: srv.URL,
		// No User: the probe stops after identification, before any
		// credentialed slot detection, so res.Detail is the switch verdict.
	})
	if !res.Identified {
		t.Fatalf("a 401 with the vendor marker must be Identified; got %+v", res)
	}
	if !strings.Contains(res.Detail, "responded 401 as expected") {
		t.Errorf("detail = %q, want the marked-401 wording (\"responded 401 as expected\")", res.Detail)
	}
}

// unmarkedUnauthorizedBoard answers 401 but WITHOUT the vendor marker body —
// some BMC / firmware simply demands auth with no recognisable phrase.
func unmarkedUnauthorizedBoard(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A 401 WITHOUT the marker is still treated as the board (something answered
// and demanded auth), but with the plainer wording. Kills probe.go:136
// CONDITIONALS_NEGATION (`StatusCode == StatusUnauthorized` → `!=`): under the
// mutation this 401 falls through to the default branch, so Identified flips to
// false and the detail becomes the "not how a Turing Pi responds" message.
func TestProbeIdentifiesUnmarkedUnauthorizedAsAuthRequired(t *testing.T) {
	srv := unmarkedUnauthorizedBoard(t)

	res := Probe(context.Background(), proto.BMCProbeCmd{
		Kind:     "turingpi",
		Endpoint: srv.URL,
	})
	if !res.Identified {
		t.Fatalf("a 401 without the marker must still be Identified as a board; got %+v", res)
	}
	if !strings.Contains(res.Detail, "requiring authentication") {
		t.Errorf("detail = %q, want the plain-401 wording (\"requiring authentication\")", res.Detail)
	}
}

// Colon-separated display form is what the UI shows and hands back, so
// the gate has to accept it rather than only raw hex.
func TestProbeAcceptsTheDisplayFingerprintForm(t *testing.T) {
	if _, err := normalizeFingerprint("41:7C:1E:EA:B9:42:7F:10:33:63:4C:7A:F2:D2:DD:F1:E8:75:8A:92:26:CE:1F:63:3F:E1:FF:D5:11:0F:B9:E1"); err != nil {
		t.Fatalf("the form shown to operators must normalize: %v", err)
	}
}
