package bmc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

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

// Colon-separated display form is what the UI shows and hands back, so
// the gate has to accept it rather than only raw hex.
func TestProbeAcceptsTheDisplayFingerprintForm(t *testing.T) {
	if _, err := normalizeFingerprint("41:7C:1E:EA:B9:42:7F:10:33:63:4C:7A:F2:D2:DD:F1:E8:75:8A:92:26:CE:1F:63:3F:E1:FF:D5:11:0F:B9:E1"); err != nil {
		t.Fatalf("the form shown to operators must normalize: %v", err)
	}
}
