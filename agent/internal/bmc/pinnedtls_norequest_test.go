package bmc

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// requestRecorder is a TLS listener that writes down every request that
// reaches it: the request line and the Authorization header, if any. It is the
// board's side of the wire, so what it saw is what the board would have seen.
type requestRecorder struct {
	mu     sync.Mutex
	lines  []string
	auths  []string
	server *httptest.Server
}

func newRequestRecorder(t *testing.T) *requestRecorder {
	t.Helper()
	rec := &requestRecorder{}
	rec.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.lines = append(rec.lines, r.Method+" "+r.URL.RequestURI()+" "+r.Proto)
		if a := r.Header.Get("Authorization"); a != "" {
			rec.auths = append(rec.auths, a)
		}
		rec.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":[{"result":[{"node1":"1","node2":"0","node3":"0","node4":"0"}]}]}`))
	}))
	// The refused handshake is expected; keep the server's note about it out
	// of the test output.
	rec.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	rec.server.StartTLS()
	t.Cleanup(rec.server.Close)
	return rec
}

func (r *requestRecorder) seen() (lines, auths []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...), append([]string(nil), r.auths...)
}

// The property #548 exists for: when the certificate does not match the pin,
// the device password never leaves this machine. Not "the call fails" — a call
// can fail AFTER the request, and its Basic header, has already been sent. So
// the assertion is made on the server's side of the wire: zero requests, zero
// Authorization headers. The correct-pin run is the control that proves the
// recorder would have seen them (geekdojo/geekdojo-brain#548).
func TestTuringPiSendsNothingToAServerThatFailsThePin(t *testing.T) {
	const pass = "SENTINEL-DUMMY-BMC-PASSWORD"
	rec := newRequestRecorder(t)
	rightPin := proto.DevicePinForCert(rec.server.Certificate())
	wrongPin := proto.DevicePinForSPKI([]byte("some-other-board"))

	query := func(t *testing.T, pin string) error {
		t.Helper()
		be, err := NewTuringPiBackend(TuringPiOptions{
			Endpoint: rec.server.URL,
			User:     "root",
			Pass:     pass,
			Pin:      pin,
			Targets:  map[string]int{"node-1": 1},
		})
		if err != nil {
			t.Fatalf("NewTuringPiBackend: %v", err)
		}
		_, _, err = be.Power(context.Background(), "node-1", proto.BMCPowerQuery)
		return err
	}

	t.Run("wrong pin", func(t *testing.T) {
		err := query(t, wrongPin)
		// The wire first: this is the property, the error text is the UX.
		lines, auths := rec.seen()
		if len(lines) != 0 || len(auths) != 0 {
			t.Errorf("the server saw %d request(s) and %d Authorization header(s) past a failed pin, want 0 and 0: %q",
				len(lines), len(auths), lines)
		}
		if err == nil {
			t.Fatal("a certificate that does not match the pin must be refused")
		}
		if !strings.Contains(err.Error(), "does not match the pin") {
			t.Errorf("the refusal must name the pin; got %q", err)
		}
		if strings.Contains(err.Error(), pass) {
			t.Errorf("the refusal must not carry the password; got %q", err)
		}
	})

	t.Run("correct pin (control)", func(t *testing.T) {
		if err := query(t, rightPin); err != nil {
			t.Fatalf("the pinned key must connect: %v", err)
		}
		lines, auths := rec.seen()
		if len(lines) != 1 || !strings.HasPrefix(lines[0], "GET /api/bmc?") {
			t.Fatalf("the recorder must see the one power query; saw %q", lines)
		}
		if len(auths) != 1 || !strings.HasPrefix(auths[0], "Basic ") {
			t.Fatalf("the recorder must see the Basic Authorization header; saw %d: %q", len(auths), auths)
		}
	})
}
