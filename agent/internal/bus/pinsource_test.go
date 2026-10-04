package bus

// The pin sources (geekdojo/geekdojo-brain#669): a pin fixed for the life of
// the process, and the controlplane's own pin file, read again on every TLS
// handshake so a running agent follows a bus key an identity restore put
// back.

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
)

// replacePin rewrites a pin file the way the api does (atrest.replace): a
// temp file renamed over it, so a reader never sees it half-written.
func replacePin(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// TC-669-01: a static pin answers the same value, and no error, every time.
func TestStaticPin_AnswersTheSamePinEveryTime(t *testing.T) {
	k := testPin(t)
	src := StaticPin(k)
	for i := range 3 {
		got, err := src()
		if err != nil || got != k {
			t.Fatalf("call %d = (%q, %v), want (%q, nil)", i, got, err, k)
		}
	}
}

// TC-669-02: PinFile reads the file on every call, so it follows a rewrite.
func TestPinFile_FollowsARewrittenFile(t *testing.T) {
	k2, k1 := mustPin(t, newKey(t)), mustPin(t, newKey(t))
	path := filepath.Join(t.TempDir(), "agent.pin")
	replacePin(t, path, k2+"\n")
	src := PinFile(path)
	if got, err := src(); err != nil || got != k2 {
		t.Fatalf("first call = (%q, %v), want (%q, nil)", got, err, k2)
	}
	replacePin(t, path, k1+"\n")
	if got, err := src(); err != nil || got != k1 {
		t.Fatalf("after the rewrite = (%q, %v), want (%q, nil)", got, err, k1)
	}
}

// TC-669-03: every shape of unusable pin file is an error naming the path, and
// no pin (resolver R39 in .github/security-resolvers.tsv). Absent is an error
// too: PinFile is only ever chosen for a file that held a pin at start. There
// is no probe behind PinFile, so the gate's probe-error case does not apply.
func TestPinFile_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	for name, put := range map[string]func(path string) error{
		"absent":     func(string) error { return nil },
		"empty":      func(p string) error { return os.WriteFile(p, nil, 0o644) },
		"whitespace": func(p string) error { return os.WriteFile(p, []byte(" \n\t\n"), 0o644) },
		"malformed":  func(p string) error { return os.WriteFile(p, []byte("sha256/short\n"), 0o644) },
		"unreadable": func(p string) error { return os.MkdirAll(p, 0o700) }, // a directory where the file should be
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.pin")
			if err := put(path); err != nil {
				t.Fatal(err)
			}
			got, err := PinFile(path)()
			if err == nil {
				t.Fatalf("PinFile(%s) = %q with no error, want an error", name, got)
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error %q does not name the path %s", err, path)
			}
			if got != "" {
				t.Errorf("pin %q returned alongside an error, want none", got)
			}
		})
	}
}

// TC-669-04: only a pin that came from the controlplane's own file is read
// again; every other source answers the pin resolved at start, whatever the
// controlplane file says later. The env case is a controlplane seeded with
// RASPUTIN_BUS_PIN.
func TestPinSourceFor_OnlyTheControlplaneFileIsReadAgain(t *testing.T) {
	k2, k1 := mustPin(t, newKey(t)), mustPin(t, newKey(t))
	for _, tc := range []struct {
		r    Resolution
		want string
	}{
		{r: Resolution{Pin: k2, Source: "controlplane"}, want: k1},
		{r: Resolution{Pin: k2, Source: "env"}, want: k2},
		{r: Resolution{Pin: k2, Source: "file"}, want: k2},
		{r: Resolution{}, want: ""},
	} {
		t.Run("source="+tc.r.Source, func(t *testing.T) {
			cp := filepath.Join(t.TempDir(), "agent.pin")
			replacePin(t, cp, k2+"\n")
			src := PinSourceFor(tc.r, cp)
			replacePin(t, cp, k1+"\n")
			got, err := src()
			if err != nil || got != tc.want {
				t.Fatalf("PinSourceFor(%+v) after the rewrite = (%q, %v), want (%q, nil)", tc.r, got, err, tc.want)
			}
		})
	}
}

// TC-669-05: New still fails closed at start, whatever the source.
func TestNew_RefusesEveryPinSourceWithNoUsablePin(t *testing.T) {
	for name, src := range map[string]PinSource{
		"nil source":       nil,
		"source fails":     func() (string, error) { return "", errors.New("no pin here") },
		"malformed answer": StaticPin("sha256/short"),
	} {
		t.Run(name, func(t *testing.T) {
			c, err := New(Config{URL: "nats://127.0.0.1:1", NodeID: testNode, Pin: src, Log: discard()})
			if c != nil || err == nil || !strings.Contains(err.Error(), "a bus pin is required") {
				t.Fatalf("New = (%v, %v), want no Client and an error saying a bus pin is required", c, err)
			}
		})
	}
	c, err := New(Config{URL: "nats://127.0.0.1:1", NodeID: testNode, Pin: StaticPin(testPin(t)), Log: discard()})
	if c == nil || err != nil {
		t.Fatalf("New with a valid pin = (%v, %v), want a Client", c, err)
	}
}

// startBusOnKey runs a TLS-required bus at port serving a key of the test's
// choosing: a controlplane that came back on another bus key.
func startBusOnKey(t *testing.T, port int, cert tls.Certificate) *natsserver.Server {
	t.Helper()
	return runServer(t, &natsserver.Options{
		Host: "127.0.0.1", Port: port, Username: testNode, Password: "tok-A",
		TLSConfig:  &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}},
		TLSTimeout: 5,
	})
}

// TC-669-06: the restore, on the agent's side. The same Client, connected on
// K2, refuses the server once it comes back on K1 while the file still says
// K2; once the file is rewritten to K1 the SAME connection reconnects — no
// re-dial, no restart — and the change of pin is logged once.
func TestClient_FollowsARewrittenPinFileWithNoRedial(t *testing.T) {
	k2 := testPin(t) // what startBus serves
	k1Key := newKey(t)
	k1 := mustPin(t, k1Key)
	path := filepath.Join(t.TempDir(), "agent.pin")
	replacePin(t, path, k2+"\n")

	s1 := startBus(t, -1, testNode, "tok-A")
	port := portOf(t, s1)
	tc := newTestClientWithPin(t, natsURL(t, s1), "tok-A", PinFile(path))
	if err := tc.Dial(); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	first := tc.Conn()
	stopServer(s1)

	// (1) The controlplane is back on K1; the file still says K2.
	s2 := startBusOnKey(t, port, alwaysValid(t, k1Key))
	waitFor(t, "three refused reconnect attempts", 20*time.Second, func() bool { return connAttempts(t, s2) >= 3 })
	waitFor(t, "the refusal in the log", 10*time.Second, func() bool {
		return len(tc.logs.records("refused the bus server's key")) > 0
	})
	refusals := tc.logs.records("refused the bus server's key")
	if len(refusals) != 1 {
		t.Fatalf("%d refusal records for one repeated error, want 1", len(refusals))
	}
	if refusals[0].Level != slog.LevelWarn {
		t.Errorf("refusal level = %s, want WARN", refusals[0].Level)
	}
	if v, _ := attr(refusals[0], "pin"); v.String() != k2 {
		t.Errorf("refusal pin = %q, want K2 %q", v, k2)
	}
	if v, _ := attr(refusals[0], "err"); !strings.Contains(v.String(), "does not match RASPUTIN_BUS_PIN") {
		t.Errorf("refusal err = %q, want the pin mismatch", v)
	}
	if first.IsConnected() {
		t.Fatal("the client joined a bus serving a key its pin file does not name")
	}
	before := tc.connected.Load()

	// (2) The api's start rewrites the file.
	replacePin(t, path, k1+"\n")
	waitFor(t, "the reconnect on K1", 20*time.Second, func() bool { return tc.connected.Load() > before })
	if tc.Redials() != 0 || tc.Conn() != first || !first.IsConnected() {
		t.Fatalf("redials=%d sameConn=%v connected=%v: want the same connection back, no re-dial",
			tc.Redials(), tc.Conn() == first, first.IsConnected())
	}

	// (3) One INFO, naming both pins.
	changes := tc.logs.records("the bus pin changed")
	if len(changes) != 1 {
		t.Fatalf("%d pin-change records, want 1", len(changes))
	}
	r := changes[0]
	if r.Level != slog.LevelInfo {
		t.Errorf("pin-change level = %s, want INFO", r.Level)
	}
	for key, want := range map[string]string{"node_id": testNode, "old_pin": k2, "new_pin": k1} {
		if v, ok := attr(r, key); !ok || v.String() != want {
			t.Errorf("pin-change %s = %q (present %v), want %q", key, v, ok, want)
		}
	}
}

// TC-669-07: a pin file that turns unusable while the agent runs fails
// CLOSED. The controlplane comes back on the SAME key, but with no usable pin
// the handshake is refused before the CONNECT: the server never sees the join
// token. The refusal is one WARN naming the file, the client keeps retrying
// without closing, and once the file is good again the same connection
// rejoins.
func TestClient_AnUnusablePinFileRefusesTheHandshake(t *testing.T) {
	for name, spoil := range map[string]func(path string) error{
		"deleted":   os.Remove,
		"emptied":   func(p string) error { return os.WriteFile(p, nil, 0o644) },
		"malformed": func(p string) error { return os.WriteFile(p, []byte("sha256/short\n"), 0o644) },
	} {
		t.Run(name, func(t *testing.T) {
			pin := testPin(t)
			path := filepath.Join(t.TempDir(), "agent.pin")
			replacePin(t, path, pin+"\n")
			s1 := startBusWith(t, &natsserver.Options{CustomClientAuthentication: &recordingAuth{}})
			port, url := portOf(t, s1), natsURL(t, s1)
			tc := newTestClientWithPin(t, url, "tok-A", PinFile(path))
			if err := tc.Dial(); err != nil {
				t.Fatalf("Dial: %v", err)
			}
			first := tc.Conn()
			stopServer(s1)

			if err := spoil(path); err != nil {
				t.Fatal(err)
			}
			seen := &recordingAuth{}
			s2 := startBusWith(t, &natsserver.Options{Port: port, CustomClientAuthentication: seen})
			waitFor(t, "three refused reconnect attempts", 20*time.Second, func() bool { return connAttempts(t, s2) >= 3 })
			waitFor(t, "the refusal in the log", 10*time.Second, func() bool {
				return len(tc.logs.records("refused the bus server's key")) > 0
			})
			if _, _, n := seen.last(); n != 0 {
				t.Fatalf("the server saw %d CONNECTs with no usable pin; the join token must never be sent", n)
			}
			refusals := tc.logs.records("refused the bus server's key")
			if len(refusals) != 1 {
				t.Fatalf("%d refusal records for one repeated error, want 1", len(refusals))
			}
			r := refusals[0]
			if r.Level != slog.LevelWarn {
				t.Errorf("refusal level = %s, want WARN", r.Level)
			}
			for key, want := range map[string]string{"node_id": testNode, "url": url, "pin": pin} {
				if v, ok := attr(r, key); !ok || v.String() != want {
					t.Errorf("refusal %s = %q (present %v), want %q", key, v, ok, want)
				}
			}
			if v, _ := attr(r, "err"); !strings.Contains(v.String(), path) {
				t.Errorf("refusal err = %q, want it to name %s", v, path)
			}
			if first.IsClosed() || tc.Redials() != 0 {
				t.Fatalf("closed=%v redials=%d: the client must keep retrying on the same connection", first.IsClosed(), tc.Redials())
			}
			before := tc.connected.Load()

			replacePin(t, path, pin+"\n")
			waitFor(t, "the reconnect once the file is good", 20*time.Second, func() bool { return tc.connected.Load() > before })
			if tc.Conn() != first || tc.Redials() != 0 {
				t.Fatalf("sameConn=%v redials=%d: want the same connection back", tc.Conn() == first, tc.Redials())
			}
			if _, _, n := seen.last(); n == 0 {
				t.Fatal("the reconnect never reached the server's auth")
			}
		})
	}
}
