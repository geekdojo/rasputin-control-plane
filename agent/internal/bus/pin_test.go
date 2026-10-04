package bus

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/server"
)

// --- pin sources -----------------------------------------------------------

func mustPin(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	pin, err := proto.BusPinForPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TC-517-07: the order is env, then the saved file, then the controlplane
// file — each alone, and in combination.
func TestResolvePin(t *testing.T) {
	envPin := mustPin(t, newKey(t))
	filePin := mustPin(t, newKey(t))
	dir := t.TempDir()
	file := PinFilePath(dir)

	// Nothing anywhere: no pin, no fault, and so no dial.
	r := ResolvePin("", file, "")
	if r.Pin != "" || r.Source != "" || len(r.Faults()) != 0 {
		t.Fatalf("empty: got %+v, want no pin and no fault", r)
	}
	writePin(t, file, filePin)
	// File only.
	if r := ResolvePin("", file, ""); r.Pin != filePin || r.Source != "file" {
		t.Fatalf("file: got %+v", r)
	}
	// Env wins over the file.
	if r := ResolvePin("  "+envPin+"\n", file, ""); r.Pin != envPin || r.Source != "env" {
		t.Fatalf("env: got %+v", r)
	}
	// A bad env pin is a fault and falls through to the file.
	r = ResolvePin("sha256/nope", file, "")
	if r.EnvErr == nil || r.FileErr != nil || r.Pin != filePin || r.Source != "file" {
		t.Fatalf("bad env: got %+v", r)
	}
	// A corrupt file is a fault and gives no pin.
	if err := os.WriteFile(file, []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r = ResolvePin("", file, "")
	if r.FileErr == nil || r.EnvErr != nil || r.Pin != "" || r.Source != "" {
		t.Fatalf("corrupt file: got %+v", r)
	}
}

// writePin puts a saved pin file where an older agent's delivery left it.
func writePin(t *testing.T, path, pin string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(pin+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TC-517-08: a bad env pin with nothing else to fall back on, and a pin file
// the node cannot read, each leave the node with no pin and a fault.
func TestResolvePin_NoPinWithNoUsableSource(t *testing.T) {
	dir := t.TempDir()
	file := PinFilePath(dir)

	r := ResolvePin("sha256/nope", file, "")
	if r.Pin != "" || r.EnvErr == nil {
		t.Fatalf("bad env alone: got %+v", r)
	}

	// A directory in the pin file's place is the portable way to make
	// os.ReadFile fail.
	blocked := filepath.Join(dir, "blocked-pin")
	if err := os.MkdirAll(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	r = ResolvePin("", blocked, "")
	if r.FileErr == nil || r.Pin != "" {
		t.Fatalf("unreadable file: got %+v, want no pin and a fault", r)
	}

	// Mode 000 is the other unreadable shape (not for root, which reads it).
	if os.Geteuid() != 0 {
		locked := filepath.Join(dir, "locked-pin")
		writePin(t, locked, mustPin(t, newKey(t)))
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		r = ResolvePin("", locked, "")
		if r.FileErr == nil || r.Pin != "" {
			t.Fatalf("mode-000 file: got %+v, want no pin and a fault", r)
		}
	}
}

// TC-517-07: the controlplane's own agent falls back to the file the api
// writes beside its bus key — last, after the seed and after a saved pin, and
// only when a path is given at all (every other role passes "").
func TestResolvePin_ControlplaneFile(t *testing.T) {
	envPin := mustPin(t, newKey(t))
	filePin := mustPin(t, newKey(t))
	cpPin := mustPin(t, newKey(t))
	dir := t.TempDir()
	file := PinFilePath(dir)
	cpFile := filepath.Join(dir, "agent.pin")
	writePin(t, cpFile, cpPin)

	if r := ResolvePin("", file, cpFile); r.Pin != cpPin || r.Source != "controlplane" {
		t.Fatalf("controlplane only: got %+v", r)
	}
	writePin(t, file, filePin)
	if r := ResolvePin("", file, cpFile); r.Pin != filePin || r.Source != "file" {
		t.Fatalf("a saved pin wins over the controlplane file: got %+v", r)
	}
	if r := ResolvePin(envPin, file, cpFile); r.Pin != envPin || r.Source != "env" {
		t.Fatalf("the seed wins over both: got %+v", r)
	}
	if err := os.WriteFile(cpFile, []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := ResolvePin("", filepath.Join(dir, "absent"), cpFile)
	if r.CPErr == nil || r.Pin != "" {
		t.Fatalf("corrupt controlplane file: got %+v", r)
	}
	// Missing files contribute nothing, and no fault.
	r = ResolvePin("", filepath.Join(dir, "absent"), filepath.Join(dir, "also-absent"))
	if r.Pin != "" || len(r.Faults()) != 0 {
		t.Fatalf("absent files: got %+v, want no pin and no fault", r)
	}
}

// TC-517-08: every shape each of the three sources can take, alone and in
// front of a good source (resolver R13 in .github/security-resolvers.tsv). The
// CLOSED outcome is a usable pin from the highest source that has one, and
// otherwise no pin — and a node with no pin does not dial. There is no probe
// behind ResolvePin, so the gate's probe-error case does not apply to it.
func TestResolvePin_FailsClosedOnEveryShapeOfInput(t *testing.T) {
	good := mustPin(t, newKey(t))
	const (
		absent = iota
		empty
		blank
		malformed
		unreadable
		valid
	)
	// file puts one shape of pin file at dir/name and returns its path.
	file := func(t *testing.T, dir, name string, shape int) string {
		t.Helper()
		path := filepath.Join(dir, name)
		var err error
		switch shape {
		case absent:
		case empty:
			err = os.WriteFile(path, nil, 0o644)
		case blank:
			err = os.WriteFile(path, []byte(" \n\t\n"), 0o644)
		case malformed:
			err = os.WriteFile(path, []byte("sha256/short\n"), 0o644)
		case unreadable:
			err = os.MkdirAll(path, 0o700) // a directory where the file should be
		case valid:
			err = os.WriteFile(path, []byte(good+"\n"), 0o644)
		}
		if err != nil {
			t.Fatal(err)
		}
		return path
	}
	envOf := map[int]string{absent: "", empty: "", blank: " \t\n", malformed: "sha256/nope", valid: good}

	for _, tc := range []struct {
		name         string
		env, pin, cp int
		noCPPath     bool // a node that is not the controlplane passes ""
		wantSource   string
		wantFaults   int
	}{
		{name: "never pinned anywhere", env: absent, pin: absent, cp: absent},
		{name: "never pinned, not the controlplane", env: absent, pin: absent, noCPPath: true},
		{name: "blank env is no env", env: blank, pin: absent, cp: absent},

		{name: "empty pin file", env: absent, pin: empty, cp: absent, wantFaults: 1},
		{name: "blank pin file", env: absent, pin: blank, cp: absent, wantFaults: 1},
		{name: "malformed pin file", env: absent, pin: malformed, cp: absent, wantFaults: 1},
		{name: "unreadable pin file", env: absent, pin: unreadable, cp: absent, wantFaults: 1},
		{name: "empty pin file, not the controlplane", env: absent, pin: empty, noCPPath: true, wantFaults: 1},

		{name: "empty controlplane file", env: absent, pin: absent, cp: empty, wantFaults: 1},
		{name: "blank controlplane file", env: absent, pin: absent, cp: blank, wantFaults: 1},
		{name: "malformed controlplane file", env: absent, pin: absent, cp: malformed, wantFaults: 1},
		{name: "unreadable controlplane file", env: absent, pin: absent, cp: unreadable, wantFaults: 1},

		{name: "malformed env alone", env: malformed, pin: absent, cp: absent, wantFaults: 1},
		{name: "malformed env, empty pin file", env: malformed, pin: empty, cp: absent, wantFaults: 2},
		{name: "every source present and unusable", env: malformed, pin: unreadable, cp: blank, wantFaults: 3},
		{name: "blank env does not mask an empty pin file", env: blank, pin: empty, cp: absent, wantFaults: 1},

		{name: "malformed env falls through to a good pin file", env: malformed, pin: valid, cp: absent, wantSource: "file", wantFaults: 1},
		{name: "empty pin file falls through to a good controlplane file", env: absent, pin: empty, cp: valid, wantSource: "controlplane", wantFaults: 1},
		{name: "unreadable pin file behind a good env", env: valid, pin: unreadable, cp: absent, wantSource: "env"},
		{name: "blank env, good pin file", env: blank, pin: valid, cp: absent, wantSource: "file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pinPath := file(t, dir, "pin", tc.pin)
			cpPath := ""
			if !tc.noCPPath {
				cpPath = file(t, dir, "agent.pin", tc.cp)
			}
			r := ResolvePin(envOf[tc.env], pinPath, cpPath)

			if r.Source != tc.wantSource {
				t.Fatalf("source %q, want %q: %+v", r.Source, tc.wantSource, r)
			}
			if tc.wantSource != "" && r.Pin != good {
				t.Fatalf("pin %q, want the good one: %+v", r.Pin, r)
			}
			if tc.wantSource == "" && r.Pin != "" {
				t.Fatalf("pin %q from no source: %+v", r.Pin, r)
			}
			if got := len(r.Faults()); got != tc.wantFaults {
				t.Fatalf("%d faults %v, want %d", got, r.Faults(), tc.wantFaults)
			}
		})
	}
}

// --- a TLS bus -------------------------------------------------------------

// selfSigned wraps k in a certificate valid from notBefore to notAfter — the
// same shape bustls.SelfSignedCert produces on the api (which this module
// cannot import).
func selfSigned(t *testing.T, k *ecdsa.PrivateKey, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rasputin-bus"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func alwaysValid(t *testing.T, k *ecdsa.PrivateKey) tls.Certificate {
	return selfSigned(t, k, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

// dialWithPin dials a TLS-required bus serving cert with a Client pinned to
// pin.
func dialWithPin(t *testing.T, cert tls.Certificate, pin string) (*Client, *natsserver.Server, error) {
	t.Helper()
	s := runServer(t, &natsserver.Options{
		Host: "127.0.0.1", Port: -1, Username: testNode, Password: "tok-A",
		TLSConfig:  &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}},
		TLSTimeout: 5,
	})
	c := mustNew(t, Config{URL: natsURL(t, s), NodeID: testNode, Pin: StaticPin(pin), Token: StaticToken("tok-A")})
	t.Cleanup(c.Close)
	return c, s, c.Dial()
}

// TC-517-04, TC-517-05: the pin decides, and nothing else does.
func TestClient_PinnedTLS(t *testing.T) {
	key := newKey(t)
	pin := mustPin(t, key)
	other := mustPin(t, newKey(t))

	// TC-517-04
	t.Run("wrong pin is refused", func(t *testing.T) {
		_, s, err := dialWithPin(t, alwaysValid(t, key), other)
		if err == nil || !strings.Contains(err.Error(), "does not match RASPUTIN_BUS_PIN") {
			t.Fatalf("Dial with the wrong pin = %v, want the pin mismatch", err)
		}
		// The server notices the aborted handshake on its own goroutine.
		waitFor(t, "the server to drop the refused connection", 5*time.Second, func() bool { return s.NumClients() == 0 })
	})

	// TC-517-04
	t.Run("right pin connects over TLS", func(t *testing.T) {
		c, _, err := dialWithPin(t, alwaysValid(t, key), pin)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if _, err := c.Conn().TLSConnectionState(); err != nil {
			t.Fatalf("connection is not TLS: %v", err)
		}
	})

	// TC-517-05: clock independence (#448 "a node that boots with a wrong
	// clock still joins the bus"): the check is the key, never the dates.
	for name, cert := range map[string]tls.Certificate{
		"certificate not valid until 2099": selfSigned(t, key, time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)),
		"certificate expired in 1991":      selfSigned(t, key, time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1991, 1, 1, 0, 0, 0, 0, time.UTC)),
	} {
		t.Run(name, func(t *testing.T) {
			c, _, err := dialWithPin(t, cert, pin)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			if _, err := c.Conn().TLSConnectionState(); err != nil {
				t.Fatalf("connection is not TLS: %v", err)
			}
		})
	}
}
