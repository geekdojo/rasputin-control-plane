package tailscale

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func writeFile755(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o755)
}

// startNATS spins up an in-process NATS server and returns a connected client.
func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	opts := &natsserver.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
	}
	ns, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("nats new server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(2 * time.Second) {
		t.Fatal("nats not ready in 2s")
	}
	t.Cleanup(func() {
		ns.Shutdown()
		ns.WaitForShutdown()
	})
	nc, err := nats.Connect("", nats.InProcessServer(ns))
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func request[T any](t *testing.T, nc *nats.Conn, subj string, cmd any, out *T) {
	t.Helper()
	payload, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	msg, err := nc.Request(subj, payload, 2*time.Second)
	if err != nil {
		t.Fatalf("request %s: %v", subj, err)
	}
	if err := json.Unmarshal(msg.Data, out); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
}

func newRegistered(t *testing.T) (*nats.Conn, *MockBackend) {
	t.Helper()
	nc := startNATS(t)
	mb, err := NewMockBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	subs, err := RegisterHandlers(nc, "node-1", mb)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})
	return nc, mb
}

func TestRegisterHandlers_EnrollHappyPath(t *testing.T) {
	nc, mb := newRegistered(t)

	var ack proto.MeshEnrollAck
	request(t, nc, proto.MeshEnrollSubject("node-1"), proto.MeshEnrollCmd{
		LoginServer:     "http://headscale.example",
		AuthKey:         "tskey-auth-xxxx",
		Hostname:        "node-1",
		AdvertiseRoutes: []string{"10.0.0.0/24"},
		AcceptDNS:       true,
		AcceptRoutes:    true,
	}, &ack)
	if !ack.OK {
		t.Fatalf("ack: %+v", ack)
	}
	if ack.Hostname != "node-1" {
		t.Errorf("hostname: %q", ack.Hostname)
	}
	if ack.Backend != "mock" {
		t.Errorf("backend: %q", ack.Backend)
	}
	if len(ack.Routes) != 1 || ack.Routes[0] != "10.0.0.0/24" {
		t.Errorf("routes: %+v", ack.Routes)
	}

	// Mock state persisted.
	st, _ := mb.Status(context.Background())
	if !st.Enrolled {
		t.Error("backend not enrolled after handler call")
	}
}

func TestRegisterHandlers_EnrollBadCmd(t *testing.T) {
	nc, _ := newRegistered(t)
	msg, err := nc.Request(proto.MeshEnrollSubject("node-1"), []byte("not-json"), 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.MeshEnrollAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ack.OK {
		t.Error("expected OK=false on bad cmd")
	}
}

func TestRegisterHandlers_EnrollBackendError(t *testing.T) {
	// Empty auth key triggers the mock backend's "empty auth key" error path.
	nc, _ := newRegistered(t)
	var ack proto.MeshEnrollAck
	request(t, nc, proto.MeshEnrollSubject("node-1"), proto.MeshEnrollCmd{
		LoginServer: "http://hs.example",
		AuthKey:     "", // intentionally empty
		Hostname:    "n",
	}, &ack)
	if ack.OK {
		t.Error("expected OK=false on backend error")
	}
	if ack.Backend != "mock" {
		t.Errorf("backend: %q", ack.Backend)
	}
}

func TestRegisterHandlers_LeaveHappyPath(t *testing.T) {
	nc, mb := newRegistered(t)
	// Seed by enrolling.
	if _, err := mb.Enroll(context.Background(), EnrollInput{
		AuthKey: "k", Hostname: "h",
	}); err != nil {
		t.Fatalf("seed enroll: %v", err)
	}
	var ack proto.MeshLeaveAck
	request(t, nc, proto.MeshLeaveSubject("node-1"), proto.MeshLeaveCmd{}, &ack)
	if !ack.OK {
		t.Errorf("leave ack: %+v", ack)
	}
	st, _ := mb.Status(context.Background())
	if st.Enrolled {
		t.Error("backend should not be enrolled after leave")
	}
}

func TestRegisterHandlers_StatusHappyPath(t *testing.T) {
	nc, _ := newRegistered(t)
	var ack proto.MeshStatusAck
	request(t, nc, proto.MeshStatusSubject("node-1"), proto.MeshStatusCmd{}, &ack)
	if !ack.OK {
		t.Errorf("status ack: %+v", ack)
	}
	if ack.Backend != "mock" {
		t.Errorf("backend: %q", ack.Backend)
	}
}

// errBackend errors from every method, exercising error branches.
type errBackend struct{}

func (errBackend) Name() string { return "errmock" }
func (errBackend) Enroll(_ context.Context, _ EnrollInput) (Status, error) {
	return Status{}, errStr("enroll bad")
}
func (errBackend) Leave(_ context.Context) error { return errStr("leave bad") }
func (errBackend) Status(_ context.Context) (Status, error) {
	return Status{}, errStr("status bad")
}

type errStr string

func (e errStr) Error() string { return string(e) }

func TestRegisterHandlers_AllErrorPaths(t *testing.T) {
	nc := startNATS(t)
	subs, err := RegisterHandlers(nc, "node-1", errBackend{})
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})

	var eack proto.MeshEnrollAck
	request(t, nc, proto.MeshEnrollSubject("node-1"), proto.MeshEnrollCmd{AuthKey: "x"}, &eack)
	if eack.OK {
		t.Error("enroll OK on error backend")
	}
	if eack.Backend != "errmock" {
		t.Errorf("enroll backend tag: %q", eack.Backend)
	}

	var lack proto.MeshLeaveAck
	request(t, nc, proto.MeshLeaveSubject("node-1"), proto.MeshLeaveCmd{}, &lack)
	if lack.OK {
		t.Error("leave OK on error backend")
	}

	var sack proto.MeshStatusAck
	request(t, nc, proto.MeshStatusSubject("node-1"), proto.MeshStatusCmd{}, &sack)
	if sack.OK {
		t.Error("status OK on error backend")
	}
	if sack.Backend != "errmock" {
		t.Errorf("status backend tag: %q", sack.Backend)
	}
}

// TestNewRealBackend_NoCLI exercises the LookPath-failure branch in
// NewRealBackend without requiring tailscale to be installed.
func TestNewRealBackend_NoCLI(t *testing.T) {
	t.Setenv("PATH", "")
	_, err := NewRealBackend()
	if err == nil {
		t.Error("expected NewRealBackend to fail with empty PATH")
	}
}

// TestRealBackend_NameAndEnrollValidation exercises pure (non-shell-out)
// branches of the real backend so the constructor and early-return validation
// in Enroll get coverage without requiring the tailscale CLI.
func TestRealBackend_NameAndEnrollValidation(t *testing.T) {
	b := &RealBackend{binary: "/nonexistent/tailscale"}
	if b.Name() != "tailscale" {
		t.Errorf("Name: %q want tailscale", b.Name())
	}
	if _, err := b.Enroll(context.Background(), EnrollInput{LoginServer: "", AuthKey: ""}); err == nil {
		t.Error("Enroll should reject empty LoginServer/AuthKey")
	}
	if _, err := b.Enroll(context.Background(), EnrollInput{LoginServer: "x", AuthKey: ""}); err == nil {
		t.Error("Enroll should reject empty AuthKey")
	}
}

// fakeTSBin writes a shell script to a temp dir that emulates the tailscale
// CLI. mode controls behavior: "ok-status" returns valid JSON from `status`,
// "fail" returns non-zero exit, "ok" returns success with no output. Returns
// the binary's absolute path. Skipped on Windows since the shim is /bin/sh.
func fakeTSBin(t *testing.T, mode string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary shim is /bin/sh; skipped on Windows")
	}
	dir := t.TempDir()
	path := dir + "/tailscale"
	var body string
	switch mode {
	case "ok-status":
		// `status --json` must emit JSON; any other subcommand exits 0.
		body = `#!/bin/sh
case "$1" in
  status)
    echo '{"Self":{"ID":"abc","HostName":"node-1","TailscaleIPs":["100.64.0.1"],"PrimaryRoutes":["10.0.0.0/24"],"Online":true},"Peer":{},"BackendState":"Running"}'
    ;;
  *)
    exit 0
    ;;
esac
`
	case "fail":
		body = `#!/bin/sh
echo "fake-failure" >&2
exit 2
`
	default:
		body = `#!/bin/sh
exit 0
`
	}
	if err := writeExecutable(path, body); err != nil {
		t.Fatalf("writeExecutable: %v", err)
	}
	return path
}

func writeExecutable(path, body string) error {
	return writeFile755(path, body)
}

func TestRealBackend_StatusWithFakeBinary(t *testing.T) {
	bin := fakeTSBin(t, "ok-status")
	b := &RealBackend{binary: bin}
	st, err := b.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Enrolled {
		t.Error("expected enrolled=true for BackendState=Running")
	}
	if st.Hostname != "node-1" {
		t.Errorf("hostname: %q", st.Hostname)
	}
	if st.TailnetIP != "100.64.0.1" {
		t.Errorf("ip: %q", st.TailnetIP)
	}
	if st.TailnetID != "abc" {
		t.Errorf("id: %q", st.TailnetID)
	}
}

func TestRealBackend_StatusBinaryFailure(t *testing.T) {
	bin := fakeTSBin(t, "fail")
	b := &RealBackend{binary: bin}
	if _, err := b.Status(context.Background()); err == nil {
		t.Error("expected error when fake tailscale exits non-zero")
	}
}

func TestRealBackend_LeaveSuccessAndFailure(t *testing.T) {
	okBin := fakeTSBin(t, "ok")
	b := &RealBackend{binary: okBin}
	if err := b.Leave(context.Background()); err != nil {
		t.Errorf("Leave with ok binary: %v", err)
	}

	failBin := fakeTSBin(t, "fail")
	b2 := &RealBackend{binary: failBin}
	if err := b2.Leave(context.Background()); err == nil {
		t.Error("Leave should error when fake binary exits non-zero")
	}
}

func TestRealBackend_EnrollSuccessAndFailureViaFakeBin(t *testing.T) {
	// On `ok-status` mode the fake binary returns success for `up` and a
	// valid JSON document for `status --json`. So Enroll's whole happy path
	// runs end-to-end without a real tailscaled.
	bin := fakeTSBin(t, "ok-status")
	b := &RealBackend{binary: bin}
	st, err := b.Enroll(context.Background(), EnrollInput{
		LoginServer:     "http://hs.example",
		AuthKey:         "tskey",
		Hostname:        "node-1",
		AdvertiseRoutes: []string{"10.0.0.0/24"},
		AcceptDNS:       true,
		AcceptRoutes:    true,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if !st.Enrolled {
		t.Error("Enroll: status not enrolled")
	}

	failBin := fakeTSBin(t, "fail")
	b2 := &RealBackend{binary: failBin}
	if _, err := b2.Enroll(context.Background(), EnrollInput{
		LoginServer: "x", AuthKey: "y",
	}); err == nil {
		t.Error("Enroll should error when `up` exits non-zero")
	}
}
