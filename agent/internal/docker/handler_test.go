package docker

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// startNATS spins up an in-process NATS server on a random port and returns
// a connected client. Both shut down on test cleanup.
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
	msg, err := nc.Request(subj, payload, 3*time.Second)
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
	b, err := NewMockBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	subs, err := RegisterHandlers(nc, "node-1", b)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})
	return nc, b
}

func TestRegisterHandlers_DeployHappyPath(t *testing.T) {
	nc, b := newRegistered(t)

	var ack proto.AppDeployAck
	request(t, nc, proto.AppDeploySubject("node-1"), proto.AppDeployCmd{
		AppID:       "app-1",
		Name:        "Whoami",
		ComposeYAML: "services: {whoami: {image: traefik/whoami}}\n",
	}, &ack)
	if !ack.OK {
		t.Errorf("deploy ack: %+v", ack)
	}
	if ack.Status != proto.AppStatusRunning {
		t.Errorf("status: %q", ack.Status)
	}

	// Backend recorded the deploy — status should now be running.
	status, _, err := b.Status(context.Background(), "app-1")
	if err != nil {
		t.Fatalf("backend Status: %v", err)
	}
	if status != proto.AppStatusRunning {
		t.Errorf("backend status: %q", status)
	}
}

func TestRegisterHandlers_DeployBadCmd(t *testing.T) {
	nc, _ := newRegistered(t)
	msg, err := nc.Request(proto.AppDeploySubject("node-1"), []byte("not-json"), 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.AppDeployAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ack.OK {
		t.Error("expected OK=false on bad cmd")
	}
	if ack.Status != proto.AppStatusFailed {
		t.Errorf("status: %q want failed", ack.Status)
	}
}

func TestRegisterHandlers_StopHappyPath(t *testing.T) {
	nc, _ := newRegistered(t)

	// Seed: deploy first.
	var dack proto.AppDeployAck
	request(t, nc, proto.AppDeploySubject("node-1"), proto.AppDeployCmd{
		AppID: "app-1", Name: "x", ComposeYAML: "services: {}\n",
	}, &dack)

	var ack proto.AppStopAck
	request(t, nc, proto.AppStopSubject("node-1"), proto.AppStopCmd{AppID: "app-1"}, &ack)
	if !ack.OK {
		t.Errorf("stop ack: %+v", ack)
	}
	if ack.Status != proto.AppStatusStopped {
		t.Errorf("status: %q", ack.Status)
	}
}

func TestRegisterHandlers_StopBadCmd(t *testing.T) {
	nc, _ := newRegistered(t)
	msg, err := nc.Request(proto.AppStopSubject("node-1"), []byte("not-json"), 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.AppStopAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ack.OK {
		t.Error("expected OK=false on bad cmd")
	}
}

func TestRegisterHandlers_StatusUnknownApp(t *testing.T) {
	nc, _ := newRegistered(t)
	var ack proto.AppStatusAck
	request(t, nc, proto.AppStatusSubject("node-1"), proto.AppStatusCmd{AppID: "never-deployed"}, &ack)
	if ack.AppID != "never-deployed" {
		t.Errorf("appId: %q", ack.AppID)
	}
	if ack.Status != proto.AppStatusStopped {
		t.Errorf("status: %q (mock backend returns stopped for unknown)", ack.Status)
	}
}

func TestRegisterHandlers_StatusBadCmd(t *testing.T) {
	nc, _ := newRegistered(t)
	msg, err := nc.Request(proto.AppStatusSubject("node-1"), []byte("not-json"), 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var ack proto.AppStatusAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ack.Status != proto.AppStatusUnknown {
		t.Errorf("status: %q want unknown", ack.Status)
	}
}

// errBackend implements Backend and errors from every method, exercising the
// handlers' error branches.
type errBackend struct{}

func (errBackend) Name() string { return "err" }
func (errBackend) Deploy(_ context.Context, _, _, _ string) (proto.AppStatus, string, error) {
	return proto.AppStatusFailed, "boom", errOh
}
func (errBackend) Stop(_ context.Context, _ string) (proto.AppStatus, string, error) {
	return proto.AppStatusFailed, "boom", errOh
}
func (errBackend) Status(_ context.Context, _ string) (proto.AppStatus, []proto.AppServiceStatus, error) {
	return proto.AppStatusUnknown, nil, errOh
}

type errStr string

func (e errStr) Error() string { return string(e) }

var errOh = errStr("boom")

// TestNewComposeBackend_NoDockerCLI exercises the LookPath-failure path in
// NewComposeBackend so we get coverage on the constructor without needing the
// docker CLI present. Forces an empty PATH so LookPath always fails.
func TestNewComposeBackend_NoDockerCLI(t *testing.T) {
	t.Setenv("PATH", "")
	_, err := NewComposeBackend(t.TempDir())
	if err == nil {
		t.Error("expected NewComposeBackend to fail when docker CLI is not on PATH")
	}
}

// composeBackendWithoutLookPath constructs a ComposeBackend without the
// LookPath check so we can exercise the early-return branches in Stop and
// Status (which both fast-path when the compose file does not exist on disk).
// This intentionally bypasses the production constructor — the methods we
// reach don't shell out to docker.
func composeBackendWithoutLookPath(t *testing.T) *ComposeBackend {
	t.Helper()
	dir := t.TempDir()
	return &ComposeBackend{dir: dir}
}

func TestComposeBackend_NameAndProjectName(t *testing.T) {
	c := composeBackendWithoutLookPath(t)
	if c.Name() != "docker" {
		t.Errorf("Name: %q want docker", c.Name())
	}
	// Also pins the appDir/composePath helpers.
	if c.appDir("xyz") == "" {
		t.Error("appDir empty")
	}
	if c.composePath("xyz") == "" {
		t.Error("composePath empty")
	}
}

func TestComposeBackend_StopWhenNoComposeFile(t *testing.T) {
	c := composeBackendWithoutLookPath(t)
	status, _, err := c.Stop(context.Background(), "never-deployed")
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if status != proto.AppStatusStopped {
		t.Errorf("status: %q want stopped", status)
	}
}

func TestComposeBackend_StatusWhenNoComposeFile(t *testing.T) {
	c := composeBackendWithoutLookPath(t)
	status, services, err := c.Status(context.Background(), "never-deployed")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status != proto.AppStatusStopped {
		t.Errorf("status: %q want stopped", status)
	}
	if services != nil {
		t.Errorf("services: %+v want nil", services)
	}
}

func TestRegisterHandlers_BackendErrorsAckFalse(t *testing.T) {
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

	var dack proto.AppDeployAck
	request(t, nc, proto.AppDeploySubject("node-1"), proto.AppDeployCmd{AppID: "a"}, &dack)
	if dack.OK {
		t.Error("deploy OK on backend err")
	}

	var sack proto.AppStopAck
	request(t, nc, proto.AppStopSubject("node-1"), proto.AppStopCmd{AppID: "a"}, &sack)
	if sack.OK {
		t.Error("stop OK on backend err")
	}

	// Status logs the error but still responds with what the backend returned.
	var stat proto.AppStatusAck
	request(t, nc, proto.AppStatusSubject("node-1"), proto.AppStatusCmd{AppID: "a"}, &stat)
	if stat.Status != proto.AppStatusUnknown {
		t.Errorf("status: %q", stat.Status)
	}
}
