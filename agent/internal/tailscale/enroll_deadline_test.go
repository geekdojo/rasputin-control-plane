package tailscale

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// slowUpBin writes a fake tailscale CLI whose `up` blocks for upFor (it execs
// sleep, so the kill lands on the process holding the pipes and Run returns
// promptly) and whose `status --json` answers with state. Everything else
// exits 0. This is the bench shape: a headscale that has not answered the
// login yet, with `tailscale up` sitting on it saying nothing.
func slowUpBin(t *testing.T, upFor time.Duration, state string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary shim is /bin/sh; skipped on Windows")
	}
	path := t.TempDir() + "/tailscale"
	body := `#!/bin/sh
case "$1" in
  up)
    exec sleep ` + fmt.Sprintf("%.2f", upFor.Seconds()) + `
    ;;
  status)
    echo '{"Self":{"ID":"abc","HostName":"node-1","TailscaleIPs":["100.64.0.1"],"PrimaryRoutes":[],"Online":true},"Peer":{},"BackendState":"` + state + `"}'
    ;;
  *)
    exit 0
    ;;
esac
`
	if err := writeExecutable(path, body); err != nil {
		t.Fatalf("writeExecutable: %v", err)
	}
	return path
}

// The reproduction of geekdojo/geekdojo-brain#402 (e3bench-compute1, agent
// dev.142, 2026-09-05 00:19:54Z): `tailscale up` outlives the enroll
// deadline and the agent reports `tailscale up: signal: killed (stderr=)`.
// The deadline is the handler's own — a NATS request carries none — and
// exec.CommandContext's default cancel is Process.Kill, so the CLI dies with
// nothing on stderr and the error names neither the deadline nor what the
// CLI was waiting on. This test drives that exact mechanism: a fake `up`
// that ignores everything until it is killed, under a context that expires
// first. Before the fix it failed with the bench string; the assertions are
// the wording the fix owes an operator.
func TestRealBackend_EnrollKilledByDeadlineIsNamed(t *testing.T) {
	bin := slowUpBin(t, 5*time.Second, "NeedsLogin")
	b := &RealBackend{binary: bin, caBundle: t.TempDir() + "/ca.pem", run: execRun}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	const key = "tskey-auth-SECRET-VALUE"
	start := time.Now()
	_, err := b.Enroll(ctx, EnrollInput{LoginServer: "https://hs.example:8443", AuthKey: key, Hostname: "node-1"})
	if err == nil {
		t.Fatal("Enroll succeeded with `up` blocked past the deadline")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("Enroll took %s to return after a 300ms deadline — the kill is not landing on the process holding the pipes", took)
	}
	msg := err.Error()
	t.Logf("enroll error: %s", msg)
	if strings.Contains(msg, "signal: killed") {
		t.Errorf("error still reads as a bare signal: %q", msg)
	}
	for _, want := range []string{"tailscale up killed after", "enroll deadline", "while still running", "https://hs.example:8443", "had not answered"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q should say %q", msg, want)
		}
	}
	if strings.Contains(msg, key) {
		t.Errorf("error carries the auth key: %q", msg)
	}
}

// The same fake, given time: a login that lands inside the budget is an
// ordinary success, and the status that follows is what the ack carries.
func TestRealBackend_EnrollSucceedsInsideTheBudget(t *testing.T) {
	bin := slowUpBin(t, 200*time.Millisecond, "Running")
	b := &RealBackend{binary: bin, caBundle: t.TempDir() + "/ca.pem", run: execRun}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := b.Enroll(ctx, EnrollInput{LoginServer: "https://hs.example:8443", AuthKey: "tskey", Hostname: "node-1"})
	if err != nil {
		t.Fatalf("Enroll inside the budget: %v", err)
	}
	if !st.Enrolled || st.TailnetIP != "100.64.0.1" {
		t.Errorf("status after enroll = %+v, want enrolled at 100.64.0.1", st)
	}
}

// A restart that outlives the deadline is named as that, not as a bare
// signal either: the mesh CA install and restart share the budget with the
// login, and an operator reading the ack must be able to tell which one
// ate it.
func TestRealBackend_EnrollRestartPastDeadlineIsNamed(t *testing.T) {
	withInitSystems(t, "/run/systemd/system")
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	b := &RealBackend{binary: "/nonexistent/tailscale", caBundle: t.TempDir() + "/ca.pem", run: run}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := b.Enroll(ctx, EnrollInput{
		LoginServer: "https://hs.example", AuthKey: "tskey", MeshCAPEM: []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
	})
	if err == nil {
		t.Fatal("Enroll succeeded with the restart blocked past the deadline")
	}
	if !strings.Contains(err.Error(), "restarting tailscaled had not finished when the enroll deadline expired") {
		t.Errorf("error %q should name the restart and the deadline", err)
	}
}

// Whatever the CLI prints, the pre-auth key never travels in the error.
func TestRedactAuthKey(t *testing.T) {
	if got := redactAuthKey("bad key tskey-auth-abc for --auth-key=tskey-auth-abc", "tskey-auth-abc"); strings.Contains(got, "tskey-auth-abc") {
		t.Errorf("key survived redaction: %q", got)
	}
	if got := redactAuthKey("unchanged", ""); got != "unchanged" {
		t.Errorf("empty key must be a no-op, got %q", got)
	}
}

// captureBackend records the deadline the handler hands its backend.
type captureBackend struct {
	*MockBackend
	deadline chan time.Time
}

func (c *captureBackend) Enroll(ctx context.Context, in EnrollInput) (Status, error) {
	if dl, ok := ctx.Deadline(); ok {
		c.deadline <- dl
	}
	return c.MockBackend.Enroll(ctx, in)
}

// The budget the command runs under is the named one, proto.MeshEnrollWork —
// not a number typed in the handler. This is the constant the api's dispatch
// timeout is derived from, so the two cannot drift apart again.
func TestHandleEnroll_RunsUnderTheNamedBudget(t *testing.T) {
	nc := startNATS(t)
	mb, err := NewMockBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewMockBackend: %v", err)
	}
	cb := &captureBackend{MockBackend: mb, deadline: make(chan time.Time, 1)}
	subs, err := RegisterHandlers(nc, "node-1", cb)
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})
	before := time.Now()
	var ack proto.MeshEnrollAck
	request(t, nc, proto.MeshEnrollSubject("node-1"), proto.MeshEnrollCmd{LoginServer: "https://hs", AuthKey: "k"}, &ack)
	if !ack.OK {
		t.Fatalf("ack: %+v", ack)
	}
	select {
	case dl := <-cb.deadline:
		// before is taken ahead of the request, so the measured budget runs a
		// hair over; a hand-typed number anywhere near it would be seconds off.
		budget := dl.Sub(before)
		if budget > proto.MeshEnrollWork+time.Second || budget < proto.MeshEnrollWork-5*time.Second {
			t.Errorf("handler deadline is %s from dispatch, want proto.MeshEnrollWork (%s)", budget, proto.MeshEnrollWork)
		}
	default:
		t.Fatal("the backend saw no deadline at all")
	}
}

// End to end over the bus: the deadline fires inside `tailscale up`, and the
// ack — not just the log — says which command died, after how long, under
// what deadline, waiting on which Headscale. The budget is shortened for the
// test; the mechanism is the real backend under the real handler.
func TestHandleEnroll_DeadlineKillReachesTheAck(t *testing.T) {
	bin := slowUpBin(t, 5*time.Second, "NeedsLogin")
	old := enrollBudget
	enrollBudget = 300 * time.Millisecond
	t.Cleanup(func() { enrollBudget = old })

	nc := startNATS(t)
	b := &RealBackend{binary: bin, caBundle: t.TempDir() + "/ca.pem", run: execRun}
	fired := make(chan struct{}, 1)
	subs, err := RegisterHandlers(nc, "node-1", b, func() { fired <- struct{}{} })
	if err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	t.Cleanup(func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	})
	const key = "tskey-auth-SECRET-VALUE"
	var ack proto.MeshEnrollAck
	request(t, nc, proto.MeshEnrollSubject("node-1"), proto.MeshEnrollCmd{
		LoginServer: "https://hs.example:8443", AuthKey: key, Hostname: "node-1",
	}, &ack)
	if ack.OK {
		t.Fatalf("enroll succeeded with `up` blocked past the deadline: %+v", ack)
	}
	if ack.Backend != "tailscale" {
		t.Errorf("backend: %q", ack.Backend)
	}
	for _, want := range []string{"tailscale up killed after", "300ms enroll deadline", "while still running", "https://hs.example:8443", "had not answered", "NeedsLogin"} {
		if !strings.Contains(ack.Detail, want) {
			t.Errorf("ack detail %q should say %q", ack.Detail, want)
		}
	}
	if strings.Contains(ack.Detail, "signal: killed") || strings.Contains(ack.Detail, key) {
		t.Errorf("ack detail leaks the bare signal or the key: %q", ack.Detail)
	}
	select {
	case <-fired:
		t.Fatal("post-enroll hook fired for a killed enroll")
	case <-time.After(100 * time.Millisecond):
	}
}
