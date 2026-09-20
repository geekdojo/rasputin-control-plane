package tailscale

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// WALL-CLOCK IN THESE TESTS, AND WHY IT IS MEASURED RATHER THAN TYPED.
//
// The mechanism under test is a deadline killing a subprocess, so a test for
// it cannot avoid time. What it can avoid is a number typed by whoever wrote
// it. These tests ran their fakes under a hand-typed 300ms deadline and
// asserted a hand-typed 3s ceiling, which made them a measurement of the
// machine rather than of the code: on a loaded host the fake had not reached
// its sleep before the deadline fired, the error then described a different
// failure, and three tests went red together with nothing wrong in the agent
// (seen 2026-09-19 with two other Go suites and a gosec scan on the same
// laptop).
//
// Every budget below is now derived from subprocessCost, measured on the
// machine actually running the test, and every assertion is either causal —
// did the child reach the state the test needs? — or a ratio with a wide
// margin over that measurement. A regression still fails; a busy laptop does
// not.

// subprocessCost measures what one round trip through the fake CLI costs on
// this machine: fork, exec /bin/sh, run a case arm, exit, reap. That is the
// unit the budgets are built from, because it is exactly what load inflates.
//
// It is measured against the binary the test will actually use, and the first
// run is thrown away. The first exec of a newly written file is not the same
// thing as the ones that follow — on this Mac it measured ~690ms against ~5ms
// afterwards — and a budget built from that outlier is as arbitrary as a
// typed one. Discarding it also WARMS the binary, so the spawn the test then
// makes is the kind that was measured.
//
// The slowest of the remaining runs, not the mean: a budget has to hold for
// the worst spawn in the test, not the average one. Floored so a fast machine
// still leaves the scheduler room. Capped so that a host slow enough to make
// the derivation meaningless fails HERE, naming the measurement, rather than
// as a confusing assertion failure further down — and the cap is what keeps
// killTimeBudget below upWaitDelay, which is the whole basis of the kill
// assertion.
func subprocessCost(t *testing.T, bin string) time.Duration {
	t.Helper()
	const (
		runs    = 5
		floorAt = 20 * time.Millisecond
		tooSlow = 300 * time.Millisecond
	)
	worst := time.Duration(0)
	for i := 0; i <= runs; i++ { // run 0 is the cold one, and is discarded
		start := time.Now()
		if err := exec.Command(bin, "status", "--json").Run(); err != nil { // #nosec G204 -- the fake binary this test just wrote
			t.Fatalf("measuring the fake CLI: %v", err)
		}
		if d := time.Since(start); i > 0 && d > worst {
			worst = d
		}
	}
	if worst > tooSlow {
		t.Fatalf("one fake-CLI round trip takes %s on this machine; no budget derived from that can still tell a landed kill (returns at the deadline) from a missed one (returns %s later). The host is the problem, not the agent.", worst, upWaitDelay)
	}
	if worst < floorAt {
		worst = floorAt
	}
	t.Logf("fake-CLI round trip on this machine: %s — every budget below is a multiple of it", worst)
	return worst
}

// enrollDeadlineFor is the deadline the kill tests run `tailscale up` under.
// One job: be comfortably longer than it takes the child to reach its sleep,
// because a deadline that fires first exercises a different path entirely —
// while staying short enough to keep the test quick. Ten spawns of headroom,
// on the machine's own number.
func enrollDeadlineFor(cost time.Duration) time.Duration { return 10 * cost }

// killTimeBudget is how long after the deadline Enroll may take to return
// and still count as "the kill landed on the process holding the pipes".
//
// What it has to separate: a landed kill returns at the deadline plus one
// more spawn (enrollKilledByDeadline probes `status` to say what tailscaled
// reports); a missed one — the kill hitting a shell whose child still holds
// the pipe — returns a whole upWaitDelay later. Five spawns of slack sits
// well clear of one and well under the other, and the test asserts that
// separation still holds rather than assuming it.
func killTimeBudget(cost time.Duration) time.Duration { return 5 * cost }

// slowUpBin writes a fake tailscale CLI whose `up` blocks for upFor and whose
// `status --json` answers with state. Everything else exits 0. This is the
// bench shape: a headscale that has not answered the login yet, with
// `tailscale up` sitting on it saying nothing.
//
// The `up` arm EXECS sleep, so the shell is replaced and the kill lands on
// the process holding the pipes — that is the behaviour real.go's WaitDelay
// exists for, and reproducing it is the point of the fake.
//
// reached, when non-empty, is a path the `up` arm creates immediately BEFORE
// it blocks. Its existence is proof the child got as far as waiting, which is
// the precondition every kill assertion here rests on; when it is missing the
// test says so in those words instead of failing on wording that describes
// some other failure.
func slowUpBin(t *testing.T, upFor time.Duration, state, reached string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary shim is /bin/sh; skipped on Windows")
	}
	mark := ":"
	if reached != "" {
		mark = "touch '" + reached + "'"
	}
	path := t.TempDir() + "/tailscale"
	body := `#!/bin/sh
case "$1" in
  up)
    ` + mark + `
    exec sleep ` + fmt.Sprintf("%.3f", upFor.Seconds()) + `
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

// waitReached blocks until the fake `up` says it is blocked, and fails the
// test naming that fact if it never does. A fact, with a deadline that exits
// non-zero saying what never became true — not a sleep.
func waitReached(t *testing.T, path string, within time.Duration) {
	t.Helper()
	// Checked once before any waiting: by the time a caller asks, the child
	// has usually long since touched it. The window is grace for a machine
	// that has not flushed the create yet, not a sleep.
	deadline := time.Now().Add(within)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the fake `tailscale up` never reached its blocking state within %s, so nothing below is testing a kill", within)
}

// deadlineNamed pulls the duration out of "... by the 300ms enroll deadline
// ...". The message renders it with tidyDuration, which rounds, and the
// value it renders is measured from inside Enroll — so the exact string
// depends on how long the call took to get started, which is precisely the
// thing that must not decide whether a test passes. What is asserted is that
// a duration IS named and that it is the budget the caller set, within the
// rounding.
var deadlineNamedRe = regexp.MustCompile(`by the ([0-9][0-9a-z.µ]*) enroll deadline`)

func deadlineNamed(t *testing.T, msg string) time.Duration {
	t.Helper()
	m := deadlineNamedRe.FindStringSubmatch(msg)
	if m == nil {
		t.Fatalf("message names no enroll deadline: %q", msg)
	}
	d, err := time.ParseDuration(m[1])
	if err != nil {
		t.Fatalf("the named deadline %q does not parse: %v", m[1], err)
	}
	return d
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
	reached := t.TempDir() + "/up-blocked"
	// An hour, not a multiple of anything: the `up` arm must never finish on
	// its own, and a kill that MISSES still returns after upWaitDelay rather
	// than waiting this out — so a large flat number costs nothing and needs
	// no derivation. The measurement below both sizes the deadline and warms
	// this binary, through its non-blocking status arm.
	bin := slowUpBin(t, time.Hour, "NeedsLogin", reached)
	cost := subprocessCost(t, bin)
	deadline := enrollDeadlineFor(cost)

	b := &RealBackend{binary: bin, caBundle: t.TempDir() + "/ca.pem", run: execRun}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	const key = "tskey-auth-SECRET-VALUE"
	start := time.Now()
	_, err := b.Enroll(ctx, EnrollInput{LoginServer: "https://hs.example:8443", AuthKey: key, Hostname: "node-1"})
	took := time.Since(start)
	if err == nil {
		t.Fatal("Enroll succeeded with `up` blocked past the deadline")
	}
	// The precondition, stated before anything is read out of the error: if
	// the child never blocked, the deadline killed something else and every
	// assertion below would be about the wrong failure.
	waitReached(t, reached, killTimeBudget(cost))

	// The kill has to land on the process holding the pipes. When it does,
	// Run returns at the deadline plus the one spawn enrollKilledByDeadline
	// makes to read tailscaled's state; when it does not, Run waits out
	// upWaitDelay first. Assert the two are still separable on this machine
	// before relying on the measurement to tell them apart.
	slack := killTimeBudget(cost)
	if slack >= upWaitDelay {
		t.Fatalf("the kill budget (%s) has grown past upWaitDelay (%s); this assertion no longer distinguishes a landed kill from a missed one", slack, upWaitDelay)
	}
	if over := took - deadline; over > slack {
		t.Errorf("Enroll returned %s after its %s deadline, %s more than the %s this machine needs — the kill is not landing on the process holding the pipes (a missed one costs %s)",
			took, deadline, over-slack, slack, upWaitDelay)
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
	// The deadline it names is the one that was set, within tidyDuration's
	// rounding and the moment Enroll took to start measuring.
	if named := deadlineNamed(t, msg); named > deadline || named < deadline-killTimeBudget(cost) {
		t.Errorf("error names a %s deadline, but the budget was %s", named, deadline)
	}
	if strings.Contains(msg, key) {
		t.Errorf("error carries the auth key: %q", msg)
	}
}

// The same fake, given time: a login that lands inside the budget is an
// ordinary success, and the status that follows is what the ack carries.
func TestRealBackend_EnrollSucceedsInsideTheBudget(t *testing.T) {
	// A short, flat block — long enough that `up` is doing something, short
	// enough to need no derivation. The budget around it is the derived part.
	const upTakes = 50 * time.Millisecond
	bin := slowUpBin(t, upTakes, "Running", "")
	cost := subprocessCost(t, bin) // also warms it
	budget := upTakes + 100*cost
	b := &RealBackend{binary: bin, caBundle: t.TempDir() + "/ca.pem", run: execRun}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	st, err := b.Enroll(ctx, EnrollInput{LoginServer: "https://hs.example:8443", AuthKey: "tskey", Hostname: "node-1"})
	if err != nil {
		t.Fatalf("Enroll inside a %s budget (`up` blocks %s; a spawn costs about %s here): %v", budget, upTakes, cost, err)
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
	reached := t.TempDir() + "/up-blocked"
	bin := slowUpBin(t, time.Hour, "NeedsLogin", reached) // as in the backend test
	cost := subprocessCost(t, bin)
	budget := enrollDeadlineFor(cost)

	old := enrollBudget
	enrollBudget = budget
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
	// Same precondition as the backend test: a deadline that fired before
	// the child blocked would produce a different message, and asserting
	// this wording against it would be a puzzle rather than a failure.
	waitReached(t, reached, killTimeBudget(cost))
	if ack.Backend != "tailscale" {
		t.Errorf("backend: %q", ack.Backend)
	}
	for _, want := range []string{"tailscale up killed after", "enroll deadline", "while still running", "https://hs.example:8443", "had not answered", "NeedsLogin"} {
		if !strings.Contains(ack.Detail, want) {
			t.Errorf("ack detail %q should say %q", ack.Detail, want)
		}
	}
	// The ack names the budget the handler ran under — the value, not a
	// literal copied into the test, and within the rounding the message
	// applies to it.
	if named := deadlineNamed(t, ack.Detail); named > budget || named < budget-killTimeBudget(cost) {
		t.Errorf("ack names a %s deadline, but the handler's budget was %s", named, budget)
	}
	if strings.Contains(ack.Detail, "signal: killed") || strings.Contains(ack.Detail, key) {
		t.Errorf("ack detail leaks the bare signal or the key: %q", ack.Detail)
	}
	// The hook must not fire for a killed enroll. handleEnroll answers the
	// request BEFORE its caller would fire the hook, so the ack already
	// arriving is not proof on its own; give it a few spawns' grace, scaled
	// like everything else here, and then say so.
	select {
	case <-fired:
		t.Fatal("post-enroll hook fired for a killed enroll")
	case <-time.After(killTimeBudget(cost)):
	}
}
