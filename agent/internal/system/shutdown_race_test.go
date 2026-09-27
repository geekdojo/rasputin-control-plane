package system

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// These tests are the agent half of the defect found benching
// geekdojo/geekdojo-brain#616 (CP dev.182, OS dev.263): cp-compute1 really
// rebooted, and the agent logged
//
//	"/usr/sbin/reboot" failed: signal: terminated. The node was NOT rebooted.
//
// and published reboot_failed, because systemd stops the agent's unit during
// the very shutdown the agent started and SIGTERMs its reboot child with it.
// A reboot command killed BECAUSE the system is shutting down has not failed.
// Only a command that fails before any shutdown began is a failure, and only
// that is reported as one.

// commandError returns the error exec gives for a real child process that ran
// script — so "killed by a signal" and "exited 1" are the genuine articles,
// not strings shaped like them.
func commandError(t *testing.T, script string) error {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh to produce a real exit status: %v", err)
	}
	err = exec.Command(sh, "-c", script).Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("sh -c %q: err = %v, want an *exec.ExitError", script, err)
	}
	return err
}

// killedBySIGTERM is what the bench saw: "signal: terminated".
func killedBySIGTERM(t *testing.T) error { return commandError(t, "kill -TERM $$") }

func exitedOne(t *testing.T) error { return commandError(t, "exit 1") }

func (r *rebootRig) setSystem(state shutdownState, evidence string) {
	r.rb.systemState = func() shutdownFact { return shutdownFact{state: state, evidence: evidence} }
}

// runFailing performs one real-mode reboot whose command ends with err, and
// returns once the command has been run. perform's outcome is then read from
// the bus with Flush (a round trip: everything published before it arrives
// first) — never by waiting.
func runFailing(t *testing.T, rig *rebootRig, err error) {
	t.Helper()
	rig.mu.Lock()
	rig.runErr = err
	rig.mu.Unlock()
	if _, rerr := rig.rb.Reboot(RebootRequest{Reason: ReasonOperator}); rerr != nil {
		t.Fatalf("Reboot: %v", rerr)
	}
	rig.nextExec(t)
}

// finished returns once perform has returned. It is a fact, not a wait: the
// performed seam is called by perform as its last act.
func (r *rebootRig) finished(t *testing.T) {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(rpcWait):
		t.Fatal("perform never returned")
	}
}

// THE BENCH DEFECT. The reboot child is SIGTERMed and systemd says the system
// is stopping: the reboot is under way. Nothing may say it failed.
func TestReboot_CommandKilledByTheShutdownItStartedIsNotAFailure(t *testing.T) {
	nc := startNATS(t)
	rig := newTestRebooter(t, nc, "node-race")
	rig.setSystem(shutdownUnderway, `systemd reports "stopping"`)
	failSub := subscribeEvt(t, nc, "node-race", "reboot_failed")

	runFailing(t, rig, killedBySIGTERM(t))
	rig.finished(t)

	nothingPublished(t, nc, failSub, "a reboot command killed by the shutdown it started")
	logs := rig.logs.String()
	if strings.Contains(logs, "NOT rebooted") || strings.Contains(logs, "FAILED") {
		t.Errorf("logs = %q — the node is rebooting, and nothing is known to have failed", logs)
	}
	for _, want := range []string{"signal: terminated", `systemd reports "stopping"`, "shutting down"} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs = %q, want them to name %q", logs, want)
		}
	}
	if !IsMuted() {
		t.Error("the node is going down; its heartbeats must stay muted")
	}
}

// The agent's own stop (its signal context cancelled by the unit stop) is the
// same fact from the other side, and it is enough on its own.
func TestReboot_CommandKilledWhileTheAgentIsBeingStoppedIsNotAFailure(t *testing.T) {
	nc := startNATS(t)
	rig := newTestRebooter(t, nc, "node-stop")
	rig.setSystem(shutdownUnknown, "no systemd on this node")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rig.rb.StopsWith(ctx)
	failSub := subscribeEvt(t, nc, "node-stop", "reboot_failed")

	runFailing(t, rig, killedBySIGTERM(t))
	rig.finished(t)

	nothingPublished(t, nc, failSub, "a reboot command killed while the agent is being stopped")
	if logs := rig.logs.String(); strings.Contains(logs, "NOT rebooted") {
		t.Errorf("logs = %q — nothing is known to have failed", logs)
	}
}

// Killed by a signal, and the system positively is NOT shutting down: someone
// killed the reboot command and nothing is going down. That is a failure, and
// it is reported as a definitive one.
func TestReboot_CommandKilledWithNoShutdownUnderwayIsAFailure(t *testing.T) {
	nc := startNATS(t)
	rig := newTestRebooter(t, nc, "node-killed")
	rig.setSystem(shutdownNotUnderway, `systemd reports "running"`)
	failSub := subscribeEvt(t, nc, "node-killed", "reboot_failed")

	runFailing(t, rig, killedBySIGTERM(t))

	ev := nextFailed(t, failSub)
	if !ev.Definitive || !strings.Contains(ev.Detail, "signal: terminated") || ev.BootID != "boot-before" {
		t.Errorf("event = %+v, want a definitive failure naming the signal and the boot still running", ev)
	}
	if IsMuted() {
		t.Error("the node did not reboot, so its heartbeats must resume")
	}
}

// Killed by a signal and the node cannot say whether a shutdown is under way:
// it does not know, so it does not claim the reboot failed. It stays muted —
// the control plane decides on the boot identity, or on the node going
// critical if it never comes back.
func TestReboot_CommandKilledWhenShutdownCannotBeDeterminedIsNotReported(t *testing.T) {
	nc := startNATS(t)
	rig := newTestRebooter(t, nc, "node-unknown")
	rig.setSystem(shutdownUnknown, "no systemd on this node")
	failSub := subscribeEvt(t, nc, "node-unknown", "reboot_failed")

	runFailing(t, rig, killedBySIGTERM(t))
	rig.finished(t)

	nothingPublished(t, nc, failSub, "a killed reboot command with no way to tell whether the node is shutting down")
	logs := rig.logs.String()
	if strings.Contains(logs, "NOT rebooted") {
		t.Errorf("logs = %q — whether the node reboots is not known here", logs)
	}
	if !strings.Contains(logs, "not known") {
		t.Errorf("logs = %q, want them to say the outcome is not known here", logs)
	}
	if !IsMuted() {
		t.Error("the reboot may be under way; heartbeats stay muted")
	}
}

// The command failed on its own terms (exit 1) before any shutdown began: the
// node is up on the boot it announced leaving, and says so definitively.
func TestReboot_CommandFailingBeforeShutdownIsADefinitiveFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		state    shutdownState
		evidence string
	}{
		{"systemd running", shutdownNotUnderway, `systemd reports "running"`},
		// OpenWrt: no systemd. busybox reboot exiting 1 is the command's own
		// failure — a shutdown kills it, it does not make it exit 1.
		{"no systemd", shutdownUnknown, "no systemd on this node"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nc := startNATS(t)
			rig := newTestRebooter(t, nc, "node-exit1")
			rig.setSystem(tc.state, tc.evidence)
			failSub := subscribeEvt(t, nc, "node-exit1", "reboot_failed")

			runFailing(t, rig, exitedOne(t))

			ev := nextFailed(t, failSub)
			if !ev.Definitive || !strings.Contains(ev.Detail, "exit status 1") {
				t.Errorf("event = %+v, want a definitive failure naming the exit status", ev)
			}
			if !strings.Contains(rig.logs.String(), "NOT rebooted") {
				t.Errorf("logs = %q, want the loud failure", rig.logs.String())
			}
			if IsMuted() {
				t.Error("the node did not reboot, so its heartbeats must resume")
			}
		})
	}
}

// Exited 1, but systemd is already stopping: a shutdown is under way, so the
// command's exit says nothing about whether the node is going down.
func TestReboot_CommandFailingWhileShutdownIsUnderwayIsNotReported(t *testing.T) {
	nc := startNATS(t)
	rig := newTestRebooter(t, nc, "node-late")
	rig.setSystem(shutdownUnderway, `systemd reports "stopping"`)
	failSub := subscribeEvt(t, nc, "node-late", "reboot_failed")

	runFailing(t, rig, exitedOne(t))
	rig.finished(t)

	nothingPublished(t, nc, failSub, "a reboot command that exited while the system was already shutting down")
}

// The systemd state is read from `systemctl is-system-running`, and only
// "stopping" means a shutdown is under way. Anything the command cannot answer
// is unknown, never "not shutting down".
func TestClassifySystemState(t *testing.T) {
	for _, tc := range []struct {
		out  string
		want shutdownState
	}{
		{"stopping\n", shutdownUnderway},
		{"running\n", shutdownNotUnderway},
		{"degraded\n", shutdownNotUnderway},
		{"starting\n", shutdownNotUnderway},
		{"initializing\n", shutdownNotUnderway},
		{"maintenance\n", shutdownNotUnderway},
		{"offline\n", shutdownUnknown},
		{"unknown\n", shutdownUnknown},
		{"", shutdownUnknown},
		{"Failed to connect to bus\n", shutdownUnknown},
	} {
		if got := classifySystemState(tc.out); got != tc.want {
			t.Errorf("classifySystemState(%q) = %v, want %v", tc.out, got, tc.want)
		}
	}
}

// With no systemctl at all (OpenWrt), the state is unknown.
func TestSystemdState_NoSystemctlIsUnknown(t *testing.T) {
	f := systemdState(
		func(string) (string, error) { return "", exec.ErrNotFound },
		func(string, ...string) ([]byte, error) {
			t.Error("ran systemctl that was not found")
			return nil, nil
		},
	)()
	if f.state != shutdownUnknown {
		t.Errorf("state = %v, want unknown", f.state)
	}
}

// is-system-running exits non-zero for every state but "running", and its
// answer is still on stdout: the exit status must not throw it away.
func TestSystemdState_ReadsTheAnswerWhateverTheExitStatus(t *testing.T) {
	f := systemdState(
		func(string) (string, error) { return "/bin/systemctl", nil },
		func(path string, args ...string) ([]byte, error) {
			if path != "/bin/systemctl" || strings.Join(args, " ") != "is-system-running" {
				t.Errorf("ran %s %v, want /bin/systemctl is-system-running", path, args)
			}
			return []byte("stopping\n"), errors.New("exit status 1")
		},
	)()
	if f.state != shutdownUnderway || !strings.Contains(f.evidence, "stopping") {
		t.Errorf("fact = %+v, want underway, naming systemd's answer", f)
	}
}

func nextFailed(t *testing.T, sub *nats.Subscription) proto.SystemRebootFailedEvt {
	t.Helper()
	msg, err := sub.NextMsg(rpcWait)
	if err != nil {
		t.Fatalf("reboot_failed event not published: %v", err)
	}
	var ev proto.SystemRebootFailedEvt
	if err := json.Unmarshal(msg.Data, &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return ev
}
