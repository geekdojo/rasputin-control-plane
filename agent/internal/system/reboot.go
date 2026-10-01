// Package system implements system-level agent operations. It owns the ONE
// function in the agent that restarts the node: (*Rebooter).Reboot.
//
// Everything that needs the node restarted calls it — the system.reboot
// command an operator's REBOOT button sends, the update saga's trial reboot,
// and the reboot back to the good slot after a mark-bad. There is no second
// implementation, and that is the point rather than a tidiness: one function
// means every reboot is announced, muted and logged the same way, so the
// journal answers "who rebooted this node, how, and from which boot" for every
// reboot and not only for the paths somebody remembered to instrument.
//
// Until geekdojo/geekdojo-brain#616 the system.reboot handler here only ever
// SIMULATED a reboot (it muted heartbeats, slept and re-registered) while the
// update path had its own real one. The simulator still exists, for a laptop
// that must not restart itself, but it is reachable only through the explicit
// dev mock selection and never on a released image — see EnableSimulation.
package system

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/host"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

const (
	rebootDefaultDelay = 3
	rebootMaxDelay     = 30

	// rebootCommand is the OS command that restarts the node. It is `reboot`
	// and deliberately not `systemctl reboot`: the Raspberry Pi trial boot
	// passes "0 tryboot" through to reboot(2), which the `reboot` compat
	// command does and the `systemctl reboot` verb does not (systemd 256 fails
	// to parse the argument and never reboots). `reboot` also exists on the
	// OpenWrt firewall image (busybox), where systemctl does not.
	rebootCommand = "reboot"

	// trybootArg arms the Raspberry Pi firmware's one-shot trial boot.
	trybootArg = "0 tryboot"

	// ReasonOperator is the Reason of a reboot asked for by the system.reboot
	// command.
	ReasonOperator = "system.reboot"
)

// muted is the agent's heartbeat mute. While true, the heartbeat loop in
// main.go skips publishing. Reboot sets it when a reboot is under way, so the
// control plane sees the node go quiet from the moment it was told to.
var muted atomic.Bool

// IsMuted reports whether heartbeats are muted because a reboot is under way.
// Read by the heartbeat loop.
func IsMuted() bool { return muted.Load() }

// MutedAtomic returns the package-level mute flag. Only Reboot writes it in
// the running agent; it is exported for tests that must restore it.
func MutedAtomic() *atomic.Bool { return &muted }

// RebootMode says HOW the node restarts.
type RebootMode string

const (
	// RebootPlain restarts into whatever the bootloader would boot anyway.
	// It is the only mode an operator's reboot may use: a trial boot asked
	// for by an operator would start an A/B trial of a slot that happened to
	// be pending.
	RebootPlain RebootMode = "plain"
	// RebootTryboot restarts a Raspberry Pi into its trial boot partition
	// once. Only the update path asks for it, and only on an image that boots
	// through the Pi firmware's tryboot mechanism.
	RebootTryboot RebootMode = "tryboot"
)

// RebootRequest is one request to restart the node.
type RebootRequest struct {
	// Reason names who is asking, and is what the journal and the rebooting
	// event carry: "system.reboot", "update.reboot bundle=…",
	// "update.mark-bad …". Required.
	Reason string
	// Mode is plain or tryboot. Empty means plain.
	Mode RebootMode
	// DelaySeconds is how long to wait between announcing the reboot and
	// running it, so the caller's reply can leave the node. Out of range
	// (<= 0 or > 30) means the default, 3.
	DelaySeconds int

	// AnnounceOnly announces the reboot exactly as a real one is announced
	// and then does NOT reboot. It exists for the update path's no-reboot
	// fault injection (updater.FaultNoReboot), which can only be armed on a
	// dev image; nothing else may set it. The node is not muted, because the
	// fault's purpose is a node that keeps answering on the boot it was told
	// to leave.
	AnnounceOnly bool

	// AfterSimulatedBoot runs only in a SIMULATED reboot, at the point the
	// simulated node "comes back". The mock update backend uses it to flip
	// its slot model. A real reboot never calls it: the process is gone.
	AfterSimulatedBoot func()
}

// Publisher is the one bus verb Reboot needs. *bus.Client and *nats.Conn both
// satisfy it; the agent hands over the Client so the announcement lands on
// the current connection.
type Publisher interface {
	Publish(subj string, data []byte) error
}

// Rebooter restarts the node. The agent constructs exactly one.
type Rebooter struct {
	nodeID string
	pub    Publisher

	// Seams, so a test can prove what would have been run without restarting
	// the machine running the test.
	bootID   func() string
	lookPath func(file string) (string, error)
	run      func(path string, args ...string) ([]byte, error)
	wait     func(d time.Duration)

	// systemState reports whether the SYSTEM is shutting down. stopping
	// reports whether this AGENT is being stopped (StopsWith). Either one
	// being a shutdown is what turns a killed reboot command from a failure
	// into the reboot under way. See shutdownFactNow.
	systemState func() shutdownFact
	stopping    func() bool

	// performed, when set, is called as perform's last act. A test seam only.
	performed func()

	// sim is nil unless EnableSimulation accepted. nil means every reboot is
	// real.
	sim *simulation

	// busy is true from the moment a reboot is accepted until it has failed
	// or a simulated one has finished. A real reboot that succeeded never
	// clears it: the OS is going down.
	busy atomic.Bool
}

type simulation struct {
	reregister func()
}

// NewRebooter returns a Rebooter that performs REAL reboots.
func NewRebooter(nodeID string, pub Publisher) *Rebooter {
	return &Rebooter{
		nodeID:   nodeID,
		pub:      pub,
		bootID:   host.BootID,
		lookPath: exec.LookPath,
		run: func(path string, args ...string) ([]byte, error) {
			return exec.Command(path, args...).CombinedOutput()
		},
		wait:        time.Sleep,
		systemState: systemdState(exec.LookPath, runOutput),
	}
}

// runOutput runs a command and returns its stdout, whatever its exit status.
func runOutput(path string, args ...string) ([]byte, error) {
	return exec.Command(path, args...).Output()
}

// StopsWith tells the Rebooter that ctx is the agent's own life: cancelled
// when the agent is told to stop (SIGTERM, which is what a unit stop and a
// shutdown send). A reboot command that ends while it is cancelled ended
// because the agent — and, during a reboot, the system — is going down.
func (r *Rebooter) StopsWith(ctx context.Context) {
	r.stopping = func() bool { return ctx.Err() != nil }
}

// shutdownState is whether the system is shutting down, as a fact the node can
// read. Unknown is a real answer: a node without systemd (the OpenWrt
// firewall) has no state to read, and unknown is never "not shutting down".
type shutdownState int

const (
	shutdownUnknown shutdownState = iota
	shutdownNotUnderway
	shutdownUnderway
)

func (s shutdownState) String() string {
	switch s {
	case shutdownNotUnderway:
		return "not-underway"
	case shutdownUnderway:
		return "underway"
	}
	return "unknown"
}

// shutdownFact is a shutdownState and what it was read from, for the log.
type shutdownFact struct {
	state    shutdownState
	evidence string
}

// classifySystemState reads `systemctl is-system-running`. systemd answers
// "stopping" from the moment a shutdown target's start job is queued — which
// happens in the same transaction that stops this agent's unit, so by the time
// the unit stop kills the reboot command, the answer is already "stopping".
// Every state of a running system is not-underway; anything else (offline, no
// answer, an error message) is unknown.
func classifySystemState(out string) shutdownState {
	switch strings.TrimSpace(out) {
	case "stopping":
		return shutdownUnderway
	case "running", "degraded", "starting", "initializing", "maintenance":
		return shutdownNotUnderway
	}
	return shutdownUnknown
}

// systemdState returns the production systemState: systemd's own answer, or
// unknown on a node without systemctl.
func systemdState(lookPath func(string) (string, error), run func(string, ...string) ([]byte, error)) func() shutdownFact {
	return func() shutdownFact {
		path, err := lookPath("systemctl")
		if err != nil {
			return shutdownFact{state: shutdownUnknown, evidence: "this node has no systemd to ask"}
		}
		// is-system-running exits non-zero for every state but "running";
		// the answer is on stdout either way, so the exit status is not read.
		out, _ := run(path, "is-system-running")
		answer := strings.TrimSpace(string(out))
		return shutdownFact{
			state:    classifySystemState(answer),
			evidence: fmt.Sprintf("systemd reports %q", answer),
		}
	}
}

// EnableSimulation switches this Rebooter to SIMULATED reboots: nothing is
// restarted; heartbeats are muted for the delay and the agent then
// re-registers. It reports whether simulation was enabled.
//
// The caller must only call it when the operator explicitly selected the dev
// mock (RASPUTIN_UPDATE_BACKEND=mock) — the agent never infers a mock. On top
// of that it REFUSES on a released image, whatever was selected: imageVersion
// is the running OS image (host.ImageVersion()), and only a -dev. build or an
// unversioned dev checkout may simulate. So on a production image a reboot is
// either performed or reported as failed; it cannot be faked.
//
// A simulated reboot does not change the boot identity the agent reports. The
// control plane therefore does not accept it as a reboot — restart the agent
// with a new RASPUTIN_BOOT_ID to stand in for one (docs/testing-updates.md).
func (r *Rebooter) EnableSimulation(imageVersion string, reregister func()) bool {
	if !host.IsDevImage(imageVersion) {
		log.Printf("rasputin-agent: reboot: ⚠️  simulated reboots REFUSED on the released image %q "+
			"(only -dev. builds and unversioned dev checkouts may simulate). Every reboot on this node is real.",
			imageVersion)
		return false
	}
	r.sim = &simulation{reregister: reregister}
	log.Printf("rasputin-agent: reboot: ⚠️  SIMULATED REBOOTS ENABLED by the dev mock selection — " +
		"this node will NOT restart when told to reboot, and the control plane will not accept it as rebooted")
	return true
}

// Simulated reports whether this Rebooter simulates.
func (r *Rebooter) Simulated() bool { return r != nil && r.sim != nil }

// ErrRebootInProgress is returned when a reboot is asked for while an earlier
// one is still under way.
var ErrRebootInProgress = errors.New("a reboot is already under way on this node")

// Reboot restarts the node. It is the only function in the agent that does.
//
// It returns once the reboot is ACCEPTED, with the delay it will apply, so the
// caller can reply before the node goes down; the reboot itself runs in the
// background. A non-nil error means the reboot was refused and nothing will
// happen — in particular, a node with no reboot command fails here. It never
// falls back to simulating.
//
// Every accepted reboot does the same things in the same order:
//
//  1. logs who asked, the mode, the delay and the boot being left;
//  2. publishes the rebooting event;
//  3. mutes heartbeats;
//  4. waits the delay;
//  5. runs the reboot command, and logs that it did.
//
// If the command fails before any shutdown began, that is logged, heartbeats
// are unmuted and a definitive reboot_failed event is published: the node is
// still up and says so. A command killed by the shutdown it started has not
// failed, and is not reported as failing — see commandEnded.
func (r *Rebooter) Reboot(req RebootRequest) (delaySeconds int, err error) {
	if r == nil {
		return 0, errors.New("reboot: no rebooter is wired")
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return 0, errors.New("reboot: refused, the caller gave no reason")
	}
	mode := req.Mode
	if mode == "" {
		mode = RebootPlain
	}
	if mode != RebootPlain && mode != RebootTryboot {
		return 0, fmt.Errorf("reboot: refused, unknown mode %q (requested by %s)", mode, reason)
	}
	delay := req.DelaySeconds
	if delay <= 0 || delay > rebootMaxDelay {
		delay = rebootDefaultDelay
	}
	leaving := r.bootID()

	if req.AnnounceOnly {
		log.Printf("rasputin-agent: reboot: ⚠️  FAULT INJECTION: announcing a reboot and NOT rebooting — "+
			"requested by %q, mode=%s, delay=%ds, leaving boot %s",
			reason, mode, delay, bootForLog(leaving))
		r.announce(reason, mode, delay, leaving)
		return delay, nil
	}

	var path string
	if r.sim == nil {
		path, err = r.lookPath(rebootCommand)
		if err != nil {
			log.Printf("rasputin-agent: reboot: FAILED — requested by %q, mode=%s, leaving boot %s: "+
				"this node has no %q command: %v. The node was NOT rebooted.",
				reason, mode, bootForLog(leaving), rebootCommand, err)
			return 0, fmt.Errorf("this node has no %q command, so it cannot be rebooted: %w", rebootCommand, err)
		}
	}

	if !r.busy.CompareAndSwap(false, true) {
		log.Printf("rasputin-agent: reboot: refused — requested by %q, mode=%s: %v", reason, mode, ErrRebootInProgress)
		return 0, ErrRebootInProgress
	}

	how := "real"
	if r.sim != nil {
		how = "SIMULATED"
	}
	log.Printf("rasputin-agent: reboot: requested by %q, mode=%s, delay=%ds, leaving boot %s (%s)",
		reason, mode, delay, bootForLog(leaving), how)

	go r.perform(req, reason, mode, delay, leaving, path)
	return delay, nil
}

func (r *Rebooter) perform(req RebootRequest, reason string, mode RebootMode, delay int, leaving, path string) {
	if r.performed != nil {
		defer r.performed()
	}
	r.announce(reason, mode, delay, leaving)
	muted.Store(true)
	r.wait(time.Duration(delay) * time.Second)

	if r.sim != nil {
		log.Printf("rasputin-agent: reboot: SIMULATED — nothing was restarted; requested by %q, mode=%s, still on boot %s",
			reason, mode, bootForLog(leaving))
		if req.AfterSimulatedBoot != nil {
			req.AfterSimulatedBoot()
		}
		muted.Store(false)
		r.busy.Store(false)
		if r.sim.reregister != nil {
			r.sim.reregister()
		}
		return
	}

	args := rebootArgs(mode)
	log.Printf("rasputin-agent: reboot: running %s — requested by %q, mode=%s, leaving boot %s",
		commandForLog(path, args), reason, mode, bootForLog(leaving))
	out, err := r.run(path, args...)
	if err != nil {
		detail := fmt.Sprintf("%s failed: %v", commandForLog(path, args), err)
		if o := strings.TrimSpace(string(out)); o != "" {
			detail += ": " + o
		}
		r.commandEnded(reason, mode, leaving, detail, killedBySignal(err))
		return
	}
	log.Printf("rasputin-agent: reboot: the OS accepted the reboot — requested by %q, mode=%s, leaving boot %s",
		reason, mode, bootForLog(leaving))
}

// commandEnded decides what a reboot command that ended with an error means,
// from facts only, and reports a failure only when one is established.
//
// The bench defect it exists for (geekdojo/geekdojo-brain#616, a compute node,
// CP dev.182): the reboot child runs in the agent's cgroup, so when systemd
// stops rasputin-agent.service during the very shutdown the child started, it
// SIGTERMs the child too. That child "failed: signal: terminated" — and the
// node rebooted. Reading its death as a failed reboot published reboot_failed
// for a node that was going down, and the job ended on that report.
//
// So, in order:
//
//  1. A shutdown is under way (systemd reports "stopping", or this agent is
//     being stopped): whatever the command's error, the node is going down.
//     Nothing is reported, heartbeats stay muted.
//  2. The command was killed by a signal and the system positively is NOT
//     shutting down: something killed the reboot and nothing is going down.
//     That is a failure, reported as definitive.
//  3. Killed by a signal and the node cannot tell whether it is shutting down
//     (no systemd to ask): a shutdown is exactly what kills it, so the outcome
//     is not known here and nothing is claimed. Heartbeats stay muted; the
//     control plane decides on the boot identity, or on the node going
//     critical if it never comes back.
//  4. Otherwise the command failed on its own terms (it could not be started,
//     or it exited with a failure status) with no shutdown under way: the
//     node is up on the boot it announced leaving. Reported as definitive.
//
// Only 2 and 4 say "NOT rebooted", because only there is it known.
func (r *Rebooter) commandEnded(reason string, mode RebootMode, leaving, detail string, killed bool) {
	fact := r.shutdownFactNow()
	switch {
	case fact.state == shutdownUnderway:
		log.Printf("rasputin-agent: reboot: the system is shutting down (%s) — %s, which is what a shutdown "+
			"does to it. Not a failure: the reboot requested by %q, mode=%s, is under way, leaving boot %s",
			fact.evidence, detail, reason, mode, bootForLog(leaving))
		return
	case killed && fact.state == shutdownUnknown:
		log.Printf("rasputin-agent: reboot: %s, and this node cannot tell whether it is shutting down (%s). "+
			"Whether it reboots is not known here, so no failure is reported; the control plane decides on the "+
			"boot identity. Requested by %q, mode=%s, leaving boot %s",
			detail, fact.evidence, reason, mode, bootForLog(leaving))
		return
	}
	log.Printf("rasputin-agent: reboot: FAILED — requested by %q, mode=%s, leaving boot %s: %s, and no shutdown "+
		"is under way (%s). The node was NOT rebooted.", reason, mode, bootForLog(leaving), detail, fact.evidence)
	muted.Store(false)
	r.busy.Store(false)
	r.publish("reboot_failed", proto.SystemRebootFailedEvt{
		NodeID:     r.nodeID,
		Reason:     reason,
		Mode:       string(mode),
		BootID:     leaving,
		Detail:     detail,
		Definitive: true,
		Ts:         time.Now().UTC(),
	})
}

// shutdownFactNow reads whether a shutdown is under way. This agent being
// stopped is read first: it is this process's own fact and needs no command.
// It is not relied on alone, because the unit stop signals the agent and its
// reboot child together and the child's exit can be seen before the agent's
// signal is — which is why systemd's own state is read as well.
func (r *Rebooter) shutdownFactNow() shutdownFact {
	if r.stopping != nil && r.stopping() {
		return shutdownFact{state: shutdownUnderway, evidence: "this agent is being stopped"}
	}
	if r.systemState == nil {
		return shutdownFact{state: shutdownUnknown, evidence: "no way to read the system state is wired"}
	}
	return r.systemState()
}

// killedBySignal reports whether err is a child process that was terminated by
// a signal rather than exiting on its own. os.ProcessState.ExitCode is -1 in
// exactly that case (and for a process that has not exited, which an
// *exec.ExitError never is).
func killedBySignal(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee) && ee.ExitCode() == -1
}

func (r *Rebooter) announce(reason string, mode RebootMode, delay int, leaving string) {
	r.publish("rebooting", proto.SystemRebootingEvt{
		NodeID:       r.nodeID,
		DelaySeconds: delay,
		Reason:       reason,
		Mode:         string(mode),
		BootID:       leaving,
		Simulated:    r.sim != nil,
		Ts:           time.Now().UTC(),
	})
}

func (r *Rebooter) publish(event string, body any) {
	payload, err := json.Marshal(body)
	if err != nil {
		log.Printf("rasputin-agent: reboot: marshal %s event: %v", event, err)
		return
	}
	if r.pub == nil {
		log.Printf("rasputin-agent: reboot: no bus connection to publish the %s event on", event)
		return
	}
	if err := r.pub.Publish(proto.NodeEvtSubject(r.nodeID, event), payload); err != nil {
		log.Printf("rasputin-agent: reboot: publish %s event: %v", event, err)
	}
}

// rebootArgs returns the arguments the reboot command takes for mode.
func rebootArgs(mode RebootMode) []string {
	if mode == RebootTryboot {
		return []string{trybootArg}
	}
	return nil
}

func commandForLog(path string, args []string) string {
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, fmt.Sprintf("%q", path))
	for _, a := range args {
		parts = append(parts, fmt.Sprintf("%q", a))
	}
	return strings.Join(parts, " ")
}

// bootForLog renders a boot identity for a log line, naming the empty case.
func bootForLog(id string) string {
	if id == "" {
		return "(unknown)"
	}
	return proto.ShortFingerprint(id)
}

// RegisterRebootHandler subscribes to rasputin.node.<nodeID>.cmd.system.reboot
// and answers it by calling rb.Reboot with a PLAIN reboot. The reply is sent
// once the reboot is accepted or refused; a refusal replies OK=false with the
// reason.
func RegisterRebootHandler(nc *nats.Conn, nodeID string, rb *Rebooter) (*nats.Subscription, error) {
	subj := proto.NodeCmdSubject(nodeID, "system.reboot")
	return nc.Subscribe(subj, func(m *nats.Msg) {
		var cmd proto.SystemRebootCmd
		_ = json.Unmarshal(m.Data, &cmd)

		ack := proto.SystemRebootAck{}
		delay, err := rb.Reboot(RebootRequest{
			Reason:       ReasonOperator,
			Mode:         RebootPlain,
			DelaySeconds: cmd.DelaySeconds,
		})
		if err != nil {
			ack.Detail = err.Error()
		} else {
			ack.OK = true
			ack.DelaySeconds = delay
		}
		payload, _ := json.Marshal(ack)
		if err := m.Respond(payload); err != nil {
			log.Printf("rasputin-agent: system.reboot: respond: %v", err)
		}
	})
}
