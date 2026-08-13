package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

const devImage = "2026.08.3-dev.159"

// captureLog runs f with the standard logger redirected and returns what it
// wrote. Arm's only channel for "I refused to arm and here is why" is a log
// line, so the log IS the interface under test.
func captureLog(f func()) string {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	f()
	return buf.String()
}

// The shipping default has to be "no fault", and it has to be the default that
// arrives when nobody has thought about it — i.e. an unset variable.
func TestArm_UnsetIsNoneAndSilent(t *testing.T) {
	t.Setenv(FaultEnv, "")
	var got Fault
	out := captureLog(func() { got = Arm(devImage) })
	if got != FaultNone {
		t.Errorf("fault = %q, want none", got)
	}
	if out != "" {
		t.Errorf("an unarmed node logged %q — it must say nothing", out)
	}
}

func TestArm_KnownValuesOnADevImage(t *testing.T) {
	for _, want := range []Fault{FaultNoReboot, FaultFailHealth} {
		t.Run(string(want), func(t *testing.T) {
			t.Setenv(FaultEnv, string(want))
			if got := Arm(devImage); got != want {
				t.Errorf("fault = %q, want %q", got, want)
			}
		})
	}
}

// ⚠️ THE REGRESSION THIS FILE EXISTS FOR.
//
// Arm must never be able to stop the agent. The previous version returned an
// error on an unrecognised value and main called log.Fatalf on it; with
// Restart=always / RestartSec=2 in rasputin-agent.service and node.env edited
// by hand to flip channels, one typo permanently prevented the agent from
// starting on a box reachable only by SSH.
//
// A signature with no error is the fix, so the strongest thing this test can
// assert is that the signature has not grown one back — a compile-time fact
// stated as a runtime test so it is visible when someone changes it. What is
// checked at runtime is the behaviour that has to survive: a bad value yields
// a working agent with nothing armed.
func TestArm_UnknownValueArmsNothingAndCannotStopTheAgent(t *testing.T) {
	// If Arm ever returns (Fault, error) again this line stops compiling —
	// which is the point. There must be nothing for a caller to be fatal on.
	var _ func(string) Fault = Arm

	t.Setenv(FaultEnv, "no-reboto")
	var got Fault
	out := captureLog(func() { got = Arm(devImage) })
	if got != FaultNone {
		t.Errorf("fault = %q, want none — a typo must not arm anything", got)
	}
	if !strings.Contains(out, "no-reboto") {
		t.Errorf("refusal %q must name the value that was rejected", out)
	}
}

// The mitigation for no-longer-being-fatal is that the refusal is loud and
// self-correcting: it names the knob, what was typed, and every valid option,
// so nobody has to read this file to fix their typo.
func TestArm_UnknownValueRefusalIsSelfCorrecting(t *testing.T) {
	t.Setenv(FaultEnv, "fail-heath")
	out := captureLog(func() { Arm(devImage) })
	for _, want := range []string{
		"fail-heath",            // what they typed
		FaultEnv,                // which knob
		string(FaultNoReboot),   // …and every valid option, so the typo is
		string(FaultFailHealth), // fixable without going to the source
	} {
		if !strings.Contains(out, want) {
			t.Errorf("refusal %q does not mention %q", out, want)
		}
	}
}

// A released image must not be faultable however node.env got edited. This is
// what keeps the seam's blast radius on the bench: the bench runs -dev. images
// by definition, so the gate costs the seam nothing.
func TestArm_RefusesToArmOnAReleasedImage(t *testing.T) {
	t.Setenv(FaultEnv, string(FaultNoReboot))
	var got Fault
	out := captureLog(func() { got = Arm("2026.08.3") })
	if got != FaultNone {
		t.Errorf("fault = %q on a released image, want none", got)
	}
	if !strings.Contains(out, "2026.08.3") {
		t.Errorf("refusal %q must name the image it refused on", out)
	}
}

// An empty version is a dev checkout with no /etc/rasputin/image-version at
// all — not an appliance, which always has one — so the seam still works when
// running the agent straight out of the repo.
func TestArm_EmptyVersionIsADevCheckoutNotAnAppliance(t *testing.T) {
	t.Setenv(FaultEnv, string(FaultFailHealth))
	if got := Arm(""); got != FaultFailHealth {
		t.Errorf("fault = %q on an unversioned dev checkout, want %q", got, FaultFailHealth)
	}
}

func TestIsDevImage(t *testing.T) {
	for _, tc := range []struct {
		version string
		dev     bool
	}{
		{"2026.08.3-dev.159", true},
		{"  2026.08.3-dev.1  ", true},
		{"", true},  // dev checkout, no image-version file
		{" ", true}, // …and whitespace is the same thing
		{"2026.08.3", false},
		{"2026.08.3-rc.1", false},
	} {
		if got := isDevImage(tc.version); got != tc.dev {
			t.Errorf("isDevImage(%q) = %v, want %v", tc.version, got, tc.dev)
		}
	}
}

// FaultNoReboot must be indistinguishable from a healthy node right up to the
// point where the reboot doesn't happen: the ack says OK and the rebooting
// event is published, so the api takes exactly the path it takes for a real
// reboot. That is what makes the resulting bootSame verdict meaningful.
func TestFaultNoReboot_AcksAndAnnouncesButDoesNotReboot(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n"
	be := &countingRebootBackend{}

	subs, err := RegisterHandlersWithFault(nc, nodeID, be, FaultNoReboot)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	}()

	evCh := make(chan *nats.Msg, 1)
	evSub, _ := nc.Subscribe(proto.NodeEvtSubject(nodeID, "rebooting"), func(m *nats.Msg) {
		select {
		case evCh <- m:
		default:
		}
	})
	defer func() { _ = evSub.Unsubscribe() }()

	cmd, _ := json.Marshal(proto.UpdateRebootCmd{BundleID: "sha", DelaySeconds: 3})
	msg, err := nc.Request(proto.UpdateRebootSubject(nodeID), cmd, 3*time.Second)
	if err != nil {
		t.Fatalf("reboot rpc: %v", err)
	}
	var ack proto.UpdateRebootAck
	if err := json.Unmarshal(msg.Data, &ack); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if !ack.OK {
		t.Error("the fault must ack OK — a visibly-failed reboot is a different scenario")
	}
	select {
	case <-evCh:
	case <-time.After(2 * time.Second):
		t.Error("rebooting event must still be published, or the api takes a different path than it does for a real reboot")
	}
	if be.reboots != 0 {
		t.Errorf("backend.Reboot called %d times — the whole point is that it is not", be.reboots)
	}
}

// And the same handler without the fault must still reboot, so the test above
// is measuring the fault rather than a broken handler.
func TestNoFault_RebootsNormally(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n"
	be := &countingRebootBackend{}

	subs, err := RegisterHandlersWithFault(nc, nodeID, be, FaultNone)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	}()

	cmd, _ := json.Marshal(proto.UpdateRebootCmd{BundleID: "sha", DelaySeconds: 3})
	if _, err := nc.Request(proto.UpdateRebootSubject(nodeID), cmd, 3*time.Second); err != nil {
		t.Fatalf("reboot rpc: %v", err)
	}
	if be.reboots != 1 {
		t.Errorf("backend.Reboot called %d times, want 1", be.reboots)
	}
}

// fail-health is not a reboot fault: the node must reboot normally and fail
// later, at conjunct (d). If it also suppressed the reboot the two faults would
// be the same test.
func TestFaultFailHealth_DoesNotTouchTheRebootPath(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n"
	be := &countingRebootBackend{}

	subs, err := RegisterHandlersWithFault(nc, nodeID, be, FaultFailHealth)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	}()

	cmd, _ := json.Marshal(proto.UpdateRebootCmd{BundleID: "sha", DelaySeconds: 3})
	if _, err := nc.Request(proto.UpdateRebootSubject(nodeID), cmd, 3*time.Second); err != nil {
		t.Fatalf("reboot rpc: %v", err)
	}
	if be.reboots != 1 {
		t.Errorf("backend.Reboot called %d times, want 1 — fail-health reboots for real", be.reboots)
	}
}

// countingRebootBackend is a Backend that records Reboot calls. Only the reboot
// verb is exercised by these tests; the rest satisfy the interface.
type countingRebootBackend struct {
	reboots  int
	onReboot func()
}

func (b *countingRebootBackend) Name() string { return "counting" }

func (b *countingRebootBackend) Precheck(context.Context) (*proto.UpdatePrecheckAck, error) {
	return &proto.UpdatePrecheckAck{OK: true, ActiveSlot: proto.SlotA, InactiveSlot: proto.SlotB}, nil
}

func (b *countingRebootBackend) Download(context.Context, string, string, string, int64, func(int64, int64)) (string, string, error) {
	return "", "", nil
}

func (b *countingRebootBackend) Install(context.Context, string, string, proto.UpdateSlot, func(string, int)) (string, error) {
	return "", nil
}

func (b *countingRebootBackend) Reboot(_ context.Context, _ string, delay int) (int, error) {
	b.reboots++
	if b.onReboot != nil {
		b.onReboot()
	}
	return delay, nil
}

func (b *countingRebootBackend) MarkGood(context.Context, string) error        { return nil }
func (b *countingRebootBackend) MarkBad(context.Context, string, string) error { return nil }

// Announce is a safety mechanism, not decoration: a node silently carrying a
// fault injector is worse than no injector at all, and this line is what the
// bench procedure greps for before dispatching a round — the check that
// replaced being fatal. Silence on an armed fault is the bug.
func TestAnnounce_ShoutsWhenArmedAndIsSilentWhenNot(t *testing.T) {
	if got := captureLog(func() { FaultNone.Announce() }); got != "" {
		t.Errorf("unarmed announce logged %q — a clean node must say nothing", got)
	}
	for _, f := range []Fault{FaultNoReboot, FaultFailHealth} {
		got := captureLog(func() { f.Announce() })
		if !strings.Contains(got, string(f)) {
			t.Errorf("announce for %q = %q, must name the armed fault", f, got)
		}
		if !strings.Contains(got, FaultEnv) {
			t.Errorf("announce for %q = %q, must name the variable to unset", f, got)
		}
	}
}
