package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// The shipping default has to be "no fault", and it has to be the default that
// arrives when nobody has thought about it — i.e. an unset variable.
func TestFaultFromEnv_UnsetIsNone(t *testing.T) {
	t.Setenv(FaultEnv, "")
	got, err := FaultFromEnv()
	if err != nil {
		t.Fatalf("unset must not error: %v", err)
	}
	if got != FaultNone {
		t.Errorf("fault = %q, want none", got)
	}
}

func TestFaultFromEnv_KnownValues(t *testing.T) {
	for _, want := range []Fault{FaultNoReboot, FaultDieAfterReboot, FaultFailHealth} {
		t.Run(string(want), func(t *testing.T) {
			t.Setenv(FaultEnv, string(want))
			got, err := FaultFromEnv()
			if err != nil {
				t.Fatalf("%s: %v", want, err)
			}
			if got != want {
				t.Errorf("fault = %q, want %q", got, want)
			}
		})
	}
}

// A typo must be LOUD. If an unrecognised value silently meant "no fault", a
// mistyped fault would produce a clean, healthy update that reads exactly like
// a passing test — the test would report success having proven nothing, which
// is worse than the test failing.
func TestFaultFromEnv_UnknownValueIsAnError(t *testing.T) {
	t.Setenv(FaultEnv, "no-reboto")
	got, err := FaultFromEnv()
	if err == nil {
		t.Fatal("an unrecognised fault must be an error, never a silent no-op")
	}
	if got != FaultNone {
		t.Errorf("fault = %q, want none alongside the error", got)
	}
}

// The marker has to survive the reboot it spans and then fire exactly once —
// a node stuck mute forever would need a hand-fix to rejoin, which defeats the
// point of reproducing c08 on a bench you want back.
func TestMuteMarker_OneShot(t *testing.T) {
	cfg := NewFaultConfig(FaultDieAfterReboot, t.TempDir())
	if cfg.TakeMuteAfterReboot() {
		t.Fatal("no marker armed, must not fire")
	}
	if err := cfg.ArmMuteAfterReboot(); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if !cfg.TakeMuteAfterReboot() {
		t.Error("armed marker must fire on the next boot")
	}
	if cfg.TakeMuteAfterReboot() {
		t.Error("marker must be consumed — a node that stays mute forever needs a hand-fix to rejoin")
	}
}

// The regression. The marker is armed by one process and consumed by ANOTHER,
// on the far side of a reboot, so the two halves only meet through the path
// they each compute. They computed different ones: armed into <stateDir>/updater,
// looked for in <stateDir>. die-after-reboot silently never fired and the update
// it was meant to break returned a clean `committed` in 63 seconds (bench
// 2026-08-13) — a fault that proves nothing while reporting success.
//
// This test spans the restart the way the real thing does: arm through one
// FaultConfig value, consume through a SEPARATE one built the same way, with
// nothing shared but the directory the caller supplies.
func TestMuteMarker_SurvivesAProcessRestart(t *testing.T) {
	dir := t.TempDir()

	// process 1: the reboot handler arms, then the process goes away
	if err := NewFaultConfig(FaultDieAfterReboot, dir).ArmMuteAfterReboot(); err != nil {
		t.Fatalf("arm: %v", err)
	}

	// process 2: startup on the far side of the reboot
	if !NewFaultConfig(FaultDieAfterReboot, dir).TakeMuteAfterReboot() {
		t.Fatal("a marker armed before the reboot was not found after it — the fault would silently not fire and the round would report a clean update")
	}
}

// A fault bound to one directory must not find a marker armed under another.
// Stated explicitly because the bug was exactly this, and "obviously they use
// the same dir" is what made it invisible for a whole bench round.
func TestMuteMarker_DoesNotLeakAcrossDirectories(t *testing.T) {
	armed := NewFaultConfig(FaultDieAfterReboot, t.TempDir())
	other := NewFaultConfig(FaultDieAfterReboot, t.TempDir())
	if err := armed.ArmMuteAfterReboot(); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if other.TakeMuteAfterReboot() {
		t.Error("a different directory must not see this marker")
	}
	if !armed.TakeMuteAfterReboot() {
		t.Error("the arming config must still see its own marker")
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

	subs, err := RegisterHandlersWithFault(nc, nodeID, be, NewFaultConfig(FaultNoReboot, t.TempDir()))
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

	subs, err := RegisterHandlersWithFault(nc, nodeID, be, NewFaultConfig(FaultNone, t.TempDir()))
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

// FaultDieAfterReboot must arm the marker BEFORE rebooting — after the reboot
// this process no longer exists, so an arm-after-reboot would never happen.
func TestFaultDieAfterReboot_ArmsMarkerBeforeRebooting(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n"
	dir := t.TempDir()
	be := &countingRebootBackend{onReboot: func() {
		// Runs inside backend.Reboot: the marker must already be on disk.
		if _, err := os.Stat(filepath.Join(dir, muteMarkerName)); err != nil {
			t.Errorf("marker not armed before the reboot: %v", err)
		}
	}}

	subs, err := RegisterHandlersWithFault(nc, nodeID, be, NewFaultConfig(FaultDieAfterReboot, dir))
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
		t.Errorf("backend.Reboot called %d times, want 1 — this fault reboots for real", be.reboots)
	}
	if !NewFaultConfig(FaultDieAfterReboot, dir).TakeMuteAfterReboot() {
		t.Error("marker must be armed for the next boot")
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

// The error message IS the mitigation. A mistyped fault is fatal at startup,
// so this string is the only thing standing between an operator and ten minutes
// of wondering why their bench round came back healthy. It has to name what was
// wrong AND what would have been right.
func TestUnknownFaultError_NamesTheBadValueAndTheValidOnes(t *testing.T) {
	t.Setenv(FaultEnv, "no-reboto")
	_, err := FaultFromEnv()
	if err == nil {
		t.Fatal("want an error")
	}
	msg := err.Error()
	for _, want := range []string{
		"no-reboto",                 // what they typed
		FaultEnv,                    // which knob
		string(FaultNoReboot),       // …and every valid option, so the
		string(FaultDieAfterReboot), // typo is self-correcting without
		string(FaultFailHealth),     // going to the source
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
}

// Announce is a safety mechanism, not decoration: a node silently carrying a
// fault injector is worse than no injector at all, and this line is what a
// confused operator greps for. Silence on an armed fault is the bug.
func TestAnnounce_ShoutsWhenArmedAndIsSilentWhenNot(t *testing.T) {
	capture := func(f Fault) string {
		var buf bytes.Buffer
		orig := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(orig)
		f.Announce()
		return buf.String()
	}

	if got := capture(FaultNone); got != "" {
		t.Errorf("unarmed announce logged %q — a clean node must say nothing", got)
	}
	for _, f := range []Fault{FaultNoReboot, FaultDieAfterReboot, FaultFailHealth} {
		got := capture(f)
		if !strings.Contains(got, string(f)) {
			t.Errorf("announce for %q = %q, must name the armed fault", f, got)
		}
		if !strings.Contains(got, FaultEnv) {
			t.Errorf("announce for %q = %q, must name the variable to unset", f, got)
		}
	}
}
