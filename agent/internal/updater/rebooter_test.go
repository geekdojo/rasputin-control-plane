package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/system"
)

// recordingRebooter stands in for the agent's one reboot function
// (*system.Rebooter). It records every request and restarts nothing, which is
// what lets these tests prove WHAT each update backend asks for — the mode,
// the reason, the delay — without any of them being able to restart the
// machine running the tests.
//
// What a request then DOES (the rebooting event, the mute, the exec, the
// logging) is system.Rebooter's behaviour and is tested in that package. The
// backends have no reboot behaviour of their own left to test.
type recordingRebooter struct {
	mu       sync.Mutex
	requests []system.RebootRequest
	// err, when set, refuses every request.
	err error
	// simulate makes an accepted request call AfterSimulatedBoot before
	// returning, the way a simulated reboot eventually does.
	simulate bool
}

func (r *recordingRebooter) Reboot(req system.RebootRequest) (int, error) {
	r.mu.Lock()
	r.requests = append(r.requests, req)
	err := r.err
	r.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if r.simulate && !req.AnnounceOnly && req.AfterSimulatedBoot != nil {
		req.AfterSimulatedBoot()
	}
	return req.DelaySeconds, nil
}

func (r *recordingRebooter) got() []system.RebootRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]system.RebootRequest(nil), r.requests...)
}

// only returns the single request recorded, failing the test otherwise.
func (r *recordingRebooter) only(t *testing.T) system.RebootRequest {
	t.Helper()
	reqs := r.got()
	if len(reqs) != 1 {
		t.Fatalf("the rebooter was asked %d times, want exactly 1: %+v", len(reqs), reqs)
	}
	return reqs[0]
}

func useTrybootMarker(t *testing.T, present bool) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "autoboot.txt")
	if present {
		if err := os.WriteFile(marker, []byte("[all]\ntryboot_a_b=1\nboot_partition=2\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	orig := trybootMarker
	t.Cleanup(func() { trybootMarker = orig })
	trybootMarker = marker
}

// The update path reboots through the same function as an operator's reboot,
// and asks for the trial boot ONLY on an image that has the tryboot marker.
func TestRAUCBackend_RebootAsksTheRebooter_TrybootOnlyWithTheMarker(t *testing.T) {
	for _, tc := range []struct {
		name   string
		marker bool
		want   system.RebootMode
	}{
		{"marker absent (GRUB image): plain", false, system.RebootPlain},
		{"marker present (Pi tryboot image): tryboot", true, system.RebootTryboot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useTrybootMarker(t, tc.marker)
			rec := &recordingRebooter{}
			b := &RAUCBackend{stateDir: t.TempDir()}
			b.SetRebooter(rec)

			got, err := b.Reboot(context.Background(), "0123456789abcdef", 5)
			if err != nil {
				t.Fatalf("Reboot: %v", err)
			}
			if got != 5 {
				t.Errorf("delay = %d, want what the rebooter applied (5)", got)
			}
			req := rec.only(t)
			if req.Mode != tc.want {
				t.Errorf("mode = %q, want %q", req.Mode, tc.want)
			}
			if req.DelaySeconds != 5 {
				t.Errorf("requested delay = %d, want 5", req.DelaySeconds)
			}
			if !strings.HasPrefix(req.Reason, "update.reboot") || !strings.Contains(req.Reason, "0123456789ab") {
				t.Errorf("reason = %q, want it to name update.reboot and the bundle", req.Reason)
			}
			if req.AnnounceOnly || req.AfterSimulatedBoot != nil {
				t.Errorf("request = %+v: a real backend must set neither AnnounceOnly nor a simulation hook", req)
			}
		})
	}
}

// Leaving a failed trial is a PLAIN reboot even on a tryboot image: the point
// is to boot the committed slot, not to trial anything.
func TestRAUCBackend_MarkBadRebootsPlainEvenOnATrybootImage(t *testing.T) {
	fakeRAUC(t, "ok")
	useTrybootMarker(t, true)
	rec := &recordingRebooter{}
	b, err := NewRAUCBackend(t.TempDir(), trustNoTLS)
	if err != nil {
		t.Fatalf("NewRAUCBackend: %v", err)
	}
	b.SetRebooter(rec)
	if err := b.MarkBad(context.Background(), "0123456789abcdef", "health failed"); err != nil {
		t.Fatalf("MarkBad: %v", err)
	}
	req := rec.only(t)
	if req.Mode != system.RebootPlain {
		t.Errorf("mode = %q, want plain", req.Mode)
	}
	if !strings.HasPrefix(req.Reason, "update.mark-bad") {
		t.Errorf("reason = %q, want update.mark-bad", req.Reason)
	}
}

// A mark-bad that failed must not reboot the node.
func TestRAUCBackend_FailedMarkBadDoesNotReboot(t *testing.T) {
	fakeRAUC(t, "fail")
	rec := &recordingRebooter{}
	b, err := NewRAUCBackend(t.TempDir(), trustNoTLS)
	if err != nil {
		t.Fatalf("NewRAUCBackend: %v", err)
	}
	b.SetRebooter(rec)
	if err := b.MarkBad(context.Background(), "x", "r"); err == nil {
		t.Fatal("MarkBad should fail")
	}
	if n := len(rec.got()); n != 0 {
		t.Errorf("the rebooter was asked %d times after a failed mark-bad, want 0", n)
	}
}

// A refused reboot is an error from every backend — never a silent success.
func TestBackends_ARefusedRebootIsAnError(t *testing.T) {
	refused := errors.New(`this node has no "reboot" command`)
	backends := map[string]func(rb Rebooter) Backend{
		"rauc": func(rb Rebooter) Backend {
			b := &RAUCBackend{stateDir: t.TempDir()}
			b.SetRebooter(rb)
			return b
		},
		"openwrt-ab": func(rb Rebooter) Backend {
			b := &OpenWrtABBackend{stateDir: t.TempDir()}
			b.SetRebooter(rb)
			return b
		},
		"mock": func(rb Rebooter) Backend {
			b, err := NewMockBackend(t.TempDir())
			if err != nil {
				t.Fatalf("NewMockBackend: %v", err)
			}
			b.SetRebooter(rb)
			return b
		},
	}
	for name, build := range backends {
		t.Run(name+"/refused", func(t *testing.T) {
			useTrybootMarker(t, false)
			if _, err := build(&recordingRebooter{err: refused}).Reboot(context.Background(), "b", 3); !errors.Is(err, refused) {
				t.Errorf("err = %v, want the rebooter's refusal", err)
			}
		})
		t.Run(name+"/not wired", func(t *testing.T) {
			useTrybootMarker(t, false)
			if _, err := build(nil).Reboot(context.Background(), "b", 3); err == nil {
				t.Error("a backend with no rebooter must refuse to reboot, not report success")
			}
		})
	}
}

// The mock has no reboot of its own either: it asks the same function, plain,
// and hands it the slot flip to run when the simulated node comes back.
func TestMockBackend_RebootAsksTheRebooterAndFlipsSlotsWhenSimulated(t *testing.T) {
	rec := &recordingRebooter{}
	mb := newUpdaterMock(t)
	mb.SetRebooter(rec)
	if _, err := mb.Reboot(context.Background(), "bundle", 4); err != nil {
		t.Fatalf("Reboot: %v", err)
	}
	req := rec.only(t)
	if req.Mode != system.RebootPlain || req.DelaySeconds != 4 {
		t.Errorf("request = %+v, want plain with delay 4", req)
	}
	if req.AfterSimulatedBoot == nil {
		t.Fatal("the mock must hand over its slot flip; without it a simulated update never changes slot")
	}
}
