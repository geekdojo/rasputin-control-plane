package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// assertSentence checks the first line of a person-facing message (ERR-MESSAGE).
func assertSentence(t *testing.T, msg string) {
	t.Helper()
	line := strings.SplitN(strings.TrimSpace(msg), "\n", 2)[0]
	if line == "" || line[0] < 'A' || line[0] > 'Z' || !strings.HasSuffix(line, ".") {
		t.Errorf("message %q is not a sentence (capital letter, full stop)", line)
	}
}

// fakeInstaller is a rootfsInstaller. It also carries a reboot counter that
// nothing in the verb can reach: the verb must never reboot.
type fakeInstaller struct {
	ack        *proto.UpdatePrecheckAck
	artifact   string
	installErr error
	version    string
	installed  []proto.UpdateSlot
	reboots    int
}

func (f *fakeInstaller) Precheck(context.Context) (*proto.UpdatePrecheckAck, error) {
	return f.ack, nil
}
func (f *fakeInstaller) ArtifactPath(string) (string, error) { return f.artifact, nil }
func (f *fakeInstaller) Install(_ context.Context, _, _ string, slot proto.UpdateSlot, _ func(string, int)) (string, error) {
	f.installed = append(f.installed, slot)
	return f.version, f.installErr
}
func (f *fakeInstaller) Reboot() { f.reboots++ }

func newFakeInstaller(t *testing.T, withRootfs, withSig bool) *fakeInstaller {
	t.Helper()
	art := filepath.Join(t.TempDir(), "b1.rootfs")
	if withRootfs {
		if err := os.WriteFile(art, []byte("SQUASHFS"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if withSig {
		if err := os.WriteFile(art+".sig", []byte("SIG"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &fakeInstaller{
		ack:      &proto.UpdatePrecheckAck{OK: true, ActiveSlot: proto.SlotA, InactiveSlot: proto.SlotB},
		artifact: art,
		version:  "2026.10.4-dev.3",
	}
}

func runInstall(f *fakeInstaller, args ...string) (code int, stdout, stderr string, stateDir string) {
	var out, errBuf bytes.Buffer
	code = runInstallRootfs(args, &out, &errBuf, quietLogger(), func(dir string, _ *slog.Logger) (rootfsInstaller, error) {
		stateDir = dir
		return f, nil
	})
	return code, out.String(), errBuf.String(), stateDir
}

// TC-888-11: the install-rootfs verb.
func TestInstallRootfs(t *testing.T) {
	t.Run("usage", func(t *testing.T) {
		for _, args := range [][]string{nil, {"a", "b"}} {
			code, _, stderr, _ := runInstall(newFakeInstaller(t, true, true), args...)
			if code != 2 {
				t.Errorf("%q: exit %d, want 2", args, code)
			}
			assertSentence(t, stderr)
		}
	})
	for _, tc := range []struct {
		name            string
		rootfs, sig     bool
		wantInStderrMsg string
	}{
		{"missing rootfs", false, true, "artifact"},
		{"missing sig", true, false, "signature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeInstaller(t, tc.rootfs, tc.sig)
			code, _, stderr, _ := runInstall(f, "b1")
			if code != 1 || !strings.Contains(stderr, tc.wantInStderrMsg) {
				t.Errorf("exit %d, stderr %q; want 1 naming the %s", code, stderr, tc.wantInStderrMsg)
			}
			assertSentence(t, stderr)
			if len(f.installed) != 0 {
				t.Error("installed without the file")
			}
		})
	}
	t.Run("success", func(t *testing.T) {
		f := newFakeInstaller(t, true, true)
		code, stdout, stderr, dir := runInstall(f, "--state-dir", "/data/updater", "b1")
		if code != 0 {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
		if dir != "/data/updater" {
			t.Errorf("state dir = %q, want the --state-dir value", dir)
		}
		if len(f.installed) != 1 || f.installed[0] != proto.SlotB {
			t.Errorf("installed into %v, want exactly the precheck's inactive slot b", f.installed)
		}
		if !strings.Contains(stdout, "2026.10.4-dev.3") || !strings.Contains(stdout, "slot B") {
			t.Errorf("stdout %q, want the version and the slot", stdout)
		}
		assertSentence(t, stdout)
		if f.reboots != 0 {
			t.Error("the verb rebooted")
		}
	})
	for _, tc := range []struct{ name, err string }{
		{"install error", "write slot B (/dev/nvme0n1p3): input/output error"},
		{"signature error", "openwrt-ab install: signature verify: chain does not build"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeInstaller(t, true, true)
			f.installErr = errors.New(tc.err)
			code, _, stderr, _ := runInstall(f, "b1")
			if code != 1 || !strings.Contains(stderr, tc.err) {
				t.Errorf("exit %d, stderr %q; want 1 with the cause", code, stderr)
			}
			assertSentence(t, stderr)
			if f.reboots != 0 {
				t.Error("the verb rebooted")
			}
		})
	}
	t.Run("backend construction fails", func(t *testing.T) {
		var errBuf bytes.Buffer
		code := runInstallRootfs([]string{"b1"}, io.Discard, &errBuf, quietLogger(),
			func(string, *slog.Logger) (rootfsInstaller, error) { return nil, errors.New("no logger wired") })
		if code != 1 {
			t.Errorf("exit %d, want 1", code)
		}
		assertSentence(t, errBuf.String())
	})
}

type fakeRepairer struct {
	outcome updater.RepairOutcome
	err     error
	reboots int
}

func (f *fakeRepairer) RepairRunningSlot() (updater.RepairOutcome, error) { return f.outcome, f.err }
func (f *fakeRepairer) Reboot()                                           { f.reboots++ }

// TC-893-12 (and TC-888-31): the repair-slot-boot verb's exit codes, which the
// kernel-match guard reads: repaired 0, fallback 0, esp_unavailable 3, refused
// for a cmdline with no slot 1, any argument 2. Also its construction without
// the agent state dir (F-888-07).
func TestRepairSlotBoot(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    *fakeRepairer
		want int
	}{
		{"repaired", &fakeRepairer{outcome: updater.RepairRepaired}, 0},
		{"fallback", &fakeRepairer{outcome: updater.RepairFallback, err: errors.New("write EFI/BOOT/bootx64.efi.new: no space left on device")}, 0},
		{"ESP unavailable", &fakeRepairer{err: fmt.Errorf("repair slot B: mount: %w", updater.ErrESPUnavailable)}, 3},
		{"refused", &fakeRepairer{err: errors.New("repair slot: cmdline: cannot determine the running slot from the kernel command line")}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := runRepairSlotBoot(nil, &out, &errBuf, quietLogger(),
				func(*slog.Logger) (slotRepairer, error) { return tc.f, nil })
			if code != tc.want {
				t.Errorf("exit %d, want %d", code, tc.want)
			}
			assertSentence(t, out.String()+errBuf.String())
			if tc.f.reboots != 0 {
				t.Error("the verb rebooted")
			}
		})
	}
	t.Run("extra argument", func(t *testing.T) {
		code, _, stderr := run(t, "repair-slot-boot", "B")
		if code != 2 {
			t.Errorf("exit %d, want 2", code)
		}
		if !strings.HasPrefix(stderr, "The repair-slot-boot command takes no arguments.\n") {
			t.Errorf("stderr %q, want it to open with the no-arguments sentence", stderr)
		}
	})
	t.Run("construction fails", func(t *testing.T) {
		var errBuf bytes.Buffer
		code := runRepairSlotBoot(nil, io.Discard, &errBuf, quietLogger(),
			func(*slog.Logger) (slotRepairer, error) { return nil, errors.New("no logger wired") })
		if code == 0 {
			t.Error("a failed construction exited 0, which tells the guard to reboot")
		}
		assertSentence(t, errBuf.String())
	})
	t.Run("built without the state dir", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "rasputin")
		if err := os.Mkdir(parent, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(parent, 0o755) })
		stateDir := filepath.Join(parent, "agent-state")
		t.Setenv("RASPUTIN_AGENT_STATE_DIR", stateDir)
		r, err := newSlotRepairer(quietLogger())
		if err != nil || r == nil {
			t.Fatalf("newSlotRepairer = (%v, %v), want a repairer", r, err)
		}
		if _, err := os.Stat(stateDir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("construction touched %s (stat err %v)", stateDir, err)
		}
	})
}
