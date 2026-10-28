package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The pinned 2026.10.3 field kernel's identity (F-888-08), split as procfs
// gives it: osrelease is `uname -r`, version is `uname -v`.
const (
	legacyRelease = "6.12.94"
	legacyVersion = "#0 SMP Mon Jun 29 12:59:20 2026"
	legacyID      = legacyRelease + " " + legacyVersion
)

// sbFixture is a backend on fake boot media whose ESP holds a real grubenv, so
// every grubenv edit goes through WithESP exactly as on the firewall.
type sbFixture struct {
	t        *testing.T
	b        *OpenWrtABBackend
	media    *fakeMedia
	mods     *fakeMods
	calls    *callLog
	logs     *logCapture
	esp      string
	slotRoot string // the bundle just written, as OpenSlot mounts it
	srcRoot  string // the running rootfs, for the repair
	kernel   []byte
	cfg      []byte
	art      string
}

func newSBFixture(t *testing.T, booted string, env map[string]string) *sbFixture {
	t.Helper()
	dir := t.TempDir()
	f := &sbFixture{
		t:        t,
		esp:      filepath.Join(dir, "esp"),
		slotRoot: filepath.Join(dir, "slot"),
		srcRoot:  filepath.Join(dir, "root"),
		kernel:   []byte("NEW-KERNEL-6.12.112"),
		cfg:      []byte("NEW-GRUB-CFG"),
		calls:    &callLog{},
		logs:     &logCapture{},
		mods:     &fakeMods{},
	}
	for _, root := range []string{f.slotRoot, f.srcRoot} {
		writeFile(t, filepath.Join(root, "boot", "vmlinuz"), f.kernel)
		writeFile(t, filepath.Join(root, "boot", "grub.cfg"), f.cfg)
	}
	writeFile(t, filepath.Join(f.srcRoot, "boot", "legacy-kmods", "kernel-id"), []byte(legacyID+"\n"))
	writeGrubenvFile(t, f.grubenvPath(), env)
	writeFile(t, filepath.Join(f.esp, "boot", "vmlinuz"), []byte("LEGACY-SHARED-KERNEL"))
	writeFile(t, filepath.Join(f.esp, espGrubCfg), []byte("OLD-GRUB-CFG"))

	f.media = &fakeMedia{
		espRoot:   f.esp,
		slotRoots: map[string]string{"/dev/slot-A": f.slotRoot, "/dev/slot-B": f.slotRoot},
		calls:     f.calls,
	}
	b, err := newOpenWrtAB(f.media, f.mods, fakeFS{list: procFilesystemsWithVFAT}, f.logs.logger())
	if err != nil {
		t.Fatal(err)
	}
	b.stateDir = filepath.Join(dir, "state")
	b.procCmdline = filepath.Join(dir, "cmdline")
	writeFile(t, b.procCmdline, []byte("root=PARTLABEL=rootfs-"+map[string]string{"A": "0", "B": "1"}[booted]+" ro\n"))
	b.procOSRelease = filepath.Join(dir, "osrelease")
	b.procKernelVersion = filepath.Join(dir, "version")
	writeFile(t, b.procOSRelease, []byte(legacyRelease+"\n"))
	writeFile(t, b.procKernelVersion, []byte(legacyVersion+"\n"))
	b.verifySig = func(context.Context, string) error { f.calls.add("verify"); return nil }
	b.resolveDevice = func(slot string) (string, error) { f.calls.add("resolve"); return "/dev/slot-" + slot, nil }
	b.writeSlot = func(context.Context, string, string, func(string, int)) error { f.calls.add("write"); return nil }
	f.b = b

	f.art = filepath.Join(b.stateDir, "bundles", "b1.rootfs")
	writeFile(t, f.art, []byte("SQUASHFS"))
	return f
}

func (f *sbFixture) grubenvPath() string { return filepath.Join(f.esp, "boot", "grub", "grubenv") }
func (f *sbFixture) env() map[string]string {
	f.t.Helper()
	return mustRead(f.t, f.grubenvPath())
}
func (f *sbFixture) envBytes() []byte {
	f.t.Helper()
	b, err := os.ReadFile(f.grubenvPath())
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}
func (f *sbFixture) espFile(rel string) []byte {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.esp, rel))
	if err != nil {
		f.t.Fatalf("ESP %s: %v", rel, err)
	}
	return b
}
func (f *sbFixture) espTree() string { return treeHash(f.t, f.esp, "boot/grub/grubenv") }
func (f *sbFixture) install() error {
	_, err := f.b.Install(context.Background(), "b1", "", proto.SlotB, nil)
	return err
}
func (f *sbFixture) noFile(rel string) {
	f.t.Helper()
	if _, err := os.Lstat(filepath.Join(f.esp, rel)); !errors.Is(err, os.ErrNotExist) {
		f.t.Errorf("ESP %s exists (err=%v), want it absent", rel, err)
	}
}

// fieldEnv is a box booted on A, with B the inactive target.
func fieldEnv() map[string]string {
	return map[string]string{"ORDER": "A B", "A_OK": "1", "A_TRY": "0", "B_OK": "1", "B_TRY": "0"}
}

// TC-888-01: installSlotBoot writes the slot's kernel as boot/vmlinuz-B, byte
// for byte, and leaves no staging file behind.
func TestInstallSlotBoot_WritesTheSlotKernel(t *testing.T) {
	f := newSBFixture(t, "A", fieldEnv())
	f.noFile("boot/vmlinuz-B")
	if err := f.b.installSlotBoot(f.slotRoot, "B"); err != nil {
		t.Fatalf("installSlotBoot: %v", err)
	}
	if got := shaOf(f.espFile("boot/vmlinuz-B")); got != shaOf(f.kernel) {
		t.Errorf("vmlinuz-B sha = %s, want the slot kernel's %s", got, shaOf(f.kernel))
	}
	f.noFile("boot/vmlinuz-B.new")
	f.noFile(espGrubCfg + ".new")
	if got := string(f.espFile("boot/vmlinuz")); got != "LEGACY-SHARED-KERNEL" {
		t.Errorf("the legacy shared kernel changed: %q", got)
	}
}

// TC-888-02: grub.cfg is replaced when it differs, and left alone (same inode,
// same mtime) when it is byte-identical; the log says which.
func TestInstallSlotBoot_ReplacesGrubCfgOnlyWhenDifferent(t *testing.T) {
	t.Run("different", func(t *testing.T) {
		f := newSBFixture(t, "A", fieldEnv())
		if err := f.b.installSlotBoot(f.slotRoot, "B"); err != nil {
			t.Fatal(err)
		}
		if got := string(f.espFile(espGrubCfg)); got != string(f.cfg) {
			t.Errorf("grub.cfg = %q, want the bundle's %q", got, f.cfg)
		}
		if got := grubCfgField(t, f.logs); got != "replaced" {
			t.Errorf("grub_cfg = %q, want replaced", got)
		}
	})
	t.Run("equal", func(t *testing.T) {
		f := newSBFixture(t, "A", fieldEnv())
		p := filepath.Join(f.esp, espGrubCfg)
		writeFile(t, p, f.cfg)
		old := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
		before, _ := os.Stat(p)
		if err := f.b.installSlotBoot(f.slotRoot, "B"); err != nil {
			t.Fatal(err)
		}
		after, _ := os.Stat(p)
		if !os.SameFile(before, after) || !after.ModTime().Equal(old) {
			t.Errorf("an identical grub.cfg was rewritten (same file %v, mtime %v)", os.SameFile(before, after), after.ModTime())
		}
		if got := grubCfgField(t, f.logs); got != "unchanged" {
			t.Errorf("grub_cfg = %q, want unchanged", got)
		}
	})
}

func grubCfgField(t *testing.T, l *logCapture) string {
	t.Helper()
	for _, r := range l.records(t) {
		if v, ok := r["grub_cfg"]; ok {
			return v.(string)
		}
	}
	t.Fatal("no record carries grub_cfg")
	return ""
}

// TC-888-03: a bundle without /boot/vmlinuz or /boot/grub.cfg is refused before
// the ESP is touched, the slot is never activated, and it stays not bootable.
func TestInstall_RefusesAPreFixBundle(t *testing.T) {
	for _, missing := range []string{"boot/vmlinuz", "boot/grub.cfg"} {
		t.Run(missing, func(t *testing.T) {
			f := newSBFixture(t, "A", fieldEnv())
			if err := os.Remove(filepath.Join(f.slotRoot, missing)); err != nil {
				t.Fatal(err)
			}
			tree := f.espTree()
			err := f.install()
			if err == nil {
				t.Fatal("Install accepted a bundle without " + missing)
			}
			for _, want := range []string{"predates per-slot kernels", "geekdojo/geekdojo-brain#888",
				"would boot on another release's kernel", missing} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not say %q", err, want)
				}
			}
			if f.espTree() != tree {
				t.Error("the ESP changed")
			}
			env := f.env()
			if env["ORDER"] != "A B" || env["B_OK"] != "0" {
				t.Errorf("grubenv ORDER=%q B_OK=%q, want ORDER kept and B not bootable", env["ORDER"], env["B_OK"])
			}
		})
	}
}

// TC-888-04: a staged kernel that reads back wrong on the fresh mount fails the
// install; the old vmlinuz-B survives and the staging file is removed.
func TestInstall_ReadBackMismatchKeepsTheOldKernel(t *testing.T) {
	f := newSBFixture(t, "A", fieldEnv())
	writeFile(t, filepath.Join(f.esp, "boot", "vmlinuz-B"), []byte("OLD-B-KERNEL"))
	// Mount 1 deactivates, 2 stages, 3 reads back: corrupt the disk before 3.
	f.media.beforeFn = map[int]func(string){3: func(root string) {
		writeFile(t, filepath.Join(root, "boot", "vmlinuz-B.new"), []byte("BIT-ROT"))
	}}
	err := f.install()
	if err == nil {
		t.Fatal("Install accepted a corrupt read-back")
	}
	for _, want := range []string{"boot/vmlinuz-B.new", "does not match", fakeESPDevice} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	if got := string(f.espFile("boot/vmlinuz-B")); got != "OLD-B-KERNEL" {
		t.Errorf("vmlinuz-B = %q, want the old kernel intact", got)
	}
	f.noFile("boot/vmlinuz-B.new")
	f.noFile(espGrubCfg + ".new")
	if env := f.env(); env["ORDER"] != "A B" || env["B_OK"] != "0" {
		t.Errorf("grubenv = %v, want B not activated", env)
	}
}

// TC-888-05: write, mount and rename failures each return a wrapped error
// naming the file or device, leave the old ESP files intact and the target
// not bootable. The write failure is induced as an unwritable staging path:
// the same error return as ENOSPC.
func TestInstall_FailuresLeaveTheESPIntact(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *sbFixture)
		want  []string
	}{
		{"kernel write", func(f *sbFixture) {
			mustMkdir(f.t, filepath.Join(f.esp, "boot", "vmlinuz-B.new", "x"))
		}, []string{"write boot/vmlinuz-B.new", fakeESPDevice}},
		{"ESP mount", func(f *sbFixture) {
			f.media.mountErr, f.media.mountErrFrom = errors.New("mount ESP "+fakeESPDevice+": no such device"), 2
		}, []string{"stage slot B", fakeESPDevice}},
		{"slot mount", func(f *sbFixture) {
			f.media.openSlotErr = errors.New("mount slot /dev/slot-B read-only: invalid argument")
		}, []string{"open slot B (/dev/slot-B)"}},
		{"kernel rename", func(f *sbFixture) {
			mustMkdir(f.t, filepath.Join(f.esp, "boot", "vmlinuz-B", "x"))
		}, []string{"rename boot/vmlinuz-B.new to boot/vmlinuz-B", fakeESPDevice}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSBFixture(t, "A", fieldEnv())
			tc.setup(f)
			tree := f.espTree()
			err := f.install()
			if err == nil {
				t.Fatal("Install succeeded")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
			if f.espTree() != tree {
				t.Errorf("the ESP changed:\nbefore:\n%s\nafter:\n%s", tree, f.espTree())
			}
			if env := f.env(); env["ORDER"] != "A B" || env["B_OK"] != "0" || env["A_OK"] != "1" {
				t.Errorf("grubenv = %v, want B not bootable, A untouched", env)
			}
		})
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TC-888-06: the target is not bootable before its partition is written, the
// steps run in order, and success activates the target only.
func TestInstall_Sequencing(t *testing.T) {
	f := newSBFixture(t, "A", fieldEnv())
	f.calls.snap = func() string {
		kv := mustRead(t, f.grubenvPath())
		return "B_OK=" + kv["B_OK"] + " B_TRY=" + kv["B_TRY"]
	}
	if err := f.install(); err != nil {
		t.Fatalf("Install: %v", err)
	}
	want := []string{"verify", "resolve", "WithESP", "write", "OpenSlot", "WithESP", "WithESP", "release", "WithESP"}
	if !reflect.DeepEqual(f.calls.names, want) {
		t.Fatalf("calls = %v, want %v (verify, resolve, deactivate, write, slot boot, activate)", f.calls.names, want)
	}
	if got := f.calls.snaps[3]; got != "B_OK=0 B_TRY=0" {
		t.Errorf("at writeSlot grubenv had %s, want B_OK=0 B_TRY=0", got)
	}
	env := f.env()
	if env["ORDER"] != "B A" || env["B_OK"] != "1" || env["B_TRY"] != "0" || env["A_OK"] != "1" || env["A_TRY"] != "0" {
		t.Errorf("grubenv = %v, want ORDER=B A, B_OK=1 B_TRY=0, A unchanged", env)
	}
	if got := shaOf(f.espFile("boot/vmlinuz-B")); got != shaOf(f.kernel) {
		t.Error("vmlinuz-B is not the bundle's kernel")
	}
}

// TC-888-07: a signature failure stops before anything is touched.
func TestInstall_SignatureFailureWritesNothing(t *testing.T) {
	f := newSBFixture(t, "A", fieldEnv())
	f.b.verifySig = func(context.Context, string) error { f.calls.add("verify"); return errors.New("chain does not build") }
	before := f.envBytes()
	err := f.install()
	if err == nil || !strings.Contains(err.Error(), "signature verify") {
		t.Fatalf("err = %v, want a signature verify failure", err)
	}
	if !reflect.DeepEqual(f.calls.names, []string{"verify"}) {
		t.Errorf("calls = %v, want only verify", f.calls.names)
	}
	if string(f.envBytes()) != string(before) {
		t.Error("grubenv changed")
	}
}

// TC-888-08 (backend side): a failing slot release is returned and stops the
// activation; a failed umount after staging is returned, and the read-back
// mount never happens, so nothing is renamed.
func TestInstall_ReleaseAndUmountErrorsAreReturned(t *testing.T) {
	t.Run("release", func(t *testing.T) {
		f := newSBFixture(t, "A", fieldEnv())
		f.media.releaseErr = errors.New("umount /dev/slot-B: device busy")
		err := f.install()
		if err == nil || !strings.Contains(err.Error(), "release slot B (/dev/slot-B)") || !strings.Contains(err.Error(), "device busy") {
			t.Fatalf("err = %v, want the release error", err)
		}
		if env := f.env(); env["ORDER"] != "A B" || env["B_OK"] != "0" {
			t.Errorf("grubenv = %v, want B not activated", env)
		}
	})
	t.Run("umount after staging", func(t *testing.T) {
		f := newSBFixture(t, "A", fieldEnv())
		f.media.umountErrOn = 2
		err := f.install()
		if err == nil || !strings.Contains(err.Error(), "device busy") {
			t.Fatalf("err = %v, want the umount error", err)
		}
		if f.media.espMounts != 2 {
			t.Errorf("ESP mounted %d times, want 2: no read-back after a failed umount", f.media.espMounts)
		}
		f.noFile("boot/vmlinuz-B")
		if env := f.env(); env["B_OK"] != "0" {
			t.Errorf("grubenv = %v, want B not bootable", env)
		}
	})
}

// TC-888-09: every collaborator is required.
func TestNewOpenWrtABBackend_RefusesEachNilCollaborator(t *testing.T) {
	media, mods, fsl, logger := &fakeMedia{}, &fakeMods{}, fakeFS{}, discardLogger()
	for _, tc := range []struct {
		name string
		call func() (*OpenWrtABBackend, error)
	}{
		{"trust", func() (*OpenWrtABBackend, error) {
			return NewOpenWrtABBackend(t.TempDir(), nil, media, mods, fsl, logger)
		}},
		{"media", func() (*OpenWrtABBackend, error) {
			return NewOpenWrtABBackend(t.TempDir(), trustNoTLS, nil, mods, fsl, logger)
		}},
		{"mods", func() (*OpenWrtABBackend, error) {
			return NewOpenWrtABBackend(t.TempDir(), trustNoTLS, media, nil, fsl, logger)
		}},
		{"fs", func() (*OpenWrtABBackend, error) {
			return NewOpenWrtABBackend(t.TempDir(), trustNoTLS, media, mods, nil, logger)
		}},
		{"logger", func() (*OpenWrtABBackend, error) {
			return NewOpenWrtABBackend(t.TempDir(), trustNoTLS, media, mods, fsl, nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if b, err := tc.call(); b != nil || err == nil {
				t.Errorf("nil %s: got (%v, %v), want (nil, error)", tc.name, b, err)
			}
		})
	}
	if b, err := NewOpenWrtABBackend(t.TempDir(), trustNoTLS, media, mods, fsl, logger); b == nil || err != nil {
		t.Errorf("all collaborators: got (%v, %v), want a backend", b, err)
	}
	if r, err := NewOpenWrtSlotRepairer(media, mods, fsl, nil); r != nil || err == nil {
		t.Errorf("slot repairer with a nil logger: got (%v, %v), want (nil, error)", r, err)
	}
	if m, err := NewOpenWrtBootMedia(nil); m != nil || err == nil {
		t.Errorf("NewOpenWrtBootMedia(nil): got (%v, %v), want (nil, error)", m, err)
	}
}

// TC-888-10: a successful install logs each step at INFO with its fields.
func TestInstallSlotBoot_LogsEachStep(t *testing.T) {
	f := newSBFixture(t, "A", fieldEnv())
	if err := f.install(); err != nil {
		t.Fatal(err)
	}
	var kernel, grub map[string]any
	for _, r := range f.logs.records(t) {
		switch r["step"] {
		case "kernel":
			kernel = r
		case "grub_cfg":
			grub = r
		}
	}
	if kernel == nil || grub == nil {
		t.Fatalf("records = %v, want a kernel step and a grub_cfg step", f.logs.records(t))
	}
	for _, r := range []map[string]any{kernel, grub} {
		if r["level"] != "INFO" || r["slot"] != "B" {
			t.Errorf("record %v: want level INFO and slot B", r)
		}
	}
	if kernel["kernel_sha256"] != shaOf(f.kernel) || kernel["kernel_bytes"] != float64(len(f.kernel)) {
		t.Errorf("kernel record %v: want kernel_sha256=%s kernel_bytes=%d", kernel, shaOf(f.kernel), len(f.kernel))
	}
	if grub["grub_cfg"] != "replaced" {
		t.Errorf("grub record %v: want grub_cfg=replaced", grub)
	}
}

// ---- RepairRunningSlot ------------------------------------------------------

func repairEnv(slot string) map[string]string {
	other := map[string]string{"A": "B", "B": "A"}[slot]
	return map[string]string{
		"ORDER":      slot + " " + other,
		slot + "_OK": "1", slot + "_TRY": "1",
		other + "_OK": "1", other + "_TRY": "0",
	}
}

// TC-888-26: the first repair writes the slot's kernel and grub.cfg, then
// re-arms the trial (X_TRY=0 X_REPAIR=1) and touches no other key.
func TestRepairRunningSlot_FirstRepair(t *testing.T) {
	for _, slot := range []string{"B", "A"} {
		t.Run(slot, func(t *testing.T) {
			before := repairEnv(slot)
			f := newSBFixture(t, slot, before)
			f.calls.snap = func() string {
				return "repair=" + mustRead(t, f.grubenvPath())[slot+"_REPAIR"] + " cfg=" + string(f.espFile(espGrubCfg))
			}
			outcome, err := f.b.repairRunningSlot(f.srcRoot)
			if outcome != RepairRepaired || err != nil {
				t.Fatalf("= (%v, %v), want (repaired, nil)", outcome, err)
			}
			if got := shaOf(f.espFile("boot/vmlinuz-" + slot)); got != shaOf(f.kernel) {
				t.Error("vmlinuz-" + slot + " is not the running rootfs's kernel")
			}
			if got := string(f.espFile(espGrubCfg)); got != string(f.cfg) {
				t.Errorf("grub.cfg = %q, want replaced", got)
			}
			want := map[string]string{}
			for k, v := range before {
				want[k] = v
			}
			want[slot+"_TRY"], want[slot+"_REPAIR"] = "0", "1"
			if got := f.env(); !reflect.DeepEqual(got, want) {
				t.Errorf("grubenv = %v, want %v", got, want)
			}
			// The grubenv write is the last mount, after the grub.cfg rename:
			// until then no mount saw X_REPAIR, and the last one already saw
			// the new grub.cfg.
			last := len(f.calls.snaps) - 1
			if last < 0 || f.calls.snaps[last] != "repair= cfg="+string(f.cfg) {
				t.Errorf("mount snapshots = %q, want the last mount to see the new grub.cfg and no repair flag yet", f.calls.snaps)
			}
			var n int
			for _, r := range f.logs.records(t) {
				if r["outcome"] == "repaired" {
					n++
					if r["level"] != "INFO" || r["slot"] != slot {
						t.Errorf("record %v: want INFO with slot %s", r, slot)
					}
				}
			}
			if n != 1 {
				t.Errorf("%d outcome=repaired records, want 1", n)
			}
		})
	}
}

// TC-888-27: a mismatched boot after a repair marks the slot bad, drops the
// flag, and writes nothing else on the ESP.
func TestRepairRunningSlot_SecondMismatchFallsBack(t *testing.T) {
	env := repairEnv("B")
	env["B_REPAIR"] = "1"
	f := newSBFixture(t, "B", env)
	tree := f.espTree()
	outcome, err := f.b.repairRunningSlot(f.srcRoot)
	if outcome != RepairFallback || err != nil {
		t.Fatalf("= (%v, %v), want (fallback, nil)", outcome, err)
	}
	got := f.env()
	if _, has := got["B_REPAIR"]; has || got["B_OK"] != "0" || got["B_TRY"] != "0" {
		t.Errorf("grubenv = %v, want B_OK=0 B_TRY=0 and no B_REPAIR", got)
	}
	if f.espTree() != tree {
		t.Error("files under the ESP changed")
	}
	assertRepairErrorRecord(t, f.logs, "fallback", "B")
}

func assertRepairErrorRecord(t *testing.T, l *logCapture, outcome, slot string) {
	t.Helper()
	for _, r := range l.records(t) {
		if r["outcome"] != outcome {
			continue
		}
		if r["level"] != "ERROR" || r["slot"] != slot || r["step"] == nil || r["step"] == "" || r["err"] == nil || r["err"] == "" {
			t.Errorf("record %v: want ERROR with slot=%s, step and err", r, slot)
		}
		return
	}
	t.Errorf("no record with outcome=%s in %v", outcome, l.records(t))
}

// TC-888-28: failures after the ESP mounts fall back with X_OK=0; an ESP that
// will not mount is ErrESPUnavailable and leaves grubenv alone; a cmdline with
// no slot writes nothing.
func TestRepairRunningSlot_FailurePaths(t *testing.T) {
	for _, tc := range []string{"boot/vmlinuz-B.new", espGrubCfg + ".new"} {
		t.Run("write "+tc, func(t *testing.T) {
			f := newSBFixture(t, "B", repairEnv("B"))
			mustMkdir(t, filepath.Join(f.esp, tc, "x"))
			outcome, err := f.b.repairRunningSlot(f.srcRoot)
			if outcome != RepairFallback || err == nil || !strings.Contains(err.Error(), "write "+tc) {
				t.Fatalf("= (%v, %v), want fallback with the write error", outcome, err)
			}
			if env := f.env(); env["B_OK"] != "0" {
				t.Errorf("grubenv = %v, want B_OK=0", env)
			}
			assertRepairErrorRecord(t, f.logs, "fallback", "B")
		})
	}
	t.Run("ESP mount", func(t *testing.T) {
		f := newSBFixture(t, "B", repairEnv("B"))
		f.media.mountErr = errors.New("mount ESP " + fakeESPDevice + ": no such device")
		before := f.envBytes()
		outcome, err := f.b.repairRunningSlot(f.srcRoot)
		if outcome == RepairRepaired || outcome == RepairFallback || !errors.Is(err, ErrESPUnavailable) {
			t.Fatalf("= (%v, %v), want ErrESPUnavailable", outcome, err)
		}
		if !strings.Contains(err.Error(), fakeESPDevice) {
			t.Errorf("error %q does not name the device", err)
		}
		if string(f.envBytes()) != string(before) {
			t.Error("grubenv changed")
		}
		assertRepairErrorRecord(t, f.logs, "esp_unavailable", "B")
	})
	t.Run("no slot on the cmdline", func(t *testing.T) {
		f := newSBFixture(t, "B", repairEnv("B"))
		writeFile(t, f.b.procCmdline, []byte("root=/dev/sda2 ro\n"))
		before, tree := f.envBytes(), f.espTree()
		outcome, err := f.b.repairRunningSlot(f.srcRoot)
		if outcome != RepairNone || err == nil || errors.Is(err, ErrESPUnavailable) {
			t.Fatalf("= (%v, %v), want a plain error and no outcome", outcome, err)
		}
		if f.media.espMounts != 0 || string(f.envBytes()) != string(before) || f.espTree() != tree {
			t.Error("a repair with no slot touched the ESP")
		}
	})
}

// TC-888-29: the bundled FAT modules load only when vfat is missing AND the
// running kernel is exactly the one they were built for.
func TestRepairRunningSlot_LegacyModuleGate(t *testing.T) {
	kmod := func(f *sbFixture, name string) string {
		return filepath.Join(f.srcRoot, "boot", "legacy-kmods", legacyRelease, name+".ko")
	}
	t.Run("vfat absent, identity matches", func(t *testing.T) {
		f := newSBFixture(t, "B", repairEnv("B"))
		f.b.fs = fakeFS{list: procFilesystemsNoVFAT}
		outcome, err := f.b.repairRunningSlot(f.srcRoot)
		if outcome != RepairRepaired || err != nil {
			t.Fatalf("= (%v, %v), want repaired", outcome, err)
		}
		var want []string
		for _, m := range []string{"fat", "vfat", "nls_cp437", "nls_iso8859-1", "nls_utf8"} {
			want = append(want, kmod(f, m))
		}
		if !reflect.DeepEqual(f.mods.loaded, want) {
			t.Errorf("loaded %v, want %v", f.mods.loaded, want)
		}
	})
	t.Run("vfat present", func(t *testing.T) {
		f := newSBFixture(t, "B", repairEnv("B"))
		if _, err := f.b.repairRunningSlot(f.srcRoot); err != nil {
			t.Fatal(err)
		}
		if len(f.mods.loaded) != 0 {
			t.Errorf("loaded %v with vfat present", f.mods.loaded)
		}
	})
	t.Run("same release, other build", func(t *testing.T) {
		f := newSBFixture(t, "B", repairEnv("B"))
		f.b.fs = fakeFS{list: procFilesystemsNoVFAT}
		writeFile(t, f.b.procKernelVersion, []byte("#0 SMP Tue Jul 14 08:00:00 2026\n"))
		outcome, err := f.b.repairRunningSlot(f.srcRoot)
		if outcome != RepairNone || !errors.Is(err, ErrESPUnavailable) {
			t.Fatalf("= (%v, %v), want ErrESPUnavailable", outcome, err)
		}
		if len(f.mods.loaded) != 0 || f.media.espMounts != 0 {
			t.Errorf("loaded %v, mounted %d times; want neither", f.mods.loaded, f.media.espMounts)
		}
	})
	t.Run("vfat fails to load", func(t *testing.T) {
		f := newSBFixture(t, "B", repairEnv("B"))
		f.b.fs = fakeFS{list: procFilesystemsNoVFAT}
		f.mods.failOn = "vfat.ko"
		outcome, err := f.b.repairRunningSlot(f.srcRoot)
		if outcome != RepairNone || !errors.Is(err, ErrESPUnavailable) {
			t.Fatalf("= (%v, %v), want ErrESPUnavailable", outcome, err)
		}
		if !reflect.DeepEqual(f.mods.loaded, []string{kmod(f, "fat")}) {
			t.Errorf("loaded %v, want only fat before the failure", f.mods.loaded)
		}
	})
}

// TC-888-30: mark-good drops the running slot's repair flag, and only that;
// mark-bad leaves it.
func TestMarkRunning_ClearsTheRepairFlagOnlyWhenGood(t *testing.T) {
	env := repairEnv("B")
	env["B_REPAIR"], env["A_REPAIR"] = "1", "1"
	f := newSBFixture(t, "B", env)
	if err := f.b.markRunning(true); err != nil {
		t.Fatal(err)
	}
	got := f.env()
	if _, has := got["B_REPAIR"]; has || got["A_REPAIR"] != "1" || got["B_OK"] != "1" || got["B_TRY"] != "0" {
		t.Errorf("after mark-good grubenv = %v, want no B_REPAIR, A_REPAIR=1, B_OK=1 B_TRY=0", got)
	}

	f2 := newSBFixture(t, "B", env)
	if err := f2.b.markRunning(false); err != nil {
		t.Fatal(err)
	}
	if got := f2.env(); got["B_OK"] != "0" || got["B_REPAIR"] != "1" {
		t.Errorf("after mark-bad grubenv = %v, want B_OK=0 and B_REPAIR kept", got)
	}
}
