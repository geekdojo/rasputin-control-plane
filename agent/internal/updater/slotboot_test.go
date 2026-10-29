package updater

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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
// every grubenv edit goes through WithESP exactly as on the firewall. The ESP
// starts on the 2026.10.3 layout: the old EFI and grub.cfg, and the shared
// kernel.
type sbFixture struct {
	t        *testing.T
	b        *OpenWrtABBackend
	media    *fakeMedia
	mods     *fakeMods
	calls    *callLog
	logs     *logCapture
	esp      string
	srcRoot  string // the running rootfs, for the repair
	efi      []byte // the running rootfs's /boot/bootx64.efi
	cfg      []byte // the running rootfs's /boot/grub.cfg
	writeErr error  // what the fake writeSlot returns
	art      string
}

const (
	oldEFI = "OLD-EFI-NO-SQUASH4"
	oldCfg = "OLD-GRUB-CFG"
)

func newSBFixture(t *testing.T, booted string, env map[string]string) *sbFixture {
	t.Helper()
	dir := t.TempDir()
	f := &sbFixture{
		t:       t,
		esp:     filepath.Join(dir, "esp"),
		srcRoot: filepath.Join(dir, "root"),
		efi:     []byte("NEW-EFI-WITH-SQUASH4"),
		cfg:     []byte("NEW-GRUB-CFG"),
		calls:   &callLog{},
		logs:    &logCapture{},
		mods:    &fakeMods{},
	}
	writeFile(t, filepath.Join(f.srcRoot, srcEFI), f.efi)
	writeFile(t, filepath.Join(f.srcRoot, srcGrubCfg), f.cfg)
	writeFile(t, filepath.Join(f.srcRoot, "boot", "legacy-kmods", "kernel-id"), []byte(legacyID+"\n"))
	writeGrubenvFile(t, f.grubenvPath(), env)
	writeFile(t, filepath.Join(f.esp, "boot", "vmlinuz"), []byte("LEGACY-SHARED-KERNEL"))
	writeFile(t, filepath.Join(f.esp, espEFI), []byte(oldEFI))
	writeFile(t, filepath.Join(f.esp, espGrubCfg), []byte(oldCfg))

	f.media = &fakeMedia{espRoot: f.esp, calls: f.calls}
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
	b.writeSlot = func(context.Context, string, string, func(string, int)) error {
		f.calls.add("write")
		return f.writeErr
	}
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

// espFiles maps every file under the ESP to its sha256.
func (f *sbFixture) espFiles() map[string]string {
	f.t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(f.esp, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(f.esp, p)
		out[filepath.ToSlash(rel)] = shaOf(b)
		return nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

// stagedFiles lists every *.new file under root.
func stagedFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(p, ".new") {
			rel, _ := filepath.Rel(root, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// bootloaderRecords returns the per-file INFO records installBootloader logs,
// keyed by file.
func bootloaderRecords(t *testing.T, l *logCapture) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, r := range l.records(t) {
		if r["step"] == "bootloader" {
			out[r["file"].(string)] = r
		}
	}
	return out
}

// fieldEnv is a box booted on A, with B the inactive target.
func fieldEnv() map[string]string {
	return map[string]string{"ORDER": "A B", "A_OK": "1", "A_TRY": "0", "B_OK": "1", "B_TRY": "0"}
}

// ---- Install ----------------------------------------------------------------

// TC-893-01: Install accepts a bundle with no /boot (#505 refused one after the
// dd). The agent never opens the bundle, so the fixture's artifact is opaque
// bytes with no /boot at all; B is activated and A's keys are unchanged.
func TestInstall_BundleWithoutBootIsInstalled(t *testing.T) {
	f := newSBFixture(t, "A", fieldEnv())
	if err := f.install(); err != nil {
		t.Fatalf("Install: %v", err)
	}
	env := f.env()
	if env["ORDER"] != "B A" || env["B_OK"] != "1" || env["B_TRY"] != "0" {
		t.Errorf("grubenv = %v, want ORDER=B A, B_OK=1, B_TRY=0", env)
	}
	if env["A_OK"] != "1" || env["A_TRY"] != "0" {
		t.Errorf("grubenv = %v, want A_OK=1 A_TRY=0 unchanged", env)
	}
}

// TC-893-02: Install writes nothing on the ESP but grubenv.
func TestInstall_WritesOnlyGrubenvOnTheESP(t *testing.T) {
	f := newSBFixture(t, "A", fieldEnv())
	before := f.espFiles()
	if err := f.install(); err != nil {
		t.Fatalf("Install: %v", err)
	}
	after := f.espFiles()
	written := map[string]bool{}
	for p, sum := range after {
		if before[p] != sum {
			written[p] = true
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			written[p] = true
		}
	}
	if want := map[string]bool{"boot/grub/grubenv": true}; !reflect.DeepEqual(written, want) {
		t.Errorf("ESP paths written = %v, want only boot/grub/grubenv", written)
	}
}

// TC-893-03: a failed deactivate refuses before the dd, with an error that
// wraps the cause and names the slot.
func TestInstall_DeactivateFailureRefusesBeforeTheWrite(t *testing.T) {
	f := newSBFixture(t, "A", fieldEnv())
	cause := errors.New("mount ESP " + fakeESPDevice + ": no such device")
	f.media.mountErr = cause
	err := f.install()
	if err == nil {
		t.Fatal("Install succeeded with grubenv unwritable")
	}
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "slot B") {
		t.Errorf("err = %v, want it to wrap the cause and name slot B", err)
	}
	for _, c := range f.calls.names {
		if c == "write" {
			t.Fatalf("calls = %v: writeSlot ran after a failed deactivate", f.calls.names)
		}
	}
}

// TC-893-04: Install runs deactivate, write, activate in that order; a write
// failure leaves the target not bootable, and ORDER and A's keys unchanged.
func TestInstall_WriteFailureLeavesTheTargetUnbootable(t *testing.T) {
	env := fieldEnv()
	env["B_TRY"] = "1"
	f := newSBFixture(t, "A", env)
	f.calls.snap = func() string {
		kv := mustRead(t, f.grubenvPath())
		return "B_OK=" + kv["B_OK"] + " B_TRY=" + kv["B_TRY"]
	}
	f.writeErr = errors.New("input/output error")
	err := f.install()
	if err == nil || !errors.Is(err, f.writeErr) {
		t.Fatalf("err = %v, want the write error", err)
	}
	if want := []string{"verify", "resolve", "WithESP", "write"}; !reflect.DeepEqual(f.calls.names, want) {
		t.Errorf("calls = %v, want %v (verify, resolve, deactivate, write; no activate)", f.calls.names, want)
	}
	if got := f.calls.snaps[3]; got != "B_OK=0 B_TRY=0" {
		t.Errorf("at writeSlot grubenv had %s, want B_OK=0 B_TRY=0", got)
	}
	got := f.env()
	if got["B_OK"] != "0" || got["B_TRY"] != "0" || got["ORDER"] != "A B" || got["A_OK"] != "1" || got["A_TRY"] != "0" {
		t.Errorf("grubenv = %v, want B_OK=0 B_TRY=0, ORDER=A B and A unchanged", got)
	}

	// And on success the same order ends with the activate.
	f2 := newSBFixture(t, "A", fieldEnv())
	if err := f2.install(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"verify", "resolve", "WithESP", "write", "WithESP"}; !reflect.DeepEqual(f2.calls.names, want) {
		t.Errorf("calls = %v, want %v (verify, resolve, deactivate, write, activate)", f2.calls.names, want)
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

// ---- installBootloader ------------------------------------------------------

// TC-893-05: installBootloader stages and renames only the files whose bytes
// differ, and logs each file with its sha256 and outcome.
func TestInstallBootloader_WritesOnlyTheFilesThatDiffer(t *testing.T) {
	for _, tc := range []struct {
		name               string
		espEFI, espCfg     string // "" = the source's bytes
		wantStaged         []string
		wantEFI, wantCfgOK string
	}{
		{"EFI differs, grub.cfg identical", oldEFI, "", []string{espEFI + ".new"}, "replaced", "unchanged"},
		{"both identical", "", "", nil, "unchanged", "unchanged"},
		{"both differ", oldEFI, oldCfg, []string{espEFI + ".new", espGrubCfg + ".new"}, "replaced", "replaced"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSBFixture(t, "B", repairEnv("B"))
			pick := func(v string, src []byte) []byte {
				if v == "" {
					return src
				}
				return []byte(v)
			}
			writeFile(t, filepath.Join(f.esp, espEFI), pick(tc.espEFI, f.efi))
			writeFile(t, filepath.Join(f.esp, espGrubCfg), pick(tc.espCfg, f.cfg))
			old := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
			stats := map[string]os.FileInfo{}
			for _, rel := range []string{espEFI, espGrubCfg} {
				p := filepath.Join(f.esp, rel)
				if err := os.Chtimes(p, old, old); err != nil {
					t.Fatal(err)
				}
				stats[rel], _ = os.Stat(p)
			}
			var staged []string
			f.media.beforeFn = map[int]func(string){2: func(root string) { staged = stagedFiles(t, root) }}

			if err := f.b.installBootloader(f.srcRoot, "B"); err != nil {
				t.Fatalf("installBootloader: %v", err)
			}

			if !reflect.DeepEqual(staged, tc.wantStaged) {
				t.Errorf("staged %v, want %v", staged, tc.wantStaged)
			}
			if tc.wantStaged == nil && f.media.espMounts != 1 {
				t.Errorf("ESP mounted %d times with nothing to write, want 1", f.media.espMounts)
			}
			if left := stagedFiles(t, f.esp); left != nil {
				t.Errorf("staging files left behind: %v", left)
			}
			if got := shaOf(f.espFile(espEFI)); got != shaOf(f.efi) {
				t.Errorf("ESP EFI sha %s, want the source's %s", got, shaOf(f.efi))
			}
			if got := shaOf(f.espFile(espGrubCfg)); got != shaOf(f.cfg) {
				t.Errorf("ESP grub.cfg sha %s, want the source's %s", got, shaOf(f.cfg))
			}
			recs := bootloaderRecords(t, f.logs)
			for rel, want := range map[string]string{espEFI: tc.wantEFI, espGrubCfg: tc.wantCfgOK} {
				if want == "unchanged" {
					after, _ := os.Stat(filepath.Join(f.esp, rel))
					if !os.SameFile(stats[rel], after) || !after.ModTime().Equal(old) {
						t.Errorf("%s is unchanged but was rewritten", rel)
					}
				}
				src := f.efi
				if rel == espGrubCfg {
					src = f.cfg
				}
				r := recs[rel]
				if r == nil || r["level"] != "INFO" || r["outcome"] != want || r["sha256"] != shaOf(src) || r["slot"] != "B" {
					t.Errorf("record for %s = %v, want INFO slot=B outcome=%s sha256=%s", rel, r, want, shaOf(src))
				}
			}
		})
	}
}

// TC-893-06: a staged file that reads back wrong on the fresh mount fails the
// install; every .new is removed and the live files keep their old bytes.
func TestInstallBootloader_ReadBackMismatchKeepsTheOldFiles(t *testing.T) {
	f := newSBFixture(t, "B", repairEnv("B"))
	before := f.espFiles()
	// Mount 1 stages, 2 reads back: corrupt the disk before 2.
	f.media.beforeFn = map[int]func(string){2: func(root string) {
		writeFile(t, filepath.Join(root, espEFI+".new"), []byte("BIT-ROT"))
	}}
	err := f.b.installBootloader(f.srcRoot, "B")
	if err == nil {
		t.Fatal("installBootloader accepted a corrupt read-back")
	}
	for _, want := range []string{espEFI + ".new", "does not match", fakeESPDevice} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	after := f.espFiles()
	for _, rel := range []string{espEFI, espGrubCfg} {
		if after[rel] != before[rel] {
			t.Errorf("%s sha %s, want the old %s", rel, after[rel], before[rel])
		}
	}
	if left := stagedFiles(t, f.esp); left != nil {
		t.Errorf("staging files left behind: %v", left)
	}
}

// TC-888-08 (F-888-04): a failed umount after staging is returned, and the
// read-back mount never happens, so nothing is renamed.
func TestInstallBootloader_UmountAfterStagingIsReturned(t *testing.T) {
	f := newSBFixture(t, "B", repairEnv("B"))
	f.media.umountErrOn = 1
	err := f.b.installBootloader(f.srcRoot, "B")
	if err == nil || !strings.Contains(err.Error(), "device busy") {
		t.Fatalf("err = %v, want the umount error", err)
	}
	if f.media.espMounts != 1 {
		t.Errorf("ESP mounted %d times, want 1: no read-back after a failed umount", f.media.espMounts)
	}
	if got := string(f.espFile(espEFI)); got != oldEFI {
		t.Errorf("ESP EFI = %q, want the old one", got)
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

// TC-893-07: the first repair writes the running rootfs's EFI and grub.cfg,
// then re-arms the trial (X_TRY=0 X_REPAIR=1) and touches no other key. Each
// file gets an INFO line with slot, file and sha256.
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
			if got := shaOf(f.espFile(espEFI)); got != shaOf(f.efi) {
				t.Error("the ESP EFI is not the running rootfs's")
			}
			if got := string(f.espFile(espGrubCfg)); got != string(f.cfg) {
				t.Errorf("grub.cfg = %q, want replaced", got)
			}
			if got := string(f.espFile("boot/vmlinuz")); got != "LEGACY-SHARED-KERNEL" {
				t.Errorf("the shared kernel changed: %q", got)
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
			recs := bootloaderRecords(t, f.logs)
			for rel, src := range map[string][]byte{espEFI: f.efi, espGrubCfg: f.cfg} {
				if r := recs[rel]; r == nil || r["level"] != "INFO" || r["slot"] != slot || r["sha256"] != shaOf(src) {
					t.Errorf("record for %s = %v, want INFO slot=%s sha256=%s", rel, r, slot, shaOf(src))
				}
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

// TC-893-08: a running rootfs missing either boot file falls back: B_OK=0, no
// live ESP boot file changed, and an ERROR record with outcome and err.
func TestRepairRunningSlot_MissingSourceFileFallsBack(t *testing.T) {
	for _, missing := range []string{srcEFI, srcGrubCfg} {
		t.Run(missing, func(t *testing.T) {
			f := newSBFixture(t, "B", repairEnv("B"))
			if err := os.Remove(filepath.Join(f.srcRoot, missing)); err != nil {
				t.Fatal(err)
			}
			tree := f.espTree()
			outcome, err := f.b.repairRunningSlot(f.srcRoot)
			if outcome != RepairFallback || err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("= (%v, %v), want fallback naming %s", outcome, err, missing)
			}
			if env := f.env(); env["B_OK"] != "0" {
				t.Errorf("grubenv = %v, want B_OK=0", env)
			}
			if f.espTree() != tree {
				t.Error("files under the ESP changed")
			}
			assertRepairErrorRecord(t, f.logs, "fallback", "B")
		})
	}
}

// TC-893-09: a mismatched boot after a repair marks the slot bad, drops the
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

// TC-893-11: the second rename failing part-way through the commit falls back
// with B_OK=0, removes that file's .new, and names the file.
func TestRepairRunningSlot_SecondRenameFailureFallsBack(t *testing.T) {
	f := newSBFixture(t, "B", repairEnv("B"))
	// Mount 1 checks B_REPAIR, 2 stages, 3 commits: before 3, make the live
	// grub.cfg a non-empty directory, so the EFI renames and grub.cfg cannot.
	f.media.beforeFn = map[int]func(string){3: func(root string) {
		p := filepath.Join(root, espGrubCfg)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(p, "x"), []byte("x"))
	}}
	outcome, err := f.b.repairRunningSlot(f.srcRoot)
	if outcome != RepairFallback || err == nil || !strings.Contains(err.Error(), "rename "+espGrubCfg+".new") {
		t.Fatalf("= (%v, %v), want fallback naming the grub.cfg rename", outcome, err)
	}
	if env := f.env(); env["B_OK"] != "0" {
		t.Errorf("grubenv = %v, want B_OK=0", env)
	}
	if left := stagedFiles(t, f.esp); left != nil {
		t.Errorf("staging files left behind: %v", left)
	}
	assertRepairErrorRecord(t, f.logs, "fallback", "B")
}

// TC-888-28: failures after the ESP mounts fall back with X_OK=0; an ESP that
// will not mount is ErrESPUnavailable and leaves grubenv alone; a cmdline with
// no slot writes nothing.
func TestRepairRunningSlot_FailurePaths(t *testing.T) {
	for _, tc := range []string{espEFI + ".new", espGrubCfg + ".new"} {
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

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TC-893-10 (and TC-888-29): the bundled FAT modules load only when vfat is
// missing AND the running kernel is exactly the one they were built for, in the
// order fat, vfat, nls_cp437, nls_iso8859-1, nls_utf8. A mismatched id loads
// nothing, never mounts the ESP and reports esp_unavailable.
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
		assertRepairErrorRecord(t, f.logs, "esp_unavailable", "B")
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
