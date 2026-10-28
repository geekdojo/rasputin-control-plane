package updater

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// slotboot.go — per-slot kernels on the firewall ESP (geekdojo/geekdojo-brain#888).
//
// Each rootfs bundle carries its own kernel and grub.cfg under /boot. Before a
// slot is activated, Install copies that kernel to the ESP as boot/vmlinuz-<S>
// and the grub.cfg to boot/grub/grub.cfg, so the slot boots the kernel its
// modules were built for and the fallback slot keeps booting its own.
//
// A box that took the bundle through an older agent boots the new rootfs on the
// old shared kernel. The rootfs's kernel-match guard then calls
// `rasputin-agent repair-slot-boot`, which is RepairRunningSlot: it does the
// same copy from inside that mismatched boot and re-arms the slot's trial.

// BootMedia is the firewall's boot storage, as the backend uses it.
type BootMedia interface {
	// OpenSlot mounts the rootfs squashfs on dev read-only. release unmounts it.
	OpenSlot(dev string) (root string, release func() error, err error)
	// WithESP mounts the ESP read-write, runs fn on its root and unmounts it.
	// A failed unmount is returned, joined with fn's error.
	WithESP(fn func(root string) error) error
}

// ModuleLoader loads a kernel module from a file.
type ModuleLoader interface {
	Load(path string) error
}

// FilesystemLister returns the running kernel's /proc/filesystems.
type FilesystemLister interface {
	Filesystems() (string, error)
}

const (
	// Inside the bundle (relative to a slot root).
	bundleKernel  = "boot/vmlinuz"
	bundleGrubCfg = "boot/grub.cfg"
	legacyKmods   = "boot/legacy-kmods"
	// On the ESP.
	espGrubCfg = "boot/grub/grub.cfg"
)

// legacyModuleOrder is the load order of the bundled 6.12.94 FAT modules: vfat
// needs fat, and the nls tables are needed by the mount's codepage/iocharset.
var legacyModuleOrder = []string{"fat", "vfat", "nls_cp437", "nls_iso8859-1", "nls_utf8"}

func espKernel(slot string) string { return "boot/vmlinuz-" + slot }

// errPreFixArtifact refuses a bundle built before per-slot kernels. Installing
// it would leave the slot booting another release's kernel, which is the
// #888 outage itself.
var errPreFixArtifact = errors.New("the artifact predates per-slot kernels (geekdojo/geekdojo-brain#888) " +
	"and would boot on another release's kernel")

// ErrESPUnavailable means the repair could not mount the ESP at all, so it
// changed nothing and could not mark the slot bad either.
var ErrESPUnavailable = errors.New("the ESP could not be mounted")

// RepairOutcome is what RepairRunningSlot did.
type RepairOutcome int

const (
	// RepairNone: nothing was written (see the returned error).
	RepairNone RepairOutcome = iota
	// RepairRepaired: the slot's kernel and grub.cfg are on the ESP and its
	// trial is re-armed. Reboot.
	RepairRepaired
	// RepairFallback: the slot is marked bad (OK=0). Reboot to fall back.
	RepairFallback
)

func (r RepairOutcome) String() string {
	switch r {
	case RepairRepaired:
		return "repaired"
	case RepairFallback:
		return "fallback"
	}
	return "none"
}

type bootFile struct {
	name string // ESP-relative
	data []byte
}

// installSlotBoot copies srcRoot's kernel and grub.cfg onto the ESP for slot.
//
// The kernel is written as <name>.new and fsynced, the ESP is unmounted (which
// drops its page cache) and mounted again, and the file is read back. Only a
// read-back whose sha256 matches is renamed into place. grub.cfg goes the same
// way, and only when its bytes differ, so an unchanged one keeps its inode.
func (o *OpenWrtABBackend) installSlotBoot(srcRoot, slot string) error {
	kernel, err := readBundleFile(srcRoot, bundleKernel)
	if err != nil {
		return err
	}
	cfg, err := readBundleFile(srcRoot, bundleGrubCfg)
	if err != nil {
		return err
	}
	files := []bootFile{{name: espKernel(slot), data: kernel}}

	cfgChanged := false
	if err := o.media.WithESP(func(root string) error {
		cur, err := os.ReadFile(filepath.Join(root, espGrubCfg))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("read %s: %w", espGrubCfg, err)
		}
		cfgChanged = err != nil || !bytes.Equal(cur, cfg)
		if cfgChanged {
			files = append(files, bootFile{name: espGrubCfg, data: cfg})
		}
		for _, f := range files {
			if err := writeSynced(filepath.Join(root, f.name+".new"), f.data); err != nil {
				return fmt.Errorf("write %s.new: %w", f.name, err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("stage slot %s boot files: %w", slot, err)
	}

	if err := o.media.WithESP(func(root string) error { return commitBootFiles(root, files) }); err != nil {
		return fmt.Errorf("install slot %s boot files: %w", slot, err)
	}

	sum := sha256.Sum256(kernel)
	o.logger.Info("openwrt-ab: slot kernel installed on the ESP", "slot", slot, "step", "kernel",
		"file", espKernel(slot), "kernel_sha256", hex.EncodeToString(sum[:]), "kernel_bytes", len(kernel))
	grub := "unchanged"
	if cfgChanged {
		grub = "replaced"
	}
	o.logger.Info("openwrt-ab: slot grub.cfg on the ESP", "slot", slot, "step", "grub_cfg", "grub_cfg", grub)
	return nil
}

// readBundleFile reads rel from a slot root, and names a missing file as a
// pre-fix artifact.
func readBundleFile(srcRoot, rel string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(srcRoot, rel))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: /%s is missing", errPreFixArtifact, rel)
	}
	if err != nil {
		return nil, fmt.Errorf("read /%s from the slot: %w", rel, err)
	}
	return b, nil
}

// commitBootFiles runs on a fresh ESP mount: every staged file is read back and
// compared first, and only if all match are they renamed into place.
func commitBootFiles(root string, files []bootFile) error {
	for _, f := range files {
		got, err := os.ReadFile(filepath.Join(root, f.name+".new"))
		if err != nil {
			return errors.Join(fmt.Errorf("read back %s.new: %w", f.name, err), removeStaged(root, files))
		}
		if sha256.Sum256(got) != sha256.Sum256(f.data) {
			return errors.Join(fmt.Errorf("read-back of %s.new does not match what was written", f.name),
				removeStaged(root, files))
		}
	}
	for i, f := range files {
		if err := os.Rename(filepath.Join(root, f.name+".new"), filepath.Join(root, f.name)); err != nil {
			return errors.Join(fmt.Errorf("rename %s.new to %s: %w", f.name, f.name, err), removeStaged(root, files[i:]))
		}
		if err := syncDir(filepath.Join(root, filepath.Dir(f.name))); err != nil {
			return fmt.Errorf("sync the directory of %s: %w", f.name, err)
		}
	}
	return nil
}

func removeStaged(root string, files []bootFile) error {
	var errs []error
	for _, f := range files {
		if err := os.Remove(filepath.Join(root, f.name+".new")); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove %s.new: %w", f.name, err))
		}
	}
	return errors.Join(errs...)
}

func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		return errors.Join(err, d.Close())
	}
	return d.Close()
}

// SlotRepairer is the backend as the repair-slot-boot verb uses it. It holds no
// bundle store and no trust source: the repair runs from a boot whose /overlay
// may be RAM-only, and it never downloads (F-888-07).
type SlotRepairer struct {
	b *OpenWrtABBackend
}

// NewOpenWrtSlotRepairer builds the repair without touching the agent's state
// directory.
func NewOpenWrtSlotRepairer(media BootMedia, mods ModuleLoader, fsl FilesystemLister, logger *slog.Logger) (*SlotRepairer, error) {
	b, err := newOpenWrtAB(media, mods, fsl, logger)
	if err != nil {
		return nil, err
	}
	return &SlotRepairer{b: b}, nil
}

// RepairRunningSlot repairs the running slot's boot files from the running
// rootfs. See repairRunningSlot.
func (r *SlotRepairer) RepairRunningSlot() (RepairOutcome, error) {
	return r.b.repairRunningSlot("/")
}

// repairRunningSlot runs from a boot whose kernel does not match its rootfs.
//
//  1. The running slot X comes from the kernel command line.
//  2. vfat is made available: if the kernel lacks it, the FAT modules bundled
//     under srcRoot/boot/legacy-kmods are loaded, but only when the running
//     kernel is exactly the one they were built for.
//  3. If grubenv already has X_REPAIR=1, this is a second mismatched boot after
//     a repair: X is marked bad (X_OK=0 X_TRY=0, X_REPAIR dropped) → Fallback.
//  4. Otherwise X's kernel and grub.cfg are installed, and the trial re-armed
//     with X_TRY=0 X_REPAIR=1, leaving X_OK and ORDER alone → Repaired.
//  5. Any failure after the ESP has mounted marks X bad → Fallback. An ESP that
//     cannot be mounted at all returns ErrESPUnavailable.
func (o *OpenWrtABBackend) repairRunningSlot(srcRoot string) (RepairOutcome, error) {
	cmdline, err := os.ReadFile(o.procCmdline)
	if err != nil {
		return o.refuse("", "cmdline", fmt.Errorf("read %s: %w", o.procCmdline, err))
	}
	slot := slotLetter(bootedSlotFromCmdline(string(cmdline)))
	if slot == "" {
		return o.refuse("", "cmdline", errors.New("cannot determine the running slot from the kernel command line"))
	}
	if err := o.ensureVFAT(srcRoot); err != nil {
		return o.espUnavailable(slot, "modules", err)
	}

	mounted, again := false, false
	err = o.withGrubenv(func(path string) error {
		mounted = true
		return editGrubenv(path, func(kv map[string]string) bool {
			if kv[slot+"_REPAIR"] != "1" {
				return false
			}
			again = true
			kv[slot+"_OK"], kv[slot+"_TRY"] = "0", "0"
			delete(kv, slot+"_REPAIR")
			return true
		})
	})
	if !mounted {
		return o.espUnavailable(slot, "mount", err)
	}
	if err != nil {
		return o.fallback(slot, "grubenv", err)
	}
	if again {
		o.logger.Error("openwrt-ab: slot repair: the slot still boots a mismatched kernel after a repair; marked it bad",
			"slot", slot, "step", "second_mismatch", "err", "kernel mismatch persists after a repair", "outcome", RepairFallback.String())
		return RepairFallback, nil
	}

	if err := o.installSlotBoot(srcRoot, slot); err != nil {
		return o.fallback(slot, "install_boot", err)
	}
	if err := o.withGrubenv(func(path string) error {
		return editGrubenv(path, func(kv map[string]string) bool {
			kv[slot+"_TRY"] = "0"
			kv[slot+"_REPAIR"] = "1"
			return true
		})
	}); err != nil {
		return o.fallback(slot, "rearm", err)
	}
	o.logger.Info("openwrt-ab: slot repair: the slot's own kernel is on the ESP; reboot to run it",
		"slot", slot, "outcome", RepairRepaired.String())
	return RepairRepaired, nil
}

// ensureVFAT makes vfat available to the running kernel, loading the bundled
// legacy modules if the kernel lacks it.
//
// The identity check is the only check on the modules' build: the field kernel
// is built without the vermagic check, so finit_module would accept a module
// built for another kernel and could crash this one.
func (o *OpenWrtABBackend) ensureVFAT(srcRoot string) error {
	list, err := o.fs.Filesystems()
	if err != nil {
		return fmt.Errorf("read the kernel's filesystem list: %w", err)
	}
	if hasFilesystem(list, "vfat") {
		return nil
	}
	idPath := filepath.Join(srcRoot, legacyKmods, "kernel-id")
	b, err := os.ReadFile(idPath)
	if err != nil {
		return fmt.Errorf("vfat is not available and the bundled modules' kernel id is unreadable: %w", err)
	}
	legacy := strings.TrimSpace(string(b))
	running, err := o.runningKernelID()
	if err != nil {
		return err
	}
	release, _, _ := strings.Cut(legacy, " ")
	if legacy == "" || running != legacy {
		return fmt.Errorf("vfat is not available, and the running kernel %q is not the one the bundled modules were built for (%q)",
			running, legacy)
	}
	for _, m := range legacyModuleOrder {
		if err := o.mods.Load(filepath.Join(srcRoot, legacyKmods, release, m+".ko")); err != nil {
			return err
		}
	}
	o.logger.Info("openwrt-ab: slot repair: loaded the bundled FAT modules", "kernel_id", running,
		"modules", strings.Join(legacyModuleOrder, ","))
	return nil
}

// runningKernelID is "$(uname -r) $(uname -v)", read from procfs.
func (o *OpenWrtABBackend) runningKernelID() (string, error) {
	r, err := os.ReadFile(o.procOSRelease)
	if err != nil {
		return "", fmt.Errorf("read the running kernel release: %w", err)
	}
	v, err := os.ReadFile(o.procKernelVersion)
	if err != nil {
		return "", fmt.Errorf("read the running kernel version: %w", err)
	}
	return strings.TrimSpace(string(r)) + " " + strings.TrimSpace(string(v)), nil
}

// hasFilesystem reports whether /proc/filesystems lists name.
func hasFilesystem(list, name string) bool {
	for _, l := range strings.Split(list, "\n") {
		f := strings.Fields(l)
		if len(f) > 0 && f[len(f)-1] == name {
			return true
		}
	}
	return false
}

// editGrubenv applies edit to grubenv's keys and, when edit reports a change,
// rewrites the block in place. Only the keys edit touches change; decodeAB's
// defaults are never written back.
func editGrubenv(path string, edit func(kv map[string]string) (changed bool)) error {
	kv, err := readGrubenv(path)
	if err != nil {
		return err
	}
	if !edit(kv) {
		return nil
	}
	return writeGrubenv(path, kv)
}

// fallback marks slot bad after a failed repair step and returns Fallback.
func (o *OpenWrtABBackend) fallback(slot, step string, cause error) (RepairOutcome, error) {
	err := fmt.Errorf("repair slot %s: %s: %w", slot, step, cause)
	if markErr := o.withGrubenv(func(path string) error {
		return editGrubenv(path, func(kv map[string]string) bool { kv[slot+"_OK"] = "0"; return true })
	}); markErr != nil {
		err = errors.Join(err, fmt.Errorf("mark slot %s bad: %w", slot, markErr))
	}
	o.logger.Error("openwrt-ab: slot repair failed; marked the slot bad", "slot", slot, "step", step,
		"err", err.Error(), "outcome", RepairFallback.String())
	return RepairFallback, err
}

func (o *OpenWrtABBackend) espUnavailable(slot, step string, cause error) (RepairOutcome, error) {
	err := fmt.Errorf("repair slot %s: %s: %w", slot, step, errors.Join(ErrESPUnavailable, cause))
	o.logger.Error("openwrt-ab: slot repair: the ESP is unavailable; nothing was changed", "slot", slot, "step", step,
		"err", err.Error(), "outcome", "esp_unavailable")
	return RepairNone, err
}

func (o *OpenWrtABBackend) refuse(slot, step string, cause error) (RepairOutcome, error) {
	err := fmt.Errorf("repair slot: %s: %w", step, cause)
	o.logger.Error("openwrt-ab: slot repair refused; nothing was changed", "slot", slot, "step", step,
		"err", err.Error(), "outcome", "refused")
	return RepairNone, err
}
