package updater

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

// espmount.go — the firewall's real BootMedia: the code that mounts the ESP and
// a rootfs slot on OpenWrt. It was the body of withGrubenv until
// geekdojo/geekdojo-brain#888 needed the same mount for the per-slot kernel and
// grub.cfg, and for a read-only look inside the slot just written.
//
// OpenWrt mounts neither at runtime, has no udev by-label links, and has no
// findfs or blkid, so the ESP is found through `block info` (parseESPDevice) and
// mounted on a fresh temp dir for each operation, then synced and unmounted
// straight away to keep the FAT-dirty window small.

// commandRunner runs one external command and returns its combined output.
type commandRunner func(name string, args ...string) ([]byte, error)

func execCombined(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// OpenWrtBootMedia mounts the firewall's ESP and rootfs slots.
type OpenWrtBootMedia struct {
	logger *slog.Logger
	run    commandRunner
}

// NewOpenWrtBootMedia builds the BootMedia the firewall uses in production.
func NewOpenWrtBootMedia(logger *slog.Logger) (*OpenWrtBootMedia, error) {
	return newOpenWrtBootMedia(logger, execCombined)
}

func newOpenWrtBootMedia(logger *slog.Logger, run commandRunner) (*OpenWrtBootMedia, error) {
	if logger == nil {
		return nil, errors.New("openwrt boot media: no logger wired")
	}
	if run == nil {
		return nil, errors.New("openwrt boot media: no command runner wired")
	}
	return &OpenWrtBootMedia{logger: logger, run: run}, nil
}

// WithESP mounts the ESP read-write, runs fn against its root, then syncs and
// unmounts it.
//
// A failed umount is an error, returned joined with fn's own (F-888-04). It is
// not merely untidy: the per-slot kernel install unmounts precisely so that the
// next mount reads the file back from the disk rather than from the page cache,
// and a read-back after an umount that did not happen proves nothing. The
// caller therefore never gets a nil error from a mount that is still live.
func (m *OpenWrtBootMedia) WithESP(fn func(root string) error) error {
	info, err := m.run("block", "info")
	if err != nil {
		return fmt.Errorf("resolve ESP: block info: %w", err)
	}
	dev := parseESPDevice(string(info))
	if dev == "" {
		return errors.New("resolve ESP: no vfat partition labelled RASPUTINEFI, or legacy RASPUTIN-FW, in `block info`")
	}
	mnt, err := m.mount(dev, "vfat", "rw,noatime", "rasputin-esp-")
	if err != nil {
		return fmt.Errorf("mount ESP %s: %w", dev, err)
	}
	fnErr := fn(mnt)
	if fnErr != nil {
		fnErr = fmt.Errorf("ESP %s: %w", dev, fnErr)
	}
	return errors.Join(fnErr, m.unmount(dev, mnt))
}

// OpenSlot mounts the squashfs on dev read-only and returns its root. release
// unmounts it, and its error is the umount's.
func (m *OpenWrtBootMedia) OpenSlot(dev string) (string, func() error, error) {
	mnt, err := m.mount(dev, "squashfs", "ro", "rasputin-slot-")
	if err != nil {
		return "", nil, fmt.Errorf("mount slot %s read-only: %w", dev, err)
	}
	return mnt, func() error { return m.unmount(dev, mnt) }, nil
}

func (m *OpenWrtBootMedia) mount(dev, fstype, opts, prefix string) (string, error) {
	mnt, err := os.MkdirTemp("", prefix)
	if err != nil {
		return "", err
	}
	if out, err := m.run("mount", "-t", fstype, "-o", opts, dev, mnt); err != nil {
		m.removeMountpoint(dev, mnt)
		return "", fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return mnt, nil
}

// unmount syncs and unmounts dev from mnt, then removes the empty mount point.
//
// The mount point is removed with os.Remove, never os.RemoveAll: the code this
// replaced deferred os.RemoveAll on it, which after a failed umount would have
// recursed into the still-mounted ESP and deleted the kernels and grubenv.
func (m *OpenWrtBootMedia) unmount(dev, mnt string) error {
	if out, err := m.run("sync"); err != nil {
		// Handled: umount writes the filesystem's dirty data back itself, so a
		// failed global sync costs nothing the umount below does not check.
		m.logger.Warn("openwrt-ab: sync before umount failed", "device", dev, "mountpoint", mnt,
			"err", err.Error(), "output", string(bytes.TrimSpace(out)))
	}
	if out, err := m.run("umount", mnt); err != nil {
		m.logger.Error("openwrt-ab: umount failed; the filesystem is still mounted",
			"device", dev, "mountpoint", mnt, "err", err.Error(), "output", string(bytes.TrimSpace(out)))
		return fmt.Errorf("umount %s from %s: %w: %s", dev, mnt, err, bytes.TrimSpace(out))
	}
	m.removeMountpoint(dev, mnt)
	return nil
}

// removeMountpoint removes an empty temp mount point. Its failure is logged and
// dropped: an empty directory left in the tmpfs /tmp changes nothing on disk.
func (m *OpenWrtBootMedia) removeMountpoint(dev, mnt string) {
	if err := os.Remove(mnt); err != nil {
		m.logger.Warn("openwrt-ab: could not remove the temporary mount point", "device", dev,
			"mountpoint", mnt, "err", err.Error())
	}
}

// ProcFilesystems lists the filesystems the running kernel supports.
type ProcFilesystems struct{}

// Filesystems returns the contents of /proc/filesystems.
func (ProcFilesystems) Filesystems() (string, error) {
	b, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
