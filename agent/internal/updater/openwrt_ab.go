package updater

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// OpenWrtABBackend drives A/B OS updates on the firewall (OpenWrt) node WITHOUT
// RAUC. It reproduces the compute (n100) image's update contract — a GRUB
// boot-counter in grubenv, two squashfs rootfs slots, a shared kernel on the
// ESP, and a persistent overlay that survives a slot switch — but does the
// slot write and the bootloader-env flip itself, because RAUC isn't packaged
// for OpenWrt.
//
// Why a separate backend instead of reusing RAUCBackend: the two differ only in
// the mechanism (rauc CLI vs. dd + a grubenv codec); the saga, the NATS
// dispatch, and the GRUB boot-counter contract are identical. The rationale and
// the signals that would make us pivot to packaging RAUC for OpenWrt instead
// are recorded in the wiki:
// projects/rasputin/design/os-images/firewall-updates-rauc-alternative.md.
//
// The install artifact is the raw rootfs squashfs (the same image genimage
// embeds in a compute slot), NOT the legacy full-disk combined-efi .img.gz —
// flashing a whole disk would clobber the other slot, the ESP, and config. The
// update path is: verify → dd the squashfs into the inactive rootfs partition →
// flip grubenv (ORDER + <slot>_OK/_TRY) → reboot → health-gated mark-good.
//
// OS-coupled operations (partition resolution, the raw block write, reboot,
// signature verification) are injectable fields so the pure logic — slot math
// and the grubenv codec — is fully unit-tested here, while the hardware-coupled
// parts are validated on the bench. This mirrors RAUCBackend's own "comes
// online when we have hardware to test against" stance.
type OpenWrtABBackend struct {
	stateDir string

	// grubenvPath is the GRUB environment block on the mounted ESP. The
	// firewall image mounts the ESP so grub.cfg's $prefix/grubenv is
	// writable from userspace; default matches that mount.
	grubenvPath string
	// procCmdline is read to determine the booted slot (root=PARTLABEL=…).
	procCmdline string
	// versionFile is the baked image version reported as CurrentVersion.
	versionFile string

	muted        *atomic.Bool
	caBundlePath string

	// --- injectable OS-coupled seams (see type doc) --------------------
	// resolveDevice maps a slot letter ("A"/"B") to its rootfs block device.
	resolveDevice func(slot string) (string, error)
	// writeSlot streams the squashfs at src into the block device dev.
	writeSlot func(ctx context.Context, src, dev string, progressFn func(phase string, percent int)) error
	// doReboot performs the (backgrounded) reboot after delaySeconds.
	doReboot func(delaySeconds int)
	// verifySig verifies the artifact's signature before install. Default is
	// a skip-with-warning until artifact signing is wired end-to-end (see the
	// design doc's hardening note); overridden in tests.
	verifySig func(ctx context.Context, rootfsPath string) error
}

// NewOpenWrtABBackend constructs the backend with production defaults. It does
// not probe the environment — the agent selects it by role (firewall) + the
// absence of rauc; see autodetectUpdaterBackend / main.go.
func NewOpenWrtABBackend(stateDir string) (*OpenWrtABBackend, error) {
	if err := os.MkdirAll(filepath.Join(stateDir, "bundles"), 0o755); err != nil {
		return nil, err
	}
	b := &OpenWrtABBackend{
		stateDir:    stateDir,
		grubenvPath: "/boot/grub/grubenv",
		procCmdline: "/proc/cmdline",
		versionFile: "/etc/rasputin/image-version",
	}
	b.resolveDevice = defaultResolveDevice
	b.writeSlot = defaultWriteSlot
	b.doReboot = b.defaultReboot
	b.verifySig = defaultVerifySig
	return b, nil
}

func (o *OpenWrtABBackend) SetMuteHook(b *atomic.Bool) { o.muted = b }

// SetCABundle mirrors RAUCBackend.SetCABundle: trust the Mesh CA (in addition
// to system roots) when pulling bundles from the api's mesh-CA HTTPS leaf.
func (o *OpenWrtABBackend) SetCABundle(path string) { o.caBundlePath = path }

func (o *OpenWrtABBackend) Name() string { return "openwrt-ab" }

// slotLetter converts a proto slot ("a"/"b") to the grub.cfg letter ("A"/"B").
func slotLetter(s proto.UpdateSlot) string {
	switch s {
	case proto.SlotA:
		return "A"
	case proto.SlotB:
		return "B"
	}
	return ""
}

// bootedSlotFromCmdline parses the booted rootfs slot from a kernel cmdline.
// Matches the firewall grub.cfg's `root=PARTLABEL=rootfs-0|rootfs-1`, and
// accepts an explicit `rasputin.slot=A|B` marker as a fallback.
func bootedSlotFromCmdline(cmdline string) proto.UpdateSlot {
	switch {
	case strings.Contains(cmdline, "PARTLABEL=rootfs-0"), strings.Contains(cmdline, "rasputin.slot=A"):
		return proto.SlotA
	case strings.Contains(cmdline, "PARTLABEL=rootfs-1"), strings.Contains(cmdline, "rasputin.slot=B"):
		return proto.SlotB
	}
	return proto.SlotUnknown
}

func otherSlot(s proto.UpdateSlot) proto.UpdateSlot {
	switch s {
	case proto.SlotA:
		return proto.SlotB
	case proto.SlotB:
		return proto.SlotA
	}
	return proto.SlotUnknown
}

func (o *OpenWrtABBackend) Precheck(ctx context.Context) (*proto.UpdatePrecheckAck, error) {
	cmdline, err := os.ReadFile(o.procCmdline)
	if err != nil {
		return &proto.UpdatePrecheckAck{OK: false, Backend: o.Name(), Detail: err.Error()}, nil
	}
	active := bootedSlotFromCmdline(string(cmdline))
	if active == proto.SlotUnknown {
		return &proto.UpdatePrecheckAck{
			OK:      false,
			Backend: o.Name(),
			Detail:  "could not determine booted slot from /proc/cmdline",
		}, nil
	}
	version := ""
	if b, err := os.ReadFile(o.versionFile); err == nil {
		version = strings.TrimSpace(string(b))
	}
	return &proto.UpdatePrecheckAck{
		OK:             true,
		ActiveSlot:     active,
		InactiveSlot:   otherSlot(active),
		CurrentVersion: version,
		AvailableBytes: 0, // rootfs slots are fixed-size raw partitions; nothing to statfs
		Backend:        o.Name(),
	}, nil
}

// httpClient mirrors RAUCBackend.httpClient — system roots plus the Mesh CA at
// caBundlePath (when set + readable), rebuilt per call so a re-enrolled CA is
// picked up without an agent restart.
func (o *OpenWrtABBackend) httpClient() *http.Client {
	if o.caBundlePath == "" {
		return http.DefaultClient
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if pem, err := os.ReadFile(o.caBundlePath); err == nil {
		pool.AppendCertsFromPEM(pem)
	}
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
}

// bundlePath is where a downloaded rootfs artifact is cached. `.rootfs` rather
// than `.raucb` — this is a bare squashfs, not a RAUC bundle.
func (o *OpenWrtABBackend) bundlePath(bundleID string) string {
	return filepath.Join(o.stateDir, "bundles", bundleID+".rootfs")
}

// pruneBundles drops every cached artifact + partial download except keepID's,
// same rationale as RAUCBackend.pruneBundles (bundles are transient cache; the
// installed OS lives on the slot, not here). Best-effort.
func (o *OpenWrtABBackend) pruneBundles(keepID string) {
	dir := filepath.Join(o.stateDir, "bundles")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	keep := keepID + ".rootfs"
	for _, e := range ents {
		name := e.Name()
		if name == keep || name == keep+".version" {
			continue
		}
		if strings.HasSuffix(name, ".rootfs") || strings.HasSuffix(name, ".version") || strings.HasPrefix(name, "download-") {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				log.Printf("rasputin-agent: prune bundle %s: %v", name, err)
			}
		}
	}
}

func (o *OpenWrtABBackend) Download(ctx context.Context, bundleID, url, expectedSHA string, sizeBytes int64,
	progressFn func(int64, int64)) (string, string, error) {
	dest := o.bundlePath(bundleID)
	o.pruneBundles(bundleID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := o.httpClient().Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("http %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), "download-*.tmp")
	if err != nil {
		return "", "", err
	}
	defer os.Remove(tmp.Name())
	total := resp.ContentLength
	if total <= 0 {
		total = sizeBytes
	}
	h := sha256.New()
	mw := io.MultiWriter(tmp, h)
	written := int64(0)
	buf := make([]byte, 64*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := mw.Write(buf[:n]); werr != nil {
				tmp.Close()
				return "", "", werr
			}
			written += int64(n)
			if progressFn != nil {
				progressFn(written, total)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			tmp.Close()
			return "", "", rerr
		}
	}
	if err := tmp.Close(); err != nil {
		return "", "", err
	}
	observed := hex.EncodeToString(h.Sum(nil))
	if expectedSHA != "" && observed != expectedSHA {
		return "", observed, fmt.Errorf("sha mismatch")
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return "", "", err
	}
	return dest, observed, nil
}

func (o *OpenWrtABBackend) Install(ctx context.Context, bundleID, localPath string, targetSlot proto.UpdateSlot,
	progressFn func(string, int)) (string, error) {
	if localPath == "" {
		localPath = o.bundlePath(bundleID)
	}
	letter := slotLetter(targetSlot)
	if letter == "" {
		return "", fmt.Errorf("openwrt-ab install: invalid target slot %q", targetSlot)
	}

	if progressFn != nil {
		progressFn("verify", 5)
	}
	if o.verifySig != nil {
		if err := o.verifySig(ctx, localPath); err != nil {
			return "", fmt.Errorf("openwrt-ab install: signature verify: %w", err)
		}
	}

	dev, err := o.resolveDevice(letter)
	if err != nil {
		return "", fmt.Errorf("openwrt-ab install: resolve slot %s: %w", letter, err)
	}
	if progressFn != nil {
		progressFn("write", 10)
	}
	if err := o.writeSlot(ctx, localPath, dev, progressFn); err != nil {
		return "", fmt.Errorf("openwrt-ab install: write slot %s (%s): %w", letter, dev, err)
	}

	// Flip the boot-counter: make the target slot the first ORDER entry, good
	// and untried, so the next boot trials it. The other slot's OK flag is left
	// intact as the rollback target — mirrors RAUC "activate" semantics.
	if progressFn != nil {
		progressFn("post-install", 90)
	}
	if err := o.activateSlot(letter); err != nil {
		return "", fmt.Errorf("openwrt-ab install: activate slot %s: %w", letter, err)
	}
	if progressFn != nil {
		progressFn("post-install", 100)
	}

	return o.installedVersion(localPath, bundleID), nil
}

// installedVersion reports the version to record for the just-installed slot.
// The raw squashfs carries no manifest, so we read an optional `<artifact>.version`
// sidecar the release pipeline ships next to the rootfs; failing that we fall
// back to the bundleID (the api already knows the version it pushed — this is
// display-only).
func (o *OpenWrtABBackend) installedVersion(localPath, bundleID string) string {
	if b, err := os.ReadFile(localPath + ".version"); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return v
		}
	}
	return bundleID
}

// activateSlot sets ORDER=[target, other] with target OK+untried, in place.
func (o *OpenWrtABBackend) activateSlot(letter string) error {
	kv, err := readGrubenv(o.grubenvPath)
	if err != nil {
		return err
	}
	st := decodeAB(kv)
	other := "A"
	if letter == "A" {
		other = "B"
	}
	st.order = []string{letter, other}
	st.ok[letter] = true
	st.try[letter] = false
	return writeGrubenv(o.grubenvPath, encodeAB(kv, st))
}

func (o *OpenWrtABBackend) Reboot(ctx context.Context, bundleID string, delaySeconds int) (int, error) {
	if delaySeconds <= 0 || delaySeconds > 30 {
		delaySeconds = 3
	}
	o.doReboot(delaySeconds)
	return delaySeconds, nil
}

// MarkGood commits the running slot: OK=1, TRY=0. Idempotent. This resets the
// GRUB boot-counter so a subsequent normal reboot stays on this slot rather
// than falling through to the other. Called by the saga after a health check
// passes; also armed on every healthy boot by the procd rasputin-mark-good
// service (defense-in-depth layer 1, mirroring the compute mark-good unit).
func (o *OpenWrtABBackend) MarkGood(ctx context.Context, bundleID string) error {
	return o.markRunning(true)
}

// MarkGoodOnBoot resets the running slot's boot-counter (OK=1, TRY=0) once the
// agent has reached its own userspace — the firewall's equivalent of compute's
// rasputin-mark-good.service (defense-in-depth layer 1: "OS + agent booted").
//
// This is REQUIRED for correct steady-state behavior, not just belt-and-braces:
// GRUB's grub.cfg consumes one TRY per boot (sets <slot>_TRY=1 + save_env), so
// without resetting it here a second ordinary reboot would see the running slot
// as already-tried, skip it, and fall through to the STALE other slot. Called
// once at agent startup (see main.go). Idempotent, so a crash-restart within the
// same boot re-runs it harmlessly. During an update trial boot it runs before
// the saga's health check — that's fine and mirrors compute: the saga can still
// MarkBad afterward (OK=0), which GRUB re-evaluates every boot.
func (o *OpenWrtABBackend) MarkGoodOnBoot(ctx context.Context) error {
	return o.markRunning(true)
}

// MarkBad marks the running slot bad (OK=0) so GRUB re-evaluates and boots the
// other (good) slot, then reboots. Best-effort on the reboot — a mark-bad that
// couldn't reboot is caught by the boot-counter on the next power cycle.
func (o *OpenWrtABBackend) MarkBad(ctx context.Context, bundleID, reason string) error {
	if err := o.markRunning(false); err != nil {
		return err
	}
	o.doReboot(2)
	return nil
}

// markRunning sets the currently-booted slot's OK flag to `good` and clears its
// TRY flag, in place. Determines the running slot from /proc/cmdline.
func (o *OpenWrtABBackend) markRunning(good bool) error {
	cmdline, err := os.ReadFile(o.procCmdline)
	if err != nil {
		return err
	}
	running := slotLetter(bootedSlotFromCmdline(string(cmdline)))
	if running == "" {
		return fmt.Errorf("openwrt-ab: cannot determine running slot from cmdline")
	}
	kv, err := readGrubenv(o.grubenvPath)
	if err != nil {
		return err
	}
	st := decodeAB(kv)
	st.ok[running] = good
	st.try[running] = false
	return writeGrubenv(o.grubenvPath, encodeAB(kv, st))
}

// ---- default OS-coupled implementations -------------------------------------

// defaultResolveDevice maps a slot letter to its rootfs block device. Prefers
// the by-partlabel symlink (present when the image populates /dev/disk/by-*);
// falls back to `findfs PARTLABEL=…` (util-linux / busybox) for OpenWrt roots
// that don't run udev.
func defaultResolveDevice(slot string) (string, error) {
	label := "rootfs-0"
	if slot == "B" {
		label = "rootfs-1"
	}
	byPartlabel := "/dev/disk/by-partlabel/" + label
	if _, err := os.Stat(byPartlabel); err == nil {
		return byPartlabel, nil
	}
	if out, err := exec.Command("findfs", "PARTLABEL="+label).Output(); err == nil {
		if dev := strings.TrimSpace(string(out)); dev != "" {
			return dev, nil
		}
	}
	return "", fmt.Errorf("cannot resolve device for slot %s (PARTLABEL=%s): no by-partlabel symlink and findfs failed", slot, label)
}

// defaultWriteSlot streams the squashfs at src into the raw block device dev.
// The agent runs as root on the firewall, so it can open the partition for
// write directly — no dd subprocess needed. Progress is reported as a coarse
// 10→90 sweep so the UI shows motion without over-reporting.
func defaultWriteSlot(ctx context.Context, src, dev string, progressFn func(string, int)) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	total := fi.Size()

	out, err := os.OpenFile(dev, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer out.Close()

	buf := make([]byte, 1<<20)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, rerr := in.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
			written += int64(n)
			if progressFn != nil && total > 0 {
				progressFn("write", 10+int(80*written/total))
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	return out.Sync()
}

// defaultReboot backgrounds a plain reboot after delaySeconds. GRUB (not the Pi
// tryboot firmware) selects the slot from grubenv, so no "0 tryboot" arg is
// needed — activateSlot already armed the counter. Uses busybox `reboot`.
func (o *OpenWrtABBackend) defaultReboot(delaySeconds int) {
	go func() {
		if o.muted != nil {
			o.muted.Store(true)
		}
		_ = exec.Command("sleep", fmt.Sprintf("%d", delaySeconds)).Run()
		if err := exec.Command("reboot").Run(); err != nil {
			log.Printf("rasputin-agent: reboot failed: %v", err)
		}
	}()
}

// defaultVerifySig is a placeholder until detached-CMS artifact signing is wired
// end-to-end (the rootfs artifact isn't signed yet; the SHA-over-mesh-TLS gate
// in Download is the current integrity guarantee). It logs once and passes.
// Tracked as a hardening item in the firewall-image design doc.
func defaultVerifySig(ctx context.Context, rootfsPath string) error {
	log.Printf("rasputin-agent: openwrt-ab: artifact signature verification not yet wired — relying on SHA gate (see firewall-image.md)")
	return nil
}
