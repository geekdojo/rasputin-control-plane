package updater

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// RAUCBackend shells out to the `rauc` CLI for real bundle install. Used
// on hardware where rauc is installed.
//
// The implementation is intentionally minimal in v0 — enough to dispatch
// `rauc install` and `rauc status` and parse the output. The dev test
// matrix covers the saga via MockBackend; this code path comes online
// when we have a Pi 5 + Buildroot image to test against.
type RAUCBackend struct {
	stateDir string
	// binary is the resolved path to the rauc CLI. Held as a field rather
	// than re-resolved via PATH on every exec — matches the tailscale
	// backend's pattern and lets tests point at a shim without touching
	// the process-wide PATH.
	binary string
	muted  *atomic.Bool
	// caBundlePath, when set, is a PEM file (the per-installation Mesh CA)
	// added to the bundle-download client's trust pool on top of the system
	// roots. The api serves /api/bundles/{sha} over its mesh-CA HTTPS leaf,
	// and the agent process has no SSL_CERT_FILE, so without this the default
	// client rejects that cert ("bad certificate") and the saga stalls before
	// install. Wired from main.go via SetCABundle(tailscale.CABundlePath()).
	caBundlePath string
}

// NewRAUCBackend constructs a RAUCBackend. Returns an error if the rauc
// CLI is not on PATH — callers should fall through to MockBackend then.
func NewRAUCBackend(stateDir string) (*RAUCBackend, error) {
	bin, err := exec.LookPath("rauc")
	if err != nil {
		return nil, fmt.Errorf("rauc not on PATH: %w", err)
	}
	return newRAUCBackend(stateDir, bin)
}

// newRAUCBackend is the lower-level constructor that takes an explicit
// rauc binary path. Used by NewRAUCBackend (after PATH lookup) and by
// tests that want to point at a shim without mutating the process env.
func newRAUCBackend(stateDir, binary string) (*RAUCBackend, error) {
	if binary == "" {
		return nil, errors.New("rauc backend: binary path required")
	}
	if err := os.MkdirAll(filepath.Join(stateDir, "bundles"), 0o755); err != nil {
		return nil, err
	}
	return &RAUCBackend{stateDir: stateDir, binary: binary}, nil
}

func (r *RAUCBackend) SetMuteHook(b *atomic.Bool) { r.muted = b }

// SetCABundle points the bundle-download HTTPS client at a CA bundle to trust
// in addition to the system roots — the per-installation Mesh CA that signs
// the api's leaf. Mirrors SetMuteHook (post-construction wiring).
func (r *RAUCBackend) SetCABundle(path string) { r.caBundlePath = path }

// httpClient returns the client used to pull bundles. Its root pool is the
// system roots plus the Mesh CA at caBundlePath (when set + readable). Built
// per call so a re-enrolled CA is picked up without restarting the agent; an
// unreadable/empty path degrades to system roots only.
func (r *RAUCBackend) httpClient() *http.Client {
	if r.caBundlePath == "" {
		return http.DefaultClient
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if pem, err := os.ReadFile(r.caBundlePath); err == nil {
		pool.AppendCertsFromPEM(pem)
	}
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
}

func (r *RAUCBackend) Name() string { return "rauc" }

func (r *RAUCBackend) Precheck(ctx context.Context) (*proto.UpdatePrecheckAck, error) {
	out, err := exec.CommandContext(ctx, r.binary, "status", "--output-format=shell").Output()
	if err != nil {
		return &proto.UpdatePrecheckAck{OK: false, Detail: err.Error()}, nil
	}
	parsed := parseRAUCStatus(string(out))
	ack := &proto.UpdatePrecheckAck{
		OK:             true,
		ActiveSlot:     parsed.activeSlot,
		InactiveSlot:   parsed.inactiveSlot,
		CurrentVersion: parsed.activeVersion,
		AvailableBytes: 0, // TODO: statfs the inactive slot's partition
		Backend:        "rauc",
	}
	return ack, nil
}

type raucStatus struct {
	activeSlot    proto.UpdateSlot
	inactiveSlot  proto.UpdateSlot
	activeVersion string
}

// slotNameFromDevice maps a RAUC slot device path to our rootfs.N name via the
// partlabel the images use (rootfs-0 / rootfs-1).
func slotNameFromDevice(dev string) string {
	switch {
	case strings.Contains(dev, "rootfs-0"):
		return "rootfs.0"
	case strings.Contains(dev, "rootfs-1"):
		return "rootfs.1"
	}
	return ""
}

// parseRAUCStatus extracts the active/inactive slot from
// `rauc status --output-format=shell`. Real RAUC (the version on our image)
// names the booted slot in RAUC_BOOT_PRIMARY and describes each slot with
// per-index RAUC_SLOT_STATE_N / RAUC_SLOT_DEVICE_N fields:
//
//	RAUC_SYSTEM_COMPATIBLE='rasputin-n100'
//	RAUC_BOOT_PRIMARY='rootfs.0'
//	RAUC_SLOTS='1 2'
//	RAUC_SLOT_STATE_1='inactive'   RAUC_SLOT_DEVICE_1='/dev/disk/by-partlabel/rootfs-1'
//	RAUC_SLOT_STATE_2='booted'     RAUC_SLOT_DEVICE_2='/dev/disk/by-partlabel/rootfs-0'
//
// We also still accept the older schema (RAUC_BOOT_SLOT +
// RAUC_SLOT_STATUS_N_BUNDLE_VERSION). The booted rootfs (rootfs.0 / rootfs.1)
// maps to our a/b model (.0→A, .1→B); the other slot is the install target.
//
// NOTE (2026-06-22): this parser previously recognized ONLY RAUC_BOOT_SLOT —
// which real RAUC never emits — so it always returned SlotUnknown and OS
// self-update failed at the install step ("agent reported no inactive slot").
// It had only been exercised against the mock + a fictional shell mock, never
// real `rauc status` output. Caught on the Mu bench deploying 2026.06.0-dev.31.
func parseRAUCStatus(s string) raucStatus {
	out := raucStatus{
		activeSlot:   proto.SlotUnknown,
		inactiveSlot: proto.SlotUnknown,
	}
	kv := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '='); i > 0 {
			kv[line[:i]] = strings.Trim(line[i+1:], "'")
		}
	}

	// Which rootfs slot are we booted from? Prefer the explicit boot key (real
	// RAUC_BOOT_PRIMARY, or legacy RAUC_BOOT_SLOT); else fall back to the slot
	// whose STATE is booted, resolved to a name via its device partlabel.
	boot := kv["RAUC_BOOT_PRIMARY"]
	if boot == "" {
		boot = kv["RAUC_BOOT_SLOT"]
	}
	if boot == "" {
		for _, idx := range strings.Fields(kv["RAUC_SLOTS"]) {
			if st := kv["RAUC_SLOT_STATE_"+idx]; st == "booted" || st == "active" {
				boot = slotNameFromDevice(kv["RAUC_SLOT_DEVICE_"+idx])
				break
			}
		}
	}

	switch {
	case strings.HasSuffix(boot, ".0") || strings.Contains(boot, "rootfs-0"):
		out.activeSlot, out.inactiveSlot = proto.SlotA, proto.SlotB
	case strings.HasSuffix(boot, ".1") || strings.Contains(boot, "rootfs-1"):
		out.activeSlot, out.inactiveSlot = proto.SlotB, proto.SlotA
	}

	// Active slot's installed version, when RAUC records it (absent on a
	// freshly-flashed slot — fine, the install step only needs the slot).
	switch out.activeSlot {
	case proto.SlotA:
		out.activeVersion = kv["RAUC_SLOT_STATUS_0_BUNDLE_VERSION"]
	case proto.SlotB:
		out.activeVersion = kv["RAUC_SLOT_STATUS_1_BUNDLE_VERSION"]
	}
	return out
}

func (r *RAUCBackend) Download(ctx context.Context, bundleID, url, expectedSHA string, sizeBytes int64,
	progressFn func(int64, int64)) (string, string, error) {
	// Same HTTP fetch as the mock; rauc doesn't have a native HTTP
	// fetcher in our setup.
	dest := filepath.Join(r.stateDir, "bundles", bundleID+".raucb")
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := r.httpClient().Do(req)
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

func (r *RAUCBackend) Install(ctx context.Context, bundleID, localPath string, targetSlot proto.UpdateSlot,
	progressFn func(string, int)) (string, error) {
	if localPath == "" {
		localPath = filepath.Join(r.stateDir, "bundles", bundleID+".raucb")
	}
	if progressFn != nil {
		progressFn("verify", 5)
	}
	cmd := exec.CommandContext(ctx, r.binary, "install", localPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("rauc install: %w: %s", err, out)
	}
	if progressFn != nil {
		progressFn("post-install", 100)
	}
	// `rauc info <bundle>` reports the version; parse it.
	infoOut, err := exec.CommandContext(ctx, r.binary, "info", "--output-format=shell", localPath).Output()
	if err != nil {
		return "", fmt.Errorf("rauc info: %w", err)
	}
	for _, line := range strings.Split(string(infoOut), "\n") {
		if strings.HasPrefix(line, "RAUC_MF_VERSION=") {
			return strings.Trim(strings.TrimPrefix(line, "RAUC_MF_VERSION="), "'"), nil
		}
	}
	return "", errors.New("could not parse RAUC_MF_VERSION from `rauc info`")
}

// trybootMarker is the OS-image file whose presence means this node boots via
// the Raspberry Pi firmware tryboot A/B mechanism (the selector partition's
// autoboot.txt; the n100/GRUB image has no such file). Package var so tests can
// point it elsewhere. Mirrors the OS-side gates
// (rasputin-rauc-reconcile.service / rasputin-mark-good.service).
var trybootMarker = "/run/rasputin-seed/autoboot.txt"

// rebootArgs returns the `systemctl` arguments for the post-install trial
// reboot. On a Pi (tryboot backend) the install armed [tryboot] boot_partition
// but NOT the firmware one-shot (no vcmailbox in-tree), so a PLAIN reboot would
// boot the still-committed slot and never trial the new one. `reboot "0 tryboot"`
// arms the firmware one-shot so the next boot loads the candidate boot
// partition; on a healthy boot the saga's health-gated mark-good commits, and a
// failed trial reverts to the committed slot on the next (normal) boot. On the
// n100 (GRUB) a plain reboot is correct — `rauc install` already set grubenv.
func rebootArgs() []string {
	if _, err := os.Stat(trybootMarker); err == nil {
		return []string{"reboot", "0 tryboot"}
	}
	return []string{"reboot"}
}

func (r *RAUCBackend) Reboot(ctx context.Context, bundleID string, delaySeconds int) (int, error) {
	if delaySeconds <= 0 || delaySeconds > 30 {
		delaySeconds = 3
	}
	args := rebootArgs()
	// Schedule the reboot in the background so we can ack synchronously.
	// `shutdown -r +0` would be immediate; we use systemctl reboot after
	// the configured delay so the agent has time to publish the rebooting
	// event.
	go func() {
		if r.muted != nil {
			r.muted.Store(true)
		}
		// time.Sleep blocks; we keep the goroutine alive until reboot.
		// We reboot via `systemctl` to ensure a clean bootloader handoff —
		// with the tryboot one-shot argument on the Pi (see rebootArgs).
		_ = exec.Command("sleep", fmt.Sprintf("%d", delaySeconds)).Run()
		_ = exec.Command("systemctl", args...).Run()
	}()
	return delaySeconds, nil
}

func (r *RAUCBackend) MarkGood(ctx context.Context, bundleID string) error {
	out, err := exec.CommandContext(ctx, r.binary, "status", "mark-good").CombinedOutput()
	if err != nil {
		return fmt.Errorf("rauc mark-good: %w: %s", err, out)
	}
	return nil
}

func (r *RAUCBackend) MarkBad(ctx context.Context, bundleID, reason string) error {
	out, err := exec.CommandContext(ctx, r.binary, "status", "mark-bad").CombinedOutput()
	if err != nil {
		return fmt.Errorf("rauc mark-bad: %w: %s", err, out)
	}
	// Reboot back to the previously-good slot.
	go func() {
		_ = exec.Command("sleep", "2").Run()
		_ = exec.Command("systemctl", "reboot").Run()
	}()
	return nil
}
