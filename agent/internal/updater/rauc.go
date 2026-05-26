package updater

import (
	"context"
	"crypto/sha256"
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
	muted    *atomic.Bool
}

// NewRAUCBackend constructs a RAUCBackend. Returns an error if the rauc
// CLI is not on PATH — callers should fall through to MockBackend then.
func NewRAUCBackend(stateDir string) (*RAUCBackend, error) {
	if _, err := exec.LookPath("rauc"); err != nil {
		return nil, fmt.Errorf("rauc not on PATH: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(stateDir, "bundles"), 0o755); err != nil {
		return nil, err
	}
	return &RAUCBackend{stateDir: stateDir}, nil
}

func (r *RAUCBackend) SetMuteHook(b *atomic.Bool) { r.muted = b }

func (r *RAUCBackend) Name() string { return "rauc" }

func (r *RAUCBackend) Precheck(ctx context.Context) (*proto.UpdatePrecheckAck, error) {
	out, err := exec.CommandContext(ctx, "rauc", "status", "--output-format=shell").Output()
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

// parseRAUCStatus extracts the bare minimum from `rauc status --output-format=shell`:
//
//	RAUC_SYSTEM_COMPATIBLE='rasputin-pi5-cm5'
//	RAUC_SYSTEM_VARIANT=''
//	RAUC_BOOT_SLOT='rootfs.0'
//	RAUC_SLOT_STATUS_0='rootfs.0:active'
//	RAUC_SLOT_STATUS_0_BUNDLE_VERSION='1.2.3'
//	RAUC_SLOT_STATUS_1='rootfs.1:inactive'
//
// We map rootfs.0/.1 to our a/b model. The v0 mapping is fixed — a future
// iteration could read RAUC's `system.compatible` to drive layout.
func parseRAUCStatus(s string) raucStatus {
	out := raucStatus{
		activeSlot:   proto.SlotUnknown,
		inactiveSlot: proto.SlotUnknown,
	}
	for _, line := range strings.Split(s, "\n") {
		switch {
		case strings.HasPrefix(line, "RAUC_BOOT_SLOT="):
			v := strings.Trim(strings.TrimPrefix(line, "RAUC_BOOT_SLOT="), "'")
			if strings.HasSuffix(v, ".0") {
				out.activeSlot = proto.SlotA
				out.inactiveSlot = proto.SlotB
			} else if strings.HasSuffix(v, ".1") {
				out.activeSlot = proto.SlotB
				out.inactiveSlot = proto.SlotA
			}
		case strings.HasPrefix(line, "RAUC_SLOT_STATUS_0_BUNDLE_VERSION=") && out.activeSlot == proto.SlotA:
			out.activeVersion = strings.Trim(strings.TrimPrefix(line, "RAUC_SLOT_STATUS_0_BUNDLE_VERSION="), "'")
		case strings.HasPrefix(line, "RAUC_SLOT_STATUS_1_BUNDLE_VERSION=") && out.activeSlot == proto.SlotB:
			out.activeVersion = strings.Trim(strings.TrimPrefix(line, "RAUC_SLOT_STATUS_1_BUNDLE_VERSION="), "'")
		}
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
	resp, err := http.DefaultClient.Do(req)
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
	cmd := exec.CommandContext(ctx, "rauc", "install", localPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("rauc install: %w: %s", err, out)
	}
	if progressFn != nil {
		progressFn("post-install", 100)
	}
	// `rauc info <bundle>` reports the version; parse it.
	infoOut, err := exec.CommandContext(ctx, "rauc", "info", "--output-format=shell", localPath).Output()
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

func (r *RAUCBackend) Reboot(ctx context.Context, bundleID string, delaySeconds int) (int, error) {
	if delaySeconds <= 0 || delaySeconds > 30 {
		delaySeconds = 3
	}
	// Schedule the reboot in the background so we can ack synchronously.
	// `shutdown -r +0` would be immediate; we use systemctl reboot after
	// the configured delay so the agent has time to publish the rebooting
	// event.
	go func() {
		if r.muted != nil {
			r.muted.Store(true)
		}
		// time.Sleep blocks; we keep the goroutine alive until reboot.
		// We use a syscall-level reboot via `systemctl reboot` to ensure
		// the bootloader handoff is clean.
		_ = exec.Command("sleep", fmt.Sprintf("%d", delaySeconds)).Run()
		_ = exec.Command("systemctl", "reboot").Run()
	}()
	return delaySeconds, nil
}

func (r *RAUCBackend) MarkGood(ctx context.Context, bundleID string) error {
	out, err := exec.CommandContext(ctx, "rauc", "status", "mark-good").CombinedOutput()
	if err != nil {
		return fmt.Errorf("rauc mark-good: %w: %s", err, out)
	}
	return nil
}

func (r *RAUCBackend) MarkBad(ctx context.Context, bundleID, reason string) error {
	out, err := exec.CommandContext(ctx, "rauc", "status", "mark-bad").CombinedOutput()
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
