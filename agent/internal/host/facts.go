package host

import (
	"os"
	"strings"
	"time"
)

var startedAt = time.Now()

// imageVersionPath is the runtime file both the Buildroot OS and the OpenWrt
// firewall image bake at build time, containing just the CalVer image version
// string (e.g. "2026.06.0-dev.13\n").
const imageVersionPath = "/etc/rasputin/image-version"

// bootIDPath is the kernel's per-boot random UUID. Present on every Linux
// (both the Buildroot OS and the OpenWrt firewall image), minted fresh by the
// kernel on every boot, and readable without privilege.
const bootIDPath = "/proc/sys/kernel/random/boot_id"

// Hostname returns the system hostname, or "" on error.
func Hostname() string {
	h, _ := os.Hostname()
	return h
}

// ImageVersion returns the OS image version (CalVer) baked into the running
// image. Precedence: the RASPUTIN_IMAGE_VERSION env override (for dev/testing)
// wins, otherwise the trimmed contents of /etc/rasputin/image-version. A
// missing file is not an error — dev boxes and pre-feature images simply have
// no version, and the helper returns "". Callers render "" gracefully.
func ImageVersion() string {
	if v := strings.TrimSpace(os.Getenv("RASPUTIN_IMAGE_VERSION")); v != "" {
		return v
	}
	b, err := os.ReadFile(imageVersionPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// BootID returns the kernel's boot identity for the running boot — the UUID at
// /proc/sys/kernel/random/boot_id, regenerated on every boot. It is an
// IDENTITY, not a timestamp: the only comparison it supports (and the only one
// the update saga needs) is equality — "is the agent answering me on a
// different boot than the one I told to reboot?" (ADR-0005 Decision 1).
//
// Deliberately not a boot *time*. Rasputin's most common node is a Pi with no
// RTC whose wall clock is wrong until timesyncd runs — the pi-clock-cert-expiry
// failure class — so any clock-derived boot marker is untrustworthy at exactly
// the moment the saga needs it. boot_id needs no clock and no ordering.
//
// Precedence mirrors ImageVersion: the RASPUTIN_BOOT_ID env override (dev /
// testing, where a "reboot" is a process restart) wins, otherwise the trimmed
// file contents. A missing or unreadable file returns "" — a pre-bootId agent
// and a kernel without the file are the same thing to a consumer, and per
// ADR-0005 Decision 3 an absent boot id is UNKNOWN, never a mismatch.
func BootID() string {
	if v := strings.TrimSpace(os.Getenv("RASPUTIN_BOOT_ID")); v != "" {
		return v
	}
	b, err := os.ReadFile(bootIDPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Uptime returns how long the agent process has been running, rounded to
// the nearest second so the formatted output stays compact.
func Uptime() time.Duration {
	return time.Since(startedAt).Round(time.Second)
}
