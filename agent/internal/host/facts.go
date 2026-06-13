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

// Uptime returns how long the agent process has been running, rounded to
// the nearest second so the formatted output stays compact.
func Uptime() time.Duration {
	return time.Since(startedAt).Round(time.Second)
}
