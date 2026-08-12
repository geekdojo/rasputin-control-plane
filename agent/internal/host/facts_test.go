package host

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestHostname_MatchesOSHostname(t *testing.T) {
	// We can't pin a value (will differ per machine), but it should match
	// what the stdlib returns. If `os.Hostname()` returns an error the
	// helper returns ""; we don't fake that here.
	want, _ := os.Hostname()
	if got := Hostname(); got != want {
		t.Errorf("Hostname() = %q, want %q (from os.Hostname)", got, want)
	}
}

func TestUptime_IsPositiveAndRoundedToSecond(t *testing.T) {
	u := Uptime()
	if u < 0 {
		t.Errorf("uptime should never be negative, got %v", u)
	}
	// Rounded to nearest second means the sub-second component is zero.
	if u%time.Second != 0 {
		t.Errorf("uptime not second-aligned: %v", u)
	}
}

func TestImageVersion_EnvOverrideWins(t *testing.T) {
	t.Setenv("RASPUTIN_IMAGE_VERSION", "  2026.06.0-dev.13\n")
	if got := ImageVersion(); got != "2026.06.0-dev.13" {
		t.Errorf("ImageVersion() = %q, want trimmed env value", got)
	}
}

func TestImageVersion_MissingFileIsEmptyNotError(t *testing.T) {
	// No env override and the real /etc/rasputin/image-version almost
	// certainly doesn't exist on the dev box / CI runner. Either way the
	// helper must degrade to "" rather than panic or error.
	t.Setenv("RASPUTIN_IMAGE_VERSION", "")
	if got := ImageVersion(); got != "" && got != trimmedFileVersion(t) {
		t.Errorf("ImageVersion() = %q, want \"\" or the trimmed file contents", got)
	}
}

// trimmedFileVersion returns the trimmed contents of the runtime version file
// if it happens to exist (so the test also passes if run on a real image),
// else "".
func trimmedFileVersion(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(imageVersionPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func TestBootID_EnvOverrideWins(t *testing.T) {
	// The dev/testing lever: on a laptop a "reboot" is a process restart, so
	// the env override is how a functional test drives a boot change.
	t.Setenv("RASPUTIN_BOOT_ID", "  4f8c2b1e-0000-4a11-9c3d-000000000001\n")
	if got := BootID(); got != "4f8c2b1e-0000-4a11-9c3d-000000000001" {
		t.Errorf("BootID() = %q, want trimmed env value", got)
	}
}

func TestBootID_MissingFileIsEmptyNotError(t *testing.T) {
	// macOS dev boxes have no /proc at all. The helper must degrade to "" —
	// which consumers read as UNKNOWN, never as a boot mismatch (ADR-0005
	// Decision 3) — rather than error or panic.
	t.Setenv("RASPUTIN_BOOT_ID", "")
	got := BootID()
	if got != "" && got != trimmedFileBootID(t) {
		t.Errorf("BootID() = %q, want \"\" or the trimmed file contents", got)
	}
	// On a real Linux host the value must look like a boot_id: a non-empty
	// single line with no surrounding whitespace.
	if got != "" && (strings.TrimSpace(got) != got || strings.Contains(got, "\n")) {
		t.Errorf("BootID() = %q, want a trimmed single line", got)
	}
}

// TestBootID_StableWithinAProcess pins the property the whole comparison rests
// on: within one boot the identity does not change, so two reads that differ
// would mean "different boot" to the update saga when nothing rebooted.
func TestBootID_StableWithinAProcess(t *testing.T) {
	t.Setenv("RASPUTIN_BOOT_ID", "")
	if a, b := BootID(), BootID(); a != b {
		t.Errorf("BootID() not stable within a process: %q then %q", a, b)
	}
}

// trimmedFileBootID returns the trimmed contents of the kernel boot_id file if
// it exists (so the test also passes on a real Linux node), else "".
func trimmedFileBootID(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(bootIDPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func TestUptime_IsMonotonicNonDecreasing(t *testing.T) {
	// Two consecutive reads taken back-to-back should never go backwards.
	// We intentionally don't sleep between them — that would push the test
	// past the 100ms budget — and we don't require strict monotonic-greater
	// since at second granularity two adjacent reads will usually tie.
	a := Uptime()
	b := Uptime()
	if b < a {
		t.Errorf("uptime decreased: %v -> %v", a, b)
	}
}
