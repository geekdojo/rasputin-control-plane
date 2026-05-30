package host

import (
	"os"
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
