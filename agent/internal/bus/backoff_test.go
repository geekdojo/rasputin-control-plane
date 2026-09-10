package bus

import (
	"errors"
	"testing"
	"time"
)

// TestBackoff_Schedule pins the re-dial schedule without jitter: 2s doubling
// to the 60s cap, then 60s forever.
func TestBackoff_Schedule(t *testing.T) {
	b := Backoff{Min: 2 * time.Second, Max: 60 * time.Second}
	want := []time.Duration{
		2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second,
		60 * time.Second, 60 * time.Second, 60 * time.Second,
	}
	for i, w := range want {
		if got := b.Delay(i + 1); got != w {
			t.Errorf("Delay(%d) = %s, want %s", i+1, got, w)
		}
	}
	// Out-of-range attempts are clamped, never negative or overflowed.
	if got := b.Delay(0); got != 2*time.Second {
		t.Errorf("Delay(0) = %s, want Min", got)
	}
	if got := b.Delay(10_000); got != 60*time.Second {
		t.Errorf("Delay(10000) = %s, want Max (no overflow)", got)
	}
}

// TestBackoff_JitterStaysWithinBounds: jitter spreads a delay by ±Jitter of
// its value, never below Min or above Max, and the cap is jittered downward
// only (there is no "more than the cap").
func TestBackoff_JitterStaysWithinBounds(t *testing.T) {
	b := DefaultBackoff
	if b.Min != 2*time.Second || b.Max != 60*time.Second || b.Jitter != 0.25 {
		t.Fatalf("DefaultBackoff = %+v; the schedule documented in doc.go changed", b)
	}
	for attempt := 1; attempt <= 8; attempt++ {
		base := Backoff{Min: b.Min, Max: b.Max}.Delay(attempt)
		lo := time.Duration(float64(base) * (1 - b.Jitter))
		hi := time.Duration(float64(base) * (1 + b.Jitter))
		if lo < b.Min {
			lo = b.Min
		}
		if hi > b.Max {
			hi = b.Max
		}
		for i := 0; i < 200; i++ {
			got := b.Delay(attempt)
			if got < lo || got > hi {
				t.Fatalf("Delay(%d) = %s outside [%s, %s]", attempt, got, lo, hi)
			}
		}
	}
}

// TestBackoff_JitterSpreadsBothDirections pins that the ±Jitter spread is
// genuinely two-sided: over many samples at a fixed attempt some delays land
// STRICTLY above the un-jittered base and some STRICTLY below it. The bounds
// test above only checks the envelope, so a jitter that was silently disabled
// (always == base) or that pushed only one way (always below / always above)
// would slip past it — this catches all three.
//
// attempt 3 gives base = 8s with a ±2s spread, comfortably inside [Min, Max],
// so neither clamp can mask a direction.
func TestBackoff_JitterSpreadsBothDirections(t *testing.T) {
	b := DefaultBackoff
	const attempt = 3
	base := Backoff{Min: b.Min, Max: b.Max}.Delay(attempt)
	if base <= b.Min || base >= b.Max {
		t.Fatalf("base %s is not strictly inside (%s, %s); a clamp could hide a direction", base, b.Min, b.Max)
	}
	var sawAbove, sawBelow bool
	for i := 0; i < 2000 && !(sawAbove && sawBelow); i++ {
		switch got := b.Delay(attempt); {
		case got > base:
			sawAbove = true
		case got < base:
			sawBelow = true
		}
	}
	if !sawAbove {
		t.Errorf("no delay ever exceeded base %s — jitter never spreads upward", base)
	}
	if !sawBelow {
		t.Errorf("no delay ever fell below base %s — jitter never spreads downward", base)
	}
}

// TestSquelch_LogsOnceThenCounts: a run of failures is one line in, one line
// out — the counter in between is what tells an operator how long the bus was
// gone from a log that would otherwise be nothing but the failures.
func TestSquelch_LogsOnceThenCounts(t *testing.T) {
	var s Squelch
	s.What = "publish heartbeat"
	s.OK() // a success with no run in progress is a no-op
	if s.failing {
		t.Fatal("OK with nothing failing set failing")
	}
	err := errors.New("nats: connection closed")
	for i := 0; i < 5; i++ {
		s.Report(err)
	}
	if !s.failing || s.suppressed != 4 {
		t.Fatalf("after 5 failures: failing=%t suppressed=%d, want true/4 (first is logged, rest counted)", s.failing, s.suppressed)
	}
	s.Report(nil)
	if s.failing || s.suppressed != 0 {
		t.Fatalf("after recovery: failing=%t suppressed=%d, want false/0", s.failing, s.suppressed)
	}
	// A second run starts its count afresh.
	s.Report(err)
	s.Report(err)
	if s.suppressed != 1 {
		t.Fatalf("second run suppressed=%d, want 1", s.suppressed)
	}
}
