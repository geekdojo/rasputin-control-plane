package bus

import (
	"math/rand/v2"
	"time"
)

// Backoff is the re-dial schedule: Min doubled per attempt, capped at Max,
// then spread by ±Jitter (a fraction of the delay) so five nodes that lost the
// same controlplane at the same instant do not hammer it in lockstep when it
// comes back. The result never leaves [Min, Max].
type Backoff struct {
	Min    time.Duration
	Max    time.Duration
	Jitter float64
}

// DefaultBackoff is what the agent re-dials with: 2s, 4s, 8s, 16s, 32s, then
// 60s for as long as it takes, each ±25%.
var DefaultBackoff = Backoff{Min: 2 * time.Second, Max: 60 * time.Second, Jitter: 0.25}

// Delay is the wait after the attempt-th consecutive failure (attempt >= 1).
func (b Backoff) Delay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := b.Min
	// Double per attempt, stopping as soon as the cap is reached rather than
	// shifting further — a shift past 62 bits wraps, and nothing is gained by
	// computing 2^attempt for an attempt that is already at Max.
	for i := 1; i < attempt && d < b.Max; i++ {
		d *= 2
	}
	if d > b.Max {
		d = b.Max
	}
	if b.Jitter > 0 {
		spread := float64(d) * b.Jitter
		d += time.Duration((rand.Float64()*2 - 1) * spread)
	}
	if d < b.Min {
		d = b.Min
	}
	if d > b.Max {
		d = b.Max
	}
	return d
}
