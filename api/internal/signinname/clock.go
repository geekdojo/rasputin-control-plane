package signinname

import "time"

// SystemClock is the production Clock, over the wall clock and time.NewTimer.
type SystemClock struct{}

// Now returns the current time.
func (SystemClock) Now() time.Time { return time.Now() }

// NewTimer arms a one-shot timer for the loop's next protocol deadline: the
// end of one of RFC 6762's listening windows (probeInterval,
// announceInterval) or a maintenance point of another host's record
// (timer-audit.tsv).
func (SystemClock) NewTimer(d time.Duration) Timer { return systemTimer{time.NewTimer(d)} }

type systemTimer struct{ t *time.Timer }

func (s systemTimer) C() <-chan time.Time { return s.t.C }
func (s systemTimer) Stop() bool          { return s.t.Stop() }
