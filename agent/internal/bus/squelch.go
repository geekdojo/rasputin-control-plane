package bus

import (
	"log"
	"time"
)

// Squelch collapses a run of publish failures from one periodic publisher
// into two log lines: the first failure, and the recovery with a count of
// what was suppressed in between. Without it every 10s publisher wrote its
// own "connection closed" line for as long as the bus was down — 17 hours of
// it on e3bench, 2026-09-04 — and the one line that mattered (the close
// itself, from the Client) scrolled off the top.
//
// One Squelch per publishing goroutine; it is not safe for concurrent use.
type Squelch struct {
	// What names the publisher in the log lines, e.g. "publish heartbeat".
	What string

	failing    bool
	suppressed int
	since      time.Time
}

// Fail records a publish failure. The first in a run is logged with its
// error; the rest are counted.
func (s *Squelch) Fail(err error) {
	if s.failing {
		s.suppressed++
		return
	}
	s.failing = true
	s.suppressed = 0
	s.since = time.Now()
	log.Printf("rasputin-agent: %s: %v — further failures suppressed until it succeeds again", s.What, err)
}

// OK records a publish success. The first after a run of failures logs how
// long the run lasted and how many failures were suppressed.
func (s *Squelch) OK() {
	if !s.failing {
		return
	}
	log.Printf("rasputin-agent: %s: succeeding again after %s (%d failure(s) suppressed)",
		s.What, time.Since(s.since).Round(time.Second), s.suppressed)
	s.failing = false
	s.suppressed = 0
}

// Report calls Fail or OK for err, so a publisher's loop is one line.
func (s *Squelch) Report(err error) {
	if err != nil {
		s.Fail(err)
		return
	}
	s.OK()
}
