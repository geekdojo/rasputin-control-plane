package catalogsync

import (
	"context"
	"log"
	"sync"
	"time"
)

// DefaultInterval is the poll cadence (ADR-0006 Decision 9).
//
// Daily rather than hourly is a deliberate cheapness call: ADR-0002 sized
// appliance polling against GitHub's 60/hr/IP anonymous limit, and a catalog
// that lands within a day is indistinguishable from instant to the person it
// serves. The operator-triggered refresh exists for the case where it isn't.
const DefaultInterval = 24 * time.Hour

// startupDelay lets the network settle before the first attempt, so a cluster
// that boots faster than its DHCP lease does not record a failure it would
// have avoided by waiting thirty seconds.
const startupDelay = 30 * time.Second

// Poller drives Sync on a cadence and on demand.
//
// It deliberately owns no state beyond scheduling. Whether a fetched bundle is
// allowed to become the catalog is Store's decision, and "what should I fetch"
// is the Fetcher's — a poller that also made those calls would be the obvious
// place for them to drift out of agreement.
type Poller struct {
	fetch *Fetcher
	store *Store

	Interval time.Duration
	// StartupDelay is how long Run waits before its first poll. A field rather
	// than the constant so tests do not have to wait out a network-settling
	// pause that exists for real hardware.
	StartupDelay time.Duration

	// refresh carries operator-triggered runs. Buffered by one: a second click
	// while a fetch is in flight is a no-op rather than a queue, because
	// running the same poll twice back to back achieves nothing and a queue of
	// them is a way to get rate-limited by your own UI.
	refresh chan struct{}

	mu          sync.RWMutex
	lastChecked time.Time
	lastErr     error
}

func NewPoller(f *Fetcher, s *Store) *Poller {
	return &Poller{fetch: f, store: s, Interval: DefaultInterval, StartupDelay: startupDelay, refresh: make(chan struct{}, 1)}
}

// Refresh asks for a poll now. It never blocks.
func (p *Poller) Refresh() {
	select {
	case p.refresh <- struct{}{}:
	default:
	}
}

// LastChecked reports when a poll last completed and what it concluded. The
// zero time means no poll has finished yet, which is NOT the same as a poll
// that found nothing — the UI has to be able to tell those apart or a cluster
// with no egress looks identical to one that is up to date.
func (p *Poller) LastChecked() (time.Time, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.lastChecked, p.lastErr
}

// Run polls until ctx is cancelled. Blocking; callers run it in a goroutine.
func (p *Poller) Run(ctx context.Context) {
	interval := p.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}

	if p.StartupDelay > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(p.StartupDelay):
		}
	}
	p.once(ctx)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.once(ctx)
		case <-p.refresh:
			p.once(ctx)
		}
	}
}

// once runs a single poll. It never returns an error: a failed poll is a
// normal condition for an appliance behind someone's home router, and the
// cluster keeps serving its last good catalog. The outcome is recorded for the
// UI instead of propagated.
func (p *Poller) once(ctx context.Context) {
	// Bounded independently of the poll interval, so a hung connection cannot
	// stall the loop until the next tick.
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	changed, err := Sync(runCtx, p.fetch, p.store)

	p.mu.Lock()
	p.lastChecked, p.lastErr = time.Now().UTC(), err
	p.mu.Unlock()

	switch {
	case err != nil:
		// Logged at every failure rather than only the first: a cluster that
		// has been unable to fetch for a month should say so a month's worth
		// of times, not once at boot where nobody will find it.
		log.Printf("catalog: poll failed, keeping v%d: %v", p.store.Current().Version, err)
	case changed:
		log.Printf("catalog: updated to v%d", p.store.Current().Version)
	}
}
