package main

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// trustedClock is the api's one answer to "may I stamp a certificate's
// validity window with the current time?".
//
// Before this there was one caller — the HTTPS leaf's mint — and it waited
// inline. Every other controlplane-CA mint (Headscale's leaf, a node's collector leaf,
// an app's leaf) stamped time.Now() with nothing checked, so a controlplane
// that came up before NTP could issue certificates anchored in a bogus window
// and hand them to nodes. Passed to the CAs as tlsca.Deps.LeafClock, this gates all of
// them.
//
// Shape:
//
//   - It WAITS at most once in the process's life. The wait is what costs
//     something, and repeating it per mint would turn a fleet-wide renewal
//     sweep on an offline node into an hour of stalls.
//   - Once the clock is trustworthy it stays trustworthy: that is latched, and
//     every later caller returns immediately with no syscall.
//   - Until then each call re-reads the fact cheaply, so a clock that
//     synchronizes AFTER the one wait gave up is picked up by the next mint
//     rather than being written off for the life of the process.
//
// It is a fact check with a bound on how long a mint will wait for the fact,
// not a timer deciding anything (design/principles.md).
type trustedClock struct {
	ctx     context.Context
	timeout time.Duration

	once   sync.Once
	synced atomic.Bool
}

func newTrustedClock(ctx context.Context, timeout time.Duration) *trustedClock {
	return &trustedClock{ctx: ctx, timeout: timeout}
}

// ok reports whether the wall clock is trustworthy, waiting for it the first
// time it is asked. False means the wait ran out (or is shutting down) and the
// caller should mint anyway — a node with no reachable NTP still has to serve
// TLS — which is why the warning is here, once, rather than at each mint.
func (c *trustedClock) ok() bool {
	if c.synced.Load() {
		return true
	}
	c.once.Do(func() {
		if waitForTrustworthyClock(c.ctx, c.timeout) {
			c.synced.Store(true)
			return
		}
		if c.ctx.Err() != nil {
			return
		}
		log.Printf("rasputin-api: WARNING — system clock not NTP-synchronized after %s; "+
			"certificates minted under the controlplane CA from here on are dated against the current "+
			"clock. If the UI, a node's collector or the mesh reports an expired or not-yet-valid "+
			"certificate, fix time sync (NTP) and restart rasputin-api.", c.timeout)
	})
	if c.synced.Load() {
		return true
	}
	// The one wait is spent, but the fact can still become true: re-read it
	// cheaply so a clock that synchronizes later is not written off.
	if c.ctx.Err() != nil {
		return false
	}
	if _, synced, _ := readClockSync(); synced {
		c.synced.Store(true)
		return true
	}
	return false
}

// readClockSync is the one non-blocking read of systemd-timesyncd's
// synchronization signal (clockSyncDir, clockSyncMarker). timesyncd is
// whether the host runs timesyncd at all (its directory exists); synced is
// whether the marker is present, empty included: timesyncd touches it, so an
// empty file means synced. A stat error other than "not found" on the marker
// is returned with synced false. Each caller applies its own policy to a
// host without timesyncd.
func readClockSync() (timesyncd, synced bool, err error) {
	if _, err := os.Stat(clockSyncDir); err != nil {
		return false, false, nil // not a systemd-timesyncd system
	}
	switch _, err := os.Stat(clockSyncMarker); {
	case err == nil:
		return true, true, nil
	case errors.Is(err, fs.ErrNotExist):
		return true, false, nil
	default:
		return true, false, err
	}
}

// clockSyncFact is the clock-sync fact the sign-in rules read
// (geekdojo/geekdojo-brain#987): CONFIGURE_TOTP is offered only while it
// holds. A host without timesyncd, or with the marker absent, is not
// synced; a marker that cannot be read is not synced either, with one WARN
// per outage (security resolver row R49).
type clockSyncFact struct {
	read func() (timesyncd, synced bool, err error)
	log  *slog.Logger

	mu   sync.Mutex
	down bool
}

// Synced reads the fact.
func (f *clockSyncFact) Synced(ctx context.Context) bool {
	timesyncd, synced, err := f.read()
	f.mu.Lock()
	first := err != nil && !f.down
	f.down = err != nil
	f.mu.Unlock()
	if first {
		f.log.LogAttrs(ctx, slog.LevelWarn, "The clock-sync signal could not be read, so the authenticator app is not offered.",
			slog.String("event", "identity.clock_sync_unreadable"), slog.String("err", err.Error()))
	}
	return timesyncd && synced && err == nil
}
