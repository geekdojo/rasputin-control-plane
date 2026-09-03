package quiesce

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The §4.7 restart guard.
//
// armed BEFORE the stop, released in a defer, fires on a deadline if the
// release never comes, restarts on its own background context, retries with
// backoff, and leaves a marker on disk that the next agent start sweeps. Every
// one of those is load-bearing; see doc.go for the contract they add up to.

// markerDirName is the directory under the agent's state dir where armed
// stops are recorded. NOT under the staging root: the boot sweep of that root
// removes regular files, and a marker is the one file that must survive
// until the app is back.
const markerDirName = "quiesce-armed"

// MarkerDir is where an armed stop is recorded, and the one place that is
// decided.
func MarkerDir(stateDir string) string { return filepath.Join(stateDir, markerDirName) }

// armedStop is the marker's contents. Everything in it is an identifier or a
// timestamp; it is read back only to know WHICH app to start.
type armedStop struct {
	AppID       string    `json:"appId"`
	AppName     string    `json:"appName,omitempty"`
	StagingName string    `json:"stagingName,omitempty"`
	StoppedAt   time.Time `json:"stoppedAt"`
}

// restartOutcome is what the guard reports once it has tried.
type restartOutcome struct {
	restored bool
	by       string // "driver" | "watchdog"
	at       time.Time
	detail   string
}

// defaultRestartBackoff is the retry schedule for a start that fails. Three
// tries over roughly twenty seconds covers a daemon that was momentarily busy;
// past that the guard keeps going in the background and the ack goes out
// saying the app is not back, which is the alert the fan-out must raise.
var defaultRestartBackoff = []time.Duration{0, 5 * time.Second, 15 * time.Second}

// restartAttemptTimeout bounds one `compose start`. Its own context, never the
// request's.
const restartAttemptTimeout = 2 * time.Minute

// defaultReleaseWait is how long Release blocks for the guard's verdict before
// answering "still trying". Long enough for the normal schedule to finish.
const defaultReleaseWait = 45 * time.Second

type guard struct {
	s        *Stager
	appID    string
	marker   string
	release  chan struct{}
	relOnce  sync.Once
	done     chan struct{}
	deadline time.Duration

	mu      sync.Mutex
	fired   bool // the deadline, not the release, is what triggered the restart
	outcome *restartOutcome
}

// arm writes the marker and starts the guard. It returns an error only if the
// marker could not be written — and the caller must then NOT stop the app,
// because a stop this process cannot leave a record of is a stop a crash
// would make permanent.
func (s *Stager) arm(appID, appName, stagingName string) (*guard, error) {
	if err := os.MkdirAll(s.markerDir, 0o700); err != nil {
		return nil, fmt.Errorf("create marker dir %s: %w", s.markerDir, err)
	}
	g := &guard{
		s: s, appID: appID,
		marker:   filepath.Join(s.markerDir, markerName(appID)),
		release:  make(chan struct{}),
		done:     make(chan struct{}),
		deadline: s.watchdogDeadline,
	}
	body, err := json.Marshal(armedStop{AppID: appID, AppName: appName, StagingName: stagingName, StoppedAt: time.Now().UTC()})
	if err != nil {
		return nil, err
	}
	if err := writeFileSync(g.marker, body); err != nil {
		return nil, fmt.Errorf("write marker %s: %w", g.marker, err)
	}
	go g.run()
	return g, nil
}

func (g *guard) run() {
	timer := time.NewTimer(g.deadline)
	defer timer.Stop()
	by := "driver"
	select {
	case <-g.release:
	case <-timer.C:
		by = "watchdog"
		g.mu.Lock()
		g.fired = true
		g.mu.Unlock()
		g.s.logf("rasputin-agent: quiesce: WATCHDOG fired for app %s after %s with no release — restarting it now", g.appID, g.deadline)
	}
	out := g.s.restart(g.appID, g.marker)
	out.by = by
	g.mu.Lock()
	g.outcome = &out
	g.mu.Unlock()
	close(g.done)
}

// Release tells the guard the driver is finished — success or not — and waits
// (bounded) for its verdict. Safe to call more than once.
func (g *guard) Release() restartOutcome {
	g.relOnce.Do(func() { close(g.release) })
	select {
	case <-g.done:
	case <-time.After(g.s.releaseWait):
		return restartOutcome{restored: false, by: "driver",
			detail: "the app has not started yet; the agent is still retrying in the background and will retry again at its next start"}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return *g.outcome
}

// Fired reports whether the deadline, rather than the driver, triggered the
// restart — in which case the app came back while the copy was still running
// and the copy is not what the strategy promised.
func (g *guard) Fired() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fired
}

// restart starts the app with retries and removes the marker on success. It
// is the ONE path both the guard and the boot sweep go through, and it takes
// no context from anyone: a request context that was cancelled is the very
// case this must survive.
func (s *Stager) restart(appID, marker string) restartOutcome {
	var last error
	for i, wait := range s.restartBackoff {
		if wait > 0 {
			time.Sleep(wait)
		}
		ctx, cancel := context.WithTimeout(context.Background(), restartAttemptTimeout)
		err := s.rt.StartApp(ctx, appID)
		cancel()
		if err == nil {
			at := time.Now().UTC()
			if rerr := os.Remove(marker); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				s.logf("rasputin-agent: quiesce: app %s started but its marker %s could not be removed: %v", appID, marker, rerr)
			}
			return restartOutcome{restored: true, at: at, detail: fmt.Sprintf("started on attempt %d", i+1)}
		}
		last = err
		s.logf("rasputin-agent: quiesce: start app %s (attempt %d/%d) failed: %v", appID, i+1, len(s.restartBackoff), err)
	}
	// The marker stays: the next agent start sweeps it and tries again.
	return restartOutcome{restored: false, detail: fmt.Sprintf("the app did not start after %d attempts (%v); its marker is kept and the next agent start will retry", len(s.restartBackoff), last)}
}

// SweepArmedStops starts every app a previous agent process stopped for a
// backup and did not live to restart — §4.7's watchdog surviving the death of
// the process that armed it. Called at agent start, before any verb is
// exposed. Returns how many markers were found.
func (s *Stager) SweepArmedStops() int {
	ents, err := os.ReadDir(s.markerDir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.markerDir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var m armedStop
		if err := json.Unmarshal(raw, &m); err != nil || m.AppID == "" {
			// Not something this package wrote. Left alone rather than acted
			// on: a start is a service-affecting operation and the only
			// authority for it is a marker this code can read.
			s.logf("rasputin-agent: quiesce: ignoring unreadable marker %s", path)
			continue
		}
		n++
		s.logf("rasputin-agent: quiesce: app %s (%s) was left stopped by a backup at %s and this agent did not live to restart it — starting it now",
			m.AppID, m.AppName, m.StoppedAt.Format(time.RFC3339))
		out := s.restart(m.AppID, path)
		if out.restored {
			s.logf("rasputin-agent: quiesce: app %s is running again", m.AppID)
		} else {
			s.logf("rasputin-agent: quiesce: app %s is STILL DOWN: %s", m.AppID, out.detail)
		}
	}
	return n
}

// markerName is the marker's file name for an app: the app id, which is a
// ULID and so already a plain file name, with anything else mapped away.
func markerName(appID string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, appID)
	if safe == "" {
		safe = "app"
	}
	return safe + ".json"
}

func writeFileSync(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
