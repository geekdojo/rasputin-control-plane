package storeaudit

import (
	"context"
	"fmt"
)

// Reopener tells the store to reopen its audit file. It returns once the
// request is delivered; the rotator then waits for the new file itself.
type Reopener interface {
	Reopen(ctx context.Context) error
}

// ReopenFunc adapts a function to Reopener. The functional test passes the
// harness's Store.Reload through it.
type ReopenFunc func(ctx context.Context) error

// Reopen calls f.
func (f ReopenFunc) Reopen(ctx context.Context) error { return f(ctx) }

// RunFunc runs a command and returns its combined output (execrun's shape).
type RunFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// SystemdReopener sends SIGHUP to the main process of unit, which makes the
// store close and reopen its audit file (and re-read its config). The unit
// has no ExecReload=, so `systemctl reload` is not the route; a restart would
// drop in-flight requests and spend the unit's start limit.
func SystemdReopener(run RunFunc, unit string) Reopener {
	return ReopenFunc(func(ctx context.Context) error {
		if _, err := run(ctx, "systemctl", "kill", "--kill-whom=main", "--signal=SIGHUP", unit); err != nil {
			return fmt.Errorf("storeaudit: signal %s: %w", unit, err)
		}
		return nil
	})
}
