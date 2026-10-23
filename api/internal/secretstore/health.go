package secretstore

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// InactiveReason names why the store is not active, from a Health call's
// answer, or returns "" when it is initialised and unsealed. The reasons are
// sealed, uninitialised, unreachable, disabled and error (any other failure).
//
// It is the one reading of a Health answer: the audit rotator (storeaudit)
// and the readiness monitor (storestate) both classify through it
// (geekdojo/geekdojo-brain#760, F-760-05).
func InactiveReason(h Health, err error) string {
	switch {
	case errors.Is(err, ErrSealed):
		return "sealed"
	case errors.Is(err, ErrUninitialised):
		return "uninitialised"
	case errors.Is(err, ErrUnreachable):
		return "unreachable"
	case errors.Is(err, ErrDisabled):
		return "disabled"
	case err != nil:
		return "error"
	case !h.Initialized:
		return "uninitialised"
	case h.Sealed:
		return "sealed"
	}
	return ""
}

// HealthReader is the one store call WaitReady makes.
type HealthReader interface {
	Health(ctx context.Context) (Health, error)
}

// readyRecheck is how often WaitReady re-asks sys/health. It decides
// nothing: the wait ends on a 200, or on its bound (timer-audit row K24).
const readyRecheck = 100 * time.Millisecond

// WaitReady returns once sys/health answers 200 initialised and unsealed, or
// an error naming the last answer when bound passes first. It is the one wait
// for a store a caller has just started: the seal-key rotation's after each
// restart (geekdojo/geekdojo-brain#830) and the backup's after its cold copy
// (#765). systemd's READY=1 comes before unseal, so neither may take the
// unit's start as the store being ready.
func WaitReady(ctx context.Context, h HealthReader, bound time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	t := time.NewTicker(readyRecheck)
	defer t.Stop()
	for {
		hl, err := h.Health(ctx)
		kind := InactiveReason(hl, err)
		if kind == "" {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the secret store did not answer 200 within %s (last: %s): %w", bound, kind, ctx.Err())
		case <-t.C:
		}
	}
}
