package idclient

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Readier is the one call WaitReady makes: *Client's Ready.
type Readier interface {
	Ready(ctx context.Context) error
}

// readyRecheck is how often WaitReady asks /health/ready again. It decides
// nothing: the wait ends on a ready answer, on the unit no longer being
// active, or on the caller's ctx (timer-audit row K25).
const readyRecheck = 500 * time.Millisecond

// errNotActive is WaitReady's answer when the unit stopped before it was
// ready.
var errNotActive = errors.New("the identity service's unit is no longer active")

// WaitReady returns once r answers ready. It is called only after the caller
// started the identity service's unit: between answers it asks active
// whether the unit is still running, and returns an error as soon as it is
// not, or when active cannot tell, or when ctx ends. The client logs each
// not-ready answer inside the wait at DEBUG only.
func WaitReady(ctx context.Context, r Readier, active func(ctx context.Context) (bool, error)) error {
	ctx = context.WithValue(ctx, waitKey{}, true)
	t := time.NewTicker(readyRecheck)
	defer t.Stop()
	for {
		last := r.Ready(ctx)
		if last == nil {
			return nil
		}
		up, err := active(ctx)
		switch {
		case err != nil:
			return fmt.Errorf("reading whether the identity service's unit is active: %w", err)
		case !up:
			return fmt.Errorf("%w (last answer: %w)", errNotActive, last)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the identity service was not ready when the wait ended (last answer: %w): %w", last, ctx.Err())
		case <-t.C:
		}
	}
}

// waitKey marks a ctx as inside WaitReady, so the client's record for a
// not-ready answer is DEBUG: the wait asks until the answer is ready.
type waitKey struct{}

func inWait(ctx context.Context) bool {
	in, _ := ctx.Value(waitKey{}).(bool)
	return in
}
