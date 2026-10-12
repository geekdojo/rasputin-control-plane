// Package deadlinetest gives a test a step deadline that fires on a fact the
// test observes, not on a wall clock. Tests import it; nothing in a shipped
// binary does.
//
// A test that wants a step to fail at a particular call cannot get there with
// context.WithTimeout: a deadline set before the step starts covers all the
// work ahead of that call, and on a loaded runner that work can spend it. The
// step then fails somewhere earlier, for a different reason, and the test
// fails on the wrong message. With a Manual deadline the test fires it once
// the call it is aimed at is in flight (typically from the fake agent's
// handler), so every run reaches the same call before the deadline lands.
//
// It is the one copy of what the updater and apps tests each needed.
package deadlinetest

import (
	"context"
	"sync"
)

// Manual is a context whose deadline fires exactly when Fire is called. Err
// then reports context.DeadlineExceeded, the same value a real step deadline
// produces, so the code under test takes its timeout branch; child contexts
// derived from it inherit that.
type Manual struct {
	context.Context
	done chan struct{}
	once sync.Once
}

// New returns a Manual deadline over context.Background that has not fired.
func New() *Manual {
	return &Manual{Context: context.Background(), done: make(chan struct{})}
}

// Done is closed when Fire is called.
func (d *Manual) Done() <-chan struct{} { return d.done }

// Err is nil until Fire is called and context.DeadlineExceeded after.
func (d *Manual) Err() error {
	select {
	case <-d.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

// Fire makes the deadline pass. Calling it again does nothing.
func (d *Manual) Fire() { d.once.Do(func() { close(d.done) }) }
