package move

import (
	"context"
	"log/slog"
	"strconv"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/converge"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// script is the trigger's facts, set step by step.
type script struct {
	ready     error
	pending   bool
	pendErr   error
	desired   string
	stored    string
	convErr   error
	newest    string
	submitted int
}

func (s *script) Ready(context.Context) error           { return s.ready }
func (s *script) Pending(context.Context) (bool, error) { return s.pending, s.pendErr }
func (s *script) ListJobsByKind(context.Context, string, int) ([]*jobs.Job, error) {
	if s.newest == "" {
		return nil, nil
	}
	return []*jobs.Job{{ID: s.newest}}, nil
}

type conv struct{ s *script }

func (c conv) Pending(context.Context) (string, string, error) {
	return c.s.desired, c.s.stored, c.s.convErr
}

// TC-1004-12: the trigger is fact-driven. Due only while the service is
// ready, Pending is true and converge's desired equals stored. A Pending
// or converger read error is not due, with one WARN per outage. A job that
// failed in a readiness episode is not submitted again in it, and is
// submitted once after a not-ready to ready transition. Once a move is
// recorded it is never due.
func TestCond_TC1004_12(t *testing.T) {
	s := &script{pending: true, desired: "h", stored: "h"}
	log, rec := logkittest.New()
	tr, err := converge.NewTrigger(converge.TriggerDeps{Kind: Kind, Ready: s, Ledger: s, Cond: Cond(s, conv{s}),
		CondErrLevel: slog.LevelWarn, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	due := func() bool {
		d, _ := tr.Due(t.Context())
		if d {
			// The scheduler submits: a new newest job.
			s.submitted++
			s.newest = "j" + strconv.Itoa(s.submitted)
		}
		return d
	}
	if !due() {
		t.Fatal("ready, pending, converged: not due")
	}
	if due() {
		t.Error("due again in the same episode after a (failed) job")
	}
	s.ready = errDown
	if due() {
		t.Error("due while not ready")
	}
	s.ready = nil
	if !due() {
		t.Error("not due after a not-ready to ready transition")
	}
	if due() {
		t.Error("due twice in the second episode")
	}
	// Converge not yet applied: not due in a new episode.
	s.ready, s.desired = errDown, "new"
	due()
	s.ready = nil
	if due() {
		t.Error("due with desired != stored")
	}
	s.desired = "h"
	// Read errors: not due, one WARN per outage.
	before := len(rec.Matching(slog.LevelWarn, "condition could not be read"))
	s.pendErr = errDown
	s.ready = errDown
	due()
	s.ready = nil
	for range 3 {
		if due() {
			t.Error("due with Pending unreadable")
		}
	}
	s.pendErr, s.convErr = nil, errDown
	if due() {
		t.Error("due with the converger unreadable")
	}
	if n := len(rec.Matching(slog.LevelWarn, "condition could not be read")) - before; n != 1 {
		t.Errorf("%d WARN records over one outage, want 1", n)
	}
	s.convErr = nil
	// Recorded: never due, in any episode.
	s.pending = false
	for range 2 {
		s.ready = errDown
		due()
		s.ready = nil
		if due() {
			t.Error("due once the move is recorded")
		}
	}
}
