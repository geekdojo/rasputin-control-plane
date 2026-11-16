package identitystate

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// exitJobError is the failed job's sentence for an out-of-memory exit.
const exitJobError = "The sign-in service ran out of memory and stopped. It restarts by itself."

// exitCreatedBy is the CreatedBy of every exit job.
const exitCreatedBy = "rasputin-api"

// exitSpec is an exit job's spec: the record it came from.
type exitSpec struct {
	InvocationID string `json:"invocationId"`
	Outcome      string `json:"outcome"`
	ExitCode     string `json:"exitCode,omitempty"`
	ExitStatus   string `json:"exitStatus,omitempty"`
}

// exitJobID is the job ID of the exit that ended invocation id.
func exitJobID(id string) string { return "identity-exit-" + id }

// consumeExits reads the exit records and returns the one `last` names, or
// nil, and whether it could read them. Each out-of-memory record becomes one
// identity.service_exit job, recorded with ON CONFLICT DO NOTHING, so a
// record read twice is never a second job. A record is removed once its job
// is recorded, or at once when it is not an out-of-memory exit, except the
// one `last` names, which #973's hook owns. A record the ledger refused, or
// that does not parse, is kept and read again on the next reading
// (m.exitsPending). It runs under exitsMu.
func (m *Monitor) consumeExits(ctx context.Context) (last *ExitRecord, ok bool) {
	d, err := m.d.Exits(ctx)
	m.mu.Lock()
	warn := err != nil && !m.exitsUnread
	m.exitsUnread = err != nil
	m.mu.Unlock()
	if err != nil {
		if warn {
			m.log.LogAttrs(ctx, slog.LevelWarn, "identity exit records unreadable; no out-of-memory or failed reading from them",
				slog.String("err", err.Error()))
		}
		m.exitsPending = true
		return nil, false
	}
	pending := false
	for _, b := range d.Bad {
		pending = true
		if !m.badWarned[b.Path] {
			m.log.LogAttrs(ctx, slog.LevelWarn, "identity exit record unreadable",
				slog.String("path", b.Path), slog.String("err", b.Err.Error()))
		}
	}
	m.badWarned = make(map[string]bool, len(d.Bad))
	for _, b := range d.Bad {
		m.badWarned[b.Path] = true
	}
	for _, rec := range d.Records {
		if ctx.Err() != nil {
			return nil, false
		}
		if rec.OutOfMemory() && !m.recordExit(ctx, rec) {
			pending = true
			continue
		}
		if d.Last != nil && rec.ID == d.Last.ID {
			continue
		}
		if err := m.d.RemoveExit(ctx, rec.ID); err != nil {
			pending = true
			m.log.LogAttrs(ctx, slog.LevelWarn, "identity exit record not removed",
				slog.String("invocation_id", rec.ID), slog.String("err", err.Error()))
		}
	}
	m.exitsPending = pending
	return d.Last, true
}

// recordExit records rec's out-of-memory job and reports whether the ledger
// holds it now.
func (m *Monitor) recordExit(ctx context.Context, rec ExitRecord) bool {
	id := exitJobID(rec.ID)
	spec, err := json.Marshal(exitSpec{InvocationID: rec.ID, Outcome: rec.Outcome, ExitCode: rec.ExitCode, ExitStatus: rec.ExitStatus})
	if err != nil {
		// A struct of strings always marshals; this is unreachable, and
		// recording the job without its spec would lose the record's facts.
		m.log.LogAttrs(ctx, slog.LevelError, "identity service exit not recorded",
			slog.String("job_id", id), slog.String("ledger_err", err.Error()))
		return false
	}
	at := rec.Written.UTC()
	j := &jobs.Job{
		ID: id, Kind: ExitKind, Spec: spec, Status: jobs.StatusFailed, CreatedBy: exitCreatedBy,
		CreatedAt: at, StartedAt: &at, FinishedAt: &at, Error: exitJobError,
	}
	inserted, err := m.d.Ledger.RecordFinishedJob(ctx, j)
	if err != nil {
		m.log.LogAttrs(ctx, slog.LevelError, "identity service exit not recorded",
			slog.String("event", ExitKind), slog.String("invocation_id", rec.ID), slog.String("job_id", id),
			slog.String("ledger_err", err.Error()))
		return false
	}
	if inserted {
		m.log.LogAttrs(ctx, slog.LevelWarn, "identity service ran out of memory",
			slog.String("event", ExitKind), slog.String("invocation_id", rec.ID), slog.String("outcome", rec.Outcome),
			slog.String("exit_code", rec.ExitCode), slog.String("exit_status", rec.ExitStatus), slog.String("job_id", id))
	}
	return true
}
