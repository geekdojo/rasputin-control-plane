package storemigrate

import (
	"context"
	"errors"
	"log/slog"
	"strings"
)

// RecoverDeps are Recover's collaborators. All are required.
type RecoverDeps struct {
	Files Files
	// Start restarts the store unit (reset-failed, then restart) and runs the
	// after-restart outcome read.
	Start func(ctx context.Context) error
	Log   *slog.Logger
}

// Recover runs at api start, before the secrets service, the app relay and
// the job runner start, and finishes what an api that died mid-migration
// left behind:
//
//   - aside.tar without a commit: the store may be serving the fresh tree,
//     so it is restarted and its root step puts the old tree back;
//   - a request without aside.tar: the store never acted on it, so it is
//     removed and nothing can act on it later in this boot (F-1132-02);
//   - an attempt alone: the root step's leftover, removed.
//
// A commit, or nothing, is left alone: the next store start finishes a
// commit. A state it cannot read is logged and left alone (ERR-CLOSED): the
// root step converges from it on the next store start.
func Recover(ctx context.Context, d RecoverDeps) error {
	if d.Files == nil || d.Start == nil || d.Log == nil {
		return errors.New("storemigrate: a recovery collaborator is nil")
	}
	present := map[string]bool{}
	for _, name := range []string{NameRequest, NameAttempt, NameAside, NameCommit} {
		p, err := d.Files.Present(name)
		if err != nil {
			d.Log.ErrorContext(ctx, "secret store migration state unreadable at start; left for the store's next start",
				"component", "secretstore", "event", "secretstore.migrate_recover_failed", "job_id", recordedJobID(d.Files),
				"file", name, "err", err.Error())
			return nil
		}
		present[name] = p
	}
	switch {
	case present[NameAside] && !present[NameCommit]:
		jobID := recordedJobID(d.Files)
		err := d.Start(ctx)
		attrs := []any{"component", "secretstore", "event", "secretstore.migrate_recovered", "job_id", jobID,
			"action", "restarted the store to put its old data back"}
		if err != nil {
			attrs = append(attrs, "err", err.Error())
		}
		d.Log.WarnContext(ctx, "secret store migration found unfinished at start", attrs...)
	case present[NameRequest] && !present[NameAside]:
		removeAtStart(ctx, d, NameRequest)
	case present[NameAttempt] && !present[NameAside]:
		removeAtStart(ctx, d, NameAttempt)
	}
	return nil
}

// removeAtStart removes one leftover file and logs it.
func removeAtStart(ctx context.Context, d RecoverDeps, name string) {
	jobID := recordedJobID(d.Files)
	attrs := []any{"component", "secretstore", "event", "secretstore.migrate_recovered", "job_id", jobID,
		"action", "removed " + name}
	if err := d.Files.Remove(name); err != nil {
		attrs = append(attrs, "err", err.Error())
	}
	d.Log.WarnContext(ctx, "secret store migration found unfinished at start", attrs...)
}

// recordedJobID is the job_id= line of attempt, else of request, else "".
func recordedJobID(f Files) string {
	for _, name := range []string{NameAttempt, NameRequest} {
		b, err := f.Read(name)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "job_id="); ok && v != "" {
				return v
			}
		}
	}
	return ""
}
