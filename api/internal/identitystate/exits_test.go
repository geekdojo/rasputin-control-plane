package identitystate

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// failOnce is a real ledger whose next RecordFinishedJob fails once.
type failOnce struct {
	*jobs.Store
	fail bool
}

func (f *failOnce) RecordFinishedJob(ctx context.Context, j *jobs.Job) (bool, error) {
	if f.fail {
		f.fail = false
		return false, errors.New("database is locked")
	}
	return f.Store.RecordFinishedJob(ctx, j)
}

// TC-979-11: one identity.service_exit job per out-of-memory invocation, on a
// real job store. The first reading inserts one job per out-of-memory record
// and removes every consumed record except the one `last` names; the second
// inserts none; a ledger failure keeps the record, logs ERROR, and the next
// reading with the tuple unchanged inserts it.
func TestExits_OneJobPerOutOfMemoryInvocation(t *testing.T) {
	store, err := jobs.OpenStore(t.Context(), filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ledger := &failOnce{Store: store}

	x := newFixture(t)
	log, rec := logkittest.New()
	x.rec = rec
	m, err := New(x.deps(log, ledger))
	if err != nil {
		t.Fatal(err)
	}
	x.m = m

	killedAt := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	exitedAt := time.Date(2026, 11, 15, 10, 5, 0, 0, time.UTC)
	x.record(t, id(1), "oom-kill", "killed", "KILL", killedAt)
	x.record(t, id(2), "exit-code", "exited", "3", exitedAt)
	x.record(t, id(3), "success", "exited", "143", exitedAt)
	x.last(t, id(2))
	x.w.set(func(w *world) { w.units.KC = kcAutoRestart })

	if got := x.state(t); got != OutOfMemory {
		t.Fatalf("state = %s, want out-of-memory", got)
	}
	got, err := store.ListAllJobsByKind(t.Context(), ExitKind)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d jobs, want 2", len(got))
	}
	byID := map[string]*jobs.Job{}
	for _, j := range got {
		byID[j.ID] = j
	}
	for inv, at := range map[string]time.Time{id(1): killedAt, id(2): exitedAt} {
		j := byID["identity-exit-"+inv]
		if j == nil {
			t.Fatalf("no job for %s", inv)
		}
		if j.Status != jobs.StatusFailed || j.CreatedBy != "rasputin-api" || j.Error != exitJobError ||
			!j.CreatedAt.Equal(at) || j.FinishedAt == nil || !j.FinishedAt.Equal(at) {
			t.Errorf("job %s = %+v", j.ID, j)
		}
	}
	if names := x.names(t); !slices.Equal(names, []string{id(2), lastName}) {
		t.Fatalf("directory after the first reading = %v, want the record last names, and last", names)
	}
	warns := rec.Matching(slog.LevelWarn, "identity service ran out of memory")
	if len(warns) != 2 {
		t.Fatalf("%d WARNs, want 2", len(warns))
	}
	for _, w := range warns {
		for _, k := range []string{"event", "invocation_id", "outcome", "exit_code", "exit_status", "job_id"} {
			if _, ok := logkittest.Attr(w, k); !ok {
				t.Errorf("WARN has no %s", k)
			}
		}
		if e, _ := logkittest.Attr(w, "event"); e != ExitKind {
			t.Errorf("event = %q", e)
		}
	}

	x.state(t)
	if got, _ := store.ListAllJobsByKind(t.Context(), ExitKind); len(got) != 2 {
		t.Fatalf("%d jobs after the second reading, want 2", len(got))
	}

	// A ledger that refuses once, with the tuple unchanged between readings.
	// id(0) sorts first, so the refusal lands on its job.
	x.record(t, id(0), "exit-code", "exited", "3", exitedAt)
	x.w.set(func(w *world) { w.units.KC = kcFailed })
	ledger.fail = true
	x.state(t)
	if errs := rec.Matching(slog.LevelError, "identity service exit not recorded"); len(errs) != 1 {
		t.Fatalf("%d ERRORs, want 1", len(errs))
	} else if v, _ := logkittest.Attr(errs[0], "ledger_err"); v == "" {
		t.Error("ERROR has no ledger_err")
	}
	if !slices.Contains(x.names(t), id(0)) {
		t.Fatal("the refused record was not kept")
	}
	if j, _ := store.GetJob(t.Context(), exitJobID(id(0))); j != nil {
		t.Fatal("the refused record's job exists")
	}
	x.state(t)
	if j, _ := store.GetJob(t.Context(), exitJobID(id(0))); j == nil {
		t.Fatal("the next reading did not insert the kept record's job")
	}
	if slices.Contains(x.names(t), id(0)) {
		t.Fatal("the kept record was not removed once its job was recorded")
	}
	if b := x.names(t); !slices.Contains(b, lastName) || !slices.Contains(b, id(2)) {
		t.Fatalf("last or its record went missing: %v", b)
	}
}
