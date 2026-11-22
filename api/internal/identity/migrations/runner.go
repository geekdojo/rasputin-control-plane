package migrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
)

// RecordAttr is the realm attribute holding the ID of the last migration
// applied. Absent is 0: none.
const RecordAttr = "rasputin.migrations"

// Deps is everything a Runner needs. New refuses an incomplete one.
type Deps struct {
	Admin Admin
	// Realm is the realm migrated: rasputin.
	Realm string
	// Lock is the realm lock, shared with converge, so the two never write
	// the realm at the same time.
	Lock *sync.Mutex
	// All is the migrations to apply, IDs 1..n in order (migrations.All).
	All []Migration
	Log *slog.Logger
}

// Runner applies pending migrations in order and records each.
type Runner struct {
	d   Deps
	log *slog.Logger
}

// New checks d and returns a Runner. It refuses IDs that are not 1..n in
// order, so a gap, a duplicate or a zero never ships. It does no I/O.
func New(d Deps) (*Runner, error) {
	if d.Admin == nil || d.Lock == nil || d.Log == nil {
		return nil, errors.New("migrations: a collaborator is nil")
	}
	if d.Realm == "" {
		return nil, errors.New("migrations: Deps.Realm is empty")
	}
	for i, m := range d.All {
		if m.ID != i+1 {
			return nil, fmt.Errorf("migrations: entry %d has ID %d, want %d: IDs are 1..n in order", i, m.ID, i+1)
		}
		if m.Apply == nil || m.Name == "" {
			return nil, fmt.Errorf("migrations: migration %d has no name or no Apply", m.ID)
		}
	}
	return &Runner{d: d, log: d.Log.With("component", "identity")}, nil
}

// realmAttrs is the realm read for its attributes, each value kept exactly as
// read so a write puts back what it found.
type realmAttrs struct {
	Attributes map[string]json.RawMessage `json:"attributes"`
}

func (r *Runner) realmPath() string { return "/admin/realms/" + url.PathEscape(r.d.Realm) }

// read reads the realm's attributes.
func (r *Runner) read(ctx context.Context) (map[string]json.RawMessage, error) {
	var rep realmAttrs
	if _, err := r.d.Admin.Admin(ctx, http.MethodGet, r.realmPath(), nil, &rep); err != nil {
		return nil, err
	}
	if rep.Attributes == nil {
		rep.Attributes = map[string]json.RawMessage{}
	}
	return rep.Attributes, nil
}

// applied is the recorded ID in attrs: 0 when absent. A value that is not a
// plain decimal, or one above n, is an error: a realm newer than this
// release, or a record nobody should trust.
func (r *Runner) applied(attrs map[string]json.RawMessage) (int, error) {
	raw, ok := attrs[RecordAttr]
	if !ok {
		return 0, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, fmt.Errorf("migrations: the realm's %s is not a string", RecordAttr)
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || strconv.Itoa(n) != s {
		return 0, fmt.Errorf("migrations: the realm's %s %q is not a migration ID", RecordAttr, s)
	}
	if n > len(r.d.All) {
		return 0, fmt.Errorf("migrations: the realm's %s is %d, newer than this release's %d", RecordAttr, n, len(r.d.All))
	}
	return n, nil
}

// Lagging reads the realm's record: applied is the last migration applied,
// want the number this release ships. A malformed record, or one above want,
// is an error.
func (r *Runner) Lagging(ctx context.Context) (applied, want int, err error) {
	attrs, err := r.read(ctx)
	if err != nil {
		return 0, 0, err
	}
	applied, err = r.applied(attrs)
	if err != nil {
		return 0, 0, err
	}
	return applied, len(r.d.All), nil
}

// Run holds the realm lock and applies each pending migration in order.
// After each it writes rasputin.migrations=<id>: the whole attribute map as
// read then, plus that key, so the record moves one step at a time and every
// other attribute stays. It stops at the first failure, with the record at
// the last success. It returns the IDs it applied.
func (r *Runner) Run(ctx context.Context) ([]int, error) {
	return r.RunJob(ctx, "")
}

// RunJob is Run for job jobID, which its log records name.
func (r *Runner) RunJob(ctx context.Context, jobID string) ([]int, error) {
	r.d.Lock.Lock()
	defer r.d.Lock.Unlock()
	attrs, err := r.read(ctx)
	if err != nil {
		r.logErr(ctx, jobID, "The realm could not be read for its migrations.", err)
		return nil, errRead
	}
	from, err := r.applied(attrs)
	if err != nil {
		r.logErr(ctx, jobID, "The realm's migration record is unusable.", err)
		return nil, errRecord
	}
	var done []int
	for _, m := range r.d.All[from:] {
		if err := m.Apply(ctx, r.d.Admin, r.d.Realm); err != nil {
			r.logErr(ctx, jobID, "A realm migration failed.", err, slog.Int("migration_id", m.ID), slog.String("migration", m.Name))
			return done, errApply
		}
		if err := r.record(ctx, m.ID); err != nil {
			r.logErr(ctx, jobID, "A realm migration was applied but not recorded.", err, slog.Int("migration_id", m.ID), slog.String("migration", m.Name))
			return done, errRecordWrite
		}
		done = append(done, m.ID)
		r.log.LogAttrs(ctx, slog.LevelInfo, "A realm migration was applied.",
			slog.String("event", "identity.migrate.applied"), slog.String("job_id", jobID),
			slog.Int("migration_id", m.ID), slog.String("migration", m.Name))
	}
	return done, nil
}

// record writes rasputin.migrations=id into the attribute map as read now.
func (r *Runner) record(ctx context.Context, id int) error {
	attrs, err := r.read(ctx)
	if err != nil {
		return err
	}
	v, _ := json.Marshal(strconv.Itoa(id))
	attrs[RecordAttr] = v
	_, err = r.d.Admin.Admin(ctx, http.MethodPut, r.realmPath(), map[string]any{"attributes": attrs}, nil)
	return err
}

// logErr writes one ERROR for a failed run, with the Admin API's detail.
func (r *Runner) logErr(ctx context.Context, jobID, msg string, err error, extra ...slog.Attr) {
	attrs := append([]slog.Attr{slog.String("event", "identity.migrate.failed"), slog.String("job_id", jobID)}, extra...)
	var ie *idclient.Error
	if errors.As(err, &ie) {
		attrs = append(attrs, ie.LogAttrs()...)
	} else {
		attrs = append(attrs, slog.String("err", err.Error()))
	}
	r.log.LogAttrs(ctx, slog.LevelError, msg, attrs...)
}

// stepError is a failure sentence a person reads: the runner stores a failed
// step's err.Error() as the job's error. The Admin API's detail goes to the
// log under the job's id.
type stepError string

func (e stepError) Error() string { return string(e) }

const (
	errRead        = stepError("The sign-in realm could not be read, so its migrations were not applied.")
	errRecord      = stepError("The sign-in realm's migration record is malformed or newer than this release, so no migration was applied.")
	errApply       = stepError("A sign-in realm migration failed; the realm stays at the last migration that succeeded.")
	errRecordWrite = stepError("A sign-in realm migration was applied but could not be recorded; it is applied again on the next run.")
)
