package storemigrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/sysunit"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// Kind is the migration's job kind.
const Kind = "secretstore.migrate"

// KeyAttemptBootID is the settings key bounding the migration to one attempt
// per boot (F-1132-07): written before anything else is done, cleared at the
// commit.
const KeyAttemptBootID = "secretstore.migrate_attempt_boot_id"

// The root step's outcome words the migration acts on (os.store_migrate).
const (
	outcomeMoved    = "moved"
	outcomeRestored = "restored"
)

// The provision record's outcomes that may trigger a migration; failed never
// does (F-1132-09).
var triggerOutcomes = map[string]bool{"applied": true, "unchanged": true}

// unitActive is systemd's ActiveState of a running unit.
const unitActive = "active"

// The steps' bounds. Each is far outside the step's normal time and only
// marks a stuck step failed (ARCH-FACTS, clarified 2026-11-14); no state
// changes on one. validate waits on the capture gate, which a backup holds
// for its whole capture.
const (
	validateTimeout  = 4 * time.Hour
	readTimeout      = 15 * time.Minute
	swapTimeout      = 15 * time.Minute
	writeBackTimeout = 15 * time.Minute
	commitTimeout    = 2 * time.Minute
	// abortTimeout bounds the put-back, which runs on a context detached
	// from the job's, so a cancelled job still disarms (F-1132-02).
	abortTimeout = 15 * time.Minute
)

// Inventory lists every entry an app may hold (*apps.Store).
type Inventory interface {
	SecretInventory(ctx context.Context) ([]apps.AppSecretInventory, error)
}

// Repo reads and writes entries over the raw store session, never the Hold
// (secrets.KVRepository).
type Repo interface {
	Get(ctx context.Context, r secrets.Ref) (secrets.Secret, error)
	Write(ctx context.Context, r secrets.Ref, value secret.Value, cas int) (int, error)
}

// Control is the store unit and its readiness (the composition root's
// storeBackupControl, quiescing for the migration).
type Control interface {
	// Readiness is "" when the store is ready, else the clause after "The
	// secret store" that says why not.
	Readiness(ctx context.Context) (string, error)
	SealKeyID() (string, error)
	Quiesce(jobID string) (release func())
	Stop(ctx context.Context) error
	// Start starts the store, and runs the after-restart outcome read.
	Start(ctx context.Context) error
	WaitReady(ctx context.Context) error
}

// Lock is the capture gate (storage.CaptureLock; sealrotate.Gate), which
// serialises the migration against a backup, a seal-key rotation and an OS
// update's pre-update copy.
type Lock interface {
	Acquire(ctx context.Context, jobID string) error
	Release(jobID string)
}

// Marker is the empty-store marker (*storemarker.Marker).
type Marker interface {
	RebaseChecked(ctx context.Context) (prev string, err error)
	RestoreSetUp(ctx context.Context, prev string) error
}

// Settings is the settings table (*setup.Store).
type Settings interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// Records reads the OS's records now, from their files.
type Records interface {
	Provision() (osoutcome.Record, error)
	Migrate() (osoutcome.Record, error)
}

// Files is the state directory (*StateDir).
type Files interface {
	Present(name string) (bool, error)
	Read(name string) ([]byte, error)
	Write(name string, data []byte) error
	Remove(name string) error
}

// Deps are the migrator's collaborators. New refuses a nil one.
type Deps struct {
	Inventory Inventory
	Repo      Repo
	Control   Control
	Lock      Lock
	Marker    Marker
	Settings  Settings
	Records   Records
	// StoreUnit reads the store unit's systemd state (sysunit.Show).
	StoreUnit func(ctx context.Context) (sysunit.Unit, error)
	Files     Files
	BootID    func() (string, error)
	Hold      *Hold
	// AfterTerminal runs once the job ends, however it ends: the reference
	// check, which then runs on the store that is live (F-1132-05).
	AfterTerminal func(ctx context.Context)
	Log           *slog.Logger
}

// Migrator is the secretstore.migrate job.
type Migrator struct {
	d Deps

	mu   sync.Mutex
	runs map[string]*run
}

// New checks d and returns a Migrator. It does no I/O.
func New(d Deps) (*Migrator, error) {
	switch {
	case d.Inventory == nil, d.Repo == nil, d.Control == nil, d.Lock == nil, d.Marker == nil, d.Settings == nil,
		d.Records == nil, d.StoreUnit == nil, d.Files == nil, d.BootID == nil, d.Hold == nil, d.AfterTerminal == nil,
		d.Log == nil:
		return nil, errors.New("storemigrate: a collaborator is nil")
	}
	return &Migrator{d: d, runs: map[string]*run{}}, nil
}

// entry is one value read from the old tree.
type entry struct {
	ref   secrets.Ref
	value secret.Value
}

// run is what one job has done so far, for its steps and its abort.
type run struct {
	boot string
	// gate, hold and release say what the job holds.
	gate    bool
	hold    bool
	release func()
	// rebased and prev are the marker move RebaseChecked made.
	rebased bool
	prev    string
	// armed is set before the request is written; stopped before the store
	// is stopped.
	armed   bool
	stopped bool
	entries []entry
	// The first failure, for migrate_aborted.
	failStep string
	failRef  string
	failErr  error
}

// Workflow is the job. It is a System kind: only the trigger starts it.
func (m *Migrator) Workflow() jobs.Workflow {
	return jobs.Workflow{
		Kind:   Kind,
		System: true,
		Steps: []jobs.WorkflowStep{
			{Name: "validate", Do: m.validate, Timeout: validateTimeout},
			{Name: "read", Do: m.read, Timeout: readTimeout},
			{Name: "swap", Do: m.swap, Timeout: swapTimeout},
			{Name: "write_back", Do: m.writeBack, Timeout: writeBackTimeout},
			{Name: "commit", Do: m.commit, Timeout: commitTimeout},
		},
		OnTerminal: m.onTerminal,
	}
}

// sentence is a job error a person reads (ERR-MESSAGE).
type sentence string

func (s sentence) Error() string { return string(s) }

// The job's errors. Each names what stopped it and what the store holds.
const (
	errNotStarted      = "The secret store upgrade did not start: "
	nothingChanged     = " Nothing was changed."
	errReadFailed      = sentence("The secret store upgrade stopped before changing anything: the secrets to copy could not all be read. Nothing was changed.")
	errSwapFailed      = sentence("The secret store upgrade did not complete: the store did not restart on its new layout. Its existing data is kept and put back on the store's next start.")
	errSwapNotArmed    = sentence("The secret store upgrade stopped before changing anything: it could not prepare the store's restart. Nothing was changed.")
	errWriteBackFailed = sentence("The secret store upgrade did not complete: the copied secrets could not all be written back and checked. The store's existing data is kept and put back.")
	errCommitFailed    = sentence("The secret store upgrade did not complete: it could not record that the copy was finished. The store's existing data is kept and put back.")
	errNoRun           = sentence("The secret store upgrade lost track of its own progress, so it stopped. The store's existing data is kept.")
)

func notStarted(why string) sentence { return sentence(errNotStarted + why + nothingChanged) }

// begin records a new run for jobID.
func (m *Migrator) begin(jobID string) *run {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := &run{}
	m.runs[jobID] = r
	return r
}

// get returns jobID's run.
func (m *Migrator) get(jobID string) (*run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[jobID]
	if !ok {
		return nil, errNoRun
	}
	return r, nil
}

// take removes jobID's run and returns it, or nil.
func (m *Migrator) take(jobID string) *run {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.runs[jobID]
	delete(m.runs, jobID)
	return r
}

// fail records the first failure and returns the job's sentence.
func (r *run) fail(step string, ref string, cause error, s sentence) error {
	if r.failErr == nil {
		r.failStep, r.failRef, r.failErr = step, ref, cause
	}
	return s
}

// stepCtx is the step's context, carrying the job id for the control's
// records.
func stepCtx(sc *jobs.StepCtx) context.Context { return jobs.ContextWithJobID(sc.Ctx, sc.JobID) }

// validate refuses before anything is held, read or written unless this
// boot's provision record asks for the migration, no state is left from an
// earlier one, the seal key is clean and the store is ready. It then takes
// the capture gate, and records the attempt for this boot before anything
// else (F-1132-07).
func (m *Migrator) validate(sc *jobs.StepCtx) (json.RawMessage, error) {
	ctx := stepCtx(sc)
	r := m.begin(sc.JobID)
	boot, err := m.d.BootID()
	if err != nil {
		return nil, r.fail("validate", "", err, notStarted("this boot's id could not be read."))
	}
	rec, err := m.d.Records.Provision()
	if err != nil {
		return nil, r.fail("validate", "", err, notStarted("the store's provisioning record could not be read."))
	}
	if rec.BootID != boot || !triggerOutcomes[rec.Outcome] || rec.Author != osoutcome.AuthorAbsent {
		return nil, r.fail("validate", "", fmt.Errorf("provision record outcome=%s author=%s boot_id=%s", rec.Outcome, rec.Author, rec.BootID),
			notStarted("the store's provisioning record from this boot does not show a store that needs it."))
	}
	for _, name := range []string{NameRequest, NameAttempt, NameAside, NameAsidePartial, NameCommit} {
		present, err := m.d.Files.Present(name)
		if err != nil {
			return nil, r.fail("validate", "", err, notStarted("its state directory could not be read."))
		}
		if present {
			return nil, r.fail("validate", "", fmt.Errorf("%s is present", name), notStarted("files from an earlier upgrade are still in place."))
		}
	}
	if _, err := m.d.Control.SealKeyID(); err != nil {
		return nil, r.fail("validate", "", err, notStarted("the store's seal key is not in a settled state."))
	}
	notReady, err := m.d.Control.Readiness(ctx)
	if err != nil {
		return nil, r.fail("validate", "", err, notStarted("the store's readiness could not be read."))
	}
	if notReady != "" {
		return nil, r.fail("validate", "", errors.New(notReady), notStarted("the secret store "+notReady+"."))
	}
	if err := m.d.Lock.Acquire(ctx, sc.JobID); err != nil {
		return nil, r.fail("validate", "", err, notStarted("the secret store could not be reserved for it."))
	}
	r.gate = true
	if err := m.d.Settings.Set(ctx, KeyAttemptBootID, boot); err != nil {
		return nil, r.fail("validate", "", err, notStarted("its attempt could not be recorded."))
	}
	r.boot = boot
	return nil, nil
}

// read holds the secrets service off the store, then reads every entry the
// inventory names. An entry that is not there is skipped and counted; any
// other error stops the job before anything is changed.
func (m *Migrator) read(sc *jobs.StepCtx) (json.RawMessage, error) {
	ctx := stepCtx(sc)
	r, err := m.get(sc.JobID)
	if err != nil {
		return nil, err
	}
	m.d.Hold.On()
	r.hold = true
	inv, err := m.d.Inventory.SecretInventory(ctx)
	if err != nil {
		return nil, r.fail("read", "", err, errReadFailed)
	}
	candidates, skipped := 0, 0
	for _, app := range inv {
		for _, tree := range []struct {
			names []string
			ref   func(appID, name string) (secrets.Ref, error)
		}{{app.Names, secrets.AppSecret}, {app.RuntimeNames, secrets.AppRuntimeSecret}} {
			for _, name := range tree.names {
				candidates++
				ref, err := tree.ref(app.AppID, name)
				if err != nil {
					return nil, r.fail("read", app.AppID+"/"+name, err, errReadFailed)
				}
				s, err := m.d.Repo.Get(ctx, ref)
				if errors.Is(err, secretstore.ErrNotFound) {
					skipped++
					continue
				}
				if err != nil {
					return nil, r.fail("read", ref.String(), err, errReadFailed)
				}
				r.entries = append(r.entries, entry{ref: ref, value: s.Value})
			}
		}
	}
	m.d.Log.InfoContext(ctx, "secret store migration read the entries to copy",
		"component", "secretstore", "event", "secretstore.migrate_started", "job_id", sc.JobID,
		"candidates", candidates, "found", len(r.entries), "not_found", skipped)
	return nil, nil
}

// swap moves the marker to this boot, arms the request, and restarts the
// store, whose root step sets the old tree aside and whose init step
// re-initialises it. It goes on only when the root step's record says moved
// in the store's current run.
func (m *Migrator) swap(sc *jobs.StepCtx) (json.RawMessage, error) {
	ctx := stepCtx(sc)
	r, err := m.get(sc.JobID)
	if err != nil {
		return nil, err
	}
	r.release = m.d.Control.Quiesce(sc.JobID)
	prev, err := m.d.Marker.RebaseChecked(ctx)
	if err != nil {
		return nil, r.fail("swap", "", err, errSwapNotArmed)
	}
	r.rebased, r.prev = true, prev
	r.armed = true
	if err := m.d.Files.Write(NameRequest, []byte("boot_id="+r.boot+"\njob_id="+sc.JobID+"\n")); err != nil {
		return nil, r.fail("swap", "", err, errSwapNotArmed)
	}
	if err := ctx.Err(); err != nil {
		return nil, r.fail("swap", "", err, errSwapNotArmed)
	}
	r.stopped = true
	if err := m.d.Control.Stop(ctx); err != nil {
		return nil, r.fail("swap", "", err, errSwapFailed)
	}
	if err := m.d.Control.Start(ctx); err != nil {
		return nil, r.fail("swap", "", err, errSwapFailed)
	}
	runID, err := m.currentOutcome(ctx, outcomeMoved, r.boot)
	if err != nil {
		return nil, r.fail("swap", "", err, errSwapFailed)
	}
	if err := m.d.Control.WaitReady(ctx); err != nil {
		return nil, r.fail("swap", "", err, errSwapFailed)
	}
	m.d.Log.InfoContext(ctx, "secret store migration swapped the store onto a fresh layout",
		"component", "secretstore", "event", "secretstore.migrate_swapped", "job_id", sc.JobID, "run_id", runID)
	return nil, nil
}

// currentOutcome checks that the os.store_migrate record says want, in
// boot, for the store unit's current run, and returns that run's id.
func (m *Migrator) currentOutcome(ctx context.Context, want, boot string) (string, error) {
	rec, err := m.d.Records.Migrate()
	if err != nil {
		return "", fmt.Errorf("reading the store migrate record: %w", err)
	}
	u, err := m.d.StoreUnit(ctx)
	if err != nil {
		return "", fmt.Errorf("reading the store unit: %w", err)
	}
	if rec.Outcome != want || rec.RunID == "" || rec.RunID != u.InvocationID || rec.BootID != boot {
		return "", fmt.Errorf("the store migrate record says %s for run %s in boot %s; want %s for run %s in boot %s",
			rec.Outcome, rec.RunID, rec.BootID, want, u.InvocationID, boot)
	}
	return rec.RunID, nil
}

// writeBack writes every entry into the fresh store, create-only, reads it
// back and compares it in constant time.
func (m *Migrator) writeBack(sc *jobs.StepCtx) (json.RawMessage, error) {
	ctx := stepCtx(sc)
	r, err := m.get(sc.JobID)
	if err != nil {
		return nil, err
	}
	for _, e := range r.entries {
		if _, err := m.d.Repo.Write(ctx, e.ref, e.value, 0); err != nil {
			return nil, r.fail("write_back", e.ref.String(), err, errWriteBackFailed)
		}
		back, err := m.d.Repo.Get(ctx, e.ref)
		if err != nil {
			return nil, r.fail("write_back", e.ref.String(), err, errWriteBackFailed)
		}
		same := secret.Equal(back.Value, e.value)
		back.Value.Destroy()
		if !same {
			return nil, r.fail("write_back", e.ref.String(), errors.New("the value read back differs"), errWriteBackFailed)
		}
	}
	return nil, nil
}

// commit makes the commit durable, then releases the Hold, clears the
// attempt bound so a later restore of an old-shape backup in this boot can
// migrate again, and lets go of everything the job held.
func (m *Migrator) commit(sc *jobs.StepCtx) (json.RawMessage, error) {
	ctx := stepCtx(sc)
	r, err := m.get(sc.JobID)
	if err != nil {
		return nil, err
	}
	if err := m.d.Files.Write(NameCommit, []byte("job_id="+sc.JobID+"\n")); err != nil {
		return nil, r.fail("commit", "", err, errCommitFailed)
	}
	m.take(sc.JobID)
	m.d.Hold.Off()
	r.hold = false
	if err := m.d.Settings.Set(ctx, KeyAttemptBootID, ""); err != nil {
		// The commit is durable, so the migration is done; the bound only
		// keeps a restored old-shape backup from migrating again in this
		// boot, and the next boot clears it.
		m.d.Log.WarnContext(ctx, "secret store migration attempt bound not cleared",
			"component", "secretstore", "event", "secretstore.migrate_bound_not_cleared", "job_id", sc.JobID, "err", err.Error())
	}
	n := len(r.entries)
	m.letGo(sc.JobID, r)
	m.d.Log.InfoContext(ctx, "secret store migration committed",
		"component", "secretstore", "event", "secretstore.migrate_committed", "job_id", sc.JobID, "count", n)
	return nil, nil
}

// letGo releases the quiesce and the gate and destroys every value.
func (m *Migrator) letGo(jobID string, r *run) {
	if r.release != nil {
		r.release()
	}
	m.d.Lock.Release(jobID)
	for _, e := range r.entries {
		e.value.Destroy()
	}
	r.entries = nil
}

// onTerminal runs once the job ends. A failed job's run is aborted; on every
// path the gate is released and the reference check is ordered after it. A
// job runner.Recover failed in a later process has no run here: Recover
// already dealt with its files at start.
func (m *Migrator) onTerminal(ctx context.Context, jobID string, success bool, _ string) {
	if r := m.take(jobID); r != nil {
		if success {
			m.letGo(jobID, r)
		} else {
			m.abort(ctx, jobID, r)
		}
	}
	m.d.Lock.Release(jobID)
	m.d.AfterTerminal(ctx)
}

// abort puts the old tree back, or disarms a request the store never acted
// on (F-1132-02). It runs on a context detached from the job's, so a
// cancelled job still disarms. When it cannot show that the old tree is
// live, the Hold stays on until Hold.Observe sees that it is.
func (m *Migrator) abort(ctx context.Context, jobID string, r *run) {
	actx, cancel := context.WithTimeout(context.WithoutCancel(jobs.ContextWithJobID(ctx, jobID)), abortTimeout)
	defer cancel()
	holdStays := false
	var abortErr error
	// Only a job that armed the request can have had the old tree set
	// aside; an aside.tar a refused validate found is not this job's.
	aside := false
	if r.armed {
		present, err := m.d.Files.Present(NameAside)
		if err != nil {
			// Not knowing is treated as a swap that ran: the put-back is
			// the path that converges from either state.
			present, abortErr = true, err
		}
		aside = present
	}
	switch {
	case aside:
		if err := m.putBack(actx, r.boot); err != nil {
			holdStays, abortErr = true, errors.Join(abortErr, err)
		}
	default:
		if r.armed {
			if err := m.d.Files.Remove(NameRequest); err != nil {
				holdStays, abortErr = true, errors.Join(abortErr, err)
			}
		}
		if r.rebased {
			if err := m.d.Marker.RestoreSetUp(actx, r.prev); err != nil {
				m.d.Log.WarnContext(actx, "secret store marker not put back after the migration stopped",
					"component", "secretstore", "event", "secretstore.migrate_marker_reset_failed", "job_id", jobID, "err", err.Error())
			}
		}
		if r.stopped {
			if err := m.startIfStopped(actx); err != nil {
				abortErr = errors.Join(abortErr, err)
			}
		}
	}
	if r.release != nil {
		r.release()
		r.release = nil
	}
	if r.hold {
		if holdStays {
			m.d.Hold.Stick(jobID)
		} else {
			m.d.Hold.Off()
		}
	}
	m.letGo(jobID, r)
	attrs := []any{"component", "secretstore", "event", "secretstore.migrate_aborted", "job_id", jobID,
		"step", r.failStep, "hold_stays", holdStays}
	if r.failRef != "" {
		attrs = append(attrs, "ref", r.failRef)
	}
	if r.failErr != nil {
		attrs = append(attrs, "err", r.failErr.Error())
		var se *secretstore.Error
		if errors.As(r.failErr, &se) {
			for _, a := range se.LogAttrs() {
				attrs = append(attrs, a)
			}
		}
	}
	if abortErr != nil {
		attrs = append(attrs, "abort_err", abortErr.Error())
	}
	m.d.Log.ErrorContext(actx, "secret store migration stopped before its commit", attrs...)
}

// putBack restarts the store so its root step puts the old tree back, and
// confirms that it did: the record says restored for the current run,
// aside.tar is gone, and the store answers ready.
func (m *Migrator) putBack(ctx context.Context, boot string) error {
	if err := m.d.Control.Stop(ctx); err != nil {
		return err
	}
	if err := m.d.Control.Start(ctx); err != nil {
		return err
	}
	if _, err := m.currentOutcome(ctx, outcomeRestored, boot); err != nil {
		return err
	}
	if present, err := m.d.Files.Present(NameAside); err != nil || present {
		return errors.Join(err, errors.New("aside.tar is still present after the put-back"))
	}
	return m.d.Control.WaitReady(ctx)
}

// startIfStopped starts the store when its unit is not active (the root
// step's nothing-to-do start), then waits for it to answer ready.
func (m *Migrator) startIfStopped(ctx context.Context) error {
	u, err := m.d.StoreUnit(ctx)
	if err == nil && u.ActiveState == unitActive {
		return nil
	}
	if err := m.d.Control.Start(ctx); err != nil {
		return err
	}
	return m.d.Control.WaitReady(ctx)
}
