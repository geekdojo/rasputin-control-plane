// Package identitystate is the api's view of whether the identity service can
// serve sign-in now (geekdojo/geekdojo-brain#979, Identity 3.3,
// lifecycle.md §5.1).
//
// Monitor computes one State when a caller asks: the alerts list, and the
// identity routes to come through Ready. It owns no loop and no timer: the
// state changes only on what a reading finds (ARCH-FACTS). A reading takes
// systemd's own properties for keycloak.service and keycloak-db.service, the
// exit records and `last` that keycloak.service's ExecStopPost= writes, the
// start hold's record, the version marker, the os.identity_* outcome jobs, the
// quiesce holds and one /health/ready call while Keycloak is active. It never
// reads a journal: facts come from the unit, never from logs (Bryce,
// 2026-11-15), and it never opens or removes the start-hold count file, which
// is #973's alone.
//
// A reading also does the bookkeeping those facts call for, on the fact that
// it found them: each out-of-memory exit record becomes one
// identity.service_exit job and is removed, the outcome records are read into
// the ledger when the database starts a new run, and the version marker is
// stored as the last version seen ready.
//
// The api boots whatever the identity service's state: nothing here is called
// at startup.
package identitystate

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/looptls"
	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
)

// The outcome kinds the Monitor reads: the database's first-init gate (#975)
// and the version gate (#1009).
const (
	DBInitKind   = "os.identity_db_init"
	RollbackKind = "os.identity_rollback"
)

// VersionReadyKey is the settings key holding the version marker's value at
// the last ready reading.
const VersionReadyKey = "identity.version_ready"

// dbCheck is the /health/ready check that names the database
// (K-HEALTH, Keycloak 26.8.2).
const dbCheck = "Keycloak database connections async health check"

// Health is the one identity service call the Monitor makes.
type Health interface {
	Health(ctx context.Context) (idclient.HealthReport, error)
}

// Ledger is the slice of the job ledger the Monitor uses. *jobs.Store
// satisfies it.
type Ledger interface {
	RecordFinishedJob(ctx context.Context, j *jobs.Job) (bool, error)
	ListJobsByKind(ctx context.Context, kind string, limit int) ([]*jobs.Job, error)
}

// Settings is the settings store slice the Monitor uses. *setup.Store
// satisfies it.
type Settings interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}

// Fact is an injected yes-or-no fact whose producer is a later story. An
// error reads as true: fail closed.
type Fact func(ctx context.Context) (bool, error)

// Deps are the Monitor's collaborators. New refuses a nil one.
type Deps struct {
	// Units reads both units' properties (SystemctlUnits).
	Units func(ctx context.Context) (Units, error)
	// Exits reads the exit records (ExitRecords); RemoveExit removes a
	// consumed one (RemoveExitRecord).
	Exits      func(ctx context.Context) (ExitDir, error)
	RemoveExit func(ctx context.Context, id string) error
	// Health asks /health/ready.
	Health Health
	// Ledger records the exit jobs and holds the outcome jobs.
	Ledger Ledger
	// ReadRecords reads the os.identity_* outcome records into the ledger.
	ReadRecords func(ctx context.Context)
	// StartHold reads the start hold's record (StartHoldRecord).
	StartHold func(ctx context.Context) (StartHold, error)
	// Marker reads the version marker (MarkerFile).
	Marker func(ctx context.Context) (string, error)
	// Settings holds VersionReadyKey.
	Settings Settings
	// JobRunning reports whether the job holding a quiesce still runs.
	JobRunning func(ctx context.Context, jobID string) (bool, error)
	// Blank, AppsPaused and HistoryBehind are the facts Identity 5.7, 7.3 and
	// 4.3 produce.
	Blank, AppsPaused, HistoryBehind Fact
	// Features compares the running service's features with the shipped
	// build for Keycloak's run kcInvocation (converge.FeatureCheck.Mismatch,
	// geekdojo/geekdojo-brain#981). true is a mismatch; an error is a check
	// that could not finish.
	Features func(ctx context.Context, kcInvocation string) (bool, error)
	// BecameReady is called once on each reading that finds the service
	// ready after any other state, or on the first reading that finds it
	// ready: the sign-in history drain is marked dirty on that fact
	// (geekdojo/geekdojo-brain#985). nil calls nothing: only the keycloak
	// mode has a drain, and its wiring sets it.
	BecameReady func()
	// Now stamps when a state was first observed, and nothing else.
	Now func() time.Time
	Log *slog.Logger
}

// Monitor reads and remembers the identity service's state.
type Monitor struct {
	d   Deps
	log *slog.Logger

	// exitsMu serialises the exit records' consumption, so two readings
	// never record or remove the same record at once. It guards the fields
	// below it up to mu.
	exitsMu sync.Mutex
	// kcSeen is Keycloak's tuple at the last exits read; kcSeenSet is false
	// before the first.
	kcSeen    Unit
	kcSeenSet bool
	// lastExit is the record `last` named at the last exits read, and
	// exitsOK whether that read could list them.
	lastExit *ExitRecord
	exitsOK  bool
	// exitsPending is set while a record is kept for the next reading: the
	// ledger refused its job, it did not parse, or it was not removed.
	exitsPending bool
	// badWarned are the unparsable records already logged.
	badWarned map[string]bool

	mu    sync.Mutex
	last  State // "" until the first reading
	since time.Time
	// dbInvocation is the database run whose outcome records were last read.
	dbInvocation string
	holds        map[*hold]struct{}
	// The once-per-outage WARN flags.
	unitsUnread, exitsUnread, markerUnread, versionUnwritten, rollbackUnread, startHoldUnread, featuresUnread bool
	factUnread                                                                                                map[string]bool
}

// hold is one Quiesce call that has not been released.
type hold struct {
	jobID  string
	warned bool
}

// New checks d and returns a Monitor. It does no I/O.
func New(d Deps) (*Monitor, error) {
	missing := ""
	switch {
	case d.Units == nil:
		missing = "Units"
	case d.Exits == nil:
		missing = "Exits"
	case d.RemoveExit == nil:
		missing = "RemoveExit"
	case d.Health == nil:
		missing = "Health"
	case d.Ledger == nil:
		missing = "Ledger"
	case d.ReadRecords == nil:
		missing = "ReadRecords"
	case d.StartHold == nil:
		missing = "StartHold"
	case d.Marker == nil:
		missing = "Marker"
	case d.Settings == nil:
		missing = "Settings"
	case d.JobRunning == nil:
		missing = "JobRunning"
	case d.Blank == nil:
		missing = "Blank"
	case d.AppsPaused == nil:
		missing = "AppsPaused"
	case d.HistoryBehind == nil:
		missing = "HistoryBehind"
	case d.Features == nil:
		missing = "Features"
	case d.Now == nil:
		missing = "Now"
	case d.Log == nil:
		missing = "Log"
	}
	if missing != "" {
		return nil, errors.New("identitystate: Deps." + missing + " is nil")
	}
	return &Monitor{
		d: d, log: d.Log.With("component", "identity"),
		holds: map[*hold]struct{}{}, factUnread: map[string]bool{}, badWarned: map[string]bool{},
	}, nil
}

// State reads the facts once and returns the state. It returns an error only
// when ctx ended before or during the reading, and then records nothing: a
// cancelled question says nothing about the service.
func (m *Monitor) State(ctx context.Context) (State, error) {
	r, err := m.read(ctx)
	return r.state, err
}

// Ready is nil when the state does not block identity work: Ready,
// AppsPaused or HistoryBehind. Otherwise it returns a *NotReadyError, or the
// ctx error when ctx ended.
func (m *Monitor) Ready(ctx context.Context) error {
	r, err := m.read(ctx)
	if err != nil {
		return err
	}
	if r.state.Blocks() {
		return &NotReadyError{State: r.state}
	}
	return nil
}

// ServiceReadiness is the Monitor's readiness of the service alone: the two
// features states read as ready, so a features check that cannot finish
// (the api's own admin login refused, for one) never blocks what repairs it.
// Every other blocking state still refuses.
type ServiceReadiness struct{ m *Monitor }

// ServiceOnly is the service-only readiness identity.recover_admin's trigger
// reads (geekdojo/geekdojo-brain#981).
func (m *Monitor) ServiceOnly() ServiceReadiness { return ServiceReadiness{m: m} }

// Ready is Monitor.Ready with FeaturesMismatch and FeaturesUnchecked read as
// ready.
func (s ServiceReadiness) Ready(ctx context.Context) error {
	r, err := s.m.read(ctx)
	if err != nil {
		return err
	}
	switch r.state {
	case FeaturesMismatch, FeaturesUnchecked:
		return nil
	}
	if r.state.Blocks() {
		return &NotReadyError{State: r.state}
	}
	return nil
}

// reading is one reading's result.
type reading struct {
	state State
	since time.Time
	// cause is Held's cause from the gate's or the start hold's record.
	cause string
}

// facts is what one reading found.
type facts struct {
	units      Units
	unitsKnown bool
	last       *ExitRecord
	exitsOK    bool

	healthCalled bool
	healthErr    error
	healthReport idclient.HealthReport
}

// read is one reading.
func (m *Monitor) read(ctx context.Context) (reading, error) {
	if err := ctx.Err(); err != nil {
		return reading{}, fmt.Errorf("identitystate: reading the identity service's state: %w", err)
	}
	var f facts
	u, err := m.d.Units(ctx)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return reading{}, fmt.Errorf("identitystate: reading the identity service's units: %w", ctxErr)
	}
	m.outage(ctx, &m.unitsUnread, err, "identity units unreadable; reading health as though the service were active")
	f.units, f.unitsKnown = u, err == nil

	if f.unitsKnown {
		f.last, f.exitsOK = m.exits(ctx, u.KC)
		m.outcomes(ctx, u.DB)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return reading{}, fmt.Errorf("identitystate: reading the identity service's exit records: %w", ctxErr)
	}

	// One /health/ready call, only while Keycloak is active: under #973's
	// start wait, active means it has started (F-979-09).
	if !f.unitsKnown || u.KC.ActiveState == "active" {
		f.healthCalled = true
		f.healthReport, f.healthErr = m.d.Health.Health(ctx)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return reading{}, fmt.Errorf("identitystate: asking the identity service's health: %w", ctxErr)
		}
	}
	ready := f.healthCalled && f.healthErr == nil
	if ready {
		m.storeReadyVersion(ctx)
	}
	st, cause := m.decide(ctx, f, ready)
	since := m.record(ctx, st, f)
	return reading{state: st, since: since, cause: cause}, nil
}

// exits reads the exit records when Keycloak's (InvocationID, ActiveState,
// SubState) changed since the last read, on the first reading, or while a
// record is kept for retry; otherwise it returns what the last read found.
func (m *Monitor) exits(ctx context.Context, kc Unit) (*ExitRecord, bool) {
	m.exitsMu.Lock()
	defer m.exitsMu.Unlock()
	if m.kcSeenSet && m.kcSeen == kc && !m.exitsPending {
		return m.lastExit, m.exitsOK
	}
	last, ok := m.consumeExits(ctx)
	if ctx.Err() != nil {
		return nil, false
	}
	m.kcSeen, m.kcSeenSet, m.lastExit, m.exitsOK = kc, true, last, ok
	return last, ok
}

// outcomes reads the os.identity_* records into the ledger once per database
// run that is active or failed: each start of the database runs the gates
// that write them.
func (m *Monitor) outcomes(ctx context.Context, db Unit) {
	if db.ActiveState != "active" && db.ActiveState != "failed" {
		return
	}
	m.mu.Lock()
	seen := db.InvocationID == m.dbInvocation
	m.dbInvocation = db.InvocationID
	m.mu.Unlock()
	if !seen {
		m.d.ReadRecords(ctx)
	}
}

// storeReadyVersion stores the marker as the last version seen ready, when it
// differs from the stored one. An unreadable marker or setting is one WARN
// per outage, and nothing is written.
func (m *Monitor) storeReadyVersion(ctx context.Context) {
	marker, stored, err := m.versions(ctx)
	if err != nil || marker == stored {
		return
	}
	err = m.d.Settings.Set(ctx, VersionReadyKey, marker)
	m.outage(ctx, &m.versionUnwritten, err, "identity version marker not stored as the ready version")
}

// versions reads the marker and the stored ready version, with one WARN per
// outage when either cannot be read.
func (m *Monitor) versions(ctx context.Context) (marker, stored string, err error) {
	marker, err = m.d.Marker(ctx)
	if err == nil {
		stored, err = m.d.Settings.Get(ctx, VersionReadyKey)
	}
	m.outage(ctx, &m.markerUnread, err, "identity version marker or ready version unreadable; reading starting rather than upgrading")
	return marker, stored, err
}

// decide picks the state from what a reading found, in lifecycle.md §5.1's
// precedence, and returns Held's cause.
func (m *Monitor) decide(ctx context.Context, f facts, ready bool) (State, string) {
	kc, db := f.units.KC, f.units.DB
	kcActive := !f.unitsKnown || kc.ActiveState == "active"
	if m.fact(ctx, "blank", m.d.Blank) {
		return Blank, ""
	}
	if !ready && m.running(ctx) {
		return Paused, ""
	}
	if cause, held := m.held(ctx, kcActive); held {
		return Held, cause
	}
	lastOK := f.exitsOK && f.last != nil
	switch {
	case !kcActive && lastOK && f.last.OutOfMemory():
		return OutOfMemory, ""
	case f.unitsKnown && dbDown(db), f.healthCalled && f.healthErr != nil && f.healthReport.Down(dbCheck):
		return DatabaseDown, ""
	case f.unitsKnown && kc.ActiveState == "failed",
		!kcActive && lastOK && !f.last.Success() && !f.last.OutOfMemory():
		return Failed, ""
	case f.healthCalled && unreachable(f.healthErr):
		return Unreachable, ""
	case !ready && f.unitsKnown && starting(kc) && m.upgrading(ctx):
		return Upgrading, ""
	case !ready:
		return Starting, ""
	}
	// The features check, only on an otherwise ready service (#981).
	if st := m.featureState(ctx, kc.InvocationID); st != "" {
		return st, ""
	}
	switch {
	case m.fact(ctx, "apps-paused", m.d.AppsPaused):
		return AppsPaused, ""
	case m.fact(ctx, "history-behind", m.d.HistoryBehind):
		return HistoryBehind, ""
	}
	return Ready, ""
}

// featureState is FeaturesMismatch or FeaturesUnchecked from the features
// check, or "" when it matches. A check that could not finish is one WARN per
// outage.
func (m *Monitor) featureState(ctx context.Context, kcInvocation string) State {
	mismatch, err := m.d.Features(ctx, kcInvocation)
	m.outage(ctx, &m.featuresUnread, err, "identity features check could not finish")
	switch {
	case err != nil:
		return FeaturesUnchecked
	case mismatch:
		return FeaturesMismatch
	}
	return ""
}

// dbDown is the database not running: stopped, failed, or waiting to be
// restarted. activating in start-pre or start is a database starting, which
// reads starting (F-979-04).
func dbDown(db Unit) bool {
	switch db.ActiveState {
	case "inactive", "failed":
		return true
	case "activating":
		return db.SubState == "auto-restart"
	}
	return false
}

// starting is Keycloak's unit in one of its start phases.
func starting(kc Unit) bool {
	if kc.ActiveState != "activating" {
		return false
	}
	switch kc.SubState {
	case "start-pre", "start", "start-post":
		return true
	}
	return false
}

// unreachable is a health answer that says the call itself is refused or
// unusable: the client certificate refused, an answer that is not the health
// JSON, a server certificate that did not verify, or our own leaf unusable. A
// refused connection or a call that ran out of its bound is a service still
// starting.
func unreachable(err error) bool {
	if err == nil {
		return false
	}
	var verr *tls.CertificateVerificationError
	return errors.Is(err, idclient.ErrDenied) || errors.Is(err, idclient.ErrProtocol) ||
		errors.As(err, &verr) || looptls.IsLeafError(err)
}

// upgrading reports whether a ready version is stored and the marker
// differs from it. Unreadable is not upgrading.
func (m *Monitor) upgrading(ctx context.Context) bool {
	marker, stored, err := m.versions(ctx)
	return err == nil && stored != "" && marker != stored
}

// held is the version gate's refusal, from the newest os.identity_rollback
// job, or the start hold's while Keycloak is not active, with its cause.
func (m *Monitor) held(ctx context.Context, kcActive bool) (string, bool) {
	newest, err := m.d.Ledger.ListJobsByKind(ctx, RollbackKind, 1)
	m.outage(ctx, &m.rollbackUnread, err, "identity version gate's outcome unreadable")
	if err == nil && len(newest) == 1 && newest[0].Status == jobs.StatusFailed {
		if outcome := rollbackOutcome(newest[0]); outcome == "refused" || outcome == "failed" {
			return newest[0].Error, true
		}
	}
	if kcActive {
		return "", false
	}
	h, err := m.d.StartHold(ctx)
	m.outage(ctx, &m.startHoldUnread, err, "identity start hold's record unreadable")
	if err == nil && h.Refused {
		return h.Reason, true
	}
	return "", false
}

// rollbackOutcome is the outcome word an os.identity_rollback job recorded.
func rollbackOutcome(j *jobs.Job) string {
	var s osoutcome.Spec
	if err := json.Unmarshal(j.Spec, &s); err != nil {
		return ""
	}
	return s.Outcome
}

// fact reads an injected fact; an error reads as true, with one WARN per
// outage.
func (m *Monitor) fact(ctx context.Context, name string, f Fact) bool {
	v, err := f(ctx)
	m.mu.Lock()
	warn := err != nil && !m.factUnread[name]
	m.factUnread[name] = err != nil
	m.mu.Unlock()
	if warn {
		m.log.LogAttrs(ctx, slog.LevelWarn, "identity fact unreadable; reading it as true",
			slog.String("fact", name), slog.String("err", err.Error()))
	}
	return v || err != nil
}

// outage logs msg at WARN once per run of errors on the flag, and clears the
// flag on a nil err.
func (m *Monitor) outage(ctx context.Context, flag *bool, err error, msg string) {
	m.mu.Lock()
	warn := err != nil && !*flag
	*flag = err != nil
	m.mu.Unlock()
	if warn {
		m.log.LogAttrs(ctx, slog.LevelWarn, msg, slog.String("err", err.Error()))
	}
}

// record remembers st and logs a transition once. It returns when st was
// first observed.
func (m *Monitor) record(ctx context.Context, st State, f facts) time.Time {
	m.mu.Lock()
	if st == m.last {
		since := m.since
		m.mu.Unlock()
		return since
	}
	m.last, m.since = st, m.d.Now()
	since := m.since
	m.mu.Unlock()
	if st == Ready {
		m.log.LogAttrs(ctx, slog.LevelInfo, "identity service ready")
		if m.d.BecameReady != nil {
			m.d.BecameReady()
		}
		return since
	}
	attrs := []slog.Attr{
		slog.String("state", string(st)),
		slog.String("kc_state", f.units.KC.ActiveState), slog.String("kc_substate", f.units.KC.SubState),
		slog.String("db_state", f.units.DB.ActiveState),
	}
	var ie *idclient.Error
	if errors.As(f.healthErr, &ie) {
		attrs = append(attrs, ie.LogAttrs()...)
	}
	m.log.LogAttrs(ctx, slog.LevelWarn, "identity service not ready", attrs...)
	return since
}

// Quiesce records that jobID holds the identity service quiesced, so a
// not-ready service reads Paused while that job runs. release ends the hold;
// calling it again does nothing.
func (m *Monitor) Quiesce(jobID string) (release func()) {
	h := &hold{jobID: jobID}
	m.mu.Lock()
	m.holds[h] = struct{}{}
	m.mu.Unlock()
	m.log.Info("identity service quiesced", "event", "identity.quiesced", "job_id", jobID)
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			delete(m.holds, h)
			m.mu.Unlock()
			m.log.Info("identity service quiesce released", "event", "identity.quiesce_released", "job_id", jobID)
		})
	}
}

// running reports whether a hold's job is running now. A hold whose job is
// not running, or whose status cannot be read, is ignored with one WARN, so a
// leaked hold cannot hide an outage.
func (m *Monitor) running(ctx context.Context) bool {
	running, _ := m.holdsNow(ctx)
	return running
}

// holdsNow reports whether a hold's job is running, and whether any hold's
// job status could not be read.
func (m *Monitor) holdsNow(ctx context.Context) (running, unreadable bool) {
	m.mu.Lock()
	holds := make([]*hold, 0, len(m.holds))
	for h := range m.holds {
		holds = append(holds, h)
	}
	m.mu.Unlock()
	for _, h := range holds {
		ok, err := m.d.JobRunning(ctx, h.jobID)
		if err == nil && ok {
			running = true
			continue
		}
		if err != nil {
			unreadable = true
		} else {
			err = errors.New("the job is not running")
		}
		m.mu.Lock()
		warn := !h.warned
		h.warned = true
		m.mu.Unlock()
		if warn {
			m.log.LogAttrs(ctx, slog.LevelWarn, "identity quiesce hold ignored",
				slog.String("job_id", h.jobID), slog.String("err", err.Error()))
		}
	}
	return running, unreadable
}

// Held reports whether a job holds the identity service quiesced now: a hold
// whose job is running, or whose status cannot be read (ERR-CLOSED), so
// identity.recover never restarts the pair under a hold it could not see.
func (m *Monitor) Held(ctx context.Context) bool {
	running, unreadable := m.holdsNow(ctx)
	return running || unreadable
}
