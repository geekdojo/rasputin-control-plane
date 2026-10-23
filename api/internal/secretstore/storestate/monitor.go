// Package storestate is the api's view of whether the secret store can serve
// secrets now, and what the api does about it when it cannot
// (geekdojo/geekdojo-brain#760, Secrets 3.3):
//
//   - Monitor reads the store's readiness from sys/health at the moment a
//     caller asks, remembers only the last state it saw and when it first saw
//     it, and turns that into an alert. There is no probe loop and no period:
//     the state changes only on an answer (ARCH-FACTS).
//   - Gate is the deploy family's secret source while a store backend is
//     requested. A compose with a ${secret:} token is refused with the stable
//     code secret_store_not_ready unless the store reads ready; a compose
//     without one always goes through.
//   - ObservedStore reports each audited call's outcome to the Monitor, which
//     is how a store whose audit sink is blocked is told apart from one that
//     is down.
//
// The api boots whatever the store's state: nothing here is called at
// startup.
package storestate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// State is the store's readiness as the api sees it.
type State string

// The states. Every state but Ready refuses secret-bearing work.
const (
	Ready         State = "ready"
	Sealed        State = "sealed"
	Uninitialised State = "uninitialised"
	Unreachable   State = "unreachable"
	// AuditBlocked: sys/health answers 200 unsealed, but an audited call ran
	// out of time on the client's own bound at that moment (#684 guard 4).
	AuditBlocked State = "audit-blocked"
	// Quiesced: the store is not ready while a running job holds a quiesce
	// for a backup (F4.1) or a seal-key rotation (#830).
	Quiesced State = "quiesced"
	// Blank: sys/health answers 200 unsealed, but the store started empty on
	// a cluster whose database says it was set up, or that verdict cannot be
	// read (geekdojo/geekdojo-brain#765, S15 part 7). Its secrets are not
	// there, so nothing may be deployed from it or backed up over a good
	// archive.
	Blank State = "blank"
)

// QuiesceReason is why a job holds the store quiesced. The alert's ID is the
// same for every reason; its title and detail name the reason, so the copy
// never describes one job as the other (ERR-MESSAGE,
// geekdojo/geekdojo-brain#830).
type QuiesceReason int

// The reasons.
const (
	// QuiesceBackup: a backup is capturing the store (F4.1).
	QuiesceBackup QuiesceReason = iota
	// QuiesceSealRotation: the seal-key rotation restarts the store
	// (geekdojo/geekdojo-brain#830).
	QuiesceSealRotation
)

// String names the reason in log fields.
func (r QuiesceReason) String() string {
	if r == QuiesceSealRotation {
		return "seal-rotation"
	}
	return "backup"
}

// phrase is the reason as the log message words it.
func (r QuiesceReason) phrase() string {
	if r == QuiesceSealRotation {
		return "a seal-key rotation"
	}
	return "a backup"
}

// Store is the one store call the Monitor makes.
type Store interface {
	Health(ctx context.Context) (secretstore.Health, error)
}

// Deps are the Monitor's collaborators. New refuses a nil one.
type Deps struct {
	Store Store
	// Now stamps when a state was first observed.
	Now func() time.Time
	Log *slog.Logger
	// JobRunning reports whether the job holding a quiesce is still running.
	JobRunning func(ctx context.Context, jobID string) (bool, error)
	// Blank reports whether the store has been recorded starting empty on a
	// set-up cluster (storemarker.Marker.Blank). An error reads as blank.
	Blank func(ctx context.Context) (bool, error)
}

// Monitor reads and remembers the store's readiness.
type Monitor struct {
	store      Store
	now        func() time.Time
	log        *slog.Logger
	jobRunning func(ctx context.Context, jobID string) (bool, error)
	blank      func(ctx context.Context) (bool, error)

	mu    sync.Mutex
	last  State // "" until the first reading
	since time.Time
	// auditBlocked is the #684 guard-4 fact, raised and cleared only by
	// ObserveAudited and a not-ready reading.
	auditBlocked bool
	holds        map[*hold]struct{}
	// reason is the reason of the hold that made the last reading Quiesced.
	reason QuiesceReason
	// blankUnread is set while the blank verdict cannot be read, so its WARN
	// is logged once per outage rather than on every reading.
	blankUnread bool
}

// hold is one Quiesce call that has not been released.
type hold struct {
	jobID  string
	reason QuiesceReason
	// warned is set once the hold has been logged as ignored, so a leaked
	// hold is reported once rather than on every reading.
	warned bool
}

// New checks d and returns a Monitor. It makes no store call.
func New(d Deps) (*Monitor, error) {
	switch {
	case d.Store == nil:
		return nil, errors.New("storestate: Deps.Store is nil")
	case d.Now == nil:
		return nil, errors.New("storestate: Deps.Now is nil")
	case d.Log == nil:
		return nil, errors.New("storestate: Deps.Log is nil")
	case d.JobRunning == nil:
		return nil, errors.New("storestate: Deps.JobRunning is nil")
	case d.Blank == nil:
		return nil, errors.New("storestate: Deps.Blank is nil")
	}
	return &Monitor{store: d.Store, now: d.Now, log: d.Log, jobRunning: d.JobRunning, blank: d.Blank, holds: map[*hold]struct{}{}}, nil
}

// State asks sys/health once and returns the store's state. It returns an
// error only when ctx ended during the reading, and then records nothing: a
// cancelled question says nothing about the store.
func (m *Monitor) State(ctx context.Context) (State, error) {
	st, _, err := m.read(ctx)
	return st, err
}

// read is State, with when the returned state was first observed.
func (m *Monitor) read(ctx context.Context) (State, time.Time, error) {
	h, err := m.store.Health(ctx)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", time.Time{}, fmt.Errorf("storestate: reading the secret store's health: %w", ctxErr)
	}
	kind := secretstore.InactiveReason(h, err)
	st := stateOf(kind)
	if st != Ready {
		// A store that went down dropped the request its audit sink held,
		// and a restarted one opens a new sink.
		m.clearAuditBlocked(ctx, "the store is not ready")
		if reason, ok := m.quiesced(ctx); ok {
			st = Quiesced
			m.mu.Lock()
			m.reason = reason
			m.mu.Unlock()
		}
	} else if m.isAuditBlocked() {
		st, kind = AuditBlocked, string(AuditBlocked)
	} else if m.isBlank(ctx) {
		st, kind = Blank, string(Blank)
	}
	since := m.record(ctx, st, kind, h, err)
	return st, since, nil
}

// stateOf maps InactiveReason's answer to a state. Anything it cannot name
// (disabled, an unclassified error) is Unreachable: fail closed.
func stateOf(kind string) State {
	switch kind {
	case "":
		return Ready
	case "sealed":
		return Sealed
	case "uninitialised":
		return Uninitialised
	}
	return Unreachable
}

// record remembers st and logs a transition once. It returns when st was
// first observed.
func (m *Monitor) record(ctx context.Context, st State, kind string, h secretstore.Health, err error) time.Time {
	m.mu.Lock()
	if st == m.last {
		since := m.since
		m.mu.Unlock()
		return since
	}
	m.last, m.since = st, m.now()
	since := m.since
	m.mu.Unlock()

	if st == Ready {
		m.log.LogAttrs(ctx, slog.LevelInfo, "secret store ready",
			slog.String("component", "secretstore"), slog.String("version", h.Version))
		return since
	}
	attrs := []slog.Attr{
		slog.String("component", "secretstore"), slog.String("state", string(st)), slog.String("kind", kind),
	}
	var se *secretstore.Error
	if errors.As(err, &se) {
		attrs = append(attrs, se.LogAttrs()...)
	}
	m.log.LogAttrs(ctx, slog.LevelWarn, "secret store not ready", attrs...)
	return since
}

// ObserveAudited takes the outcome of one audited store call (a read, a
// write or a version listing), with that call's own ctx, right after it
// returned (#684 guard 4, F-760-01):
//
//   - ctx is done (the caller cancelled, or its own deadline passed): nothing
//     is recorded, because the store was not given the time to answer;
//   - the store answered (nil, not found, a check-and-set mismatch, denied):
//     its audit sink took the request, so audit-blocked clears;
//   - the call ran out of time on the client's own bound: sys/health is read
//     now, with the same ctx, and only a 200 unsealed answer raises
//     audit-blocked. A hung store hangs sys/health too, so it never reads as
//     audit-blocked;
//   - anything else changes nothing.
func (m *Monitor) ObserveAudited(ctx context.Context, err error) {
	if ctx.Err() != nil {
		return
	}
	switch {
	case err == nil, errors.Is(err, secretstore.ErrNotFound), errors.Is(err, secretstore.ErrCASMismatch),
		errors.Is(err, secretstore.ErrDenied):
		m.clearAuditBlocked(ctx, "an audited call was answered")
	case isClientTimeout(err):
		h, herr := m.store.Health(ctx)
		if ctx.Err() != nil || secretstore.InactiveReason(h, herr) != "" {
			return
		}
		m.mu.Lock()
		m.auditBlocked = true
		m.mu.Unlock()
		m.record(ctx, AuditBlocked, string(AuditBlocked), h, nil)
	}
}

// isClientTimeout reports whether err is a store call that ran out of time on
// the client's per-call bound. The caller's ctx is checked separately: a
// caller deadline leaves the caller's ctx done.
func isClientTimeout(err error) bool {
	return errors.Is(err, secretstore.ErrUnreachable) && errors.Is(err, context.DeadlineExceeded)
}

// isBlank reads the blank verdict. A verdict that cannot be read is blank,
// with one WARN until it reads again: fail closed (ERR-CLOSED).
func (m *Monitor) isBlank(ctx context.Context) bool {
	blank, err := m.blank(ctx)
	m.mu.Lock()
	warn := err != nil && !m.blankUnread
	m.blankUnread = err != nil
	m.mu.Unlock()
	if warn {
		m.log.LogAttrs(ctx, slog.LevelWarn, "secret store blank verdict unreadable; reading the store as blank",
			slog.String("component", "secretstore"), slog.String("err", err.Error()))
	}
	return blank || err != nil
}

func (m *Monitor) isAuditBlocked() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.auditBlocked
}

// clearAuditBlocked lowers the audit-blocked fact, logging only when it was
// raised.
func (m *Monitor) clearAuditBlocked(ctx context.Context, why string) {
	m.mu.Lock()
	was := m.auditBlocked
	m.auditBlocked = false
	m.mu.Unlock()
	if was {
		m.log.LogAttrs(ctx, slog.LevelInfo, "secret store accepting audit records again",
			slog.String("component", "secretstore"), slog.String("reason", why))
	}
}

// Quiesce records that jobID holds the store quiesced for reason, so a
// not-ready store reads Quiesced while that job runs (F4.1,
// geekdojo/geekdojo-brain#765, #830). release ends the hold; calling it again
// does nothing.
func (m *Monitor) Quiesce(jobID string, reason QuiesceReason) (release func()) {
	h := &hold{jobID: jobID, reason: reason}
	m.mu.Lock()
	m.holds[h] = struct{}{}
	m.mu.Unlock()
	m.log.Info("secret store quiesced for "+reason.phrase(),
		"component", "secretstore", "event", "secretstore.quiesced", "job_id", jobID, "reason", reason.String())
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			delete(m.holds, h)
			m.mu.Unlock()
			m.log.Info("secret store quiesce released",
				"component", "secretstore", "event", "secretstore.quiesce_released", "job_id", jobID, "reason", reason.String())
		})
	}
}

// quiesced reports whether a hold is held by a job that is running now, and
// that hold's reason. A hold whose job is not running, or whose status cannot
// be read, is ignored with a WARN, so a leaked hold cannot hide an outage.
// With two running holds, a seal rotation's reason wins: it is the one that
// restarts the store.
func (m *Monitor) quiesced(ctx context.Context) (QuiesceReason, bool) {
	m.mu.Lock()
	holds := make([]*hold, 0, len(m.holds))
	for h := range m.holds {
		holds = append(holds, h)
	}
	m.mu.Unlock()
	running := false
	reason := QuiesceBackup
	for _, h := range holds {
		ok, err := m.jobRunning(ctx, h.jobID)
		if err == nil && ok {
			running = true
			reason = max(reason, h.reason)
			continue
		}
		if err == nil {
			err = errors.New("the job is not running")
		}
		m.mu.Lock()
		warn := !h.warned
		h.warned = true
		m.mu.Unlock()
		if warn {
			m.log.LogAttrs(ctx, slog.LevelWarn, "secret store quiesce hold ignored",
				slog.String("component", "secretstore"), slog.String("job_id", h.jobID), slog.String("err", err.Error()))
		}
	}
	return reason, running
}

// Alerts reads the state now and returns its alert, or none when the store
// is ready. Since is when the state was first observed. A reading whose ctx
// ended returns none: nobody is waiting for the list.
func (m *Monitor) Alerts(ctx context.Context, _ time.Time) []proto.Alert {
	st, since, err := m.read(ctx)
	if err != nil {
		return nil
	}
	m.mu.Lock()
	reason := m.reason
	m.mu.Unlock()
	a, ok := alertFor(st, reason)
	if !ok {
		return nil
	}
	a.Since = since
	return []proto.Alert{a}
}

// alertFor is the alert a state raises; reason words the Quiesced copy. The
// copy never names the vendor.
func alertFor(st State, reason QuiesceReason) (proto.Alert, bool) {
	const unaffected = " Running apps are not affected."
	a := proto.Alert{ID: "secret-store:" + string(st), Severity: proto.AlertCrit, Source: proto.AlertSourceSecurity}
	switch st {
	case Sealed:
		a.Title = "The secret store is sealed."
		a.Detail = "The secret store is running but sealed, so it cannot serve secrets. " +
			"Apps that use secrets cannot be deployed until it is unsealed." + unaffected
	case Uninitialised:
		a.Title = "The secret store has not been set up."
		a.Detail = "The secret store is running but has never been initialised, so it cannot serve secrets. " +
			"Apps that use secrets cannot be deployed until it is." + unaffected
	case Unreachable:
		a.Title = "The control plane cannot use the secret store."
		a.Detail = "The control plane cannot use the secret store: it is stopped, not answering, or its configuration was refused. " +
			"Apps that use secrets cannot be deployed until this is fixed." + unaffected + " The api log names the cause."
	case AuditBlocked:
		a.Title = "The secret store is not accepting audit records."
		a.Detail = "The secret store answers, but requests it must audit are timing out, so it cannot serve secrets. " +
			"Apps that use secrets cannot be deployed until it recovers." + unaffected + " The api log names the cause."
	case Blank:
		a.Title = "The secret store is empty, but this cluster was set up."
		a.Detail = "The secret store started with no data on a cluster that was set up, so the secrets it held are not there. " +
			"Apps that use secrets cannot be deployed, and backups are refused so the empty store never replaces a good backup." + unaffected +
			" Restore this cluster from a backup to bring the secret store's data back."
	case Quiesced:
		a.Severity = proto.AlertWarn
		if reason == QuiesceSealRotation {
			a.Title = "The secret store is paused for a seal-key rotation."
			a.Detail = "The secret store is paused while its seal key is rotated. " +
				"Apps that use secrets cannot be deployed until the rotation finishes." + unaffected
			break
		}
		a.Title = "The secret store is paused for a backup."
		a.Detail = "The secret store is paused while a backup runs. " +
			"Apps that use secrets cannot be deployed until the backup finishes." + unaffected
	default:
		return proto.Alert{}, false
	}
	return a, true
}
