package recoveradmin

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The trigger (geekdojo/geekdojo-brain#1127, Identity 2.8): what submits
// identity.recover_admin, and the only thing that does.
//
// The fact is three conditions, read on the scheduler's per-minute check:
//
//   - the identity service is ready (Ready answers nil);
//   - the api's own Admin API session, logging in as rasputin-admin, is
//     refused for its own client: the token endpoint answers invalid_client
//     or unauthorized_client (ErrDenied with an OAuth error code), or its
//     GET of the realm answers 403 (ErrForbidden: the client has lost its
//     roles);
//   - no identity.recover_admin job has been created since the trigger was
//     last armed.
//
// Nothing else is the fact. A TLS refusal (ErrDenied with no OAuth error)
// cannot be fixed by a recovery. invalid_request is what a disabled or
// brute-force-locked service-account user answers, which anyone outside can
// try to cause, so it never fires (F-1127-01). The trigger reads only its own
// login's answer, never the identity service's events or log.
//
// The latch is the job ledger (F-1127-03): armedAt is the newest
// identity.recover_admin job's id when the trigger was armed, and the fact
// holds only while the newest is still that one. A submit that failed leaves
// no row, so the next check fires again; a run, in flight or finished, latches
// it. The trigger is armed on the first refused reading of a process and
// again after any probe that succeeds, so a failed run is tried again at most
// once per api start and never on a timer or a count.

// AdminRefusedAlertID is the still-refused alert's id (F-1127-08).
const AdminRefusedAlertID = "identity:admin-client-refused"

const (
	reasonDue           = "the identity service refuses the api's admin client"
	reasonLedgerUnread  = "the job ledger could not be read"
	adminRefusedTitle   = "The control plane cannot administer its sign-in service."
	adminRefusedDetail  = "Its admin client is refused and the automatic recovery failed (see Tasks). Restarting the control plane retries the recovery once."
	triggerComponent    = "identity"
	eventRecoverDue     = "identity.recover_admin_due"
	eventRecoverRearmed = "identity.recover_admin_rearmed"
)

// readiness is whether the identity service is ready
// (identitystate.Monitor.Ready, or idclient.Client.Ready in a test).
type readiness interface {
	Ready(ctx context.Context) error
}

// adminSession is the api's Admin API session as rasputin-admin
// (*idclient.Session).
type adminSession interface {
	Admin(ctx context.Context, method, path string, in, out any) (idclient.Response, error)
}

// jobLedger is the job ledger as the trigger reads it (*jobs.Store).
type jobLedger interface {
	ListJobsByKind(ctx context.Context, kind string, limit int) ([]*jobs.Job, error)
}

// TriggerDeps is everything a Trigger needs. NewTrigger refuses an
// incomplete one.
type TriggerDeps struct {
	Ready  readiness
	Admin  adminSession
	Ledger jobLedger
	Log    *slog.Logger
}

// Trigger decides, on each check, whether identity.recover_admin is due. It
// is safe for concurrent use: the scheduler calls Due, the alerts list calls
// Alerts.
type Trigger struct {
	d TriggerDeps

	mu sync.Mutex
	// armed is set by a refused reading and cleared by a probe that
	// succeeds, so while it is set the last probe that decided anything was
	// refused. armedAt is the newest job's id when it was set, empty for
	// none.
	armed   bool
	armedAt string
	// ledgerDown is set while the ledger cannot be read, so an outage writes
	// one WARN.
	ledgerDown bool
}

// NewTrigger checks d and returns a Trigger. It does no I/O.
func NewTrigger(d TriggerDeps) (*Trigger, error) {
	if d.Ready == nil || d.Admin == nil || d.Ledger == nil || d.Log == nil {
		return nil, errors.New("recoveradmin: a trigger collaborator is nil")
	}
	return &Trigger{d: d}, nil
}

// Due is one reading of the fact. It returns true with a reason when the job
// should be submitted. Every answer that is not the fact, and every check it
// could not make, is not due.
func (t *Trigger) Due(ctx context.Context) (bool, string) {
	if err := t.d.Ready.Ready(ctx); err != nil || ctx.Err() != nil {
		return false, ""
	}
	_, err := t.d.Admin.Admin(ctx, http.MethodGet, "/admin/realms/"+realm, nil, nil)
	if err == nil {
		t.rearm(ctx)
		return false, ""
	}
	e, refused := refusedClient(err)
	if !refused || ctx.Err() != nil {
		return false, ""
	}
	newest, err := t.newest(ctx)
	if err != nil {
		return false, reasonLedgerUnread
	}
	newestID := ""
	if newest != nil {
		newestID = newest.ID
	}
	t.mu.Lock()
	if !t.armed {
		t.armed, t.armedAt = true, newestID
	}
	due := newestID == t.armedAt
	t.mu.Unlock()
	if !due {
		return false, ""
	}
	attrs := append([]slog.Attr{slog.String("component", triggerComponent), slog.String("event", eventRecoverDue)}, e.LogAttrs()...)
	t.d.Log.LogAttrs(ctx, slog.LevelWarn, "The identity service refuses the api's admin client; its recovery is submitted.", attrs...)
	return true, reasonDue
}

// rearm clears the latch after a probe that succeeded: the client works, so
// a later loss is a new incident.
func (t *Trigger) rearm(ctx context.Context) {
	t.mu.Lock()
	was := t.armed
	t.armed, t.armedAt = false, ""
	t.mu.Unlock()
	if was {
		t.d.Log.LogAttrs(ctx, slog.LevelInfo, "The api's admin client works again; its recovery is re-armed.",
			slog.String("component", triggerComponent), slog.String("event", eventRecoverRearmed))
	}
}

// newest is the newest identity.recover_admin job, nil for none. A read that
// fails writes one WARN per outage.
func (t *Trigger) newest(ctx context.Context) (*jobs.Job, error) {
	list, err := t.d.Ledger.ListJobsByKind(ctx, Kind, 1)
	t.mu.Lock()
	wasDown := t.ledgerDown
	t.ledgerDown = err != nil
	t.mu.Unlock()
	if err != nil {
		if !wasDown {
			t.d.Log.WarnContext(ctx, "The job ledger could not be read; the admin client's recovery was not checked.",
				"component", triggerComponent, "err", err.Error())
		}
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}
	return list[0], nil
}

// Alerts is the still-refused alert, computed when read (F-1127-08): present
// while the trigger is latched, its last deciding probe was refused, and the
// run it latched on failed. It clears on the re-arm facts: a probe that
// succeeds, or a new process. A ledger that cannot be read raises nothing
// here; the alerts list's own job read reports it.
func (t *Trigger) Alerts(ctx context.Context, _ time.Time) []proto.Alert {
	t.mu.Lock()
	armed, armedAt := t.armed, t.armedAt
	t.mu.Unlock()
	if !armed {
		return nil
	}
	list, err := t.d.Ledger.ListJobsByKind(ctx, Kind, 1)
	if err != nil || len(list) == 0 {
		return nil
	}
	j := list[0]
	if j.ID == armedAt || j.Status != jobs.StatusFailed {
		return nil
	}
	since := j.CreatedAt
	if j.FinishedAt != nil {
		since = *j.FinishedAt
	}
	return []proto.Alert{{
		ID:          AdminRefusedAlertID,
		Severity:    proto.AlertWarn,
		Source:      proto.AlertSourceSecurity,
		Title:       adminRefusedTitle,
		Detail:      adminRefusedDetail,
		Since:       since,
		RelatedKind: "job",
		RelatedID:   j.ID,
	}}
}

// refusedClient is whether err is the identity service refusing the api's
// own admin client: invalid_client or unauthorized_client at the token
// endpoint, or 403 on the Admin API. It returns the error to log.
func refusedClient(err error) (*idclient.Error, bool) {
	var e *idclient.Error
	if !errors.As(err, &e) {
		return nil, false
	}
	switch {
	case e.Kind == idclient.ErrDenied && (e.OAuthError == "invalid_client" || e.OAuthError == "unauthorized_client"):
		return e, true
	case e.Kind == idclient.ErrForbidden:
		return e, true
	}
	return nil, false
}
