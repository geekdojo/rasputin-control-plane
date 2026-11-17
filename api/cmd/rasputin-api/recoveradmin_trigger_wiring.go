package main

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/recoveradmin"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/scheduler"
)

// What submits identity.recover_admin (geekdojo/geekdojo-brain#1127,
// Identity 2.8), under keycloak only: recoveradmin.Trigger, read on the
// identity check's cadence (storeAuditCheckEvery, K03).
//
// The restored alert is raised through a holder, because the job is
// registered before runner.Recover while the alerts service is built much
// later. The entry is not due while the holder is unset, so setting it is the
// fact the first run waits on, not the scheduler's first delay (F-1127-04).

// restoredFunc raises the restored alert for one job
// (alerts.Service.RaiseIdentityAdminRestored).
type restoredFunc func(ctx context.Context, jobID string) error

// errRestoredUnwired is a restored alert raised before the alerts service
// was wired; the gated entry makes it unreachable from the trigger.
var errRestoredUnwired = errors.New("the restored alert is not wired yet")

// restoredVia is recoveradmin.Deps.Restored over the holder.
func restoredVia(holder *atomic.Pointer[restoredFunc]) func(ctx context.Context, jobID string) error {
	return func(ctx context.Context, jobID string) error {
		f := holder.Load()
		if f == nil {
			return errRestoredUnwired
		}
		return (*f)(ctx, jobID)
	}
}

// identityAdminTrigger builds the trigger and its scheduler entry under
// keycloak; outside it, both are nil. It does no I/O. An error is a
// programming error, which main treats as fatal.
func identityAdminTrigger(mode string, mon *identitystate.Monitor, session *idclient.Session, ledger *jobs.Store,
	holder *atomic.Pointer[restoredFunc], log *slog.Logger) (*scheduler.Entry, *recoveradmin.Trigger, error) {
	if mode != identityModeKeycloak {
		return nil, nil, nil
	}
	if mon == nil || session == nil || ledger == nil || holder == nil || log == nil {
		return nil, nil, errors.New("identity admin trigger: a collaborator is nil under keycloak")
	}
	trig, err := recoveradmin.NewTrigger(recoveradmin.TriggerDeps{Ready: mon, Admin: session, Ledger: ledger, Log: log})
	if err != nil {
		return nil, nil, err
	}
	gated := func(ctx context.Context) (bool, string) {
		if holder.Load() == nil {
			return false, ""
		}
		return trig.Due(ctx)
	}
	return &scheduler.Entry{Kind: recoveradmin.Kind, Interval: storeAuditCheckEvery, Due: gated}, trig, nil
}

// entriesOf is the entry as a slice to append: it, or none.
func entriesOf(e *scheduler.Entry) []scheduler.Entry {
	if e == nil {
		return nil
	}
	return []scheduler.Entry{*e}
}
