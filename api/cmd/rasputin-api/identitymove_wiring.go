package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/converge"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/move"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/scheduler"
)

// identity.move (geekdojo/geekdojo-brain#1004, Identity 5.1), under keycloak
// only: the move's record, its state, its workflow and its trigger, read on
// the identity check's cadence (storeAuditCheckEvery, K03). The kind table
// is built long before the accounts exist, so it reads the move's state
// through moveStateHolder, filled here; while it is empty every repair
// submission of the move is refused.

// errMoveUnwired is the move's state read before it was wired, or outside
// keycloak.
var errMoveUnwired = errors.New("the identity move is not wired")

// moveStateHolder is authz.MoveState over the state this wiring builds.
type moveStateHolder struct{ p atomic.Pointer[move.State] }

// RepairToken is the held state's, or errMoveUnwired, which the kind table
// answers as a check that failed.
func (h *moveStateHolder) RepairToken(ctx context.Context) (string, bool, error) {
	s := h.p.Load()
	if s == nil {
		return "", false, errMoveUnwired
	}
	return s.RepairToken(ctx)
}

// identityMoveDeps is what the wiring takes from main.
type identityMoveDeps struct {
	mode         string
	dbPath       string
	session      *idclient.Session
	oldUsers     *auth.Store
	acct         accountsWiring
	designations *accounts.Designations
	monitor      *identitystate.Monitor
	converger    *converge.Converger
	ledger       *jobs.Store
	holder       *moveStateHolder
	now          func() time.Time
	log          *slog.Logger
}

// identityMove is what identityMoveWiring built; empty outside keycloak.
type identityMove struct {
	workflow *jobs.Workflow
	entry    *scheduler.Entry
	store    *move.Store
}

// register registers identity.move, under keycloak only.
func (w identityMove) register(r interface{ Register(jobs.Workflow) }) {
	if w.workflow != nil {
		r.Register(*w.workflow)
	}
}

// close closes the move's record.
func (w identityMove) close() {
	if w.store != nil {
		_ = w.store.Close()
	}
}

// identityMoveWiring builds the move under keycloak and fills the holder.
// Its one I/O is opening the record, which creates the table. An error is
// fatal to main.
func identityMoveWiring(ctx context.Context, d identityMoveDeps) (identityMove, error) {
	if d.mode != identityModeKeycloak {
		return identityMove{}, nil
	}
	if d.dbPath == "" || d.session == nil || d.oldUsers == nil || d.acct.users == nil || d.acct.lock == nil || d.acct.facts == nil ||
		d.acct.removed == nil || d.designations == nil || d.monitor == nil || d.converger == nil || d.ledger == nil ||
		d.holder == nil || d.now == nil || d.log == nil {
		return identityMove{}, errors.New("identity move: a collaborator is nil under keycloak")
	}
	store, err := move.OpenStore(ctx, d.dbPath)
	if err != nil {
		return identityMove{}, fmt.Errorf("identity move: %w", err)
	}
	w, err := buildMove(d, store)
	if err != nil {
		_ = store.Close()
		return identityMove{}, err
	}
	return w, nil
}

func buildMove(d identityMoveDeps, store *move.Store) (identityMove, error) {
	state, err := move.NewState(d.oldUsers, store, d.acct.users, d.acct.removed)
	if err != nil {
		return identityMove{}, fmt.Errorf("identity move: %w", err)
	}
	mover, err := move.New(move.Deps{
		Admin: d.session, OldUsers: d.oldUsers, Persons: d.acct.users, Designations: d.designations,
		Facts: d.acct.facts, Removed: d.acct.removed, Ready: d.monitor, Records: store, Lock: d.acct.lock,
		Realm: identityRealm, Now: d.now, Log: d.log, StepTimeout: identityRealmStepTimeout,
	})
	if err != nil {
		return identityMove{}, fmt.Errorf("identity move: %w", err)
	}
	trig, err := converge.NewTrigger(converge.TriggerDeps{
		Kind: move.Kind, Ready: d.monitor, Ledger: d.ledger, Cond: move.Cond(state, d.converger),
		CondErrLevel: slog.LevelWarn, Log: d.log,
	})
	if err != nil {
		return identityMove{}, fmt.Errorf("identity move: %w", err)
	}
	wf := mover.Workflow()
	d.holder.p.Store(state)
	return identityMove{workflow: &wf, entry: &scheduler.Entry{Kind: move.Kind, Interval: storeAuditCheckEvery, Due: trig.Due}, store: store}, nil
}
