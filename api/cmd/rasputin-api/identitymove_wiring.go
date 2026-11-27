package main

import (
	"context"
	"errors"
	"fmt"
	"io"
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
// submission of the move is refused. Identity 5.2 (#1005) adds the move's
// bridge: the moved accounts' local facts, accounts.set_first_password, and
// their install on the auth service, which also turns on the pre-update
// session.

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

// Repair is the held state's C9 state, or errMoveUnwired: the break-glass
// repair page and the lost-accounts alert read it (#321).
func (h *moveStateHolder) Repair(ctx context.Context) (move.Repair, error) {
	s := h.p.Load()
	if s == nil {
		return move.Repair{}, errMoveUnwired
	}
	return s.Repair(ctx)
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
	// auth is the service the bridge is installed on; runner submits the
	// first password; signInOrigin is the home door's origin, "" while the
	// doors are off; newCorrelationID and rand are the bridge's (#1005).
	auth             *auth.Service
	runner           accounts.Submitter
	signInOrigin     string
	newCorrelationID func() string
	rand             io.Reader
	now              func() time.Time
	log              *slog.Logger
}

// identityMove is what identityMoveWiring built; empty outside keycloak.
type identityMove struct {
	workflow *jobs.Workflow
	entry    *scheduler.Entry
	store    *move.Store
	// firstPassword is accounts.set_first_password, the bridge's job.
	firstPassword *jobs.Workflow
}

// register registers identity.move and accounts.set_first_password, under
// keycloak only.
func (w identityMove) register(r interface{ Register(jobs.Workflow) }) {
	if w.workflow != nil {
		r.Register(*w.workflow)
	}
	if w.firstPassword != nil {
		r.Register(*w.firstPassword)
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
		d.acct.removed == nil || d.acct.checker == nil || d.designations == nil || d.monitor == nil || d.converger == nil || d.ledger == nil ||
		d.holder == nil || d.auth == nil || d.runner == nil || d.newCorrelationID == nil || d.rand == nil || d.now == nil || d.log == nil {
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
	fp, err := installBridge(d, store, state)
	if err != nil {
		return identityMove{}, err
	}
	wf := mover.Workflow()
	d.holder.p.Store(state)
	return identityMove{workflow: &wf, entry: &scheduler.Entry{Kind: move.Kind, Interval: storeAuditCheckEvery, Due: trig.Due}, store: store,
		firstPassword: fp}, nil
}

// installBridge builds the move's bridge (#1005) and installs it, with the
// pre-update session, on the auth service, and returns its job. With the
// doors off there is no home door to send the person on to, so nothing is
// installed: the bridge's routes answer 404 and no pre-update session
// resolves.
func installBridge(d identityMoveDeps, store *move.Store, state *move.State) (*jobs.Workflow, error) {
	if d.signInOrigin == "" {
		d.log.Info("The move's bridge is off: the sign-in doors are off.", "component", "identity.move", "event", "bridge.off")
		return nil, nil
	}
	accts, err := move.NewAccounts(store, state, d.oldUsers, d.designations)
	if err != nil {
		return nil, fmt.Errorf("identity move: %w", err)
	}
	fp, err := accounts.NewFirstPassword(accounts.FirstPasswordDeps{
		Users: d.acct.users, Checker: d.acct.checker, Removed: d.acct.removed, Facts: store, Runner: d.runner,
		Passwords: accounts.NewHeld(), Emails: accounts.NewHeld(), Lock: d.acct.lock, Log: d.log, StepTimeout: identityRealmStepTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("identity move: %w", err)
	}
	if err := d.auth.InstallBridge(auth.BridgeDeps{Accounts: accts, FirstPassword: fp, SignInOrigin: d.signInOrigin,
		NewCorrelationID: d.newCorrelationID, Now: d.now, Rand: d.rand, Log: d.log}); err != nil {
		return nil, fmt.Errorf("identity move: %w", err)
	}
	wf := fp.Workflow()
	return &wf, nil
}
