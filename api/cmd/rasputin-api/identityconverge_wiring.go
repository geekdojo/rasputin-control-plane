package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"time"

	idclient "github.com/geekdojo/rasputin-control-plane/api/internal/identity/client"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/converge"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/migrations"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/scheduler"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The identity realm's lifecycle on facts (geekdojo/geekdojo-brain#981,
// Identity 3.5), under keycloak only: the features check the identity state
// reads, and identity.converge, identity.migrate and identity.arm with their
// triggers, read on the identity check's cadence (storeAuditCheckEvery, K03).

const (
	// identityBuildConf is the shipped build options the features check
	// compares the running service with (scripts/build-release.sh).
	identityBuildConf = "/usr/share/rasputin/identity/keycloak-build.conf"
	// identityArmedMarker is identity.arm's marker; the OS's stage step
	// removes the staged realm import once it is present.
	identityArmedMarker = "/var/lib/rasputin/identity/armed"
	// identityRealmStepTimeout bounds one converge, migrate or arm step: a
	// few Admin API calls. It only marks a job gone far outside that as
	// dead, and decides nothing else.
	identityRealmStepTimeout = 5 * time.Minute
)

// identityFeatures is the identity state's features check under keycloak,
// and nil in every other mode. A nil session under keycloak is nil too,
// which identityStateWiring refuses.
func identityFeatures(mode string, session *idclient.Session, log *slog.Logger) func(context.Context, string) (bool, error) {
	if mode != identityModeKeycloak || session == nil || log == nil {
		return nil
	}
	f, err := converge.NewFeatureCheck(session, func() ([]byte, error) { return os.ReadFile(identityBuildConf) }, log)
	if err != nil {
		return nil
	}
	return f.Mismatch
}

// identityConvergeDeps is what the wiring takes from main.
type identityConvergeDeps struct {
	mode     string
	session  *idclient.Session
	monitor  *identitystate.Monitor
	ledger   *jobs.Store
	settings *setup.Store
	// createArmed creates the armed marker once (atrest.CreateSecretFile);
	// stat reads whether it is there (os.Stat).
	createArmed func(path string, data []byte) error
	stat        func(path string) (fs.FileInfo, error)
	now         func() time.Time
	log         *slog.Logger
}

// identityConverge is what identityConvergeWiring built. Every field is
// empty outside keycloak.
type identityConverge struct {
	workflows []jobs.Workflow
	entryList []scheduler.Entry
	converger *converge.Converger
}

// register registers the three workflows.
func (w identityConverge) register(r interface{ Register(jobs.Workflow) }) {
	for _, wf := range w.workflows {
		r.Register(wf)
	}
}

// entries is the three triggers' scheduler entries, or none.
func (w identityConverge) entries() []scheduler.Entry { return w.entryList }

// alerts is converge's drift alert, for the identity alerts composition.
func (w identityConverge) alerts(ctx context.Context, now time.Time) []proto.Alert {
	if w.converger == nil {
		return nil
	}
	return w.converger.Alerts(ctx, now)
}

// identityConvergeWiring builds the realm lock, the migrations runner, the
// converger, the armer, their workflows and their three triggers under
// keycloak. It does no I/O. An error is a programming error, which main
// treats as fatal.
func identityConvergeWiring(d identityConvergeDeps) (identityConverge, error) {
	if d.mode != identityModeKeycloak {
		return identityConverge{}, nil
	}
	if d.session == nil || d.monitor == nil || d.ledger == nil || d.settings == nil || d.createArmed == nil ||
		d.stat == nil || d.now == nil || d.log == nil {
		return identityConverge{}, errors.New("identity converge: a collaborator is nil under keycloak")
	}
	lock := &sync.Mutex{}
	runner, err := migrations.New(migrations.Deps{Admin: d.session, Realm: identityRealm, Lock: lock, All: migrations.All, Log: d.log})
	if err != nil {
		return identityConverge{}, fmt.Errorf("identity converge: %w", err)
	}
	settings := d.settings
	conv, err := converge.New(converge.Deps{
		Admin: d.session, Settings: settings, Realm: identityRealm, Lock: lock,
		// RedirectURIs is empty until Identity 4.1's door table passes one
		// (#983): the baseline's own state, so it fails closed.
		Inputs: func(ctx context.Context) (converge.Inputs, error) {
			name, err := settings.Get(ctx, setup.KeyInstallName)
			return converge.Inputs{InstallName: name, RedirectURIs: map[string][]string{}}, err
		},
		Now: d.now, Log: d.log,
	})
	if err != nil {
		return identityConverge{}, fmt.Errorf("identity converge: %w", err)
	}
	armer, err := converge.NewArmer(converge.ArmDeps{
		Admin: d.session, Settings: settings, Realm: identityRealm,
		Path: identityArmedMarker, CreateArmed: d.createArmed, Stat: d.stat, Log: d.log,
	})
	if err != nil {
		return identityConverge{}, fmt.Errorf("identity converge: %w", err)
	}
	w := identityConverge{
		workflows: []jobs.Workflow{
			converge.ConvergeWorkflow(conv, identityRealmStepTimeout),
			converge.MigrateWorkflow(runner, identityRealmStepTimeout),
			converge.ArmWorkflow(armer, identityRealmStepTimeout),
		},
		converger: conv,
	}
	for _, t := range []struct {
		kind  string
		cond  converge.Cond
		level slog.Level
	}{
		{converge.ConvergeKind, converge.ConvergeCond(conv, runner), slog.LevelWarn},
		{converge.MigrateKind, converge.MigrateCond(runner), slog.LevelError},
		{converge.ArmKind, converge.ArmCond(armer), slog.LevelWarn},
	} {
		trig, err := converge.NewTrigger(converge.TriggerDeps{
			Kind: t.kind, Ready: d.monitor, Ledger: d.ledger, Cond: t.cond, CondErrLevel: t.level, Log: d.log,
		})
		if err != nil {
			return identityConverge{}, fmt.Errorf("identity converge: %w", err)
		}
		w.entryList = append(w.entryList, scheduler.Entry{Kind: t.kind, Interval: storeAuditCheckEvery, Due: trig.Due})
	}
	return w, nil
}
