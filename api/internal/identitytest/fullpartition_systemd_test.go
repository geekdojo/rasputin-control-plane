package identitytest

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/proctest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/api/internal/sysunit"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
	"github.com/geekdojo/rasputin-control-plane/api/internal/unitrecover"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// fullBelow is this test's "partition full" line: far below what the
// database's data leaves free on the 128 MiB tmpfs, far above the nothing a
// filled one has.
const fullBelow = 8 << 20

// TestIdentitySystemd_FullPartition is TC-979-04
// (geekdojo/geekdojo-brain#979): with the data partition full, the database
// unit leaves active and Keycloak stops with it; the state reads
// database-down and identity.recover arms but is not due; once there is room
// it is due exactly once, its step restarts the pair through
// sysunit.RestartUnits, and the state reaches Ready.
func TestIdentitySystemd_FullPartition(t *testing.T) {
	cfg, ok := systemdPreflight(t)
	if !ok {
		return
	}
	ctx := waitCtx(t)
	pair := newPair(t, cfg)
	if err := pair.StartDB(ctx, 128); err != nil {
		t.Fatal(err)
	}
	if err := pair.StartKeycloak(ctx, KeycloakOptions{}); err != nil {
		t.Fatal(err)
	}
	leaf, err := pair.KC.CA().MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
	if err != nil {
		t.Fatal(err)
	}
	run := identitystate.RunFunc(cfg.Run)
	units := identitystate.SystemctlUnits(run, pair.KCUnit, pair.DBUnit)
	mon := newStateMonitor(t, cfg, stateDeps{
		units: units, exits: pair.Exits, health: productionClient(t, pair.KC, leaf), ledger: openJobs(t),
	})
	awaitState(t, ctx, cfg.Logger, mon, identitystate.Ready, pair.KCOutput)

	log, rec := logkittest.New()
	rcv, err := unitrecover.New(unitrecover.Deps{
		Kind: "identity.recover", Service: "sign-in service", Component: "identity",
		Dir: pair.PGData, Free: storage.FreeBytes, FullBelow: fullBelow,
		Unit:      pair.KCUnit,
		UnitState: identitystate.PairStateOf(units),
		Held:      func(context.Context) bool { return false },
		Restoring: func() (string, bool) { return "", false },
		Restart: func(ctx context.Context) error {
			return sysunit.RestartUnits(ctx, run, []string{pair.DBUnit, pair.KCUnit}, pair.KCUnit)
		},
		Log:         log,
		StepTimeout: 15 * time.Minute, // identityRecoverStepTimeout
	})
	if err != nil {
		t.Fatal(err)
	}

	// Full.
	if err := pair.Fill(); err != nil {
		t.Fatal(err)
	}
	dbState, err := pair.AwaitDBDown(ctx)
	if err != nil {
		t.Fatalf("%v\n%s", err, pair.KCOutput())
	}
	kcState := pair.awaitKCNotActive(ctx)
	t.Logf("TC-979-04 full: database unit %s, identity unit %s", dbState, kcState)
	if st, err := mon.State(ctx); err != nil || st != identitystate.DatabaseDown {
		t.Fatalf("full: state %s (%v), want database-down", st, err)
	}
	if due, _ := rcv.Due(ctx); due {
		t.Fatal("full: identity.recover was due")
	}
	if n := len(rec.Matching(slog.LevelInfo, "sign-in service failed while the data partition was full")); n != 1 {
		t.Fatalf("full: %d armed records, want 1\n%s", n, rec.Text())
	}

	// Room again.
	if err := pair.Free(); err != nil {
		t.Fatal(err)
	}
	due1, reason := rcv.Due(ctx)
	due2, _ := rcv.Due(ctx)
	if !due1 || due2 {
		t.Fatalf("with room: due %t (%s) then %t, want exactly once", due1, reason, due2)
	}
	store := openJobs(t)
	runner := jobs.NewRunner(store, nil)
	runner.Register(rcv.Workflow())
	j, err := runner.Submit(ctx, "identity.recover", nil, "system")
	if err != nil {
		t.Fatal(err)
	}
	runner.Wait()
	steps, err := store.ListSteps(ctx, j.ID)
	if err != nil || len(steps) != 1 || string(steps[0].Result) != `{"restarted":true}` {
		var got any = steps
		if len(steps) == 1 {
			got = string(steps[0].Result) + " " + steps[0].Error
		}
		t.Fatalf("recover job steps: %v (%v), want restarted:true", got, err)
	}
	awaitState(t, ctx, cfg.Logger, mon, identitystate.Ready, pair.KCOutput)
	if due, _ := rcv.Due(ctx); due {
		t.Fatal("after the restart: identity.recover was due again")
	}
}

// AwaitDBDown pushes WAL through the database's current container until the
// unit is failed or in auto-restart, and returns that state. A logical
// message writes WAL and no table row, so what needs a block is the next WAL
// segment. A deadline failure names the fact.
func (p *systemdPair) AwaitDBDown(ctx context.Context) (string, error) {
	var state string
	err := proctest.Await(ctx, nil, func(ctx context.Context) (bool, string, error) {
		if id, err := p.DBContainer(ctx); err == nil && id != "" {
			// Its failure is the point: ENOSPC ends it.
			_, _ = p.d.exec(ctx, strings.Fields(id)[0], "psql", "-U", dbUser, "-d", dbName, "-c",
				"SELECT pg_logical_emit_message(false, 'fill', repeat('x', 4000000))")
		}
		s, err := unitState(ctx, p.run, p.DBUnit)
		if err != nil {
			return false, "", err
		}
		state = s
		return strings.HasPrefix(s, "failed/") || s == "activating/auto-restart", "unit " + s, nil
	}, func(last string) {
		p.cfg.Logger.Info("database unit with the partition full", "unit", p.DBUnit, "state", last)
	})
	if err != nil {
		return "", errNamed("the database unit "+p.DBUnit+" is failed or in auto-restart with the partition full", err)
	}
	return state, nil
}

// awaitKCNotActive waits until the identity unit is not active, which
// Requires= makes it once its database is not running, and returns its state.
func (p *systemdPair) awaitKCNotActive(ctx context.Context) string {
	p.t.Helper()
	var state string
	err := proctest.Await(ctx, nil, func(ctx context.Context) (bool, string, error) {
		s, err := unitState(ctx, p.run, p.KCUnit)
		state = s
		return err == nil && !strings.HasPrefix(s, "active/"), s, err
	}, nil)
	if err != nil {
		p.t.Fatal(errNamed("the identity unit "+p.KCUnit+" is not active", err))
	}
	return state
}

// awaitState waits until the monitor reads want, naming the fact on a
// deadline, with output's text.
func awaitState(t *testing.T, ctx context.Context, log *slog.Logger, m *identitystate.Monitor, want identitystate.State, output func() string) {
	t.Helper()
	err := proctest.Await(ctx, nil, func(ctx context.Context) (bool, string, error) {
		st, err := m.State(ctx)
		return err == nil && st == want, string(st), err
	}, func(last string) { log.Info("identity state", "state", last) })
	if err != nil {
		t.Fatalf("%v\n%s", errNamed("the identity state is "+string(want), err), output())
	}
}
