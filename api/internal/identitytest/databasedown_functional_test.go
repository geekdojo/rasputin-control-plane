package identitytest

import (
	"context"
	"errors"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/functest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// TestIdentityState_DatabaseDown is TC-979-01 (geekdojo/geekdojo-brain#979),
// and capability row T80 K-HEALTH: with the pinned Keycloak ready, docker
// stop on its pinned PostgreSQL makes /health/ready answer 503 naming the
// database check DOWN, so the identity state reads database-down and Ready
// refuses with identity_not_ready; docker start brings it back to Ready with
// no identity alert. The units stand-in reports both units active, as they
// would be: a container stopped under the unit is the database the service
// cannot reach. It runs its own Env, whose database survives a stop.
func TestIdentityState_DatabaseDown(t *testing.T) {
	p := NewPackage(func() (Config, error) {
		c, err := ConfigFromEnv()
		c.pgRestartable = true
		return c, err
	})
	cfg, err := p.loadConfig()
	if err != nil {
		functest.SkipOrFail(t, SwitchEnv, "%v", err)
		return
	}
	if !p.preflight(t, cfg) {
		return
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	env, err := h.Start(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Close(context.Background()); err != nil {
			t.Errorf("teardown: %v", err)
		}
	})
	leaf, err := env.CA().MintLeafToDisk(t.TempDir(), tlsca.LeafSpec{Usage: tlsca.UsageClient, CommonName: "rasputin-api"})
	if err != nil {
		t.Fatal(err)
	}
	health := &recordingHealth{inner: productionClient(t, env, leaf)}
	active := identitystate.Unit{ActiveState: "active", SubState: "running", InvocationID: "0123456789abcdef0123456789abcdef"}
	mon := newStateMonitor(t, cfg, stateDeps{
		units: func(context.Context) (identitystate.Units, error) {
			return identitystate.Units{KC: active, DB: active}, nil
		},
		exits:  t.TempDir(),
		health: health,
		ledger: openJobs(t),
	})
	ctx := waitCtx(t)
	noOutput := func() string { return "" }
	if err := mon.Ready(ctx); err != nil {
		t.Fatalf("Ready before the stop: %v", err)
	}

	if _, err := env.docker.run(ctx, env.docker.bin, "stop", env.pgID); err != nil {
		t.Fatalf("docker stop: %v", err)
	}
	awaitState(t, ctx, cfg.Logger, mon, identitystate.DatabaseDown, noOutput)
	rep, herr := health.last()
	t.Logf("TC-979-01: the database stopped: %v; checks %+v", herr, rep.Checks)
	if !rep.Down("Keycloak database connections async health check") {
		t.Fatalf("the 503's report %+v does not name the database check DOWN", rep)
	}
	a := mon.Alerts(ctx, cfg.Now())
	if len(a) != 1 || a[0].ID != "identity:database-down" || a[0].Title != "Sign-in is unavailable because its database is not running." {
		t.Fatalf("alerts = %+v, want identity:database-down with its sentence", a)
	}
	err = mon.Ready(ctx)
	var nr *identitystate.NotReadyError
	if !errors.As(err, &nr) || nr.Code() != "identity_not_ready" {
		t.Fatalf("Ready = %v, want a NotReadyError with identity_not_ready", err)
	}

	if _, err := env.docker.run(ctx, env.docker.bin, "start", env.pgID); err != nil {
		t.Fatalf("docker start: %v", err)
	}
	awaitState(t, ctx, cfg.Logger, mon, identitystate.Ready, noOutput)
	if a := mon.Alerts(ctx, cfg.Now()); len(a) != 0 {
		t.Fatalf("alerts after the start = %+v, want none", a)
	}
}
