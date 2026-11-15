package identitytest

import (
	"context"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/proctest"
)

// TestIdentitySystemd_FullPartition is TC-979-04's pre-build proof
// (geekdojo/geekdojo-brain#979): with the identity database's partition full,
// real PostgreSQL leaves active under real systemd.
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
	if err := pair.Fill(); err != nil {
		t.Fatal(err)
	}
	state, err := pair.AwaitDBDown(ctx)
	if err != nil {
		t.Fatalf("%v\n%s", err, pair.journalTail(context.Background(), pair.DBUnit))
	}
	t.Logf("TC-979-04 proof: with the partition full the database unit is %s", state)
}

// AwaitDBDown pushes WAL through the database's current container until the
// unit is failed or in auto-restart, and returns that state.
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
