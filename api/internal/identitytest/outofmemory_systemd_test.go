package identitytest

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/identitystate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/proctest"
)

// TestIdentitySystemd_OutOfMemory is TC-979-02 (geekdojo/geekdojo-brain#979),
// and capability row T79 K-OOMEXIT: the pinned Keycloak with a 16 MiB heap
// runs out of memory and exits with Java's status 3, which systemd hands to
// ExecStopPost= as EXIT_CODE=exited and EXIT_STATUS=3. Under Restart=always
// it loops until systemd's own start limit (StartLimitBurst=3,
// StartLimitIntervalSec=infinity) fails the unit, with no stop issued. The
// stand-in writes one record per invocation; a reading then gives
// out-of-memory and exactly one identity.service_exit job per record, and
// consumes every record but the one `last` names; a second reading adds none.
func TestIdentitySystemd_OutOfMemory(t *testing.T) {
	cfg, ok := systemdPreflight(t)
	if !ok {
		return
	}
	standIn, err := filepath.Abs(filepath.Join("testdata", "exit-record-standin.sh"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := waitCtx(t)
	pair := newPair(t, cfg)
	if err := pair.StartDB(ctx, 256); err != nil {
		t.Fatal(err)
	}
	if err := pair.StartKeycloak(ctx, KeycloakOptions{Heap: "-Xms16m -Xmx16m", StartLimitBurst: 3, StandIn: standIn}); err != nil {
		t.Fatal(err)
	}

	err = proctest.Await(ctx, nil, func(ctx context.Context) (bool, string, error) {
		m, err := unitProps(ctx, pair.run, pair.KCUnit, "ActiveState", "Result")
		if err != nil {
			return false, "", err
		}
		s := m["ActiveState"] + " Result=" + m["Result"]
		return m["ActiveState"] == "failed" && m["Result"] == "start-limit-hit", s, nil
	}, func(last string) { cfg.Logger.Info("identity unit", "unit", pair.KCUnit, "state", last) })
	if err != nil {
		t.Fatalf("%v\nidentity service output:\n%s", errNamed("the identity unit is failed with Result=start-limit-hit", err), pair.KCOutput())
	}

	// The snapshot: exactly three records plus last, each systemd's own
	// out-of-memory exit, and last naming the unit's last invocation.
	ents, err := os.ReadDir(pair.Exits)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range ents {
		if e.Name() == "last" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(pair.Exits, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		want := "outcome=exit-code\ninvocation_id=" + e.Name() + "\nexit_code=exited\nexit_status=3\n"
		if string(b) != want {
			t.Errorf("record %s = %q, want %q", e.Name(), b, want)
		}
		t.Logf("TC-979-02 record %s: %q", e.Name(), b)
		ids = append(ids, e.Name())
	}
	if len(ids) != 3 || len(ents) != 4 {
		t.Fatalf("exits directory holds %d entries (%d records), want three records and last\n%s", len(ents), len(ids), pair.KCOutput())
	}
	lastB, err := os.ReadFile(filepath.Join(pair.Exits, "last"))
	if err != nil {
		t.Fatal(err)
	}
	last := strings.TrimSpace(string(lastB))
	inv, err := unitProps(ctx, pair.run, pair.KCUnit, "InvocationID")
	if err != nil {
		t.Fatal(err)
	}
	if last != inv["InvocationID"] || !slices.Contains(ids, last) {
		t.Fatalf("last = %s, InvocationID = %s, records %v: last must name the unit's last invocation", last, inv["InvocationID"], ids)
	}

	store := openJobs(t)
	mon := newStateMonitor(t, cfg, stateDeps{
		units: identitystate.SystemctlUnits(identitystate.RunFunc(cfg.Run), pair.KCUnit, pair.DBUnit),
		exits: pair.Exits, health: noHealth{t}, ledger: store,
	})
	st, err := mon.State(ctx)
	if err != nil || st != identitystate.OutOfMemory {
		t.Fatalf("first reading: %s (%v), want out-of-memory", st, err)
	}
	a := mon.Alerts(ctx, cfg.Now())
	if len(a) != 1 || a[0].Title != "Sign-in stopped because the sign-in service ran out of memory. It restarts by itself." {
		t.Fatalf("alerts = %+v, want the out-of-memory sentence", a)
	}
	jobsGot, err := store.ListAllJobsByKind(ctx, identitystate.ExitKind)
	if err != nil {
		t.Fatal(err)
	}
	var jobIDs, wantIDs []string
	for _, j := range jobsGot {
		if j.Status != "failed" {
			t.Errorf("job %s status %s, want failed", j.ID, j.Status)
		}
		jobIDs = append(jobIDs, j.ID)
	}
	for _, id := range ids {
		wantIDs = append(wantIDs, "identity-exit-"+id)
	}
	sort.Strings(jobIDs)
	sort.Strings(wantIDs)
	if !slices.Equal(jobIDs, wantIDs) {
		t.Fatalf("jobs = %v, want one per record %v", jobIDs, wantIDs)
	}
	left, err := os.ReadDir(pair.Exits)
	if err != nil {
		t.Fatal(err)
	}
	var leftNames []string
	for _, e := range left {
		leftNames = append(leftNames, e.Name())
	}
	sort.Strings(leftNames)
	if want := []string{last, "last"}; !slices.Equal(leftNames, want) {
		t.Fatalf("after the reading the directory holds %v, want %v", leftNames, want)
	}

	st, err = mon.State(ctx)
	if err != nil || st != identitystate.OutOfMemory {
		t.Fatalf("second reading: %s (%v), want out-of-memory", st, err)
	}
	if again, _ := store.ListAllJobsByKind(ctx, identitystate.ExitKind); len(again) != len(ids) {
		t.Fatalf("the second reading made %d jobs, want %d", len(again), len(ids))
	}
}
