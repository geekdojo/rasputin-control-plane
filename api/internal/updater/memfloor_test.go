package updater

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/dbutil"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// The release's control-plane memory floor (geekdojo/geekdojo-brain#1011):
// 3,584 MiB, which every sentence renders as 3.5 GiB.
const (
	testFloor   = int64(3758096384)
	mib         = float64(1 << 20)
	floorVer    = "2026.11.9"
	belowPlan   = "This update needs at least 3.5 GiB of memory on the control plane; s4c-cp1 has 900.0 MiB. No node was updated."
	armCompat   = "rasputin-rpi-arm64"
	amdCompat   = "rasputin-n100"
	floorCPID   = "cp-1"
	floorCPHost = "s4c-cp1"
)

// ----- fixtures -------------------------------------------------------------

// logCapture is a slog handler that keeps every record, so a test can assert
// the refusal's structured fields.
type logCapture struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }
func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, r.Clone())
	return nil
}
func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }

// refusals returns the attributes of every updater.memory_floor_refused record,
// and fails the test if one is not at WARN.
func (c *logCapture) refusals(t *testing.T) []map[string]string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []map[string]string
	for _, r := range c.recs {
		attrs := map[string]string{}
		r.Attrs(func(a slog.Attr) bool { attrs[a.Key] = a.Value.String(); return true })
		if attrs["event"] != "updater.memory_floor_refused" {
			continue
		}
		if r.Level != slog.LevelWarn {
			t.Errorf("refusal logged at %v, want WARN", r.Level)
		}
		out = append(out, attrs)
	}
	return out
}

// countingMemory wraps a reader and counts its calls; err, when set, is what
// every call returns instead.
type countingMemory struct {
	inner NodeMemory
	err   error
	calls atomic.Int32
}

func (m *countingMemory) LatestValue(ctx context.Context, nodeID, name string) (float64, bool, error) {
	m.calls.Add(1)
	if m.err != nil {
		return 0, false, m.err
	}
	if m.inner == nil {
		return 0, false, nil
	}
	return m.inner.LatestValue(ctx, nodeID, name)
}

func newMetrics(t *testing.T) *metrics.Store {
	t.Helper()
	m, err := metrics.OpenStore(context.Background(), filepath.Join(t.TempDir(), "metrics.db"))
	if err != nil {
		t.Fatalf("metrics OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// reportMemory records one mem_total_bytes sample for a node.
func reportMemory(t *testing.T, m *metrics.Store, nodeID string, v float64) {
	t.Helper()
	if err := m.Insert(context.Background(), &proto.MetricsEvt{
		NodeID: nodeID, Ts: time.Now().UTC(), Metrics: map[string]float64{proto.MetricMemTotalBytes: v},
	}); err != nil {
		t.Fatalf("metrics insert: %v", err)
	}
}

type floorFixture struct {
	store *Store
	inv   *inventory.Store
	mem   *metrics.Store
}

// newFloorFixture: control plane cp-1 (hostname s4c-cp1) and two computes,
// all arm64 and online, with release floorVer staged for arm64 at floor.
func newFloorFixture(t *testing.T, floor int64) floorFixture {
	t.Helper()
	ctx := context.Background()
	f := floorFixture{store: newStoreFixture(t).store, inv: newInventory(t), mem: newMetrics(t)}
	now := time.Now().UTC()
	for _, n := range []*proto.Node{
		{ID: floorCPID, Hostname: floorCPHost, Role: proto.RoleControlPlane, Architecture: "arm64"},
		{ID: "c-1", Hostname: "c-1", Role: proto.RoleCompute, Architecture: "arm64"},
		{ID: "c-2", Hostname: "c-2", Role: proto.RoleCompute, Architecture: "arm64"},
	} {
		n.FirstSeen, n.LastSeen = now, now
		if err := f.inv.Insert(ctx, n); err != nil {
			t.Fatalf("inv insert %s: %v", n.ID, err)
		}
	}
	f.stage(t, "sha-arm64", floorVer, armCompat, floor)
	return f
}

func (f floorFixture) stage(t *testing.T, sha, version, compat string, floor int64) {
	t.Helper()
	if err := f.store.CreateBundle(context.Background(), &Bundle{
		SHA256: sha, Version: version, Compatible: compat, UploadedAt: time.Now().UTC(),
		MemoryFloorBytes: floor,
	}); err != nil {
		t.Fatalf("bundle %s: %v", sha, err)
	}
}

func versionSpec() proto.SystemUpdateSpec {
	return proto.SystemUpdateSpec{Version: floorVer, Component: "os"}
}

// runPlanStep runs the real plan step and returns its error and log records.
func runPlanStep(t *testing.T, f floorFixture, spec proto.SystemUpdateSpec, mem NodeMemory) (json.RawMessage, error, *logCapture) {
	t.Helper()
	logs := &logCapture{}
	raw, _ := json.Marshal(spec)
	sc := newUpdaterCtx("parent-1", string(raw), nil)
	out, err := systemPlan(f.store, f.inv, SystemUpdateConfig{Memory: mem, Log: slog.New(logs)})(sc)
	return out, err, logs
}

// ----- TC-1011-08: the store ------------------------------------------------

// TC-1011-08: an updater database from before the column migrates; its old
// bundle row reads back with floor 0; a new row round-trips its floor through
// CreateBundle, GetBundle and ListBundles; a second open is a no-op.
func TestOpenStore_MigratesTheBundleMemoryFloor(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	// bundles exactly as it shipped before memory_floor_bytes.
	const oldSchema = `
CREATE TABLE bundles (
    sha256        TEXT PRIMARY KEY,
    version       TEXT NOT NULL,
    compatible    TEXT NOT NULL,
    architecture  TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    build_date    TEXT NOT NULL DEFAULT '',
    size_bytes    INTEGER NOT NULL,
    signed_by     TEXT NOT NULL DEFAULT '',
    storage_path  TEXT NOT NULL,
    uploaded_at   INTEGER NOT NULL,
    uploaded_by   TEXT NOT NULL DEFAULT ''
);`
	db, err := dbutil.Open(ctx, path, oldSchema, "updater-old")
	if err != nil {
		t.Fatalf("open old db: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
        INSERT INTO bundles (sha256, version, compatible, architecture, size_bytes, storage_path, uploaded_at)
        VALUES ('old-sha', '2026.10.0', 'rasputin-n100', 'amd64', 10, '/b/old-sha', ?)`,
		time.Now().UTC().UnixMilli()); err != nil {
		t.Fatalf("seed old row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	open := func() *Store {
		s, err := OpenStore(ctx, path)
		if err != nil {
			t.Fatalf("OpenStore: %v", err)
		}
		return s
	}
	s := open()
	old, err := s.GetBundle(ctx, "old-sha")
	if err != nil || old == nil {
		t.Fatalf("pre-existing bundle must still read: %+v, %v", old, err)
	}
	if old.MemoryFloorBytes != 0 || old.Version != "2026.10.0" {
		t.Errorf("old bundle = %+v, want its row intact with floor 0", old)
	}
	if err := s.CreateBundle(ctx, &Bundle{
		SHA256: "new-sha", Version: floorVer, Compatible: armCompat, Architecture: "arm64",
		SizeBytes: 20, StoragePath: "/b/new-sha", UploadedAt: time.Now().UTC().Add(time.Second),
		MemoryFloorBytes: testFloor,
	}); err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}
	if b, _ := s.GetBundle(ctx, "new-sha"); b == nil || b.MemoryFloorBytes != testFloor {
		t.Errorf("GetBundle(new) = %+v, want floor %d", b, testFloor)
	}
	_ = s.Close()

	// A second open runs the migration again and changes nothing.
	s = open()
	t.Cleanup(func() { _ = s.Close() })
	all, err := s.ListBundles(ctx)
	if err != nil {
		t.Fatalf("ListBundles: %v", err)
	}
	got := map[string]int64{}
	for _, b := range all {
		got[b.SHA256] = b.MemoryFloorBytes
	}
	if want := map[string]int64{"old-sha": 0, "new-sha": testFloor}; !reflect.DeepEqual(got, want) {
		t.Errorf("ListBundles floors = %v, want %v", got, want)
	}
}

// ----- TC-1011-10: below the floor -----------------------------------------

// TC-1011-10: a control plane reporting 900 MiB against the 3.5 GiB floor
// refuses the run at the plan step with the exact sentence, one WARN record,
// and no plan. With no hostname it is named by its node id.
func TestSystemPlan_RefusesBelowTheMemoryFloor(t *testing.T) {
	f := newFloorFixture(t, testFloor)
	reportMemory(t, f.mem, floorCPID, 900*mib)

	out, err, logs := runPlanStep(t, f, versionSpec(), f.mem)
	if err == nil || out != nil {
		t.Fatalf("systemPlan = (%s, %v), want no plan and a refusal", out, err)
	}
	if err.Error() != belowPlan {
		t.Errorf("error = %q\nwant    %q", err.Error(), belowPlan)
	}
	recs := logs.refusals(t)
	if len(recs) != 1 {
		t.Fatalf("refusal records = %d, want 1", len(recs))
	}
	want := map[string]string{
		"component": "updater", "node_id": floorCPID, "job_id": "parent-1", "version": floorVer,
		"floor_bytes": "3758096384", "mem_total_bytes": "9.437184e+08", "reason": "below",
	}
	for k, v := range want {
		if recs[0][k] != v {
			t.Errorf("record %s = %q, want %q", k, recs[0][k], v)
		}
	}
	if _, has := recs[0]["err"]; has {
		t.Errorf("a below-floor record carries err = %q, want none", recs[0]["err"])
	}

	// No hostname: the node id names the board.
	g := newFloorFixture(t, testFloor)
	n, _ := g.inv.Get(context.Background(), floorCPID)
	n.Hostname = ""
	if err := g.inv.Update(context.Background(), n); err != nil {
		t.Fatalf("clear hostname: %v", err)
	}
	reportMemory(t, g.mem, floorCPID, 900*mib)
	_, err, _ = runPlanStep(t, g, versionSpec(), g.mem)
	if want := strings.Replace(belowPlan, floorCPHost, floorCPID, 1); err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
}

// ----- TC-1011-11: at and above the floor ----------------------------------

// TC-1011-11: memory exactly at the floor, and a CM5 Lite's 3,994.8 MiB, plan
// exactly what a floor-0 run of the same fleet plans, and log no refusal.
func TestSystemPlan_AtOrAboveTheMemoryFloorPlansAsWithoutOne(t *testing.T) {
	base := newFloorFixture(t, 0)
	baseline, err := buildPlan(context.Background(), base.store, base.inv, versionSpec(), SystemUpdateConfig{})
	if err != nil {
		t.Fatalf("baseline plan: %v", err)
	}
	for _, v := range []float64{float64(testFloor), 3994.8 * mib} {
		f := newFloorFixture(t, testFloor)
		reportMemory(t, f.mem, floorCPID, v)
		out, err, logs := runPlanStep(t, f, versionSpec(), f.mem)
		if err != nil {
			t.Fatalf("memory %.0f: plan refused: %v", v, err)
		}
		var got systemPlanState
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !reflect.DeepEqual(planShape(got), planShape(baseline)) {
			t.Errorf("memory %.0f: plan %+v, want the floor-0 plan %+v", v, planShape(got), planShape(baseline))
		}
		if recs := logs.refusals(t); len(recs) != 0 {
			t.Errorf("memory %.0f: %d refusal record(s), want none", v, len(recs))
		}
	}
}

// planShape is the part of a plan an operator sees: ordered targets with
// their bundle and canary flag, and the skips.
func planShape(s systemPlanState) []string {
	var out []string
	for _, t := range s.Targets {
		out = append(out, t.NodeID+"|"+t.BundleSHA256+"|"+string(t.Tier)+"|"+map[bool]string{true: "canary", false: ""}[t.Canary])
	}
	for _, sk := range s.Skipped {
		out = append(out, "skip:"+sk.NodeID+"|"+string(sk.Reason))
	}
	return out
}

// ----- TC-1011-12: releases without the field -----------------------------

// TC-1011-12: an OS release and a firewall release with no floor plan, and
// preview, exactly as before: the memory reader is never called, and a nil
// reader neither panics nor refuses.
func TestSystemPlan_NoFloorNeverReadsMemory(t *testing.T) {
	ctx := context.Background()
	f := newFloorFixture(t, 0)
	now := time.Now().UTC()
	if err := f.inv.Insert(ctx, &proto.Node{ID: "fw-1", Role: proto.RoleFirewall, FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatalf("inv fw: %v", err)
	}
	f.stage(t, "sha-fw", "2026.07.1", releases.FirewallCompatible, 0)

	counting := &countingMemory{inner: f.mem}
	for _, c := range []struct {
		name string
		spec proto.SystemUpdateSpec
		want []string
	}{
		{"os", versionSpec(), []string{"c-1", "c-2", floorCPID}},
		{"fw", proto.SystemUpdateSpec{Version: "2026.07.1", Component: "fw"}, []string{"fw-1"}},
	} {
		for _, mem := range []NodeMemory{nil, counting} {
			state, err := buildPlan(ctx, f.store, f.inv, c.spec, SystemUpdateConfig{Memory: mem})
			if err != nil {
				t.Fatalf("%s: buildPlan: %v", c.name, err)
			}
			if got := state.targetIDs(); !reflect.DeepEqual(got, c.want) {
				t.Errorf("%s: targets = %v, want %v", c.name, got, c.want)
			}
			plan, err := PreviewPlan(ctx, f.store, f.inv, c.spec, SystemUpdateConfig{Memory: mem})
			if err != nil || len(plan.Targets) != len(c.want) {
				t.Errorf("%s: PreviewPlan = (%d targets, %v), want %d targets", c.name, len(plan.Targets), err, len(c.want))
			}
		}
	}
	if n := counting.calls.Load(); n != 0 {
		t.Errorf("memory reader called %d time(s) for runs with no floor, want 0", n)
	}
}

// ----- TC-1011-13: fail closed ---------------------------------------------

// TC-1011-13: with a floor, every way the control plane's memory cannot be
// judged refuses with no plan, and with a sentence that says which. The raw
// read error is in the log record only.
func TestSystemPlan_FailsClosedWhenMemoryCannotBeJudged(t *testing.T) {
	const (
		notReported = "This update needs at least 3.5 GiB of memory on the control plane, and s4c-cp1 has not reported its memory, so the update was refused. No node was updated."
		unreadable  = "This update needs at least 3.5 GiB of memory on the control plane, and the memory of s4c-cp1 could not be read, so the update was refused. No node was updated."
		noCP        = "This update needs at least 3.5 GiB of memory on the control plane, and this cluster has no control plane that reports its memory, so the update was refused. No node was updated."
		readErr     = "database is locked: injected"
	)
	type row struct {
		name       string
		sample     *float64 // nil = no sample
		mem        func(f floorFixture) NodeMemory
		dropCP     bool
		want       string
		wantReason string
		wantErr    string // substring of the record's err; "" = no err attribute
	}
	val := func(v float64) *float64 { return &v }
	real := func(f floorFixture) NodeMemory { return f.mem }
	rows := []row{
		{name: "no sample", mem: real, want: notReported, wantReason: "not_reported"},
		{name: "zero", sample: val(0), mem: real, want: unreadable, wantReason: "unreadable", wantErr: "not a positive finite number"},
		{name: "negative", sample: val(-1), mem: real, want: unreadable, wantReason: "unreadable", wantErr: "not a positive finite number"},
		{name: "NaN", sample: val(math.NaN()), mem: real, want: unreadable, wantReason: "unreadable", wantErr: "not a positive finite number"},
		{name: "+Inf", sample: val(math.Inf(1)), mem: real, want: unreadable, wantReason: "unreadable", wantErr: "not a positive finite number"},
		{name: "read error", mem: func(floorFixture) NodeMemory { return &countingMemory{err: errors.New(readErr)} },
			want: unreadable, wantReason: "unreadable", wantErr: readErr},
		{name: "nil reader", mem: func(floorFixture) NodeMemory { return nil }, want: unreadable, wantReason: "unreadable", wantErr: "no memory reader"},
		{name: "no control plane", dropCP: true, mem: real, want: noCP, wantReason: "not_reported"},
	}
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			f := newFloorFixture(t, testFloor)
			if c.sample != nil {
				// SQLite stores NaN as NULL, which the REAL column refuses, so a
				// non-finite sample goes through a reader that returns it as is.
				if math.IsNaN(*c.sample) || math.IsInf(*c.sample, 0) {
					v := *c.sample
					c.mem = func(floorFixture) NodeMemory { return fixedMemory(v) }
				} else {
					reportMemory(t, f.mem, floorCPID, *c.sample)
				}
			}
			if c.dropCP {
				n, _ := f.inv.Get(context.Background(), floorCPID)
				n.Role = proto.RoleCompute
				if err := f.inv.Update(context.Background(), n); err != nil {
					t.Fatalf("drop cp: %v", err)
				}
			}
			out, err, logs := runPlanStep(t, f, versionSpec(), c.mem(f))
			if err == nil || out != nil {
				t.Fatalf("systemPlan = (%s, %v), want no plan and a refusal", out, err)
			}
			if err.Error() != c.want {
				t.Errorf("error = %q\nwant    %q", err.Error(), c.want)
			}
			if strings.Contains(err.Error(), readErr) {
				t.Errorf("the sentence carries the raw read error: %q", err.Error())
			}
			recs := logs.refusals(t)
			if len(recs) != 1 {
				t.Fatalf("refusal records = %d, want 1", len(recs))
			}
			if recs[0]["reason"] != c.wantReason {
				t.Errorf("reason = %q, want %q", recs[0]["reason"], c.wantReason)
			}
			if c.wantErr == "" {
				if e, has := recs[0]["err"]; has {
					t.Errorf("record err = %q, want none", e)
				}
			} else if !strings.Contains(recs[0]["err"], c.wantErr) {
				t.Errorf("record err = %q, want it to contain %q", recs[0]["err"], c.wantErr)
			}
		})
	}
}

// fixedMemory is a reader that reports one value for every node.
type fixedMemory float64

func (m fixedMemory) LatestValue(context.Context, string, string) (float64, bool, error) {
	return float64(m), true, nil
}

// ----- TC-1011-14: every control plane, whatever the targeting --------------

// TC-1011-14: a below-floor control plane refuses the run when it is excluded,
// offline, or of a SKU the run's one bundle does not match; and a run carrying
// bundles at floors 0 and N applies N.
func TestSystemPlan_ChecksEveryControlPlane(t *testing.T) {
	ctx := context.Background()

	t.Run("excluded", func(t *testing.T) {
		f := newFloorFixture(t, testFloor)
		reportMemory(t, f.mem, floorCPID, 900*mib)
		spec := versionSpec()
		spec.ExcludeNodes = []string{floorCPID}
		if _, err := buildPlan(ctx, f.store, f.inv, spec, SystemUpdateConfig{Memory: f.mem}); err == nil || err.Error() != belowPlan {
			t.Errorf("error = %v, want %q", err, belowPlan)
		}
	})
	t.Run("offline", func(t *testing.T) {
		f := newFloorFixture(t, testFloor)
		reportMemory(t, f.mem, floorCPID, 900*mib)
		n, _ := f.inv.Get(ctx, floorCPID)
		n.LastSeen = time.Now().UTC().Add(-2 * time.Hour)
		if err := f.inv.Update(ctx, n); err != nil {
			t.Fatalf("age cp: %v", err)
		}
		if _, err := buildPlan(ctx, f.store, f.inv, versionSpec(), SystemUpdateConfig{Memory: f.mem}); err == nil || err.Error() != belowPlan {
			t.Errorf("error = %v, want %q", err, belowPlan)
		}
	})
	t.Run("sku mismatch", func(t *testing.T) {
		// The run's one bundle is amd64; the arm64 control plane is no target.
		f := newFloorFixture(t, 0)
		f.stage(t, "sha-amd64", floorVer, amdCompat, testFloor)
		reportMemory(t, f.mem, floorCPID, 900*mib)
		spec := proto.SystemUpdateSpec{BundleSHA256: "sha-amd64"}
		if _, err := buildPlan(ctx, f.store, f.inv, spec, SystemUpdateConfig{Memory: f.mem}); err == nil || err.Error() != belowPlan {
			t.Errorf("error = %v, want %q", err, belowPlan)
		}
	})
	t.Run("largest floor applies", func(t *testing.T) {
		// arm64 (the control plane's own SKU) states no floor; amd64 states N.
		f := newFloorFixture(t, 0)
		f.stage(t, "sha-amd64", floorVer, amdCompat, testFloor)
		reportMemory(t, f.mem, floorCPID, 900*mib)
		if _, err := buildPlan(ctx, f.store, f.inv, versionSpec(), SystemUpdateConfig{Memory: f.mem}); err == nil || err.Error() != belowPlan {
			t.Errorf("error = %v, want %q", err, belowPlan)
		}
	})
}

// ----- TC-1011-16: the saga ------------------------------------------------

// TC-1011-16: on the real runner, stores and bus, a system.update whose release
// states a floor the control plane is below fails at plan with the sentence,
// submits no child job, and sends no precheck, download or install to any node.
func TestFleetFunctional_MemoryFloorRefusesTheRunBeforeAnyChild(t *testing.T) {
	specs := append(computeFleet(2, "arm64"), simNodeSpec{ID: floorCPID, Role: proto.RoleControlPlane, Arch: "arm64"})
	bundles := osBundles(fleetVersion)
	for i := range bundles {
		bundles[i].MemoryFloor = testFloor
	}
	mem := newMetrics(t)
	reportMemory(t, mem, floorCPID, 900*mib)
	f := newFleetWithMemory(t, specs, bundles, mem)

	var cmds atomic.Int32
	for _, verb := range []string{"update.precheck", "update.download", "update.install"} {
		sub, err := f.nc.Subscribe(proto.NodeCmdSubject("*", verb), func(*nats.Msg) { cmds.Add(1) })
		if err != nil {
			t.Fatalf("subscribe %s: %v", verb, err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
	}
	if err := f.nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	run := f.run(releaseSpec(fleetVersion))
	if run.Status != jobs.StatusFailed {
		t.Fatalf("parent job = %s, want failed", run.Status)
	}
	// The harness's hostname is the node id.
	want := strings.Replace(belowPlan, floorCPHost, floorCPID, 1)
	if !strings.Contains(run.Error, want) {
		t.Errorf("parent error = %q, want it to carry %q", run.Error, want)
	}
	if step := failedStep(t, f.jobStore, run.JobID); step != "plan" {
		t.Errorf("parent failed at step %q, want plan", step)
	}
	children, err := f.jobStore.ListChildJobs(context.Background(), run.JobID)
	if err != nil {
		t.Fatalf("ListChildJobs: %v", err)
	}
	if len(children) != 0 {
		t.Errorf("child jobs = %d, want none", len(children))
	}
	if err := f.nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if n := cmds.Load(); n != 0 {
		t.Errorf("%d precheck/download/install command(s) reached a node, want none", n)
	}
}

// ----- TC-1011-17: the backstop at validate --------------------------------

type backstopFixture struct {
	floorFixture
	jobStore  *jobs.Store
	runner    *jobs.Runner
	nc        *nats.Conn
	logs      *logCapture
	prechecks atomic.Int32
}

func newBackstopFixture(t *testing.T, mem func(*testing.T, floorFixture) NodeMemory) *backstopFixture {
	t.Helper()
	f := &backstopFixture{floorFixture: newFloorFixture(t, testFloor), nc: startNATS(t), logs: &logCapture{}}
	f.stage(t, "sha-nofloor", "2026.10.0", armCompat, 0)
	f.jobStore = newJobStore(t)
	// The one "agent" here counts prechecks and refuses each, so a job that
	// passes validate ends at precheck at once.
	sub, err := f.nc.Subscribe(proto.NodeCmdSubject("*", "update.precheck"), func(m *nats.Msg) {
		f.prechecks.Add(1)
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{OK: false, Detail: "test agent"})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := f.nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	f.runner = jobs.NewRunner(f.jobStore, f.nc)
	f.runner.Register(UpdateWorkflow(f.store, f.inv, f.nc, Config{
		PublicBaseURL: "http://localhost:8080", Memory: mem(t, f.floorFixture), Log: slog.New(f.logs),
	}))
	t.Cleanup(f.runner.Wait)
	return f
}

// update submits a node.update and waits for it to end failed: the refusal at
// validate, or the test agent's refused precheck.
func (f *backstopFixture) update(t *testing.T, nodeID, sha string) (*jobs.Job, *NodeUpdate) {
	t.Helper()
	j, err := f.runner.Submit(context.Background(), "node.update", UpdateSpec{NodeID: nodeID, BundleSHA256: sha}, "test")
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitJobStatus(t, f.jobStore, j.ID, jobs.StatusFailed)
	f.runner.Wait() // the terminal hook has written the row
	j, _ = f.jobStore.GetJob(context.Background(), j.ID)
	row, _ := f.store.GetNodeUpdate(context.Background(), j.ID)
	return j, row
}

// TC-1011-17 (a), (d): a direct update of a control plane below the floor, or
// whose memory read fails, fails at validate with the backstop's sentence,
// records it on a failed row, logs step=validate, and never prechecks.
func TestUpdateValidate_MemoryFloorBackstopRefusesAControlPlane(t *testing.T) {
	const below = "This update needs at least 3.5 GiB of memory on the control plane; s4c-cp1 has 900.0 MiB. Nothing was installed on s4c-cp1."
	const unreadable = "This update needs at least 3.5 GiB of memory on the control plane, and the memory of s4c-cp1 could not be read, so the update was refused. Nothing was installed on s4c-cp1."
	for _, c := range []struct {
		name, want, reason string
		mem                func(*testing.T, floorFixture) NodeMemory
	}{
		{"below", below, "below", func(t *testing.T, f floorFixture) NodeMemory {
			reportMemory(t, f.mem, floorCPID, 900*mib)
			return f.mem
		}},
		{"read error", unreadable, "unreadable", func(*testing.T, floorFixture) NodeMemory { return &countingMemory{err: errors.New("boom")} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newBackstopFixture(t, c.mem)
			j, row := f.update(t, floorCPID, "sha-arm64")
			if step := failedStep(t, f.jobStore, j.ID); step != "validate" || j.Error != c.want {
				t.Errorf("job = step %q error %q, want step validate error %q", step, j.Error, c.want)
			}
			if row == nil || row.Status != NodeUpdateFailed || row.Error != c.want {
				t.Errorf("row = %+v, want failed with the sentence", row)
			}
			recs := f.logs.refusals(t)
			if len(recs) != 1 || recs[0]["step"] != "validate" || recs[0]["reason"] != c.reason || recs[0]["node_id"] != floorCPID {
				t.Errorf("refusal records = %v, want one with step=validate reason=%s", recs, c.reason)
			}
			if err := f.nc.Flush(); err != nil {
				t.Fatalf("flush: %v", err)
			}
			if n := f.prechecks.Load(); n != 0 {
				t.Errorf("%d precheck(s) sent, want none", n)
			}
		})
	}
}

// TC-1011-17 (b), (c): a compute target with a floor bundle, and a control
// plane with a floor-0 bundle, pass validate without reading memory; both
// reach precheck.
func TestUpdateValidate_MemoryFloorBackstopReadsOnlyForAControlPlaneWithAFloor(t *testing.T) {
	counting := &countingMemory{}
	f := newBackstopFixture(t, func(*testing.T, floorFixture) NodeMemory { return counting })
	for _, c := range []struct{ node, sha string }{
		{"c-1", "sha-arm64"},       // (b) compute, floor bundle
		{floorCPID, "sha-nofloor"}, // (c) control plane, floor-0 bundle
	} {
		before := f.prechecks.Load()
		j, _ := f.update(t, c.node, c.sha)
		if step := failedStep(t, f.jobStore, j.ID); step != "precheck" {
			t.Errorf("%s/%s: failed at %q (%s), want past validate to precheck", c.node, c.sha, step, j.Error)
		}
		if err := f.nc.Flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if f.prechecks.Load() == before {
			t.Errorf("%s/%s: no precheck sent, want validate to have passed", c.node, c.sha)
		}
	}
	if n := counting.calls.Load(); n != 0 {
		t.Errorf("memory read %d time(s), want none", n)
	}
	if recs := f.logs.refusals(t); len(recs) != 0 {
		t.Errorf("refusal records = %v, want none", recs)
	}
}

// failedStep is the name of the job's failed step.
func failedStep(t *testing.T, js *jobs.Store, jobID string) string {
	t.Helper()
	steps, err := js.ListSteps(context.Background(), jobID)
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	for _, st := range steps {
		if st.Status == jobs.StepFailed {
			return st.Name
		}
	}
	return ""
}
