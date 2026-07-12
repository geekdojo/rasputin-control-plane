package alerts

import (
	"context"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// fixture holds the four fresh subsystem stores + the alerts Service under
// test. Each call to newFixture creates a new tempdir so tests are fully
// isolated; sqlite is file-backed (one DB per store). hasUsers is a
// mutable knob so markSetupComplete can actually flip the wizard to
// completed — without a real users probe, setup.Service.GetState always
// reports the passkey step undone, and the setup-incomplete alert fires
// in every test no matter what.
type fixture struct {
	inv      *inventory.Store
	jobs     *jobs.Store
	apps     *apps.Store
	setup    *setup.Service
	svc      *Service
	ctx      context.Context
	hasUsers bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()

	invStore, err := inventory.OpenStore(ctx, filepath.Join(dir, "inv.db"))
	if err != nil {
		t.Fatalf("open inventory: %v", err)
	}
	t.Cleanup(func() { _ = invStore.Close() })

	jobStore, err := jobs.OpenStore(ctx, filepath.Join(dir, "jobs.db"))
	if err != nil {
		t.Fatalf("open jobs: %v", err)
	}
	t.Cleanup(func() { _ = jobStore.Close() })

	appStore, err := apps.OpenStore(ctx, filepath.Join(dir, "apps.db"))
	if err != nil {
		t.Fatalf("open apps: %v", err)
	}
	t.Cleanup(func() { _ = appStore.Close() })

	setupStore, err := setup.OpenStore(ctx, filepath.Join(dir, "setup.db"))
	if err != nil {
		t.Fatalf("open setup: %v", err)
	}
	t.Cleanup(func() { _ = setupStore.Close() })

	f := &fixture{
		inv:  invStore,
		jobs: jobStore,
		apps: appStore,
		ctx:  ctx,
	}
	// HasUsers closes over the fixture's mutable hasUsers field so tests
	// can opt in (markSetupComplete) without rebuilding the Service.
	probes := setup.Probes{
		HasUsers: func(ctx context.Context) (bool, error) { return f.hasUsers, nil },
	}
	f.setup = setup.NewService(setupStore, probes, "")
	f.svc = New(invStore, jobStore, appStore, f.setup, nil, nil, true)
	return f
}

// insertNode is a convenience helper for putting a node with a chosen
// LastSeen into the inventory store. Tests assert on the alerts derived
// from that LastSeen.
func (f *fixture) insertNode(t *testing.T, id string, lastSeenAgo time.Duration) {
	t.Helper()
	n := &proto.Node{
		ID:        id,
		Role:      proto.RoleCompute,
		Hostname:  id + ".test",
		FirstSeen: time.Now().Add(-time.Hour).UTC(),
		LastSeen:  time.Now().Add(-lastSeenAgo).UTC(),
	}
	if err := f.inv.Insert(f.ctx, n); err != nil {
		t.Fatalf("insert node %s: %v", id, err)
	}
}

func (f *fixture) insertFailedJob(t *testing.T, id, kind, errMsg string, finishedAgo time.Duration) {
	t.Helper()
	finished := time.Now().Add(-finishedAgo).UTC()
	j := &jobs.Job{
		ID:        id,
		Kind:      kind,
		Status:    jobs.StatusQueued,
		CreatedBy: "test",
		CreatedAt: finished.Add(-time.Second),
	}
	if err := f.jobs.CreateJob(f.ctx, j); err != nil {
		t.Fatalf("create job %s: %v", id, err)
	}
	if err := f.jobs.MarkJobFailed(f.ctx, id, errMsg, finished); err != nil {
		t.Fatalf("mark failed %s: %v", id, err)
	}
}

func (f *fixture) insertApp(t *testing.T, id, name string, status proto.AppStatus, detail string) {
	t.Helper()
	now := time.Now().UTC()
	// Create persists only the declarative fields. last_status / last_detail
	// / last_status_at are written by RecordStatus, which is what the agent
	// triggers when it reports back. Tests have to mirror that two-step
	// shape to exercise the same code path.
	a := &apps.App{
		ID:          id,
		Name:        name,
		ComposeYAML: "services: {}",
		TargetNode:  "node-test",
		LastStatus:  proto.AppStatusUnknown,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := f.apps.Create(f.ctx, a); err != nil {
		t.Fatalf("create app %s: %v", id, err)
	}
	if err := f.apps.RecordStatus(f.ctx, id, status, detail, now); err != nil {
		t.Fatalf("record status %s: %v", id, err)
	}
}

func (f *fixture) markSetupComplete(t *testing.T) {
	t.Helper()
	// Satisfy all the required gates the wizard checks (see setup.GetState):
	// (1) HasUsers probe true, (2) install name set, (3) a deployment mode
	// chosen (LAN-peer needs no firewall node), (4) operator explicitly
	// clicked Finish (recorded via MarkCompleted).
	f.hasUsers = true
	if err := f.setup.SetInstallName(f.ctx, "Test Cluster"); err != nil {
		t.Fatalf("set install name: %v", err)
	}
	if err := f.setup.SetMode(f.ctx, string(setup.ModeLANPeer)); err != nil {
		t.Fatalf("set mode: %v", err)
	}
	if err := f.setup.MarkCompleted(f.ctx); err != nil {
		t.Fatalf("mark completed: %v", err)
	}
}

func find(alerts []proto.Alert, id string) (proto.Alert, bool) {
	for _, a := range alerts {
		if a.ID == id {
			return a, true
		}
	}
	return proto.Alert{}, false
}

// ============================================================================
// Node alerts
// ============================================================================

// TestNodeAlerts_RegressionLongSilentNodeFiresCrit is the canary for the bug
// that shipped in the first cut of this aggregator: inventory.Store.List
// doesn't populate Status, so switching on n.Status saw "" forever and no
// node alert ever fired even when a node had been silent for hours. If this
// regresses, the TopBar badge will silently go back to "NONE" no matter
// what.
func TestNodeAlerts_RegressionLongSilentNodeFiresCrit(t *testing.T) {
	f := newFixture(t)
	// Mimic the real-world condition that masked the bug for two days:
	// node-dev silent for 47 hours.
	f.insertNode(t, "cp-dev", 47*time.Hour)
	f.markSetupComplete(t) // suppress the setup-incomplete noise

	alerts, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got, ok := find(alerts, "node-offline:cp-dev")
	if !ok {
		t.Fatalf("expected node-offline:cp-dev alert, got %d alerts: %+v", len(alerts), alerts)
	}
	if got.Severity != proto.AlertCrit {
		t.Errorf("severity: want crit, got %q", got.Severity)
	}
	if got.Source != proto.AlertSourceNode {
		t.Errorf("source: want node, got %q", got.Source)
	}
	if got.RelatedKind != "node" || got.RelatedID != "cp-dev" {
		t.Errorf("drill-through: want (node, cp-dev), got (%s, %s)", got.RelatedKind, got.RelatedID)
	}
}

func TestNodeAlerts_StatusBuckets(t *testing.T) {
	cases := []struct {
		name      string
		silentFor time.Duration
		wantAlert bool
		wantID    string
		wantSev   proto.AlertSeverity
	}{
		// staleAfter = 30s, offlineAfter = 2m
		{name: "fresh online", silentFor: 5 * time.Second, wantAlert: false},
		{name: "edge online (29s)", silentFor: 29 * time.Second, wantAlert: false},
		{name: "stale warn (45s)", silentFor: 45 * time.Second, wantAlert: true, wantID: "node-stale:n", wantSev: proto.AlertWarn},
		{name: "edge stale (119s)", silentFor: 119 * time.Second, wantAlert: true, wantID: "node-stale:n", wantSev: proto.AlertWarn},
		{name: "crit offline (3m)", silentFor: 3 * time.Minute, wantAlert: true, wantID: "node-offline:n", wantSev: proto.AlertCrit},
		{name: "crit offline (47h)", silentFor: 47 * time.Hour, wantAlert: true, wantID: "node-offline:n", wantSev: proto.AlertCrit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.insertNode(t, "n", tc.silentFor)
			f.markSetupComplete(t)

			alerts, err := f.svc.List(f.ctx)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if !tc.wantAlert {
				if len(alerts) != 0 {
					t.Fatalf("want no alerts, got %+v", alerts)
				}
				return
			}
			got, ok := find(alerts, tc.wantID)
			if !ok {
				t.Fatalf("want alert %s, got: %+v", tc.wantID, alerts)
			}
			if got.Severity != tc.wantSev {
				t.Errorf("severity: want %q, got %q", tc.wantSev, got.Severity)
			}
		})
	}
}

// ============================================================================
// Job alerts
// ============================================================================

func TestJobAlerts_RecentFailureSurfaces(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	f.insertFailedJob(t, "j-1", "node.update", "verify step exit code 1", 5*time.Minute)

	alerts, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got, ok := find(alerts, "job-failed:j-1")
	if !ok {
		t.Fatalf("expected job-failed:j-1 alert: %+v", alerts)
	}
	if got.Severity != proto.AlertWarn {
		t.Errorf("severity: want warn, got %q", got.Severity)
	}
	if got.Title != "node.update failed" {
		t.Errorf("title: want %q, got %q", "node.update failed", got.Title)
	}
	if got.Detail != "verify step exit code 1" {
		t.Errorf("detail: want error message, got %q", got.Detail)
	}
	if got.RelatedKind != "job" || got.RelatedID != "j-1" {
		t.Errorf("drill-through: want (job, j-1), got (%s, %s)", got.RelatedKind, got.RelatedID)
	}
}

func TestJobAlerts_FailureOutsideLookbackIsSuppressed(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	// 25 hours ago — past the 24h lookback window.
	f.insertFailedJob(t, "j-old", "diag.ping", "timeout", 25*time.Hour)

	alerts, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, ok := find(alerts, "job-failed:j-old"); ok {
		t.Errorf("expected no alert for job outside lookback, got: %+v", alerts)
	}
}

func TestJobAlerts_EmptyErrorGetsFallbackDetail(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	f.insertFailedJob(t, "j-blank", "system.reboot", "", 1*time.Minute)

	alerts, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got, ok := find(alerts, "job-failed:j-blank")
	if !ok {
		t.Fatalf("expected job-failed:j-blank alert: %+v", alerts)
	}
	if got.Detail == "" {
		t.Errorf("expected fallback detail when error is empty, got empty string")
	}
}

// ============================================================================
// App alerts
// ============================================================================

func TestAppAlerts_OnlyFailedSurfaces(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	f.insertApp(t, "a-ok", "minecraft", proto.AppStatusRunning, "")
	f.insertApp(t, "a-stopped", "jellyfin", proto.AppStatusStopped, "")
	f.insertApp(t, "a-fail", "homeassistant", proto.AppStatusFailed, "container exit 1")

	alerts, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, ok := find(alerts, "app-failed:a-ok"); ok {
		t.Error("running app should not produce alert")
	}
	if _, ok := find(alerts, "app-failed:a-stopped"); ok {
		t.Error("stopped app should not produce alert")
	}
	got, ok := find(alerts, "app-failed:a-fail")
	if !ok {
		t.Fatalf("expected app-failed:a-fail alert: %+v", alerts)
	}
	if got.Severity != proto.AlertWarn {
		t.Errorf("severity: want warn, got %q", got.Severity)
	}
	if got.Detail != "container exit 1" {
		t.Errorf("detail: want %q, got %q", "container exit 1", got.Detail)
	}
}

// ============================================================================
// Setup alerts
// ============================================================================

func TestSetupAlerts_IncompleteSurfaces(t *testing.T) {
	f := newFixture(t)
	// Do NOT mark setup complete.
	alerts, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got, ok := find(alerts, "setup-incomplete")
	if !ok {
		t.Fatalf("expected setup-incomplete alert: %+v", alerts)
	}
	if got.Severity != proto.AlertWarn {
		t.Errorf("severity: want warn, got %q", got.Severity)
	}
}

func TestSetupAlerts_CompletedSuppresses(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)

	alerts, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, ok := find(alerts, "setup-incomplete"); ok {
		t.Errorf("setup-incomplete should not fire when setup is complete, got: %+v", alerts)
	}
}

// ============================================================================
// Security alerts
// ============================================================================

// The fixture constructs the Service with busAuthEnforced=true so the
// standing bus-auth-off warn doesn't pollute every other test; this test
// builds a second Service over the same stores with enforcement off and
// asserts the alert fires there and only there.
func TestList_BusAuthOffFiresStandingWarn(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)

	open := New(f.inv, f.jobs, f.apps, f.setup, nil, nil, false)
	alerts, err := open.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got, ok := find(alerts, "bus-auth-off")
	if !ok {
		t.Fatalf("expected bus-auth-off alert with enforcement off, got: %+v", alerts)
	}
	if got.Severity != proto.AlertWarn {
		t.Errorf("severity: want warn, got %q", got.Severity)
	}
	if got.Source != proto.AlertSourceSecurity {
		t.Errorf("source: want security, got %q", got.Source)
	}

	// The enforced fixture Service over the same stores must NOT emit it.
	enforced, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List (enforced): %v", err)
	}
	if _, ok := find(enforced, "bus-auth-off"); ok {
		t.Errorf("bus-auth-off must not fire when enforcement is on: %+v", enforced)
	}
}

// ============================================================================
// Empty / sort / stability
// ============================================================================

func TestList_NoConcernsReturnsEmpty(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	// No nodes, no failed jobs, no failed apps, setup complete → empty.

	alerts, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected zero alerts, got: %+v", alerts)
	}
}

func TestList_SortedByCritFirstThenOldestSince(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	// A WARN (stale node) and two CRITs (offline nodes) with different Since.
	f.insertNode(t, "warn-node", 45*time.Second)   // stale → warn
	f.insertNode(t, "crit-recent", 5*time.Minute)  // offline → crit, since ≈ 5min ago
	f.insertNode(t, "crit-very-old", 48*time.Hour) // offline → crit, since ≈ 48h ago

	alerts, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(alerts) != 3 {
		t.Fatalf("want 3 alerts, got %d: %+v", len(alerts), alerts)
	}
	// First two must be CRIT; first CRIT is the older one.
	if alerts[0].Severity != proto.AlertCrit || alerts[0].RelatedID != "crit-very-old" {
		t.Errorf("alerts[0]: want crit/crit-very-old, got %+v", alerts[0])
	}
	if alerts[1].Severity != proto.AlertCrit || alerts[1].RelatedID != "crit-recent" {
		t.Errorf("alerts[1]: want crit/crit-recent, got %+v", alerts[1])
	}
	if alerts[2].Severity != proto.AlertWarn || alerts[2].RelatedID != "warn-node" {
		t.Errorf("alerts[2]: want warn/warn-node, got %+v", alerts[2])
	}
}

func TestList_IDsAreStableAcrossCalls(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	f.insertNode(t, "cp-dev", 47*time.Hour)
	f.insertFailedJob(t, "j-1", "diag.ping", "timeout", 1*time.Minute)
	f.insertApp(t, "a-1", "minecraft", proto.AppStatusFailed, "container exit 1")

	first, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List #1: %v", err)
	}
	second, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatalf("List #2: %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("call counts differ: %d vs %d", len(first), len(second))
	}
	firstIDs := alertIDs(first)
	secondIDs := alertIDs(second)
	sort.Strings(firstIDs)
	sort.Strings(secondIDs)
	for i := range firstIDs {
		if firstIDs[i] != secondIDs[i] {
			t.Errorf("ID at sorted position %d differs: %q vs %q", i, firstIDs[i], secondIDs[i])
		}
	}
}

func alertIDs(alerts []proto.Alert) []string {
	out := make([]string, len(alerts))
	for i, a := range alerts {
		out[i] = a.ID
	}
	return out
}

// ============================================================================
// humanizeDuration — pure helper used in the Detail field
// ============================================================================

func TestHumanizeDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{d: -time.Second, want: "0s"},
		{d: 0, want: "0s"},
		{d: 7 * time.Second, want: "7s"},
		{d: 59 * time.Second, want: "59s"},
		{d: 60 * time.Second, want: "1m"},
		{d: 90 * time.Second, want: "1m 30s"},
		{d: 59*time.Minute + 59*time.Second, want: "59m 59s"},
		{d: time.Hour, want: "1h"},
		{d: 90 * time.Minute, want: "1h 30m"},
		{d: 23*time.Hour + 59*time.Minute, want: "23h 59m"},
		{d: 24 * time.Hour, want: "1d"},
		{d: 47 * time.Hour, want: "1d 23h"},
		{d: 72 * time.Hour, want: "3d"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if got := humanizeDuration(tc.d); got != tc.want {
				t.Errorf("humanizeDuration(%v) = %q, want %q", tc.d, got, tc.want)
			}
		})
	}
}
