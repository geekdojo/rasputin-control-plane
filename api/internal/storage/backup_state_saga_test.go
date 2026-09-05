package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/alerts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// design/storage.md §4.4's named case, on every surface at once (#298): the
// node hosting immich is offline at backup time. The run's terminal entry
// names immich and why; the derivation says immich is OVERDUE with the
// off-node reason while the two apps that landed are ok; and the alerts
// aggregator, reading the same derivation, carries one alert for immich and
// none for the others.

// statesOf runs the derivation over the harness's ledger.
func statesOf(t *testing.T, h *runHarness, installed []*apps.App, tiles TileVolumes) map[string]proto.AppBackupStatus {
	t.Helper()
	src := NewBackupStates(h.store, h.jobStore, &fakeApps{list: installed}, tiles, h.settings, true)
	all, err := src.AppBackupStates(context.Background())
	if err != nil {
		t.Fatalf("AppBackupStates: %v", err)
	}
	out := map[string]proto.AppBackupStatus{}
	for _, st := range all {
		out[st.AppName] = st
	}
	return out
}

// alertsOver builds the real aggregator over the harness's ledger, with fresh
// stores for the sources this case is not about.
func alertsOver(t *testing.T, h *runHarness, installed []*apps.App, tiles TileVolumes) []proto.Alert {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	appStore, err := apps.OpenStore(ctx, filepath.Join(dir, "apps.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = appStore.Close() })
	setupStore, err := setup.OpenStore(ctx, filepath.Join(dir, "setup.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = setupStore.Close() })
	inv := h.inv
	if inv == nil {
		inv = newInventory(t)
	}
	svc := alerts.New(inv, h.jobStore, appStore, setup.NewService(setupStore, setup.Probes{}, "", "", ""), nil, nil, true)
	svc.SetBackupStates(NewBackupStates(h.store, h.jobStore, &fakeApps{list: installed}, tiles, h.settings, true))
	out, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("alerts.List: %v", err)
	}
	return out
}

func backupAlerts(all []proto.Alert) map[string]proto.Alert {
	out := map[string]proto.Alert{}
	for _, a := range all {
		if strings.HasPrefix(a.ID, "backup-overdue:") {
			out[a.RelatedID] = a
		}
	}
	return out
}

func TestOfflineNodeIsLoudOnEverySurface(t *testing.T) {
	installed, tiles := clusterApps(), clusterTiles()
	r := runWithApps(t, runHarnessOpts{apps: installed, tiles: tiles}) // no compute agent: immich's node is offline
	if r.job.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s; an offline node's volume must fail the run", r.job.Status)
	}

	// Surface 3, the job feed: the terminal entry names the app, its node,
	// its volume and the reason, on its own line.
	for _, want := range []string{"BACKUP FAILED FOR APP immich", "\n  • immich on " + computeNodeID + ": immich/immich-upload — node " + computeNodeID + " is OFFLINE", "§4.4"} {
		if !strings.Contains(r.job.Error, want) {
			t.Errorf("terminal error lacks %q:\n%s", want, r.job.Error)
		}
	}
	// And the structured form, in the assemble step's result, one entry
	// per app — not a synthetic job per app.
	var asm runAssembleResult
	steps, err := r.h.jobStore.ListSteps(context.Background(), r.jobID)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range steps {
		if st.Name == "assemble" {
			if err := json.Unmarshal(st.Result, &asm); err != nil {
				t.Fatalf("assemble result: %v", err)
			}
		}
	}
	if len(asm.FailedApps) != 1 || asm.FailedApps[0].App != "immich" || asm.FailedApps[0].AppID != "app-im" ||
		asm.FailedApps[0].Node != computeNodeID || len(asm.FailedApps[0].Volumes) != 1 || asm.FailedApps[0].Volumes[0] != "immich-upload" ||
		!strings.Contains(asm.FailedApps[0].Reason, "OFFLINE") {
		t.Errorf("failedApps = %+v; one entry for immich naming its node, volume and the off-node reason", asm.FailedApps)
	}
	if js, _ := r.h.jobStore.ListJobs(context.Background(), 0); len(js) != 1 {
		t.Errorf("%d jobs in the ledger; the per-app failure must not become a job per app", len(js))
	}

	// Surface 1, the tile: immich is OVERDUE with the off-node reason, and
	// the two apps whose volumes landed are ok — a run that failed for
	// immich is a success for them.
	states := statesOf(t, r.h, installed, tiles)
	im := states["immich"]
	if im.State != proto.AppBackupOverdue {
		t.Fatalf("immich state = %s (%s), want overdue", im.State, im.Reason)
	}
	for _, want := range []string{"most recent backup attempt FAILED", "immich-upload", "node " + computeNodeID + " is OFFLINE"} {
		if !strings.Contains(im.Reason, want) {
			t.Errorf("immich reason %q does not say %q", im.Reason, want)
		}
	}
	if im.LastSuccessAt != nil || im.LastAttemptAt == nil || im.OverdueSince == nil || im.Class != "state" {
		t.Errorf("immich = %+v; never succeeded, attempted, overdue since the attempt, class state", im.AppBackupState)
	}
	for _, name := range []string{"vaultwarden", "paperless"} {
		st := states[name]
		if st.State != proto.AppBackupOK || st.LastSuccessAt == nil {
			t.Errorf("%s state = %s (%s); its volume landed in this run, so it is ok", name, st.State, st.Reason)
		}
	}
	if states["vaultwarden"].Class != "critical" {
		t.Errorf("vaultwarden class = %q, want critical", states["vaultwarden"].Class)
	}

	// Surface 2, the alert: one, for immich, warn (its volume is `state`),
	// naming the app and the reason, drilling through to the app.
	got := backupAlerts(alertsOver(t, r.h, installed, tiles))
	if len(got) != 1 {
		t.Fatalf("backup alerts = %+v, want exactly one (immich)", got)
	}
	a, ok := got["app-im"]
	if !ok {
		t.Fatalf("no alert for immich: %+v", got)
	}
	if a.Severity != proto.AlertWarn || !strings.Contains(a.Title, "immich") || !strings.Contains(a.Title, "OVERDUE") || !strings.Contains(a.Detail, "OFFLINE") {
		t.Errorf("alert = %+v; warn, naming immich and the off-node reason", a)
	}

	// The node comes back and the next run captures everything: immich is
	// ok and the alert is gone, with no operator action.
	r2 := runWithApps(t, runHarnessOpts{apps: installed, tiles: tiles, computeAgent: true})
	if r2.job.Status != jobs.StatusSucceeded {
		t.Fatalf("second run = %s: %s", r2.job.Status, r2.job.Error)
	}
	if st := statesOf(t, r2.h, installed, tiles)["immich"]; st.State != proto.AppBackupOK {
		t.Errorf("immich after a good run = %s (%s), want ok", st.State, st.Reason)
	}
	if left := backupAlerts(alertsOver(t, r2.h, installed, tiles)); len(left) != 0 {
		t.Errorf("alerts after a good run = %+v, want none", left)
	}
}

// TestRunWithEveryAppOfflineIsNotSuccess: every app is hosted on the offline
// node, so the run captured nothing. It must end FAILED naming each app —
// never as a green run that wrote an identity-only generation.
func TestRunWithEveryAppOfflineIsNotSuccess(t *testing.T) {
	installed := []*apps.App{
		testApp("app-im", "immich", computeNodeID, "immich"),
		testApp("app-pl", "paperless", computeNodeID, "paperless"),
	}
	tiles := clusterTiles()
	r := runWithApps(t, runHarnessOpts{apps: installed, tiles: tiles})
	if r.job.Status != jobs.StatusFailed {
		t.Fatalf("job status = %s; a run that captured no app must not read as success", r.job.Status)
	}
	for _, want := range []string{"BACKUP FAILED FOR 2 APPS", "• immich on " + computeNodeID, "• paperless on " + computeNodeID, "OFFLINE"} {
		if !strings.Contains(r.job.Error, want) {
			t.Errorf("terminal error lacks %q:\n%s", want, r.job.Error)
		}
	}
	if r.row.Status != RunFailed || r.row.AppVolumesCaptured != 0 || r.row.AppVolumesFailed != 2 {
		t.Errorf("row = %s captured %d failed %d", r.row.Status, r.row.AppVolumesCaptured, r.row.AppVolumesFailed)
	}
	states := statesOf(t, r.h, installed, tiles)
	for _, name := range []string{"immich", "paperless"} {
		if st := states[name]; st.State != proto.AppBackupOverdue || !strings.Contains(st.Reason, "OFFLINE") {
			t.Errorf("%s = %s (%s), want overdue for the offline node", name, st.State, st.Reason)
		}
	}
	if got := backupAlerts(alertsOver(t, r.h, installed, tiles)); len(got) != 2 {
		t.Errorf("backup alerts = %+v, want one per app", got)
	}
}

// TestBackupStatesUnconfiguredIsNotOverdue: with no target claimed nothing is
// due, so an app that has never been captured is `unconfigured` — #299's
// state — and raises no alert here, whatever its class.
func TestBackupStatesUnconfiguredIsNotOverdue(t *testing.T) {
	installed, tiles := clusterApps(), clusterTiles()
	h := newRunHarness(t, nil, runHarnessOpts{noTarget: true, apps: installed, tiles: tiles})
	states := statesOf(t, h, installed, tiles)
	for _, name := range []string{"vaultwarden", "paperless", "immich"} {
		st := states[name]
		if st.State != proto.AppBackupUnconfigured || !strings.Contains(st.Reason, "no backup target") {
			t.Errorf("%s = %s (%s), want unconfigured for want of a target", name, st.State, st.Reason)
		}
	}
	if got := backupAlerts(alertsOver(t, h, installed, tiles)); len(got) != 0 {
		t.Errorf("unconfigured raised %+v", got)
	}
	// The schedule turned off is the other half of unconfigured.
	h2 := newRunHarness(t, nil, runHarnessOpts{apps: installed, tiles: tiles})
	if _, err := SetBackupSchedule(context.Background(), h2.settings, BackupSchedule{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if st := statesOf(t, h2, installed, tiles)["vaultwarden"]; st.State != proto.AppBackupUnconfigured || !strings.Contains(st.Reason, "turned off") {
		t.Errorf("schedule off: vaultwarden = %s (%s)", st.State, st.Reason)
	}
}
