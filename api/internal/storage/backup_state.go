package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// design/storage.md §4.4's "failure is loud in three places", derived
// (geekdojo/geekdojo-brain#298).
//
// # One signal, three surfaces, per app
//
// The app tile's OVERDUE badge, the alert and the job feed's per-app lines
// are three renderings of ONE derivation, made here from data the api already
// has: the backup_runs ledger says which runs wrote a generation and when; each
// run's `fan_out` step result carries the manifest's per-volume record —
// captured, or not, with the reason; the installed-app list joined to the
// catalog says which volumes an app has that a backup takes at all; and the
// schedule says how often it should have happened. No new agent verb, no new
// table: everything a tile needs to say OVERDUE was already being written, by
// #290 and #296, for exactly this reader.
//
// # Why the unit is the app and not the run
//
// A run is cluster-wide. It ends FAILED when immich's node is offline, and in
// the same run vaultwarden's vault landed, sealed and indexed. "The last backup
// failed" is true and useless to the vaultwarden tile; "immich has not been
// captured for nine days because its node is offline" is what the operator has
// to act on. So every judgement below is made per app, over that app's own
// backed-up volumes, and a run that failed for someone else's volume counts as
// a SUCCESS for the app whose volumes it captured.
//
// # Grace
//
// A weekly cadence judged to the minute would flag every app overdue while the
// scheduler's own hourly check was still deciding whether to run. The grace is
// a quarter of the cadence with a six-hour floor: a weekly schedule is overdue
// after eight days and eighteen hours, a daily one after thirty hours, an
// hourly one after seven hours. Grace applies to AGE only. A failed attempt is
// overdue the moment it fails — the backup did not happen, and there is no
// window in which that is fine.

// backupGraceFraction and backupGraceMin define the grace: cadence/4, but
// never less than six hours.
const (
	backupGraceFraction = 4
	backupGraceMin      = 6 * time.Hour
)

// BackupGrace is how long past its cadence an app's last success may be before
// the app is overdue by age.
func BackupGrace(cadence time.Duration) time.Duration {
	g := cadence / backupGraceFraction
	if g < backupGraceMin {
		g = backupGraceMin
	}
	return g
}

// AppFailure is one app's share of a run that could not capture everything:
// the volumes the run tried to take from it and could not, and why. It is the
// structured form of the job's terminal error — one entry per app, so the
// Tasks page can render a line per app rather than one prose blob.
type AppFailure struct {
	AppID string `json:"appId,omitempty"`
	App   string `json:"app"`
	Node  string `json:"node,omitempty"`
	// Class is the highest §4.2 class among the failed volumes.
	Class   string   `json:"class,omitempty"`
	Volumes []string `json:"volumes"`
	// Reason is the fan-out's own sentence for the volume — or, when the
	// app's volumes failed for different reasons, those sentences joined.
	Reason string `json:"reason"`
}

// FailedApps groups a report's FAILED records by app, in the order the plan
// stages them: `critical` first, then by app name.
func (r AppVolumeReport) FailedApps() []AppFailure {
	byApp := map[string]*AppFailure{}
	var order []string
	for _, v := range r.Volumes {
		if !v.Failed {
			continue
		}
		key := v.AppID
		if key == "" {
			key = v.App
		}
		f, ok := byApp[key]
		if !ok {
			f = &AppFailure{AppID: v.AppID, App: v.App, Node: v.Node, Class: v.Class}
			byApp[key] = f
			order = append(order, key)
		}
		f.Volumes = append(f.Volumes, v.Volume)
		if classRank(v.Class) < classRank(f.Class) {
			f.Class = v.Class
		}
		if reason := strings.TrimSpace(v.Reason); reason != "" && !strings.Contains(f.Reason, reason) {
			if f.Reason != "" {
				f.Reason += "; "
			}
			f.Reason += reason
		}
	}
	out := make([]AppFailure, 0, len(order))
	for _, key := range order {
		out = append(out, *byApp[key])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := classRank(out[i].Class), classRank(out[j].Class); ri != rj {
			return ri < rj
		}
		return out[i].App < out[j].App
	})
	return out
}

// backupAttempt is one terminal run as it bears on an app: when it ended, how
// it ended, whether it wrote a generation, and the manifest's per-volume
// record if the run got as far as the fan-out.
type backupAttempt struct {
	JobID string
	At    time.Time
	// Status is the run's verdict — a run that failed for another app's
	// volume is still a success for the app whose volumes it captured.
	Status RunStatus
	// HasGeneration is whether the write landed: a fan-out whose members
	// reached the partial generation and whose write then failed left
	// nothing on the disk, and is not a success for anyone.
	HasGeneration bool
	// Report is the fan-out's record, nil when the run failed before it.
	Report *AppVolumeReport
	// Error is the run's terminal error, for the reason when there is no
	// per-volume record to quote.
	Error string
}

// backupStateInput is everything the derivation needs about ONE app. A value
// rather than a store lookup so the decision table can be tested as a table.
type backupStateInput struct {
	AppID   string
	AppName string
	// InstalledAt is when the app row was created — the clock a never-backed
	// app is judged against.
	InstalledAt time.Time
	// Volumes is every volume a backup takes from this app: the plan's
	// `critical`/`state` set, including one it could not stage for want of a
	// node. Empty is AppBackupNone.
	Volumes []PlannedVolume
	// NoneReason says why Volumes is empty, when it is.
	NoneReason string
	// Configured is whether a target is claimed AND the schedule is on;
	// UnconfiguredReason says which is missing.
	Configured         bool
	UnconfiguredReason string
	Cadence            time.Duration
	// Attempts is every terminal run, newest first.
	Attempts []backupAttempt
}

// appOutcome is what one run did for one app.
type appOutcome struct {
	// attempted is false when the run never concerned this app: it ran
	// before the app was installed, or its fan-out enumerated the cluster
	// and this app was not in it. Such a run is neither a success nor a
	// failure for the app and says nothing about its state.
	attempted bool
	success   bool
	reason    string
}

// outcomeFor judges one attempt for one app: a success only when the run wrote
// a generation and the manifest records EVERY one of the app's backed-up
// volumes as captured. Anything less is a failure with the manifest's own
// reason — or the run's, when it never reached the fan-out.
func outcomeFor(in backupStateInput, a backupAttempt) appOutcome {
	if a.At.Before(in.InstalledAt) {
		return appOutcome{}
	}
	if a.Report == nil {
		reason := strings.TrimSpace(a.Error)
		if reason == "" {
			reason = "the run ended before it reached this app's volumes"
		}
		return appOutcome{attempted: true, reason: "the backup run failed before reaching this app: " + reason}
	}
	captured := map[string]bool{}
	var failed []string
	mentioned := false
	for _, v := range a.Report.Volumes {
		if !strings.EqualFold(v.AppID, in.AppID) {
			continue
		}
		mentioned = true
		if v.Captured {
			captured[v.Volume] = true
		} else if v.Failed {
			failed = append(failed, v.Volume+": "+strings.TrimSpace(v.Reason))
		}
	}
	if !mentioned {
		return appOutcome{}
	}
	if len(failed) > 0 {
		return appOutcome{attempted: true, reason: strings.Join(failed, "; ")}
	}
	var missing []string
	for _, v := range in.Volumes {
		if !captured[v.Volume] {
			missing = append(missing, v.Volume)
		}
	}
	if len(missing) > 0 {
		return appOutcome{attempted: true, reason: fmt.Sprintf("that generation does not hold %s", strings.Join(missing, ", "))}
	}
	if !a.HasGeneration {
		return appOutcome{attempted: true, reason: "the volumes were staged but the run never wrote its generation to the target, so nothing of them is on the disk"}
	}
	return appOutcome{attempted: true, success: true}
}

// deriveBackupState is the decision table. Pure: the clock is an argument.
func deriveBackupState(in backupStateInput, now time.Time) proto.AppBackupState {
	out := proto.AppBackupState{Cadence: in.Cadence.String()}
	if len(in.Volumes) == 0 {
		out.State = proto.AppBackupNone
		out.Reason = in.NoneReason
		out.Cadence = ""
		return out
	}
	out.Class = tileschema.BackupState
	for _, v := range in.Volumes {
		if v.Class == tileschema.BackupCritical {
			out.Class = tileschema.BackupCritical
		}
	}

	// The record, before the policy: what the ledger says happened for this
	// app, newest first. Found once, used by every branch below.
	var (
		lastAttempt *backupAttempt
		lastOutcome appOutcome
		lastSuccess *backupAttempt
	)
	for i := range in.Attempts {
		a := in.Attempts[i]
		if a.Status != RunSucceeded && a.Status != RunFailed {
			continue
		}
		oc := outcomeFor(in, a)
		if !oc.attempted {
			continue
		}
		if lastAttempt == nil {
			lastAttempt = &in.Attempts[i]
			lastOutcome = oc
		}
		if oc.success {
			lastSuccess = &in.Attempts[i]
			break
		}
	}
	if lastAttempt != nil {
		t := lastAttempt.At
		out.LastAttemptAt = &t
	}
	if lastSuccess != nil {
		t := lastSuccess.At
		out.LastSuccessAt = &t
	}

	if !in.Configured {
		// Nothing was due, so nothing is overdue. #299's nag, not #298's
		// badge — and the distinction is the whole reason this branch comes
		// before the failure check: a cluster that turned its schedule off
		// must not light every tile red for a run that was never scheduled.
		out.State = proto.AppBackupUnconfigured
		out.Reason = in.UnconfiguredReason
		return out
	}

	grace := BackupGrace(in.Cadence)
	limit := in.Cadence + grace

	// A failed most-recent attempt is overdue NOW, whatever the age of the
	// last success: the backup did not happen. §4.4 — failed, not skipped.
	if lastAttempt != nil && !lastOutcome.success {
		out.State = proto.AppBackupOverdue
		since := lastAttempt.At
		out.OverdueSince = &since
		out.Reason = "the most recent backup attempt FAILED for this app — " + lastOutcome.reason
		return out
	}

	if lastSuccess == nil {
		due := in.InstalledAt.Add(limit)
		if !now.Before(due) {
			out.State = proto.AppBackupOverdue
			out.OverdueSince = &due
			out.Reason = fmt.Sprintf("never backed up: installed %s ago and no generation has ever captured its data (cadence %s, grace %s)",
				compactAge(now.Sub(in.InstalledAt)), in.Cadence, grace)
			return out
		}
		out.State = proto.AppBackupNever
		out.Reason = fmt.Sprintf("not backed up yet: installed %s ago; the first scheduled backup is due within %s",
			compactAge(now.Sub(in.InstalledAt)), compactAge(due.Sub(now)))
		return out
	}

	age := now.Sub(lastSuccess.At)
	if age > limit {
		out.State = proto.AppBackupOverdue
		since := lastSuccess.At.Add(limit)
		out.OverdueSince = &since
		out.Reason = fmt.Sprintf("the last successful backup was %s ago, past the %s cadence plus %s grace, and no run has captured it since",
			compactAge(age), in.Cadence, grace)
		return out
	}
	out.State = proto.AppBackupOK
	out.Reason = fmt.Sprintf("backed up %s ago (cadence %s)", compactAge(age), in.Cadence)
	return out
}

// compactAge is the compact "9d 4h" / "2h" / "40m" a tile has room for.
func compactAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		h := int(d.Hours())
		if m := int(d.Minutes()) - h*60; m > 0 {
			return fmt.Sprintf("%dh %dm", h, m)
		}
		return fmt.Sprintf("%dh", h)
	default:
		days := int(d.Hours() / 24)
		if h := int(d.Hours()) - days*24; h > 0 {
			return fmt.Sprintf("%dd %dh", days, h)
		}
		return fmt.Sprintf("%dd", days)
	}
}

// BackupStates answers "where does every app stand against its backup
// cadence?" from the ledger, for the two readers that need it on every
// request: the /api/apps rows and the alerts aggregator.
//
// A run's fan-out record never changes once the run is terminal, so it is read
// from the job ledger once per run and kept; the steady-state cost of a call is
// one query over backup_runs plus the plan, which is what lets the apps page
// poll it every twenty seconds without the job ledger noticing.
type BackupStates struct {
	store    *Store
	jobs     *jobs.Store
	apps     AppLister
	tiles    TileVolumes
	settings ScheduleSettings
	// scheduleDefault is whether the schedule is on when nothing has been
	// set — main passes true, as it does to DueFunc.
	scheduleDefault bool
	// now is the clock, replaceable by tests.
	now func() time.Time

	mu      sync.Mutex
	reports map[string]*AppVolumeReport // job id → fan-out record (nil = none)
}

// backupStatesReportCache bounds the per-run cache. Well above retention and
// the ledger page size, so it is a leak guard rather than a working-set limit.
const backupStatesReportCache = 512

// NewBackupStates wires the derivation to the ledger, the job store the fan-out
// records live in, the installed-app list, the catalog that classifies their
// volumes, and the settings the schedule lives in.
func NewBackupStates(store *Store, jobStore *jobs.Store, apps AppLister, tiles TileVolumes, settings ScheduleSettings, scheduleDefault bool) *BackupStates {
	return &BackupStates{
		store: store, jobs: jobStore, apps: apps, tiles: tiles, settings: settings,
		scheduleDefault: scheduleDefault,
		now:             func() time.Time { return time.Now().UTC() },
		reports:         map[string]*AppVolumeReport{},
	}
}

// AppBackupStates derives the state of every installed app, sorted by app
// name.
func (b *BackupStates) AppBackupStates(ctx context.Context) ([]proto.AppBackupStatus, error) {
	if b == nil || b.store == nil || b.apps == nil || b.tiles == nil {
		return nil, nil
	}
	installed, err := b.apps.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("backup state: list apps: %w", err)
	}
	if len(installed) == 0 {
		return []proto.AppBackupStatus{}, nil
	}
	configured, unconfiguredReason, cadence, err := b.configuration(ctx)
	if err != nil {
		return nil, err
	}
	attempts, err := b.attempts(ctx)
	if err != nil {
		return nil, err
	}
	plan := PlanAppVolumes(installed, b.tiles)
	volumesByApp := map[string][]PlannedVolume{}
	for _, v := range plan.Stage {
		volumesByApp[v.AppID] = append(volumesByApp[v.AppID], v)
	}
	noneReason := map[string]string{}
	for _, rec := range plan.Skipped {
		if rec.Failed {
			// A classified volume with no node to stage on is still one a
			// backup owes the app: it is in the set, and every run fails it.
			volumesByApp[rec.AppID] = append(volumesByApp[rec.AppID], PlannedVolume{
				AppID: rec.AppID, AppName: rec.App, TileID: rec.TileID, NodeID: rec.Node,
				Volume: rec.Volume, Class: rec.Class, Quiesce: rec.Strategy,
			})
			continue
		}
		if _, ok := noneReason[rec.AppID]; !ok {
			noneReason[rec.AppID] = rec.Reason
		}
	}
	now := b.now()
	out := make([]proto.AppBackupStatus, 0, len(installed))
	for _, a := range installed {
		if a == nil {
			continue
		}
		in := backupStateInput{
			AppID: a.ID, AppName: a.Name, InstalledAt: a.CreatedAt,
			Volumes:    volumesByApp[a.ID],
			Configured: configured, UnconfiguredReason: unconfiguredReason,
			Cadence:  cadence,
			Attempts: attempts,
		}
		if len(in.Volumes) == 0 {
			in.NoneReason = noneReason[a.ID]
			if in.NoneReason == "" {
				in.NoneReason = "every volume this app's tile declares is classed `cache` or `bulk`, so a scheduled backup takes nothing from it (§4.2)"
			}
		}
		out = append(out, proto.AppBackupStatus{AppID: a.ID, AppName: a.Name, AppBackupState: deriveBackupState(in, now)})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].AppName < out[j].AppName })
	return out, nil
}

// AppBackupState derives one app's state, or nil when the app is not
// installed.
func (b *BackupStates) AppBackupState(ctx context.Context, appID string) (*proto.AppBackupState, error) {
	all, err := b.AppBackupStates(ctx)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].AppID == appID {
			return &all[i].AppBackupState, nil
		}
	}
	return nil, nil
}

// configuration is the "is anything due at all?" half: a claimed target and
// a schedule that is on. A settings read that fails reads as configured — a
// corrupt schedule value must not be able to turn every tile grey, which is
// the same posture BackupSchedule.Interval takes.
func (b *BackupStates) configuration(ctx context.Context) (configured bool, reason string, cadence time.Duration, err error) {
	claimed, err := b.store.ListClaimed(ctx)
	if err != nil {
		return false, "", 0, fmt.Errorf("backup state: claimed targets: %w", err)
	}
	sched, serr := GetBackupSchedule(ctx, b.settings, b.scheduleDefault)
	if serr != nil {
		sched = BackupSchedule{Enabled: true}
	}
	cadence = sched.Interval()
	switch {
	case len(claimed) == 0:
		return false, "no backup target is claimed, so nothing on this cluster is backed up anywhere. Claim a disk under Storage → Backups", cadence, nil
	case !sched.Enabled:
		return false, "scheduled backups are turned off, so nothing runs on its own. Choose a cadence under Storage → Backups", cadence, nil
	}
	return true, "", cadence, nil
}

// attempts reads every terminal run, newest first, with its fan-out record.
func (b *BackupStates) attempts(ctx context.Context) ([]backupAttempt, error) {
	runs, err := b.store.ListRuns(ctx, 0)
	if err != nil {
		return nil, fmt.Errorf("backup state: runs: %w", err)
	}
	out := make([]backupAttempt, 0, len(runs))
	for _, run := range runs {
		if run.Status != RunSucceeded && run.Status != RunFailed {
			continue
		}
		at := run.StartedAt
		if run.FinishedAt != nil {
			at = *run.FinishedAt
		}
		out = append(out, backupAttempt{
			JobID: run.JobID, At: at, Status: run.Status,
			HasGeneration: strings.TrimSpace(run.GenerationID) != "",
			Report:        b.report(ctx, run.JobID),
			Error:         run.Error,
		})
	}
	// Newest first by the time the derivation judges by, whatever order the
	// ledger handed them back in.
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out, nil
}

// report is a run's fan-out record, read from the job ledger once and kept.
// nil means the run left none — it failed before the fan-out, or predates it.
func (b *BackupStates) report(ctx context.Context, jobID string) *AppVolumeReport {
	b.mu.Lock()
	if rep, ok := b.reports[jobID]; ok {
		b.mu.Unlock()
		return rep
	}
	b.mu.Unlock()
	var rep *AppVolumeReport
	if b.jobs != nil {
		if steps, err := b.jobs.ListSteps(ctx, jobID); err == nil {
			for _, st := range steps {
				if st.Name != "fan_out" || st.Status != jobs.StepSucceeded || len(st.Result) == 0 {
					continue
				}
				var res runFanOutResult
				if err := json.Unmarshal(st.Result, &res); err == nil {
					r := res.Report
					rep = &r
				}
				break
			}
		} else {
			// Not cached: a ledger read that failed says nothing about the
			// run, and the next call should ask again.
			return nil
		}
	}
	b.mu.Lock()
	if len(b.reports) >= backupStatesReportCache {
		b.reports = map[string]*AppVolumeReport{}
	}
	b.reports[jobID] = rep
	b.mu.Unlock()
	return rep
}
