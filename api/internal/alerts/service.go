// Package alerts is the v0 "current concerns" aggregator. It does NOT
// implement a rules engine, persistence, or ack/dismiss — it derives a
// snapshot from the existing subsystem stores on every read.
//
// The shape of the returned []proto.Alert is the public contract that the
// UI (TopBar count, sidebar Bell, /alerts page) consumes. A future
// rules-engine + alerts-table implementation can replace this aggregator
// without changing that contract.
//
// Sources and the alerts they produce:
//
//   - inventory  → node-offline (crit) / node-stale (warn), one per node
//   - jobs       → job-failed (warn), one per failed job in the last 24h
//   - apps       → app-failed (warn), one per app whose last status is failed
//   - setup      → setup-incomplete (warn), at most one
//   - security   → bus-auth-off (warn), at most one
//   - backups    → backup-overdue (warn for `state`, crit for `critical`),
//     one per app whose data has not been captured within its cadence
//     (design/storage.md §4.4, #298). Computed on read like the rest, from
//     the same per-app derivation the app tile renders, so it raises once
//     (a stable id), never duplicates across ticks, and resolves on its own
//     the moment a generation captures the app again.
//   - backups    → backup-unconfigured (warn), one per app with a `critical`
//     volume while no backup target is claimed or the schedule is off
//     (§4.4's persistent nag, #299). Same derivation, same lifecycle; see
//     backup_unconfigured.go for why it is warn and why only `critical`.
//   - backup targets → backup-target (crit), one per claimed target whose
//     last five-minute health check found it missing, unmounted, unwritable
//     or unreachable (#398, backup_target.go). Resolves on the next healthy
//     poll.
//
// Adding a source is a single function on Service that appends to the
// accumulator; everything else (HTTP handler, UI types, drill-through) is
// generic on proto.Alert.
package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Status derivation lives in inventory.DeriveStatus — see nodeAlerts (node.go).

// failedJobLookback bounds how far back we surface failed jobs. Past this
// window the failure is "history" — the operator should look at /tasks if
// they care, not be nagged by a banner.
const failedJobLookback = 24 * time.Hour

// BackupStates is the per-app backup derivation the aggregator reads for
// backup-overdue alerts. Satisfied by *storage.BackupStates; an interface so
// this package depends on the wire type in proto rather than on the backup
// package, which lets the backup package's own tests drive this aggregator.
type BackupStates interface {
	AppBackupStates(ctx context.Context) ([]proto.AppBackupStatus, error)
}

// Service aggregates alerts from the subsystem stores AND merges in
// rule-engine alerts persisted by RunRuleSync (Slice 1.5). The
// aggregator's view stays computed-on-read; persisted alerts come from
// the Store and round out the picture with vmalert-driven entries the
// aggregator can't compute (e.g. "CPU > 90% for 5m").
type Service struct {
	inv   *inventory.Store
	jobs  *jobs.Store
	apps  *apps.Store
	setup *setup.Service
	store *Store     // optional — nil means "no persistence; aggregator only"
	nc    *nats.Conn // optional — nil disables NATS push of alert changes
	// backups is optional — nil means no backup-overdue alerts, which is
	// the state of an api with no backup ledger wired.
	backups BackupStates
	// targets is optional — nil means no backup-target health alerts (#398).
	targets BackupTargets
	// mesh is optional — nil leaves mesh membership undetermined, so a lapsed
	// node is OFFLINE rather than OFF BUS (node.go).
	mesh inventory.MeshLookup
	// now is the clock List stamps on a snapshot; nil (production) is
	// time.Now. A test pins it because the details rendered from it count
	// whole seconds below a minute, so an unpinned snapshot taken a second
	// after its fixture says "41s ago" where the fixture said 40.
	now func() time.Time

	// busAuthEnforced mirrors the api's RASPUTIN_BUS_AUTH=enforce state.
	// When false the aggregator emits a standing bus-auth-off warn — the
	// default is the alerting state on purpose, so wiring that forgets to
	// pass the real value produces a visible false warning, not a silently
	// missing security alert.
	busAuthEnforced bool
	// busTLSAlert, when set, reports the bus TLS posture's standing warning
	// (bus TLS mode pinned below require, or the bus key unusable), or nil.
	busTLSAlert func(now time.Time) *proto.Alert
}

// SetBusTLSAlert wires the bus TLS posture warning (bustls.Service.Alert, or
// bustls.UnavailableAlert when the bus key did not load). Set before List.
func (s *Service) SetBusTLSAlert(fn func(now time.Time) *proto.Alert) { s.busTLSAlert = fn }

// New constructs an alerts Service. The store + nats.Conn are optional;
// dev-time wiring may pass nil for both (the aggregator still works).
// Production wiring passes both so rule alerts can persist and
// the UI's /ws/alerts gets push updates. busAuthEnforced is whether the
// api runs with RASPUTIN_BUS_AUTH=enforce — see securityAlerts.
func New(inv *inventory.Store, j *jobs.Store, a *apps.Store, s *setup.Service, store *Store, nc *nats.Conn, busAuthEnforced bool) *Service {
	return &Service{inv: inv, jobs: j, apps: a, setup: s, store: store, nc: nc, busAuthEnforced: busAuthEnforced}
}

// SetBackupStates wires the per-app backup derivation. Wired by main after
// New, the same way the api server takes the backup store: the derivation
// needs the job ledger, the catalog and the settings, none of which the
// aggregator otherwise knows about.
func (s *Service) SetBackupStates(b BackupStates) { s.backups = b }

// SetNow wires the clock a snapshot is stamped with. Nil (what production
// leaves it) is time.Now. Set before List, as SetMeshMembership is.
func (s *Service) SetNow(fn func() time.Time) { s.now = fn }

// clock is now, or the wall clock when none was injected.
func (s *Service) clock() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

// List returns the current alert snapshot, sorted by severity descending
// then by Since ascending (oldest concern first within a severity tier).
func (s *Service) List(ctx context.Context) ([]proto.Alert, error) {
	now := s.clock()
	out := make([]proto.Alert, 0, 8)

	if alerts, err := s.nodeAlerts(ctx, now); err != nil {
		return nil, fmt.Errorf("alerts: nodes: %w", err)
	} else {
		out = append(out, alerts...)
	}
	if alerts, err := s.jobAlerts(ctx, now); err != nil {
		return nil, fmt.Errorf("alerts: jobs: %w", err)
	} else {
		out = append(out, alerts...)
	}
	if alerts, err := s.appAlerts(ctx, now); err != nil {
		return nil, fmt.Errorf("alerts: apps: %w", err)
	} else {
		out = append(out, alerts...)
	}
	if alerts, err := s.setupAlerts(ctx, now); err != nil {
		return nil, fmt.Errorf("alerts: setup: %w", err)
	} else {
		out = append(out, alerts...)
	}
	out = append(out, s.securityAlerts(now)...)
	if alerts, err := s.backupAlerts(ctx, now); err != nil {
		return nil, fmt.Errorf("alerts: backups: %w", err)
	} else {
		out = append(out, alerts...)
	}
	if alerts, err := s.backupTargetAlerts(ctx, now); err != nil {
		return nil, fmt.Errorf("alerts: backup targets: %w", err)
	} else {
		out = append(out, alerts...)
	}
	if alerts, err := s.ruleAlerts(ctx); err != nil {
		return nil, fmt.Errorf("alerts: rules: %w", err)
	} else {
		out = append(out, alerts...)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		return out[i].Since.Before(out[j].Since)
	})
	return out, nil
}

func (s *Service) jobAlerts(ctx context.Context, now time.Time) ([]proto.Alert, error) {
	failed, err := s.jobs.ListJobsByStatus(ctx, []jobs.Status{jobs.StatusFailed})
	if err != nil {
		return nil, err
	}
	cutoff := now.Add(-failedJobLookback)
	out := make([]proto.Alert, 0, len(failed))
	for _, j := range failed {
		// "When did this fail" — prefer FinishedAt, fall back to CreatedAt
		// (a job marked failed without finished_at is malformed but
		// shouldn't crash the aggregator).
		when := j.CreatedAt
		if j.FinishedAt != nil {
			when = *j.FinishedAt
		}
		if when.Before(cutoff) {
			continue
		}
		detail := j.Error
		if detail == "" {
			detail = "see Tasks for details"
		}
		out = append(out, proto.Alert{
			ID:          "job-failed:" + j.ID,
			Severity:    proto.AlertWarn,
			Source:      proto.AlertSourceJob,
			Title:       fmt.Sprintf("%s failed", j.Kind),
			Detail:      detail,
			Since:       when,
			RelatedKind: "job",
			RelatedID:   j.ID,
		})
	}
	return out, nil
}

func (s *Service) appAlerts(ctx context.Context, _ time.Time) ([]proto.Alert, error) {
	all, err := s.apps.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]proto.Alert, 0)
	for _, a := range all {
		if a.LastStatus != proto.AppStatusFailed {
			continue
		}
		when := a.UpdatedAt
		if a.LastStatusAt != nil {
			when = *a.LastStatusAt
		}
		detail := a.LastDetail
		if detail == "" {
			detail = "app status is failed"
		}
		out = append(out, proto.Alert{
			ID:          "app-failed:" + a.ID,
			Severity:    proto.AlertWarn,
			Source:      proto.AlertSourceApp,
			Title:       fmt.Sprintf("App %s is failed", a.Name),
			Detail:      detail,
			Since:       when,
			RelatedKind: "app",
			RelatedID:   a.ID,
		})
	}
	return out, nil
}

func (s *Service) setupAlerts(ctx context.Context, now time.Time) ([]proto.Alert, error) {
	state, err := s.setup.GetState(ctx)
	if err != nil {
		return nil, err
	}
	if state.Completed {
		return nil, nil
	}
	// "Since" for setup is now — we don't track when the wizard first
	// became required. The UI shouldn't surface duration for setup-source
	// alerts.
	return []proto.Alert{{
		ID:       "setup-incomplete",
		Severity: proto.AlertWarn,
		Source:   proto.AlertSourceSetup,
		Title:    "First-run setup is incomplete",
		Detail:   "Finish the wizard to enable cluster name, identity, and OS update flow.",
		Since:    now,
	}}, nil
}

// securityAlerts surfaces standing security-posture concerns. v0: exactly
// one — the api running with bus auth off. Bus auth is now fail-closed by
// default (enforce unless `RASPUTIN_BUS_AUTH=off`), so an open bus is a
// deliberate opt-out; this alert makes that opt-out visible rather than a
// single boot-log line, so an open cluster can't look healthy in the UI
// indefinitely (rasputin-local
// ran 24 nodes on an open bus unnoticed, found 2026-07-12). A standing
// warn keeps the posture honest without blocking dev clusters that are
// deliberately open.
func (s *Service) securityAlerts(now time.Time) []proto.Alert {
	var out []proto.Alert
	if s.busTLSAlert != nil {
		if a := s.busTLSAlert(now); a != nil {
			out = append(out, *a)
		}
	}
	if s.busAuthEnforced {
		return out
	}
	// Like setup-incomplete, Since is "now" — the condition holds since api
	// start but we don't track that; the UI doesn't render duration for
	// cluster-wide standing alerts.
	return append(out, proto.Alert{
		ID:       "bus-auth-off",
		Severity: proto.AlertWarn,
		Source:   proto.AlertSourceSecurity,
		Title:    "Node bus authentication is off",
		Detail:   "The NATS bus accepts any connection — any device on the LAN can join as any node. Provision node join tokens and set RASPUTIN_BUS_AUTH=enforce on the controlplane to close it.",
		Since:    now,
	})
}

// backupAlerts is design/storage.md §4.4's alert path (#298): one alert per
// app whose backup is OVERDUE — its data not captured within its cadence plus
// grace, never captured since an install older than that, or its most recent
// attempt FAILED (node offline, agent refused, upload did not land).
//
// Severity follows the app's §4.2 class: `critical` (a password vault) is
// crit, `state` is warn. The id is stable per app, so a second read is the
// same alert and not a second one; Since is when the state became overdue,
// so the row's age reads as "how long has this been wrong". It disappears on
// its own when a generation captures the app again — the derivation is the
// lifecycle, exactly as node-offline's is.
//
// An app whose backups are UNCONFIGURED (no target, schedule off) raises
// #299's backup-unconfigured instead — from the same read of the derivation,
// so the two cannot disagree and the ledger is consulted once per tick — and
// never this one: nothing was due, and the nag must not wear OVERDUE's words.
// An app with nothing to back up raises neither.
func (s *Service) backupAlerts(ctx context.Context, now time.Time) ([]proto.Alert, error) {
	if s.backups == nil {
		return nil, nil
	}
	states, err := s.backups.AppBackupStates(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]proto.Alert, 0)
	for _, st := range states {
		if a, ok := backupUnconfiguredAlert(st, now); ok {
			out = append(out, a)
			continue
		}
		if !st.Overdue() {
			continue
		}
		sev := proto.AlertWarn
		if st.Class == "critical" {
			sev = proto.AlertCrit
		}
		since := now
		if st.OverdueSince != nil {
			since = *st.OverdueSince
		}
		elapsed := "never backed up"
		if st.LastSuccessAt != nil {
			elapsed = "last backed up " + humanizeDuration(now.Sub(*st.LastSuccessAt)) + " ago"
		}
		out = append(out, proto.Alert{
			ID:          "backup-overdue:" + st.AppID,
			Severity:    sev,
			Source:      proto.AlertSourceApp,
			Title:       fmt.Sprintf("Backup of %s is OVERDUE — %s", st.AppName, elapsed),
			Detail:      st.Reason,
			Since:       since,
			RelatedKind: "app",
			RelatedID:   st.AppID,
		})
	}
	return out, nil
}

// ruleAlerts pulls every non-dismissed persisted (rule-engine) alert.
// Returns empty when no store is wired — dev mode keeps working.
func (s *Service) ruleAlerts(ctx context.Context) ([]proto.Alert, error) {
	if s.store == nil {
		return nil, nil
	}
	rows, err := s.store.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]proto.Alert, 0, len(rows))
	for _, p := range rows {
		// Only include alerts that are currently firing OR have been
		// acked but not dismissed (so the operator can see "yes I know,
		// still ongoing"). A resolved + non-acked alert is treated as
		// "self-healed" and dropped from the live view — operators
		// who want history hit a future /api/alerts/history.
		if p.Status != "firing" && p.AckedAt == nil {
			continue
		}
		out = append(out, toAlert(p))
	}
	return out, nil
}

// FiringRule is one alert the rules engine reports as firing right now.
// Labels are the alert's labels (alertname, severity, the series labels);
// ActiveAt is when it became active, zero when unknown; Summary is the
// operator-facing one-liner, empty when the rule has none.
type FiringRule struct {
	Labels   map[string]string
	ActiveAt time.Time
	Summary  string
}

// SyncRuleAlerts reconciles the persisted rule alerts with the complete set of
// alerts the rules engine reports as firing now. It is called from
// RunRuleSync; tests drive it directly.
//
// Each firing alert is upserted by fingerprint (a hash of its labels); a row
// that is new, or was not firing, publishes AlertFired. Every persisted row
// that is firing but absent from the set is marked resolved and publishes
// AlertResolved. A row whose state has not changed is not rewritten.
//
// firing must be the whole current set: an empty slice resolves everything.
// A caller that could not read the set must not call this.
func (s *Service) SyncRuleAlerts(ctx context.Context, firing []FiringRule) error {
	if s.store == nil {
		return fmt.Errorf("alerts: rule sync: no store wired")
	}
	now := s.clock()
	current, err := s.store.ListFiring(ctx)
	if err != nil {
		return err
	}
	wasFiring := make(map[string]*PersistedAlert, len(current))
	for _, p := range current {
		wasFiring[p.Fingerprint] = p
	}

	seen := make(map[string]bool, len(firing))
	for _, f := range firing {
		fp := fingerprintFromLabels(f.Labels)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		title := f.Labels["alertname"]
		if title == "" {
			title = "alert"
		}
		sev := proto.AlertWarn
		if f.Labels["severity"] == "critical" || f.Labels["severity"] == "crit" {
			sev = proto.AlertCrit
		}
		starts := f.ActiveAt.UTC()
		prev := wasFiring[fp]
		if starts.IsZero() {
			// No activation time: keep the one already recorded for a
			// continuing alert, otherwise this is the first sighting.
			starts = now
			if prev != nil {
				starts = prev.StartsAt
			}
		}
		if prev != nil && prev.Severity == sev && prev.Title == title &&
			prev.Detail == f.Summary && prev.StartsAt.Equal(starts.Truncate(time.Millisecond)) {
			continue // still firing, nothing changed
		}
		saved, _, err := s.store.Upsert(ctx, &PersistedAlert{
			Fingerprint: fp,
			Status:      "firing",
			Severity:    sev,
			Title:       title,
			Detail:      f.Summary,
			Labels:      f.Labels,
			Annotations: map[string]string{},
			StartsAt:    starts,
		})
		if err != nil {
			return err
		}
		if prev == nil {
			s.publishChange(proto.AlertFired, saved)
		}
	}

	for fp, p := range wasFiring {
		if seen[fp] {
			continue
		}
		p.Status = "resolved"
		ended := now
		p.EndsAt = &ended
		saved, _, err := s.store.Upsert(ctx, p)
		if err != nil {
			return err
		}
		s.publishChange(proto.AlertResolved, saved)
	}
	return nil
}

// RuleReader returns the complete set of rule alerts firing now, or an error
// when that is unknown.
type RuleReader func(ctx context.Context) ([]FiringRule, error)

// RunRuleSync keeps the persisted rule alerts in step with the rules engine
// until ctx ends: it reads the firing set with read and applies it with
// SyncRuleAlerts, once at start and then every period.
//
// The loop is a safety-net tick that re-reads a fact, not a clock that
// decides state (design/principles.md): the rules engine evaluates on its own
// schedule and records its verdicts where read finds them, and each tick only
// copies the latest verdict. Nothing here decides that an alert has fired or
// resolved because time passed. period only sets how soon a new verdict is
// seen; the caller passes the engine's own evaluation interval, since reading
// faster than verdicts are produced gains nothing.
//
// A failed read skips the tick and changes nothing: not knowing the firing
// set is not the same as it being empty.
func (s *Service) RunRuleSync(ctx context.Context, read RuleReader, period time.Duration) {
	var lastErr string
	tick := func() {
		firing, err := read(ctx)
		if err == nil {
			err = s.SyncRuleAlerts(ctx, firing)
		}
		// Log a failure once, and its recovery once, rather than every tick.
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		if msg != lastErr {
			if msg != "" {
				log.Printf("alerts: rule sync: %v", err)
			} else {
				log.Printf("alerts: rule sync: recovered")
			}
			lastErr = msg
		}
	}
	tick()
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}

// Ack persists the operator's acknowledgement of an alert and publishes
// an AlertAcked event. Returns the updated alert.
func (s *Service) Ack(ctx context.Context, id string) (*proto.Alert, error) {
	if s.store == nil {
		return nil, fmt.Errorf("alerts: ack: no store wired")
	}
	saved, err := s.store.Ack(ctx, id)
	if err != nil {
		return nil, err
	}
	a := toAlert(saved)
	s.publishChange(proto.AlertAcked, saved)
	return &a, nil
}

// Dismiss marks the alert hidden from the live list. Same flow as Ack.
func (s *Service) Dismiss(ctx context.Context, id string) (*proto.Alert, error) {
	if s.store == nil {
		return nil, fmt.Errorf("alerts: dismiss: no store wired")
	}
	saved, err := s.store.Dismiss(ctx, id)
	if err != nil {
		return nil, err
	}
	a := toAlert(saved)
	s.publishChange(proto.AlertDismissed, saved)
	return &a, nil
}

// publishChange best-effort sends an AlertChangeEvt on the NATS push
// subject. Failures are logged but never block the caller — push is a
// nice-to-have, not the source of truth.
func (s *Service) publishChange(change proto.AlertChangeType, p *PersistedAlert) {
	if s.nc == nil || p == nil {
		return
	}
	ev := proto.AlertChangeEvt{
		Change: change,
		Alert:  toAlert(p),
		Ts:     time.Now().UTC(),
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	if err := s.nc.Publish(proto.AlertsChangesSubject, body); err != nil {
		log.Printf("alerts: publish %s: %v", change, err)
	}
}

// toAlert flattens a PersistedAlert into the proto.Alert wire shape.
func toAlert(p *PersistedAlert) proto.Alert {
	a := proto.Alert{
		ID:       p.ID,
		Severity: p.Severity,
		Source:   proto.AlertSourceRule,
		Title:    p.Title,
		Detail:   p.Detail,
		Since:    p.StartsAt,
	}
	if p.AckedAt != nil {
		a.Acked = true
		a.AckedAt = *p.AckedAt
	}
	// Surface related node/job/app if the labels point at one — the
	// UI's drill-through becomes useful for vmalert rules whose
	// expressions group by nodeId.
	if n := p.Labels["nodeId"]; n != "" {
		a.RelatedKind = "node"
		a.RelatedID = n
	}
	return a
}

// fingerprintFromLabels derives a stable hash from an alert's labels —
// the persisted alert's natural key. It is the same derivation the
// persisted rows have always been keyed by, so rows written before rule
// alerts were read from VictoriaMetrics keep their identity. Sorted label
// k=v pairs joined by | hashed to a hex string is enough —
// collision-resistant for the homelab alert volume we care about.
func fingerprintFromLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf []byte
	for _, k := range keys {
		buf = append(buf, k...)
		buf = append(buf, '=')
		buf = append(buf, labels[k]...)
		buf = append(buf, '|')
	}
	return fmt.Sprintf("%x", fnv64(buf))
}

// fnv64 is a tiny FNV-1a — avoids pulling crypto/sha256 for a non-security hash.
func fnv64(b []byte) uint64 {
	var h uint64 = 14695981039346656037
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

func severityRank(s proto.AlertSeverity) int {
	switch s {
	case proto.AlertCrit:
		return 2
	case proto.AlertWarn:
		return 1
	default:
		return 0
	}
}

// humanizeDuration returns a compact "Nm Ns" / "Nh Nm" / "Nd Nh" string.
// Negative durations clamp to "0s" — callers shouldn't pass them but the
// alerts page should never render "-3s ago".
func humanizeDuration(d time.Duration) string {
	if d < 0 {
		return "0s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) - m*60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm %ds", m, s)
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) - h*60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh %dm", h, m)
	}
	days := int(d.Hours() / 24)
	h := int(d.Hours()) - days*24
	if h == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd %dh", days, h)
}
