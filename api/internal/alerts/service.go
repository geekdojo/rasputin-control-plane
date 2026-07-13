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

// Status derivation lives in inventory.ComputeStatus — see nodeAlerts.

// failedJobLookback bounds how far back we surface failed jobs. Past this
// window the failure is "history" — the operator should look at /tasks if
// they care, not be nagged by a banner.
const failedJobLookback = 24 * time.Hour

// Service aggregates alerts from the subsystem stores AND merges in
// rule-engine alerts persisted via the webhook (Slice 1.5). The
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

	// busAuthEnforced mirrors the api's RASPUTIN_BUS_AUTH=enforce state.
	// When false the aggregator emits a standing bus-auth-off warn — the
	// default is the alerting state on purpose, so wiring that forgets to
	// pass the real value produces a visible false warning, not a silently
	// missing security alert.
	busAuthEnforced bool
}

// New constructs an alerts Service. The store + nats.Conn are optional;
// dev-time wiring may pass nil for both (the aggregator still works).
// Production wiring passes both so the webhook receiver can persist and
// the UI's /ws/alerts gets push updates. busAuthEnforced is whether the
// api runs with RASPUTIN_BUS_AUTH=enforce — see securityAlerts.
func New(inv *inventory.Store, j *jobs.Store, a *apps.Store, s *setup.Service, store *Store, nc *nats.Conn, busAuthEnforced bool) *Service {
	return &Service{inv: inv, jobs: j, apps: a, setup: s, store: store, nc: nc, busAuthEnforced: busAuthEnforced}
}

// List returns the current alert snapshot, sorted by severity descending
// then by Since ascending (oldest concern first within a severity tier).
func (s *Service) List(ctx context.Context) ([]proto.Alert, error) {
	now := time.Now().UTC()
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

func (s *Service) nodeAlerts(ctx context.Context, _ time.Time) ([]proto.Alert, error) {
	nodes, err := s.inv.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]proto.Alert, 0, len(nodes))
	for _, n := range nodes {
		// inventory.Store.List doesn't populate Status — the column doesn't
		// exist, status is derived from last_seen. Use the same helper the
		// /api/nodes handler uses so all three readers agree.
		switch inventory.ComputeStatus(n.LastSeen) {
		case proto.StatusOffline:
			out = append(out, proto.Alert{
				ID:          "node-offline:" + n.ID,
				Severity:    proto.AlertCrit,
				Source:      proto.AlertSourceNode,
				Title:       fmt.Sprintf("Node %s is offline", n.ID),
				Detail:      fmt.Sprintf("Last heartbeat %s ago", humanizeDuration(time.Since(n.LastSeen))),
				Since:       n.LastSeen,
				RelatedKind: "node",
				RelatedID:   n.ID,
			})
		case proto.StatusStale:
			out = append(out, proto.Alert{
				ID:          "node-stale:" + n.ID,
				Severity:    proto.AlertWarn,
				Source:      proto.AlertSourceNode,
				Title:       fmt.Sprintf("Node %s heartbeat is stale", n.ID),
				Detail:      fmt.Sprintf("Last heartbeat %s ago", humanizeDuration(time.Since(n.LastSeen))),
				Since:       n.LastSeen,
				RelatedKind: "node",
				RelatedID:   n.ID,
			})
		}
	}
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
	if s.busAuthEnforced {
		return nil
	}
	// Like setup-incomplete, Since is "now" — the condition holds since api
	// start but we don't track that; the UI doesn't render duration for
	// cluster-wide standing alerts.
	return []proto.Alert{{
		ID:       "bus-auth-off",
		Severity: proto.AlertWarn,
		Source:   proto.AlertSourceSecurity,
		Title:    "Node bus authentication is off",
		Detail:   "The NATS bus accepts any connection — any device on the LAN can join as any node. Provision node join tokens and set RASPUTIN_BUS_AUTH=enforce on the controlplane to close it.",
		Since:    now,
	}}
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

// IngestWebhook handles an Alertmanager-v2-format webhook POST. vmalert
// (configured with -notifier.url=http://api:8080/api/alerts/webhook) is
// the production caller; tests can drive it directly.
//
// Each alert in the payload is upsert-ed by fingerprint. A NEW row
// triggers AlertFired on the NATS push topic; status transition to
// "resolved" triggers AlertResolved. Both are best-effort — webhook
// success is gated on the database write, not the push.
func (s *Service) IngestWebhook(ctx context.Context, body []byte) (ingested int, err error) {
	if s.store == nil {
		return 0, fmt.Errorf("alerts: webhook: no store wired")
	}
	var wh AlertmanagerWebhook
	if err := json.Unmarshal(body, &wh); err != nil {
		return 0, fmt.Errorf("alerts: webhook: decode: %w", err)
	}
	for _, a := range wh.Alerts {
		fp := a.Fingerprint
		if fp == "" {
			fp = fingerprintFromLabels(a.Labels)
		}
		title := a.Labels["alertname"]
		if title == "" {
			title = "alert"
		}
		sev := proto.AlertWarn
		if a.Labels["severity"] == "critical" || a.Labels["severity"] == "crit" {
			sev = proto.AlertCrit
		}
		detail := a.Annotations["summary"]
		if detail == "" {
			detail = a.Annotations["description"]
		}
		row := &PersistedAlert{
			Fingerprint: fp,
			Status:      a.Status,
			Severity:    sev,
			Title:       title,
			Detail:      detail,
			Labels:      a.Labels,
			Annotations: a.Annotations,
			StartsAt:    a.StartsAt,
		}
		if !a.EndsAt.IsZero() {
			t := a.EndsAt
			row.EndsAt = &t
		}
		saved, isNew, err := s.store.Upsert(ctx, row)
		if err != nil {
			return ingested, err
		}
		ingested++
		change := proto.AlertResolved
		switch {
		case isNew:
			change = proto.AlertFired
		case saved.Status == "firing":
			change = proto.AlertFired
		case saved.Status == "resolved":
			change = proto.AlertResolved
		}
		s.publishChange(change, saved)
	}
	return ingested, nil
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

// AlertmanagerWebhook is the v2 webhook payload Alertmanager / vmalert
// POST. Only the fields we actually use are decoded.
type AlertmanagerWebhook struct {
	Version  string              `json:"version"`
	GroupKey string              `json:"groupKey"`
	Status   string              `json:"status"`
	Alerts   []AlertmanagerAlert `json:"alerts"`
}

// AlertmanagerAlert is a single entry inside the webhook payload.
type AlertmanagerAlert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

// fingerprintFromLabels derives a stable hash from the labels for
// Alertmanager payloads that don't include a fingerprint field
// (vmalert older versions). Sorted label k=v pairs joined by | hashed
// to a hex string is enough — collision-resistant for the homelab
// alert volume we care about.
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
