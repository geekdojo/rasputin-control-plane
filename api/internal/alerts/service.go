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
//
// Adding a source is a single function on Service that appends to the
// accumulator; everything else (HTTP handler, UI types, drill-through) is
// generic on proto.Alert.
package alerts

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// failedJobLookback bounds how far back we surface failed jobs. Past this
// window the failure is "history" — the operator should look at /tasks if
// they care, not be nagged by a banner.
const failedJobLookback = 24 * time.Hour

// Service aggregates alerts from the subsystem stores.
type Service struct {
	inv   *inventory.Store
	jobs  *jobs.Store
	apps  *apps.Store
	setup *setup.Service
}

// New constructs an alerts Service. All sources are required; if a future
// version wants to gate one, expose it as an option here rather than
// passing nil.
func New(inv *inventory.Store, j *jobs.Store, a *apps.Store, s *setup.Service) *Service {
	return &Service{inv: inv, jobs: j, apps: a, setup: s}
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
		// exist, status is derived from last_seen. Compute it the same way
		// /api/nodes does. (Third copy of this logic; see TODO at bottom.)
		switch computeNodeStatus(n.LastSeen) {
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

// computeNodeStatus mirrors inventory.computeStatus (unexported) and the
// same helper in api/handlers.go. Thresholds:
//
//	gap < 30s  → online
//	gap < 2m   → stale
//	gap >= 2m  → offline
//
// TODO(consolidate): this is now duplicated in three places (here,
// inventory/service.go, api/handlers.go). The cleanest fix is to export
// it from inventory. Keeping the duplication today because the cycle-risk
// note in api/handlers.go suggests the author already considered it; a
// dedicated refactor PR can lift this into one place.
func computeNodeStatus(lastSeen time.Time) proto.NodeStatus {
	gap := time.Since(lastSeen)
	switch {
	case gap < 30*time.Second:
		return proto.StatusOnline
	case gap < 2*time.Minute:
		return proto.StatusStale
	default:
		return proto.StatusOffline
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
