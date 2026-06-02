package proto

import "time"

// AlertSeverity classifies how aggressively the UI surfaces an alert.
// v0 keeps this binary (warn/crit) — INFO-level signals live in their own
// affordances (Tasks pane, banners) and don't belong on the Alerts page.
type AlertSeverity string

const (
	AlertWarn AlertSeverity = "warn"
	AlertCrit AlertSeverity = "crit"
)

// AlertSource identifies which subsystem the alert was derived from. The UI
// uses this for grouping and iconography; for drill-through, prefer
// (RelatedKind, RelatedID).
type AlertSource string

const (
	AlertSourceNode  AlertSource = "node"
	AlertSourceJob   AlertSource = "job"
	AlertSourceApp   AlertSource = "app"
	AlertSourceSetup AlertSource = "setup"
	// AlertSourceRule is used by alerts that arrive from vmalert (or any
	// future Alertmanager-compatible rules engine) via the webhook
	// receiver at /api/alerts/webhook. The aggregator's source-specific
	// alerts (node/job/app/setup) are computed on every read; rule
	// alerts are persisted.
	AlertSourceRule AlertSource = "rule"
)

// Alert is a single "the operator should look at this" line item. v0 is
// computed-on-read by the alerts aggregator from existing subsystem state
// (no alerts table, no rules engine, no persistent ack/dismiss). Future
// observability work — alert rules over VictoriaMetrics, Loki, etc. —
// slots in behind the same handler so the wire shape stays stable.
//
// The ID is stable across re-derivations for the same underlying condition
// (e.g. "node-offline:node-fw"), so the UI can dedupe and animate
// transitions without flicker.
type Alert struct {
	ID          string        `json:"id"`
	Severity    AlertSeverity `json:"severity"`
	Source      AlertSource   `json:"source"`
	Title       string        `json:"title"`
	Detail      string        `json:"detail,omitempty"`
	Since       time.Time     `json:"since"`
	RelatedKind string        `json:"relatedKind,omitempty"` // "node" | "job" | "app"
	RelatedID   string        `json:"relatedId,omitempty"`
	// Acked is true when the operator has acknowledged the alert via
	// POST /api/alerts/{id}/ack. Only meaningful for Source=rule; the
	// aggregator-derived alerts always report false since their
	// lifecycle is computed-on-read.
	Acked bool `json:"acked,omitempty"`
	// AckedAt is when the alert was acknowledged. Zero when !Acked.
	AckedAt time.Time `json:"ackedAt,omitempty"`
}

// AlertChangeType identifies what happened to a persisted alert. Used
// by the NATS push topic the UI subscribes to so live updates land
// without poll.
type AlertChangeType string

const (
	AlertFired     AlertChangeType = "fired"     // first time we've seen this fingerprint OR a new firing after resolved
	AlertResolved  AlertChangeType = "resolved"  // vmalert says it's no longer firing
	AlertAcked     AlertChangeType = "acked"     // operator ack'd
	AlertDismissed AlertChangeType = "dismissed" // operator dismissed (hidden from list)
)

// AlertChangeEvt is the payload published on AlertsChangesSubject.
type AlertChangeEvt struct {
	Change AlertChangeType `json:"change"`
	Alert  Alert           `json:"alert"`
	Ts     time.Time       `json:"ts"`
}

// AlertsChangesSubject is the NATS subject for live alert updates.
// /ws/alerts bridges this to the UI.
const AlertsChangesSubject = "rasputin.alerts.changes"
