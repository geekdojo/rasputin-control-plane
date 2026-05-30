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
}
