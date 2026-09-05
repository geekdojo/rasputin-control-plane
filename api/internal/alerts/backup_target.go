package alerts

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// BackupTargets is the claimed-target health the aggregator reads for
// backup-target alerts (design/storage.md §4.4, #398). Satisfied by
// *storage.Store; an interface for the same reason BackupStates is — this
// package depends on the wire type in proto, and the storage package's own
// tests can drive the aggregator.
type BackupTargets interface {
	ClaimedTargetHealth(ctx context.Context) ([]proto.BackupTargetHealthReport, error)
}

// SetBackupTargets wires the target-health source. Wired by main after New,
// like SetBackupStates.
func (s *Service) SetBackupTargets(b BackupTargets) { s.targets = b }

// backupTargetAlerts is #398's alert path: one alert per claimed target whose
// last health check found it MISSING, UNMOUNTED, UNWRITABLE or UNREACHABLE.
//
// Crit, always: a target in any of those states fails every backup run until
// it changes, and at the default weekly cadence the run that would have said
// so is up to six days away. The id is stable per target, so a second read is
// the same alert and not a second one; Since is when the state was first
// observed, so the row's age reads as "how long has this been wrong"; the
// title names the label and that elapsed time; Detail is the probe's own
// finding. It disappears on its own the moment a poll finds the target
// healthy — the record is the lifecycle, as node-offline's is.
//
// A target never polled (`unknown`) raises nothing: nothing was found.
func (s *Service) backupTargetAlerts(ctx context.Context, now time.Time) ([]proto.Alert, error) {
	if s.targets == nil {
		return nil, nil
	}
	reports, err := s.targets.ClaimedTargetHealth(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]proto.Alert, 0)
	for _, r := range reports {
		h := r.Health
		if !h.State.Unhealthy() {
			continue
		}
		since := h.Since
		if since.IsZero() {
			since = h.CheckedAt
		}
		if since.IsZero() {
			since = now
		}
		label := strings.TrimSpace(r.Label)
		if label == "" {
			label = r.PartUUID
		}
		detail := h.Detail
		if detail == "" {
			detail = "the last health check found the target " + string(h.State)
		}
		out = append(out, proto.Alert{
			ID:          "backup-target:" + r.PartUUID,
			Severity:    proto.AlertCrit,
			Source:      proto.AlertSourceNode,
			Title:       fmt.Sprintf("Backup target %s is %s — for %s; every backup will fail", label, strings.ToUpper(string(h.State)), humanizeDuration(now.Sub(since))),
			Detail:      detail,
			Since:       since,
			RelatedKind: "node",
			RelatedID:   r.NodeID,
		})
	}
	return out, nil
}
