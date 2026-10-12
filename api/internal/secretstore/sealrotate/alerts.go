package sealrotate

import (
	"context"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// The incomplete-rotation alert (plan, "The incomplete-rotation alert";
// F-830-03). The copy never names the vendor.
const (
	IncompleteAlertID = "secret-store:seal-rotation-incomplete"
	incompleteTitle   = "A seal-key rotation did not finish."
	incompleteDetail  = "The secret store's key change stopped before it finished, so backups are paused. " +
		"Start the seal-key rotation again to finish it. " +
		"Do not restart the node or the secret store until it has finished: a restart now can leave the store unable to open."
)

// Alerts is the incomplete-rotation alert source, computed when the list is
// read: one crit alert while the seal files are not a Clean tree and no
// rotation job is running, none otherwise. A tree that cannot be read raises
// it too (ERR-CLOSED): backups refuse on it just the same. It clears on the
// fact Clean.
func (r *Rotator) Alerts(ctx context.Context, _ time.Time) []proto.Alert {
	tree, err := r.d.Files.State()
	if err == nil && tree.Fragment.Shape == Clean {
		r.mu.Lock()
		r.since = time.Time{}
		r.mu.Unlock()
		return nil
	}
	if holder := r.d.Gate.RotationHolder(); holder != "" {
		if running, rerr := r.d.JobRunning(ctx, holder); rerr == nil && running {
			return nil
		}
	}
	r.mu.Lock()
	if r.since.IsZero() {
		r.since = r.d.Now()
	}
	since := r.since
	r.mu.Unlock()
	return []proto.Alert{{
		ID:       IncompleteAlertID,
		Severity: proto.AlertCrit,
		Source:   proto.AlertSourceSecurity,
		Title:    incompleteTitle,
		Detail:   incompleteDetail,
		Since:    since,
	}}
}
