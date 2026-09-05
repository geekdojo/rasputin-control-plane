package alerts

import (
	"fmt"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// design/storage.md §4.4's persistent nag (geekdojo/geekdojo-brain#299): one
// alert per installed app that has a `critical` volume while backups are
// UNCONFIGURED — no target claimed, or the schedule off.
//
// # Why warn and not crit
//
// Nothing was due, so nothing is overdue. #298's backup-overdue is crit for a
// critical app because a backup that should have happened did not; this one
// says a backup CANNOT happen yet. Both are loud; only one is a failure.
//
// # Why only `critical`
//
// An app with only `state` volumes wears the same NO BACKUP TARGET badge on
// the apps page and the same sentence in its drawer, but does not raise here:
// the alert path is for the class whose staleness is itself harmful, and a
// fresh cluster with six state-class apps and no disk yet would otherwise
// open its alerts page to six copies of one fact.
//
// # Lifecycle
//
// Computed on read from the same per-app derivation the app tile renders, so
// it raises once with a stable id, never duplicates across ticks, and is gone
// the moment a target is claimed and the schedule is on — the derivation is
// the lifecycle. It applies to every installed app, not only to one that came
// through the install gate: a target forgotten after install is the same
// exposure as one never claimed, and the gate's acknowledgement record is not
// consulted.

// backupUnconfiguredID is the alert's id prefix; the app id follows.
const backupUnconfiguredID = "backup-unconfigured:"

// backupUnconfiguredAlert is the alert for one app, or false when the app's
// state does not earn one.
func backupUnconfiguredAlert(st proto.AppBackupStatus, now time.Time) (proto.Alert, bool) {
	if st.State != proto.AppBackupUnconfigured || st.Class != tileschema.BackupCritical {
		return proto.Alert{}, false
	}
	detail := st.Reason
	if detail == "" {
		detail = "No backup target is claimed, so this app's data is not backed up anywhere."
	}
	return proto.Alert{
		ID:       backupUnconfiguredID + st.AppID,
		Severity: proto.AlertWarn,
		Source:   proto.AlertSourceApp,
		Title:    fmt.Sprintf("%s has no backup target — its critical data is not protected", st.AppName),
		Detail:   detail + " Open /storage to claim a disk and turn the schedule on; this clears on its own once both are done.",
		// A standing condition with no start the ledger records — the same
		// posture as bus-auth-off and setup-incomplete. The id, not Since,
		// is what makes a second read the same alert.
		Since:       now,
		RelatedKind: "app",
		RelatedID:   st.AppID,
	}, true
}
