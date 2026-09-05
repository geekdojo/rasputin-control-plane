package proto

import "time"

// Per-app backup state — design/storage.md §4.4's "failure is loud", as one
// signal with three surfaces (geekdojo/geekdojo-brain#298).
//
// The unit is the APP, not the run. A run is a cluster-wide event and can end
// failed because of one app on one offline node while every other app's data
// landed; what an operator needs to know per app is a single question — "has
// this app's data been captured within its cadence?" — and this is the answer
// to it, derived on the api from the backup ledger and served on every
// /api/apps row. The app tile, the alert path and the job feed all read the
// same derivation, so they cannot disagree.

// AppBackupStateKind is where an app stands against its backup cadence.
type AppBackupStateKind string

const (
	// AppBackupOK — a generation still on the target holds every one of the
	// app's backed-up volumes, captured inside the cadence, and nothing newer
	// has failed for it.
	AppBackupOK AppBackupStateKind = "ok"
	// AppBackupOverdue — §4.4's red state. The app's data has not been
	// captured within its cadence plus grace, or has never been captured and
	// the app has been installed longer than that, or the most recent
	// attempt to capture it FAILED (its node was offline, its agent refused,
	// its upload did not land). A backup that did not happen is a failed
	// backup, never a skipped one — this is the state that says so.
	AppBackupOverdue AppBackupStateKind = "overdue"
	// AppBackupNever — no generation has ever captured the app, and it was
	// installed recently enough that the first scheduled run is still ahead.
	// Not red: a fresh install is not a missed backup. It becomes overdue on
	// its own once the cadence plus grace has elapsed.
	AppBackupNever AppBackupStateKind = "never"
	// AppBackupUnconfigured — backups are not set up on this cluster: no
	// target is claimed, or the schedule is turned off. Deliberately NOT
	// overdue: nothing was due. This is the standing-nag state
	// geekdojo/geekdojo-brain#299 owns, and it must not render as OVERDUE.
	AppBackupUnconfigured AppBackupStateKind = "unconfigured"
	// AppBackupNone — the app has nothing a backup would take: every volume
	// its tile declares is `cache` or `bulk`, or it has no tile (a custom
	// compose app) and so no classification. Never overdue. Reason says
	// which.
	AppBackupNone AppBackupStateKind = "none"
)

// AppBackupState is the per-app answer, served as the `backup` field of an
// /api/apps row. Identifiers, times and prose only — nothing key-shaped can
// appear here, and nothing does.
type AppBackupState struct {
	State AppBackupStateKind `json:"state"`
	// Class is the highest §4.2 class among the app's backed-up volumes —
	// `critical` if any volume is, else `state`. It is what decides the
	// alert's severity: a stale password vault is crit, stale app state is
	// warn. Empty for AppBackupNone.
	Class string `json:"class,omitempty"`
	// LastSuccessAt is when a generation last captured EVERY one of this
	// app's backed-up volumes. Absent means never.
	LastSuccessAt *time.Time `json:"lastSuccessAt,omitempty"`
	// LastAttemptAt is when a run last tried — the newest terminal run that
	// reached this app, or that failed before reaching anything.
	LastAttemptAt *time.Time `json:"lastAttemptAt,omitempty"`
	// OverdueSince is when the state became overdue: the moment the cadence
	// plus grace ran out, or the moment the failed attempt ended. Only set
	// when State is overdue; the alert's Since.
	OverdueSince *time.Time `json:"overdueSince,omitempty"`
	// Reason is the sentence beside the state — for overdue, the fan-out's
	// own per-volume reason (off-node, refused, upload did not land) or
	// the age; for the other states, why the app is in it.
	Reason string `json:"reason,omitempty"`
	// Cadence is the schedule the state was judged against, as a duration
	// string, so a tile can say "weekly" beside "9d".
	Cadence string `json:"cadence,omitempty"`
}

// Overdue reports whether the state is §4.4's red one.
func (s AppBackupState) Overdue() bool { return s.State == AppBackupOverdue }

// AppBackupStatus is one app's state with the app named, for the consumers
// that walk every app rather than one row — the alerts aggregator.
type AppBackupStatus struct {
	AppID   string `json:"appId"`
	AppName string `json:"appName"`
	AppBackupState
}
