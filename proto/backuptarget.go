package proto

import "time"

// Backup-target health — design/storage.md §4.4's "loud about failure" applied
// to the GAP BETWEEN RUNS (geekdojo/geekdojo-brain#398).
//
// A claimed target's row keeps whatever status its claim left behind. That is
// correct — the operator's intent has not changed when a disk falls off the
// bus — and it is also how a target that physically left the machine on
// e3bench (2026-09-02) went on rendering CLAIMED. The claim status says what
// the operator decided; the health below says what the disk is doing now, and
// the two are rendered side by side rather than one overwriting the other.
//
// Derived on the controlplane by a five-minute poll: storage.inspect on the
// node that holds the target, with a write probe (StorageInspectCmd.Probe),
// because the same e3bench stick answered enumeration for some time after it
// had begun failing writes. What the poll can and cannot promise is stated
// where the operator reads it — see BackupTargetHealthCaveat.

// BackupTargetHealthState is where a claimed target stands as of its last
// health check.
type BackupTargetHealthState string

const (
	// BackupTargetHealthUnknown — no health check has completed yet. The
	// state a claimed row is in from claim until the first poll, and NEVER
	// after: a poll that gets no answer records a failure that names the
	// silence, not this.
	BackupTargetHealthUnknown BackupTargetHealthState = "unknown"
	// BackupTargetHealthOK — the target is attached, mounted, its marker
	// names it, and a small file was written, fsynced, read back and deleted.
	BackupTargetHealthOK BackupTargetHealthState = "ok"
	// BackupTargetHealthMissing — nothing attached to the node carries the
	// target's partition UUID. The disk was unplugged, died, or a DIFFERENT
	// disk sits at its old device path (the §4.8 fingerprint check says which
	// in Detail). Also what a disk whose marker no longer names this target
	// reads as: by its own account it is not the claimed target.
	BackupTargetHealthMissing BackupTargetHealthState = "missing"
	// BackupTargetHealthUnmounted — the partition is attached and could not
	// be mounted. A filesystem the kernel rejects is a disk that has started
	// to go, or one that was yanked mid-write last time.
	BackupTargetHealthUnmounted BackupTargetHealthState = "unmounted"
	// BackupTargetHealthUnwritable — attached and mounted, and the write
	// probe failed. The e3bench failure mode: enumeration fine, writes
	// refused. Every backup run to this disk will fail at the write.
	BackupTargetHealthUnwritable BackupTargetHealthState = "unwritable"
	// BackupTargetHealthUnreachable — the node holding the target did not
	// answer storage.inspect inside the budget. The disk's own state is
	// unknown, and this says so rather than guessing at it; it is still a
	// failure and not a skip, because a backup run would fail the same way.
	// Detail carries inventory's reading of the silence (node offline, agent
	// predates the verb, or a real fault).
	BackupTargetHealthUnreachable BackupTargetHealthState = "unreachable"
)

// Healthy reports whether s is a state a backup run could succeed against.
// Unknown is not healthy and not unhealthy — it is "not yet checked" — and
// callers that alert or refuse must treat it as neither.
func (s BackupTargetHealthState) Healthy() bool { return s == BackupTargetHealthOK }

// Unhealthy reports whether s is a checked, failing state — the ones that
// raise an alert and refuse a run.
func (s BackupTargetHealthState) Unhealthy() bool {
	switch s {
	case BackupTargetHealthMissing, BackupTargetHealthUnmounted,
		BackupTargetHealthUnwritable, BackupTargetHealthUnreachable:
		return true
	}
	return false
}

// BackupTargetHealth is one target's health as the last check left it. Served
// as the `health` field of a /api/backup/targets row. Identifiers, times and
// prose only.
type BackupTargetHealth struct {
	State BackupTargetHealthState `json:"state"`
	// CheckedAt is when the most recent check completed. Zero for Unknown.
	CheckedAt time.Time `json:"checkedAt,omitzero"`
	// Since is when the target entered its current State — preserved across
	// polls that find the same state, so "MISSING · since 3h" counts from the
	// first poll that noticed, not the most recent. Zero for Unknown.
	Since time.Time `json:"since,omitzero"`
	// Detail is the probe's finding, in prose: what was checked, what
	// answered, what failed. The alert's body and the row's hover text.
	Detail string `json:"detail,omitempty"`
	// ProbeDurationMs is how long the write probe took when one ran.
	ProbeDurationMs int64 `json:"probeDurationMs,omitempty"`
}

// BackupTargetHealthReport is one claimed target with its health, the shape
// the alerts aggregator reads (#398's alert path).
type BackupTargetHealthReport struct {
	PartUUID string             `json:"partUuid"`
	Label    string             `json:"label,omitempty"`
	NodeID   string             `json:"nodeId"`
	Health   BackupTargetHealth `json:"health"`
}

// BackupTargetHealthInterval is how often the controlplane polls a claimed
// target. Named on the wire so the UI's honesty line and the api's freshness
// window read the same number.
const BackupTargetHealthInterval = 5 * time.Minute

// BackupTargetHealthCaveat is what the health check can and cannot promise,
// in the operator's words. Served beside the targets so the page says it in
// the api's words rather than a copy that drifts.
//
// The first half is what the poll does; the second is the limit the e3bench
// evidence set — a disk that passes a 4 KiB probe at 03:55 can still fail a
// gigabyte at 04:00, and no poll can promise otherwise.
const BackupTargetHealthCaveat = "Checked every 5 min with a small write (create, fsync, read back, delete). " +
	"That catches a disk that has left the bus or stopped taking writes between backups; " +
	"it cannot promise the next full run will succeed — a disk can still fail mid-run, and the run's own result is the record of that."
