package proto

import "time"

// Staging one app volume — the wire contract for design/storage.md §4.3's
// quiesce drivers and §4.7's staged copy, on the node that hosts the app.
//
// This is the primitive the §4.5 per-node fan-out calls, one volume at a time:
// given a volume, its backup class and its quiesce strategy, produce a
// CONSISTENT copy under the agent's staging root, as one file with a known
// length and a digest, and put the app back exactly as it was found.
//
// # The split of labour, unchanged from the other backup verbs
//
// The control plane owns policy: which volumes, in what order, when, and what
// happens to the staged file afterwards. The agent owns the two things that
// have to happen on the app's own host — making the copy safe to take, and
// restoring service afterwards. The class and the strategy travel in the
// command because they are the tile's declaration (tileschema.Volume), and the
// api is the party holding the tile; the agent does not read the catalog.
//
// # What the agent refuses, by design
//
// A `cache` volume — §4.2 says it is never copied, so a command naming one is
// a caller bug and not a request. A `bulk` volume — §4.7 streams those direct
// and never stages them: a terabyte media library cannot be staged on a node
// whose boot medium is smaller than it, so staging one would trip the
// free-space guard on every media node while looking like a transient
// failure. A `postgres` or `mysql` strategy — declared in the enum, used by no
// shipped tile (the 2026-09-02 classification takes `stop` for both database
// volumes), and so deliberately NOT implemented in this build: the refusal
// names the volume, so a future tile that declares one fails visibly on its
// first backup rather than being silently skipped. And anything that would
// leave the staging partition below its reserve.
//
// # The restart contract (§4.7)
//
// For `stop`, the agent's restart of the app is UNCONDITIONAL AND ENTIRELY
// LOCAL. A watchdog armed before the stop fires on success, on failure, on a
// panic, on a cancelled context, on a lost reply and on a deadline — and it
// fires whether or not the api ever acknowledges anything. The ack REPORTS the
// outcome (AppRestored) so the fan-out can alert on an app that did not come
// back; it does not participate in bringing it back.

// Agent-side work budgets for the staging verbs. Same contract as every other
// budget in this package: the bus reply grant in busreply.go is DERIVED from
// these, so both are in AgentWorkBudgetMax.
//
// Stage gets thirty minutes. Its cost is a local disk-to-disk copy of one
// volume — but the volume can be tens of gigabytes (an immich upload set, a
// Minecraft world with years of chunks) and the disk can be an SD card on a
// Pi 4 writing at twenty megabytes a second. The alternative to waiting is an
// RPC timeout on a step that has the app STOPPED, which is the one outcome
// the watchdog exists to make impossible; a generous budget is what keeps the
// watchdog a backstop rather than the normal path.
const (
	BackupStageWork   = 30 * time.Minute
	BackupUnstageWork = 60 * time.Second
)

// BackupStopGraceSeconds is how long `stop` gives each container to shut down
// cleanly before the runtime kills it. Compose's own default is ten seconds,
// which is not enough for a database checkpointing a large WAL or a game
// server saving its world — and a SIGKILL'd database is precisely the torn
// state the stop exists to avoid. So the copy that follows a stop is only as
// consistent as the shutdown was clean, and this is the number that decides
// how clean it gets to be.
const BackupStopGraceSeconds = 60

// BackupStagingReserveBytes is the free space the staging partition must
// RETAIN after a staged copy lands — §4.7's source-side free-space guard, the
// one that stops a backup job filling the disk it is protecting.
//
// It is the same 2 GiB the api keeps on the controlplane (§5's
// VictoriaMetrics reservation, `-storage.minFreeDiskSpaceBytes=2GB`), applied
// on every node rather than only the one with a metrics store: a compute node
// wedged at 100% cannot pull an image, write a container log, or take the
// next backup either. One number in one place so the two halves of the guard
// cannot drift.
const BackupStagingReserveBytes uint64 = 2 << 30 // 2 GiB

// BackupConsistency names what the staged copy is consistent WITH — the
// guarantee each §4.3 strategy actually delivers, stated on the ack rather
// than left to be inferred from the strategy name. A restore reads this to
// know what it is holding.
type BackupConsistency string

const (
	// BackupConsistencyCleanShutdown: every file is as the app left it after a
	// clean stop, and every file agrees with every other. The strongest
	// guarantee, and the one `stop` buys — or a `none`/`sqlite` volume whose
	// app happened to be stopped when the copy ran. Window: none. The app
	// was down for DowntimeMillis.
	BackupConsistencyCleanShutdown BackupConsistency = "clean-shutdown"
	// BackupConsistencySnapshotPlusLive: each SQLite database is a
	// transactionally consistent snapshot taken through the running app's own
	// SQLite (the Online Backup API or VACUUM INTO); every OTHER file was
	// copied live. Window: a non-database file the app rewrote during the copy
	// may be torn, and the databases and the rest of the volume are each
	// consistent with themselves but not necessarily with each other — the
	// snapshot is of one instant and the file copy spans the copy's duration.
	// For homeassistant-config that means the recorder database and
	// `.storage/` can disagree by the length of the copy. `sqlite` delivers
	// this; the app stayed up.
	BackupConsistencySnapshotPlusLive BackupConsistency = "snapshot-plus-live-copy"
	// BackupConsistencyLiveCopy: a plain copy of the volume while the app may
	// have been writing it. Window: the whole copy — any file rewritten in
	// place during it may be torn, and files may disagree with each other.
	// Only safe where the tile declared `none` because nothing writes the
	// volume while the app runs.
	BackupConsistencyLiveCopy BackupConsistency = "live-copy"
)

// The staging refusals. Each is a REFUSAL and never a warning: there is no path
// where the agent stages a copy it has just said is unsafe or unaffordable.

// BackupRefusalQuiesceUnsupported: the tile declared a strategy this build has
// no driver for — `postgres` or `mysql`. Deliberate, see the file comment. The
// detail names the volume.
const BackupRefusalQuiesceUnsupported StorageRefusal = "quiesce-unsupported"

// BackupRefusalClassNotStaged: the volume's class is never staged — `cache` is
// never copied at all, and `bulk` streams direct (§4.7) rather than through
// the staging root.
const BackupRefusalClassNotStaged StorageRefusal = "class-not-staged"

// BackupRefusalVolumeNotFound: the runtime has no volume by that name for that
// app. The tile's declaration and the compose stack have disagreed, or the app
// was never deployed on this node.
const BackupRefusalVolumeNotFound StorageRefusal = "volume-not-found"

// BackupRefusalQuiesceFailed: the strategy could not be carried out — the stop
// failed, or a database snapshot failed — so no copy was taken. NOT the same as
// a copy that failed after a successful quiesce; that is a backend error, and
// the app has been restarted either way.
const BackupRefusalQuiesceFailed StorageRefusal = "quiesce-failed"

// BackupRefusalStagingExists: a file with that staging name is already under
// the root. Refused rather than overwritten — the api mints names per run, so
// a collision is a replay, and the file already there may be mid-upload.
const BackupRefusalStagingExists StorageRefusal = "staging-exists"

// BackupStageVolumeCmd stages one app volume. THIS IS THE VERB THAT STOPS AN
// APP, for the `stop` strategy, and the api should say so in the job feed
// before it sends one.
type BackupStageVolumeCmd struct {
	// AppID is the app whose compose stack owns the volume.
	AppID string `json:"appId"`
	// AppName is the instance name — logging only, so the agent's log line
	// says "stopping Vaultwarden" rather than a ULID.
	AppName string `json:"appName,omitempty"`
	// Volume is the compose volume name AS THE TILE DECLARES IT
	// (tileschema.Volume.Name) — `vaultwarden-data`, not the runtime's
	// project-prefixed `rasp_<app>_vaultwarden-data`. The agent resolves the
	// prefix; the api never learns a host path.
	Volume string `json:"volume"`
	// Class is the tile's backup class for this volume: critical|state|cache|bulk.
	Class string `json:"class"`
	// Quiesce is the tile's strategy: none|stop|sqlite|postgres|mysql.
	Quiesce string `json:"quiesce"`
	// StagingName is the file name the copy lands under, minted by the api —
	// a plain file name, never a path, validated with BackupValidStagingName
	// exactly as the write verb validates its input. The staged file is an
	// uncompressed tar of the volume's contents, paths relative to the
	// volume root.
	StagingName string `json:"stagingName"`
}

// BackupStageVolumeAck reports the staged copy, and — for every strategy —
// what happened to the app.
type BackupStageVolumeAck struct {
	OK     bool   `json:"ok"`
	AppID  string `json:"appId,omitempty"`
	Volume string `json:"volume,omitempty"`
	// StagingName echoes the command; StagedPath is where it landed on the
	// agent's node, reported so a log line can name the file.
	StagingName string `json:"stagingName,omitempty"`
	StagedPath  string `json:"stagedPath,omitempty"`
	// SizeBytes is the staged tar's length and Digest its SHA-256, lower-case
	// hex — §4.7's "known length and a checksum before transmission". The
	// agent computed both while writing and the file is fsynced, so the
	// transport that consumes this can size and verify before it moves a
	// byte.
	SizeBytes uint64 `json:"sizeBytes,omitempty"`
	Digest    string `json:"digest,omitempty"`
	// PlaintextBytes is the sum of member sizes and FileCount the number of
	// regular files captured — what "the volume" amounted to.
	PlaintextBytes uint64 `json:"plaintextBytes,omitempty"`
	FileCount      int    `json:"fileCount,omitempty"`

	// Consistency is the guarantee the copy carries, and Window the same in
	// an operator's words. See BackupConsistency for what each strategy
	// leaves open.
	Consistency BackupConsistency `json:"consistency,omitempty"`
	Window      string            `json:"window,omitempty"`

	// ServiceInterrupting says the strategy takes the app down — true for
	// `stop`, false otherwise. Reported so the fan-out can eventually
	// schedule around it (a Minecraft server drops players; a vault is
	// seconds); nothing here schedules.
	ServiceInterrupting bool `json:"serviceInterrupting"`
	// WasRunning is the app's state when the command arrived. A `stop` on an
	// app that was already stopped copies without stopping anything and —
	// deliberately — does NOT start it afterwards: restoring service means
	// restoring the state the app was found in, and an operator who stopped
	// an app did not ask a backup to start it.
	WasRunning bool `json:"wasRunning"`
	// Stopped says the agent actually stopped the app for this copy.
	Stopped bool `json:"stopped"`
	// StoppedAt and RestartedAt bracket the outage, and DowntimeMillis is the
	// difference — the measured cost of `stop` on this volume, which is what a
	// scheduler would want to know.
	StoppedAt      time.Time `json:"stoppedAt,omitempty"`
	RestartedAt    time.Time `json:"restartedAt,omitempty"`
	DowntimeMillis int64     `json:"downtimeMillis,omitempty"`
	// AppRestored is true when the app is in the state it was found in: it was
	// never stopped, or it was stopped and is running again. FALSE IS AN
	// ALERT. The copy may have succeeded (OK true) and the app still be down;
	// the fan-out must treat that as louder than a failed backup, because
	// §4.7 says it is worse than one. The agent keeps retrying in the
	// background and again at its next start, and RestoreDetail says what it
	// saw.
	AppRestored   bool   `json:"appRestored"`
	RestoreDetail string `json:"restoreDetail,omitempty"`
	// RestoredBy says which path brought the app back: "driver" when the
	// normal path released the watchdog after the copy, "watchdog" when the
	// deadline fired because the driver did not.
	RestoredBy string `json:"restoredBy,omitempty"`

	// Databases lists, for `sqlite`, every database the driver found in the
	// volume and snapshotted, as paths relative to the volume root. Reported
	// so the manifest can say which files are point-in-time snapshots and
	// which are live copies; empty for the other strategies.
	Databases []string `json:"databases,omitempty"`
	// SnapshotTool names what took the snapshots — "sqlite3" for the CLI's
	// VACUUM INTO, "python3" for the sqlite3 module's Online Backup API. The
	// pinned Home Assistant image ships no sqlite3 binary and does ship
	// python3 (probed 2026-09-02), which is why there are two.
	SnapshotTool string `json:"snapshotTool,omitempty"`

	Refusal StorageRefusal `json:"refusal,omitempty"`
	Detail  string         `json:"detail,omitempty"`
}

// BackupUnstageCmd removes one staged file by name — the delete half of §4.7's
// "stage one volume at a time and delete each after a confirmed upload", which
// is what keeps peak usage at the largest single volume rather than the sum.
// A name, never a path, and only a regular file directly under the root.
type BackupUnstageCmd struct {
	StagingName string `json:"stagingName"`
}

// BackupUnstageAck reports what was removed. Removing a file that is not there
// is a success with Existed false — the api may retry after a lost ack.
type BackupUnstageAck struct {
	OK          bool           `json:"ok"`
	StagingName string         `json:"stagingName,omitempty"`
	Existed     bool           `json:"existed"`
	FreedBytes  uint64         `json:"freedBytes,omitempty"`
	Refusal     StorageRefusal `json:"refusal,omitempty"`
	Detail      string         `json:"detail,omitempty"`
}

// BackupStageVolumeSubject stages one app volume under the node's staging root.
func BackupStageVolumeSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "storage.backup_stage_volume")
}

// BackupUnstageSubject removes one staged file.
func BackupUnstageSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "storage.backup_unstage")
}
