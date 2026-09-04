package proto

import "time"

// Restoring one app volume to the node that hosts the app — the wire contract
// for design/storage.md §4.5's restore, phase 2 (geekdojo-brain#291): the
// REVERSE of the §4.7 staged transport.
//
// # The shape, and why it is this way round
//
// A generation's volume members were sealed on their hosting nodes to the
// target's PUBLIC key. Only the private key opens them, and the private key
// exists in one place for one operation: unwrapped in the operator's browser
// from a custody secret, sent once over TLS to the api, held in memory, and
// zeroed. §4.6's whole design is that the controlplane keeps no secret; a
// restore that handed the private key to N nodes so each could open its own
// member would put the key on N nodes. So THE API UNSEALS, and the node
// receives the PLAINTEXT tar over the api's HTTPS — the same mesh-CA leaf and
// the same tailnet the OS update bundles already travel over — on a
// credential the api minted for exactly this member, this node, this restore.
// The trade is stated once, here: plaintext app data crosses the LAN inside
// TLS, as update bundles do; the key does not fan out.
//
// # What the agent does with it, and the two things it must never do
//
// It fetches the stream into a STAGING DIRECTORY BESIDE THE VOLUME — never
// into it — through the same no-symlink primitives every other consumer of
// backup bytes uses (backupxfer/fsat): regular files and directories only,
// `..` and absolute paths refused, sizes bounded by what the manifest said,
// the whole tar's sha256 verified against the manifest before a single rename.
// Then, and only then, it arms the §4.7 restart guard, stops the app, swaps
// the staged tree for the live one IN ONE RENAME, and starts the app. A
// failure anywhere before the swap leaves the live volume byte-for-byte
// untouched, and the app is running (it was never stopped, or the guard
// restarted it). The previous contents are moved aside beside the volume,
// never deleted, and the ack names where.
//
// It must never write into the live volume while the app runs, and it must
// never make the app's restart depend on the api: the guard is armed before
// the stop and fires on every exit — success, refusal, panic, cancelled
// context, lost reply, deadline — exactly as it does for the backup's stop.
//
// # Explicit, per app, operator-initiated. Never automatic.
//
// An identity restore leaves app volumes alone, and that stays true. On the
// cluster this was designed against (e3bench, 2026-09-04) the controlplane
// was wiped and restored while a compute node kept running Vaultwarden with
// NEWER data than the backup; an automatic push would have clobbered it. This
// verb is sent only by a saga an operator started for one app from one
// generation after an informed confirmation.

// BackupRestoreVolumeWork is the agent's budget for one restore: download,
// unpack, verify, stop, swap, start. Forty-five minutes, like the transfer
// it reverses — tens of gigabytes over the gigabit fabric §4.7 budgets, onto
// an SD card. In AgentWorkBudgetMax like every other budget.
const BackupRestoreVolumeWork = 45 * time.Minute

// BackupRefusalClassNotRestored: the volume's class is never restored —
// `cache` is never captured (§4.2) and `bulk` is never staged (§4.7), so a
// generation cannot hold either and a command naming one is a caller bug.
const BackupRefusalClassNotRestored StorageRefusal = "class-not-restored"

// BackupRefusalSourceRefused: the source answered and said no — a credential
// it did not accept, a member it does not have, a restore that is no longer
// open. The detail carries the source's own code.
const BackupRefusalSourceRefused StorageRefusal = "source-refused"

// BackupRefusalArchiveInvalid: the plaintext stream is not something this
// verb will put into a volume — a member that is not a regular file or a
// directory (a symlink is refused, never recreated), a path that is not a
// plain descent beneath the volume root, more bytes or more entries than the
// manifest bounds. The live volume was not touched.
const BackupRefusalArchiveInvalid StorageRefusal = "archive-invalid"

// BackupRefusalSwapFailed: the staged tree was complete and verified, the
// app was stopped, and the rename that replaces the live volume failed. The
// live volume is as it was; the app has been restarted. The staged tree is
// removed.
const BackupRefusalSwapFailed StorageRefusal = "swap-failed"

// BackupRestoreVolumeCmd restores one app volume from a plaintext stream.
// THIS IS THE VERB THAT STOPS AN APP AND REPLACES ITS DATA, and the api says
// so in the job feed before it sends one.
type BackupRestoreVolumeCmd struct {
	// AppID is the app whose compose stack owns the volume — the app AS IT IS
	// INSTALLED NOW, which may be a different node than the one that made the
	// backup. AppName is for log lines.
	AppID   string `json:"appId"`
	AppName string `json:"appName,omitempty"`
	// Volume is the compose volume name AS THE TILE DECLARES IT. The agent
	// resolves the runtime's name; the api never learns a host path.
	Volume string `json:"volume"`
	// Class is the tile's backup class for this volume. `cache` and `bulk`
	// are refused: neither can be in a generation.
	Class string `json:"class,omitempty"`
	// Source is the URL the plaintext stream is fetched from — the api's
	// restore-stream endpoint for this generation and member. Its scheme
	// selects the transport exactly as BackupTransferCmd.Destination does.
	Source string `json:"source"`
	// Credential is the scoped, short-lived download credential: one
	// generation, one member, one node, one restore, with a TTL. Presented,
	// never logged, never echoed into the ack, never written to disk.
	Credential string `json:"credential"`
	// GenerationID and Member name what is being restored, for the log line
	// and the marker.
	GenerationID string `json:"generationId"`
	Member       string `json:"member"`
	// RestoreID names the restore for the log line and the marker; the api
	// mints it.
	RestoreID string `json:"restoreId,omitempty"`
	// PlaintextDigest and PlaintextBytes are what the MANIFEST recorded for
	// this member's plaintext tar — the digest the stage verb computed when
	// the volume was captured, re-computed as it was sealed. The agent hashes
	// the stream as it arrives and refuses the volume on any difference; the
	// byte count bounds the download. Both required.
	PlaintextDigest string `json:"plaintextDigest"`
	PlaintextBytes  uint64 `json:"plaintextBytes"`
	// FileCount is what the manifest recorded, advisory: reported back
	// beside what was actually unpacked so a reader can compare.
	FileCount int `json:"fileCount,omitempty"`
}

// BackupRestoreVolumeAck reports the restore, and — whatever happened — the
// app's state afterwards.
type BackupRestoreVolumeAck struct {
	OK     bool   `json:"ok"`
	AppID  string `json:"appId,omitempty"`
	Volume string `json:"volume,omitempty"`
	Member string `json:"member,omitempty"`
	// Replaced is true only when the live volume's contents were swapped for
	// the restored ones. False with OK true cannot happen.
	Replaced bool `json:"replaced"`
	// ReceivedBytes and Digest are over the plaintext tar as it arrived —
	// equal to the command's bound and digest, or the volume was refused.
	ReceivedBytes uint64 `json:"receivedBytes,omitempty"`
	Digest        string `json:"digest,omitempty"`
	// FileCount and DirCount are what was unpacked; UnpackedBytes the sum of
	// the regular files' sizes.
	FileCount     int    `json:"fileCount,omitempty"`
	DirCount      int    `json:"dirCount,omitempty"`
	UnpackedBytes uint64 `json:"unpackedBytes,omitempty"`
	// OwnershipApplied says the entries' uid/gid from the tar were applied.
	// Only a root agent can; a dev-box agent reports false and the files are
	// owned by whoever it runs as.
	OwnershipApplied bool `json:"ownershipApplied"`
	// PreviousKept is where the volume's previous contents were moved aside
	// on the node — a directory beside the volume, never deleted by this
	// verb. Empty when nothing was replaced.
	PreviousKept string `json:"previousKept,omitempty"`

	// The restart facts, in the shape BackupStageVolumeAck reports them and
	// with the same meaning: WasRunning is the state the app was found in;
	// Stopped says the agent stopped it; AppRestored FALSE IS AN ALERT.
	WasRunning     bool      `json:"wasRunning"`
	Stopped        bool      `json:"stopped"`
	StoppedAt      time.Time `json:"stoppedAt,omitempty"`
	RestartedAt    time.Time `json:"restartedAt,omitempty"`
	DowntimeMillis int64     `json:"downtimeMillis,omitempty"`
	AppRestored    bool      `json:"appRestored"`
	RestoreDetail  string    `json:"restoreDetail,omitempty"`
	RestoredBy     string    `json:"restoredBy,omitempty"`

	// SourceCode is the source's own refusal code when it refused.
	SourceCode string         `json:"sourceCode,omitempty"`
	Refusal    StorageRefusal `json:"refusal,omitempty"`
	Detail     string         `json:"detail,omitempty"`
}

// BackupRestoreVolumeSubject restores one app volume on the node that hosts
// the app.
func BackupRestoreVolumeSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "storage.backup_restore_volume")
}
