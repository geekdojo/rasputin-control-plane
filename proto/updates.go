package proto

import (
	"fmt"
	"time"
)

// UpdateSlot identifies one of the two A/B slots managed by RAUC. "unknown"
// is used by the api on first contact before the agent has reported.
type UpdateSlot string

const (
	SlotA       UpdateSlot = "a"
	SlotB       UpdateSlot = "b"
	SlotUnknown UpdateSlot = "unknown"
)

// UpdateSlotState is RAUC's per-slot health flag.
//
//	good     — slot booted successfully at least once
//	bad      — slot was marked bad by a health check; bootloader will not boot it
//	active   — slot is currently running
//	inactive — slot is not running but is bootable
type UpdateSlotState string

const (
	SlotStateGood     UpdateSlotState = "good"
	SlotStateBad      UpdateSlotState = "bad"
	SlotStateActive   UpdateSlotState = "active"
	SlotStateInactive UpdateSlotState = "inactive"
)

// UpdatePrecheckCmd is sent on rasputin.node.<id>.cmd.update.precheck. The
// agent reports its current view of the slot layout without mutating
// anything. The api uses it to validate the target before starting download.
type UpdatePrecheckCmd struct{}

// UpdatePrecheckAck describes the agent's current slot reality.
type UpdatePrecheckAck struct {
	OK             bool       `json:"ok"`
	ActiveSlot     UpdateSlot `json:"activeSlot"`
	InactiveSlot   UpdateSlot `json:"inactiveSlot"`
	CurrentVersion string     `json:"currentVersion"`
	AvailableBytes int64      `json:"availableBytes"` // free space on inactive slot's partition
	Backend        string     `json:"backend"`        // "rauc" or "mock"
	Detail         string     `json:"detail,omitempty"`
}

// UpdateDownloadCmd tells the agent where to fetch the bundle. URL is
// expected to be HTTPS over the tailnet; ExpectedSHA256 is the bundle's
// content hash, verified after download.
type UpdateDownloadCmd struct {
	BundleID       string `json:"bundleId"`
	URL            string `json:"url"`
	ExpectedSHA256 string `json:"expectedSha256"`
	SizeBytes      int64  `json:"sizeBytes,omitempty"`
}

// UpdateDownloadAck reports the local filesystem path the agent placed the
// bundle at (used by the install step) and the size it actually fetched.
type UpdateDownloadAck struct {
	OK        bool   `json:"ok"`
	LocalPath string `json:"localPath"`
	SizeBytes int64  `json:"sizeBytes"`
	SHA256    string `json:"sha256"`
	Detail    string `json:"detail,omitempty"`
}

// UpdateDownloadProgressEvt is published on
// rasputin.node.<id>.evt.update.download.progress while the agent is
// downloading. Cadence: every ~500ms or every 1% — whichever is rarer.
type UpdateDownloadProgressEvt struct {
	NodeID         string    `json:"nodeId"`
	BundleID       string    `json:"bundleId"`
	BytesCompleted int64     `json:"bytesCompleted"`
	BytesTotal     int64     `json:"bytesTotal"`
	Ts             time.Time `json:"ts"`
}

// UpdateInstallCmd tells the agent to install a previously-downloaded bundle.
// The api sets TargetSlot from the precheck's inactiveSlot.
type UpdateInstallCmd struct {
	BundleID   string     `json:"bundleId"`
	LocalPath  string     `json:"localPath"`
	TargetSlot UpdateSlot `json:"targetSlot"`
}

// UpdateInstallAck reports the install outcome. NewVersion is the version
// string the bundle declares (read from manifest).
type UpdateInstallAck struct {
	OK         bool       `json:"ok"`
	TargetSlot UpdateSlot `json:"targetSlot"`
	NewVersion string     `json:"newVersion"`
	Detail     string     `json:"detail,omitempty"`
}

// UpdateInstallProgressEvt mirrors RAUC's own progress events. Phase is one
// of "verify", "extract", "write", "post-install"; percent is 0-100.
type UpdateInstallProgressEvt struct {
	NodeID   string    `json:"nodeId"`
	BundleID string    `json:"bundleId"`
	Phase    string    `json:"phase"`
	Percent  int       `json:"percent"`
	Ts       time.Time `json:"ts"`
}

// UpdateRebootCmd asks the agent to reboot into the slot that was just
// installed. Mirrors system.reboot but is gated on an install having
// happened — the agent rejects this if its last-install marker is empty.
type UpdateRebootCmd struct {
	BundleID     string `json:"bundleId"`
	DelaySeconds int    `json:"delaySeconds,omitempty"`
}

// UpdateRebootAck is the synchronous reply before the reboot starts.
type UpdateRebootAck struct {
	OK           bool `json:"ok"`
	DelaySeconds int  `json:"delaySeconds"`
}

// UpdateMarkGoodCmd is sent after the post-reboot health check passes. The
// agent calls `rauc status mark-good` (or the mock equivalent), which
// disarms the bootloader watchdog.
type UpdateMarkGoodCmd struct {
	BundleID string `json:"bundleId"`
}

type UpdateMarkGoodAck struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// UpdateMarkBadCmd is sent when the post-reboot health check fails. The
// agent calls `rauc status mark-bad` and reboots itself, which falls back to
// the prior slot.
type UpdateMarkBadCmd struct {
	BundleID string `json:"bundleId"`
	Reason   string `json:"reason"`
}

type UpdateMarkBadAck struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// UpdateChangeType enumerates lifecycle events the api publishes on
// rasputin.updates.<nodeId>.<change>.
type UpdateChangeType string

const (
	UpdateStarted    UpdateChangeType = "started"
	UpdateDownloaded UpdateChangeType = "downloaded"
	UpdateInstalled  UpdateChangeType = "installed"
	UpdateCommitted  UpdateChangeType = "committed"
	UpdateRolledBack UpdateChangeType = "rolled_back"
	UpdateFailed     UpdateChangeType = "failed"
)

// UpdateChangeEvt is the payload published when a node transitions through
// an update lifecycle state. Subscribed by the UI for live progress.
type UpdateChangeEvt struct {
	NodeID   string           `json:"nodeId"`
	JobID    string           `json:"jobId"`
	BundleID string           `json:"bundleId,omitempty"`
	Change   UpdateChangeType `json:"change"`
	FromSlot UpdateSlot       `json:"fromSlot,omitempty"`
	ToSlot   UpdateSlot       `json:"toSlot,omitempty"`
	Version  string           `json:"version,omitempty"`
	Reason   string           `json:"reason,omitempty"`
	Ts       time.Time        `json:"ts"`
}

// ----- Bundle metadata ----------------------------------------------------

// BundleManifest is the metadata the api reads out of a `.raucb` bundle (or
// mock equivalent). RAUC's real manifest has more fields; we keep the
// minimum the saga needs and the UI displays. SignedBy carries the CN of
// the leaf cert that signed the bundle, for audit.
type BundleManifest struct {
	Version      string   `json:"version"`
	Compatible   string   `json:"compatible"` // hardware compat string, e.g. "rasputin-pi5-cm5"
	Description  string   `json:"description,omitempty"`
	BuildDate    string   `json:"buildDate,omitempty"`
	Architecture string   `json:"architecture"` // arm64 | amd64
	SHA256       string   `json:"sha256"`
	SizeBytes    int64    `json:"sizeBytes"`
	SignedBy     string   `json:"signedBy,omitempty"`
	SlotImages   []string `json:"slotImages,omitempty"`
}

// ----- Subject helpers ----------------------------------------------------

// UpdatePrecheckSubject returns the cmd subject for precheck on nodeID.
func UpdatePrecheckSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "update.precheck")
}

// UpdateDownloadSubject returns the cmd subject for download on nodeID.
func UpdateDownloadSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "update.download")
}

// UpdateInstallSubject returns the cmd subject for install on nodeID.
func UpdateInstallSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "update.install")
}

// UpdateRebootSubject returns the cmd subject for the post-install reboot.
func UpdateRebootSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "update.reboot")
}

// UpdateMarkGoodSubject returns the cmd subject for the post-reboot commit.
func UpdateMarkGoodSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "update.mark-good")
}

// UpdateMarkBadSubject returns the cmd subject for the post-reboot abort.
func UpdateMarkBadSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "update.mark-bad")
}

// UpdateDownloadProgressSubject is what the agent publishes on while
// streaming download bytes.
func UpdateDownloadProgressSubject(nodeID string) string {
	return NodeEvtSubject(nodeID, "update.download.progress")
}

// UpdateInstallProgressSubject is what the agent publishes on while
// installing.
func UpdateInstallProgressSubject(nodeID string) string {
	return NodeEvtSubject(nodeID, "update.install.progress")
}

// UpdateChangeSubject is the publish subject for a lifecycle change.
func UpdateChangeSubject(nodeID string, change UpdateChangeType) string {
	return fmt.Sprintf("rasputin.updates.%s.%s", nodeID, string(change))
}

// AllUpdatesFilter matches every update change event. Used by the UI
// WebSocket bridge.
const AllUpdatesFilter = "rasputin.updates.>"

// AllUpdateProgressFilter matches both download and install progress for
// every node. Used by the UI to render per-node progress bars.
const AllUpdateProgressFilter = "rasputin.node.*.evt.update.>"

// ----- System-wide updates ------------------------------------------------

// SystemUpdateSpec is the spec body the api accepts for a system.update
// job. The saga plans an ordered list of per-node updates, spawns each as
// a child node.update job, and rolls up the outcome.
type SystemUpdateSpec struct {
	BundleSHA256 string `json:"bundleSha256"`
	// ExcludeNodes optionally skips specific node ids. Always implicitly
	// includes the api's own self node id (RASPUTIN_SELF_NODE_ID) — the
	// operator updates that one manually after the cascade.
	ExcludeNodes []string `json:"excludeNodes,omitempty"`
}

// SystemUpdateChangeType enumerates lifecycle events the api publishes on
// rasputin.updates.system.<parentJobId>.<change>.
type SystemUpdateChangeType string

const (
	SystemUpdatePlanned       SystemUpdateChangeType = "planned"
	SystemUpdateNodeStarted   SystemUpdateChangeType = "node_started"
	SystemUpdateNodeSucceeded SystemUpdateChangeType = "node_succeeded"
	SystemUpdateNodeFailed    SystemUpdateChangeType = "node_failed"
	SystemUpdateCompleted     SystemUpdateChangeType = "completed"
	SystemUpdateAborted       SystemUpdateChangeType = "aborted"
)

// SystemUpdateChangeEvt is the payload published on each lifecycle
// transition. NodeID is empty on planned/completed/aborted; populated on
// node_*.
type SystemUpdateChangeEvt struct {
	ParentJobID string                 `json:"parentJobId"`
	Change      SystemUpdateChangeType `json:"change"`
	NodeID      string                 `json:"nodeId,omitempty"`
	ChildJobID  string                 `json:"childJobId,omitempty"`
	BundleID    string                 `json:"bundleId,omitempty"`
	Detail      string                 `json:"detail,omitempty"`
	// Counts is filled on planned/completed/aborted: total, succeeded, failed.
	Counts *SystemUpdateCounts `json:"counts,omitempty"`
	Ts     time.Time           `json:"ts"`
}

// SystemUpdateCounts is the per-cascade rollup carried on the planned and
// terminal change events.
type SystemUpdateCounts struct {
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Skipped   int `json:"skipped"`
}

// SystemUpdateChangeSubject returns the publish subject for a system-update
// lifecycle change. parentJobID is the system.update job id.
func SystemUpdateChangeSubject(parentJobID string, change SystemUpdateChangeType) string {
	return fmt.Sprintf("rasputin.updates.system.%s.%s", parentJobID, string(change))
}

// AllSystemUpdatesFilter matches every system-update change event.
const AllSystemUpdatesFilter = "rasputin.updates.system.>"
