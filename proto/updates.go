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

// Updater work budgets: how long the AGENT may spend on one step before it
// answers. They live here, next to the wire types, for the same reason the
// deploy pair in apps.go does — they are half of a contract whose other half
// lives in another process, and the bus reply grant in busreply.go is derived
// from them, so they must be visible to something that can see all of them at
// once.
//
// Note the api's matching saga step timeouts (api/internal/updater/jobs.go) are
// SHORTER at 10m, unlike deploy where the api's deadline is deliberately the
// longer of the pair. That inversion is documented in the agent handler as
// intentional ("the api's step timeout is shorter (10m) so the saga will time
// out first if needed"); it is recorded here, not changed here.
const (
	UpdateDownloadWork = 15 * time.Minute
	UpdateInstallWork  = 15 * time.Minute
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
	// BootID is the kernel's per-boot UUID (/proc/sys/kernel/random/boot_id)
	// for the boot that is answering. It is the update saga's boot IDENTITY:
	// the pre-reboot value is captured at precheck and compared for EQUALITY
	// after the reboot, which is the only question step 6 actually wants to ask
	// — "is this a different boot than the one I told to reboot?" A boot
	// *timestamp* would not do: the majority node is a Pi with no RTC whose
	// clock is wrong until timesyncd runs. ADR-0005 Decision 1.
	//
	// Empty from a pre-bootId agent. Consumers treat "" as UNKNOWN and never as
	// a mismatch (ADR-0005 Decision 3) — a fleet update is mixed-version by
	// definition, so the first rollout onto any existing cluster gets no boot
	// identity from any node, and hard-failing would mean no existing cluster
	// could ever adopt the feature. Same tolerance as Architecture / LANIP /
	// Storage on NodeRegisteredEvt.
	BootID string `json:"bootId,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// UpdateDownloadCmd tells the agent where to fetch the bundle. URL is
// expected to be HTTPS over the tailnet; ExpectedSHA256 is the bundle's
// content hash, verified after download.
type UpdateDownloadCmd struct {
	BundleID       string `json:"bundleId"`
	URL            string `json:"url"`
	ExpectedSHA256 string `json:"expectedSha256"`
	SizeBytes      int64  `json:"sizeBytes,omitempty"`
	// SigURL is where the artifact's DETACHED CMS signature lives — the
	// `${artifact}.sig` the release pipeline publishes, staged beside the
	// bundle blob and served at /api/bundles/{sha}/sig.
	//
	// It is separate from ExpectedSHA256 because the two answer different
	// questions and only one of them is a security control. The sha proves the
	// bytes arrived from the api unaltered — TRANSPORT integrity. The signature
	// proves the bytes were published by whoever holds the offline Rasputin
	// root — PUBLISHER authenticity. The firewall shipped with only the former
	// for its whole life, which meant anything that could reach the bundle
	// store could reach the partition that terminates the WAN
	// (geekdojo/geekdojo-brain#154).
	//
	// Empty means the api had no signature to offer. Backends that verify
	// signatures MUST treat that as a hard failure rather than falling back to
	// the sha gate — a gate with a fallback is a gate an attacker selects.
	SigURL string `json:"sigUrl,omitempty"`
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
	// UnverifiedBoot / UnverifiedVersion mark a verify that PASSED on fewer
	// than all its conjuncts because some could not be evaluated — a node whose
	// agent reported no boot identity, or no image version (ADR-0005
	// Decision 3). Carried on terminal events so a live watcher, and later the
	// canary gate, can tell a fully-verified outcome from a degraded one.
	//
	// A degraded result is still a pass and still fans out: a fleet update is
	// mixed-version by definition, so every existing cluster's FIRST rollout
	// after boot identity shipped is degraded on every node. Refusing would
	// mean no existing cluster could ever adopt the feature. These fields exist
	// so that is visible rather than silent.
	UnverifiedBoot    bool      `json:"unverifiedBoot,omitempty"`
	UnverifiedVersion bool      `json:"unverifiedVersion,omitempty"`
	Ts                time.Time `json:"ts"`
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
// Exactly one of Version or BundleSHA256 must be set.
type SystemUpdateSpec struct {
	// Version keys the cascade on a RELEASE. The plan then resolves the
	// correct per-arch bundle FOR EACH NODE, so "UPDATE ALL" means all nodes
	// on a mixed arm64/amd64 cluster. This is the form the UI uses.
	//
	// Keying on a single bundle made the SKU filter do target *rejection*:
	// one bundle was chosen, every node wanting a different one was bucketed
	// under `skipped`, and the parent succeeded. Resolving per node turns the
	// same filter into bundle *selection* — which subsumes its original job
	// while keeping the firewall's protection intact, since the firewall's
	// artifact is still selected by its own SKU and it still cascades alone,
	// never handed an OS image to dd. ADR-0005 Decision 11.
	Version string `json:"version,omitempty"`
	// Component scopes a Version-keyed run to one product line ("os" | "fw").
	// Required because a version alone cannot say which: the OS and the
	// firewall are separate images on separate release cadences, and nodes
	// outside the chosen component are skipped as `firewall-sku` — the
	// designed single-SKU filter, not a stranding. Defaults to "os".
	Component string `json:"component,omitempty"`
	// BundleSHA256 keys the cascade on ONE bundle. Retained for a targeted
	// run — deploying a specific artifact to whatever matches it — and it is
	// the only form that existed before Decision 11.
	BundleSHA256 string `json:"bundleSha256,omitempty"`
	// ExcludeNodes optionally skips specific node ids. Always implicitly
	// includes the api's own self node id (RASPUTIN_SELF_NODE_ID) — the
	// operator updates that one manually after the cascade.
	ExcludeNodes []string `json:"excludeNodes,omitempty"`
	// CanaryNodes optionally overrides which node is the canary. The plan
	// otherwise picks the first target in planned order for each (tier, arch)
	// pair; naming a node here makes it that pair's canary instead. At most
	// one override per pair, each must be a target of this plan, and none may
	// be the controlplane or the firewall — the plan fails loudly rather than
	// silently ignoring an override, because an operator who names a canary
	// has a reason and getting a different one is worse than being told no.
	// ADR-0005 Decision 6.
	CanaryNodes []string `json:"canaryNodes,omitempty"`
	// MaxInFlight bounds how many nodes of ONE TIER update at the same time.
	// nil means DefaultMaxInFlight.
	//
	// `1` reproduces the serial cascade exactly, which is what makes bounded
	// fan-out expressible as a backwards-compatible change. The governing
	// constraint on the default is availability blast radius — 4 in flight on
	// a 24-node compute tier is about a sixth of it rebooting at once — not
	// control-plane I/O; whether concurrent bundle pulls off a Pi 5 become the
	// binding constraint is an open measurement owed on the bench (#81), and
	// the default is a starting point rather than a measured one.
	//
	// Always clamped per tier, see ClampMaxInFlight.
	MaxInFlight *IntOrString `json:"maxInFlight,omitempty"`
	// MaxFailures is how many nodes of ONE TIER may fail before the cascade
	// stops STARTING new ones. Nodes already in flight are allowed to finish.
	// nil means DefaultMaxFailures; an absolute `0` means unlimited.
	//
	// The rationale is that the canary has already cleared the image, so
	// several independent failures during fan-out indicate fleet
	// heterogeneity rather than a bad bundle — a condition an operator should
	// look at before it touches twenty more nodes.
	//
	// See ResolveMaxFailures for why it is tier-relative and what a percentage
	// that rounds to zero means.
	MaxFailures *IntOrString `json:"maxFailures,omitempty"`
	// CanarySoakSeconds holds a tier's fan-out for this long after its
	// canaries pass. Defaults to 0 and is expected to stay there: the health
	// battery that gates mark-good is synchronous, so a soak adds latency
	// without adding a signal we do not already take. The knob exists so that
	// late-manifesting field failures are a config change rather than a
	// redesign (ADR-0005 Decision 6, recorded as a revisit criterion).
	CanarySoakSeconds int `json:"canarySoakSeconds,omitempty"`
}

// MaxCanarySoakSeconds bounds CanarySoakSeconds. The cascade step's own
// timeout is two hours and a soak spends it doing nothing, so an unbounded
// value turns a knob into a way to fail a fleet update by timeout.
const MaxCanarySoakSeconds = 3600

// DefaultMaxInFlight is the fan-out width when the caller does not say
// (approved 2026-08-11). Unmeasured on purpose and recorded as such: it is
// chosen for blast radius, and the bench that would turn it into a measured
// number is its own Spike.
var DefaultMaxInFlight = Int(4)

// ClampMaxInFlight is the rule that makes a flat default safe to leave alone
// at every cluster size: min(k, max(1, tierSize−1)).
//
// The subtraction is the whole point — it holds AT LEAST ONE NODE BACK in
// every tier however small. At 22 compute nodes the clamp is inert (4 < 21);
// at 2 nodes it forces 1, which is serial. Without it, `k=4` on a two-node
// tier is not a bounded fan-out at all, it is one unbounded batch wearing the
// word "bounded".
//
// It also partly rescues the failure budget. That breaker can only act while
// nodes are still WAITING to start, so it is inert once tierSize ≤ k; the
// clamp guarantees k < tierSize whenever tierSize ≥ 2, which keeps the final
// node gated behind the failure count. One held-back node is a thin brake and
// this does not make the breaker useful at three nodes — on small fleets the
// canary is the real gate — but it stops it being structurally dead.
//
// ADR-0005 Decision 6.
func ClampMaxInFlight(k, tierSize int) int {
	if ceiling := tierSize - 1; k > ceiling {
		k = ceiling
	}
	if k < 1 {
		return 1
	}
	return k
}

// DefaultMaxFailures is the failure budget when the caller does not say.
//
// 15% lands on the approved anchor — a 24-node cluster's ~22-node compute tier
// gives floor(3.3) = 3 — and degrades sensibly on the way down: 8 nodes → 1,
// 3 nodes → 1. An absolute 3 was rejected because it can never trip on a
// 2-node compute tier (Bryce, 2026-08-11: "3 is fine for 24 nodes, useless on
// a 3-node cluster"). ADR-0005 Decision 7.
var DefaultMaxFailures = Percent(15)

// UnlimitedFailures is the budget that never trips.
const UnlimitedFailures = 0

// ResolveMaxFailures turns the budget into a count of nodes for one tier.
//
// Two rules that are not symmetric, deliberately:
//
//   - an ABSOLUTE zero means UNLIMITED. It is the only way to say "attempt
//     every node whatever happens", and best-effort fan-out (Decision 7) makes
//     that a legitimate thing to want.
//   - a PERCENTAGE that rounds down to zero floors to ONE. 15% of a 3-node
//     tier is 0.45, and reading that as "unlimited" would turn the safest-
//     sounding setting into the least safe one on the smallest cluster —
//     exactly backwards. A percentage is a request for a proportionate brake,
//     never a request to remove it.
//
// ⚠️ The breaker is weak on a small cluster whatever this returns, because it
// can only act while nodes are still WAITING to start — it bites only when
// tierSize > k. Decision 6's clamp stops that being structurally dead by
// always holding one node back, but one node is a thin brake. On small fleets
// safety comes from the canary and from per-node A/B rollback, and the ADR
// states that rather than implying otherwise.
func ResolveMaxFailures(v IntOrString, tierSize int) int {
	if !v.Percent {
		return v.Value
	}
	if n := v.Resolve(tierSize); n > 0 {
		return n
	}
	return 1
}

// SystemUpdatePlan is the read-only resolution of a system.update spec: what
// the cascade WOULD do, without submitting anything. It powers the pre-flight
// UI (#95) — the operator sees the ordered targets and the per-arch canary
// picks, and can override the canary or the knobs, before committing to a
// rollout. It is produced by the same buildPlan the saga runs, so the preview
// cannot drift from what actually executes.
type SystemUpdatePlan struct {
	BundleVersion string        `json:"bundleVersion"`
	Component     string        `json:"component,omitempty"`
	Targets       []PlanTarget  `json:"targets"`
	Skipped       []SkippedNode `json:"skipped"`
	// SelfNodeID is the node hosting the api, when it is one of the targets
	// (#56). The pre-flight drawer needs it to name the one consequence an
	// operator cannot see coming from a list of node ids: the last node in
	// this plan is the one serving the page they are reading.
	SelfNodeID string `json:"selfNodeId,omitempty"`
}

// PlanTarget is one node the plan would update, in planned order, flagged if it
// is the canary for its (tier, arch) pair.
type PlanTarget struct {
	NodeID     string   `json:"nodeId"`
	Tier       NodeRole `json:"tier"`
	Compatible string   `json:"compatible"`
	Canary     bool     `json:"canary"`
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
	// SystemUpdateCanaryPassed / SystemUpdateCanaryFailed are the GATE's
	// verdict for one (tier, arch) pair, which is a different fact from the
	// canary node's own outcome — that already arrives as node_succeeded /
	// node_failed with Canary set. The gate event is the one that says whether
	// the arch's fan-out is authorised, and it is what a results grid renders
	// as the row separating "one node proved the image" from "and then twenty
	// more got it". ADR-0005 Decisions 6 + 11.
	SystemUpdateCanaryPassed SystemUpdateChangeType = "canary_passed"
	SystemUpdateCanaryFailed SystemUpdateChangeType = "canary_failed"
	// SystemUpdateBudgetSpent — a tier's failure budget was reached and the
	// cascade stopped starting new nodes there. Its own event because the
	// alternative is an operator inferring it from a run that simply stopped:
	// "we stopped on purpose" and "it ran out of nodes" look identical in a
	// grid full of not-attempted rows. ADR-0005 Decision 7.
	SystemUpdateBudgetSpent SystemUpdateChangeType = "budget_spent"
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
	// Tier is the node's role, which is also the unit the cascade advances in:
	// compute → storage → controlplane → firewall, sequential between tiers.
	// Populated on node_* and canary_*.
	Tier NodeRole `json:"tier,omitempty"`
	// Compatible is the release SKU of the artifact this node is receiving —
	// the arch, in practice. Carried because the canary is scoped per arch, so
	// "the canary passed" is only ever a claim about one of them.
	Compatible string `json:"compatible,omitempty"`
	// Canary marks a node_* event as belonging to a canary rather than to a
	// fan-out target.
	Canary bool `json:"canary,omitempty"`
	// Counts is filled on planned/completed/aborted: total, succeeded, failed.
	Counts *SystemUpdateCounts `json:"counts,omitempty"`
	// Skipped is filled on planned/completed with the per-node reason each
	// non-target was left out. Carried as well as Counts.Skipped because a
	// count cannot answer the only question that matters — whether a skip was
	// designed or a node was left behind (see SkipReason).
	Skipped []SkippedNode `json:"skipped,omitempty"`
	// Results is the per-node grid, filled on `completed`: one row per planned
	// target, in planned order. Skipped nodes are NOT in here — they are in
	// Skipped, with a reason, because "never a target" and "a target that
	// failed" are different rows of the same report.
	Results []NodeResult `json:"results,omitempty"`
	Ts      time.Time    `json:"ts"`
}

// SkipReason names why a node was left out of a system.update plan.
//
// The distinction is load-bearing, not cosmetic. Three of these are the plan
// working exactly as designed; SkipNoArtifactForArch is a node left behind.
// Until ADR-0005 Decision 11 they rendered identically — a bare id in a list
// and a bare count on the wire — so "UPDATE ALL" on a mixed arm64/amd64
// cluster could update eleven nodes, strand eleven more, and report green.
type SkipReason string

const (
	// SkipExcluded — the operator (or the self-node rule) asked for it.
	SkipExcluded SkipReason = "excluded"
	// SkipOffline — the node was not reachable when the plan was made.
	SkipOffline SkipReason = "offline"
	// SkipFirewallSKU — the SKU filter working as designed: a system.update
	// carries one bundle, so an OS cascade skips the firewall and a firewall
	// cascade contains only it. This is what keeps an OS squashfs from ever
	// reaching the firewall's openwrt-ab backend (ADR-0005 Decision 8).
	SkipFirewallSKU SkipReason = "firewall-sku"
	// SkipNoArtifactForArch — THE STRANDED ONE. The node runs an architecture
	// this cascade has no artifact for, either because the run was keyed on a
	// single bundle of another arch or because the node never reported an arch
	// at all. Nobody asked for this node to be left out; it just was.
	SkipNoArtifactForArch SkipReason = "no-artifact-for-arch"
)

// Stranded reports whether a skip means a node was left behind rather than
// deliberately left out. A plan containing any stranded node must not leave
// its parent job green (ADR-0005 Decision 11).
func (r SkipReason) Stranded() bool { return r == SkipNoArtifactForArch }

// SkippedNode is one non-target of a system.update plan, with the reason it
// was not planned. Detail is human-readable colour for the UI (e.g. which SKU
// the node wanted versus which the bundle carries); Reason is what code
// branches on.
type SkippedNode struct {
	NodeID string     `json:"nodeId"`
	Reason SkipReason `json:"reason"`
	Detail string     `json:"detail,omitempty"`
	// Tier and Compatible are the node's role and the SKU it WOULD have taken.
	// A skipped node is still a row of the same report as a target, and a
	// report whose skipped half has no dimensions reads as broken data rather
	// than as a deliberate omission — which is what a firewall run looked like
	// on the bench, one populated row above six blank ones.
	//
	// Both are known at plan time and were simply dropped. Compatible carries
	// most of the weight: on a SkipNoArtifactForArch row the arch the node
	// needed is the whole content of the row, and Decision 11 exists to keep
	// exactly that visible. Empty when the node reported an architecture with
	// no known artifact — the honest answer there is that we do not know.
	Tier       NodeRole `json:"tier,omitempty"`
	Compatible string   `json:"compatible,omitempty"`
}

// NodeOutcome is what happened to ONE planned target of a fleet update.
//
// A third value beyond succeeded/failed is the whole point. Under best-effort
// fan-out (ADR-0005 Decision 7) every planned target is attempted, so a target
// that was NOT attempted is a specific and rarer event — the canary gate
// aborted before it, or the failure budget stopped the tier — and it is not
// the same as a failure. Collapsing the two would report a node the cascade
// deliberately protected as a node that broke.
type NodeOutcome string

const (
	NodeOutcomeSucceeded NodeOutcome = "succeeded"
	NodeOutcomeFailed    NodeOutcome = "failed"
	// NodeOutcomeNotAttempted — planned, never started. Nothing happened to
	// this node; it is still on its old slot.
	NodeOutcomeNotAttempted NodeOutcome = "not-attempted"
)

// NodeResult is one row of the per-node results grid.
//
// The grid is the primary artifact of a fleet update, not a detail view: once
// the cascade stops halting on the first failure, partial success becomes the
// COMMON outcome and "3 of 22 failed, here is which three" is the answer an
// operator actually needs. A parent status and a set of counts cannot give it.
//
// Carried alongside the child jobs rather than derived from them because the
// grid has to include rows that have no child — a target that was never
// attempted — and dimensions a child job does not know: which tier it was in,
// which architecture's artifact it took, and whether it was the canary.
type NodeResult struct {
	NodeID     string      `json:"nodeId"`
	Outcome    NodeOutcome `json:"outcome"`
	Tier       NodeRole    `json:"tier,omitempty"`
	Compatible string      `json:"compatible,omitempty"`
	Canary     bool        `json:"canary,omitempty"`
	ChildJobID string      `json:"childJobId,omitempty"`
	// Detail is the failure reason, or why the node was never attempted.
	Detail string `json:"detail,omitempty"`
}

// SystemUpdateCounts is the per-cascade rollup carried on the planned and
// terminal change events.
type SystemUpdateCounts struct {
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Skipped   int `json:"skipped"`
	// NotAttempted is planned targets the cascade never started. Separate from
	// Failed and from Skipped: a skip was decided at plan time and a failure
	// happened to a node, but this is a node the run stopped short of. It is
	// also what tells "every node was tried and every one failed" apart from
	// "the canary caught it and we stopped" — two red screens that ask the
	// operator for completely different next moves.
	NotAttempted int `json:"notAttempted,omitempty"`
	// Stranded is the subset of Skipped that nobody asked for — nodes with no
	// artifact for their arch. Broken out rather than left inside Skipped
	// because it is the number that decides whether the run was honest, and a
	// UI that renders "3 skipped" next to a green tick is the bug this exists
	// to close.
	Stranded int `json:"stranded,omitempty"`
}

// SystemUpdateChangeSubject returns the publish subject for a system-update
// lifecycle change. parentJobID is the system.update job id.
func SystemUpdateChangeSubject(parentJobID string, change SystemUpdateChangeType) string {
	return fmt.Sprintf("rasputin.updates.system.%s.%s", parentJobID, string(change))
}

// AllSystemUpdatesFilter matches every system-update change event.
const AllSystemUpdatesFilter = "rasputin.updates.system.>"
