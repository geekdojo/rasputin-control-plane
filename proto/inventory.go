package proto

import "time"

// NodeRole classifies a node by what it does in the system. The MVS uses
// controlplane + firewall; compute and storage are reserved for nodes that
// land in later phases.
type NodeRole string

const (
	RoleControlPlane NodeRole = "controlplane"
	RoleFirewall     NodeRole = "firewall"
	RoleCompute      NodeRole = "compute"
	RoleStorage      NodeRole = "storage"
)

// AllRoles lists the role values recognized by the api. Unknown values are
// rejected on registration.
var AllRoles = []NodeRole{RoleControlPlane, RoleFirewall, RoleCompute, RoleStorage}

// ValidRole reports whether r is one of AllRoles.
func ValidRole(r NodeRole) bool {
	for _, ok := range AllRoles {
		if ok == r {
			return true
		}
	}
	return false
}

// MaxClusterNodes is the deliberate cluster-size cap, controlplane included
// (product decision 2026-07-12). The UI's hex grid is designed around it —
// ui/components/NodeGrid.tsx MAX_NODES must stay in sync. The api enforces it
// in two places: bus-token minting (a mint that would commit a new node id
// past the cap is refused) and node registration (a registration that would
// insert a row past the cap is dropped — the backstop for preseeded matched
// sets and direct bus connects, which never pass through mint).
const MaxClusterNodes = 24

// NodeStatus is computed by the api from a node's last heartbeat. It is
// never sent by an agent.
type NodeStatus string

const (
	StatusOnline  NodeStatus = "online"
	StatusStale   NodeStatus = "stale"
	StatusOffline NodeStatus = "offline"
)

// NodeRegisteredEvt is published by an agent on every NATS connect and
// reconnect. The api treats it as an idempotent upsert of the node row.
type NodeRegisteredEvt struct {
	NodeID       string   `json:"nodeId"`
	Role         NodeRole `json:"role"`
	Hostname     string   `json:"hostname"`
	AgentVersion string   `json:"agentVersion"`
	ImageVersion string   `json:"imageVersion"`
	// Architecture is the node's CPU arch ("amd64" | "arm64"), reported as the
	// agent binary's runtime.GOARCH (the agent ships per-arch, so this is the
	// node's arch). Drives arch-aware update deploys + the UI "Type" field.
	// Empty from pre-arch agents; consumers treat "" as unknown.
	Architecture string `json:"architecture,omitempty"`
	// LANIP is the node's LAN IPv4 — its default-route source address, computed
	// by the agent the same way the control plane computes its own. The CP
	// nameserver answers <hostname>.<cluster-id>.internal (and apps homed on this
	// node) with it (ADR-0004 §8). Because Rasputin makes no DHCP MAC
	// reservations, it changes on most reboots, so it is re-reported on every
	// reconnect (this event fires on every NATS connect). "" from a pre-LANIP
	// agent; consumers treat "" as unknown and never let it wipe a learned value.
	LANIP        string         `json:"lanIP,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	// Storage is the agent's boot-time snapshot of the persistent data
	// partition. Nil from pre-storage agents; consumers treat nil as unknown
	// (and, like Architecture, never let a nil report wipe a learned value).
	Storage *StorageInfo `json:"storage,omitempty"`
	// BootID is the kernel's per-boot UUID (/proc/sys/kernel/random/boot_id)
	// for the boot publishing this registration — the same identity carried on
	// UpdatePrecheckAck, and documented there. Carried here so the update
	// saga's wait step can compare boot identity straight off the registration
	// event it is already subscribed to, without a second round trip.
	//
	// Note this event fires on every NATS *connect*, not every boot, so two
	// registrations with the same BootID are the normal case (an agent
	// reconnecting after an api restart). Equality means "same boot", nothing
	// more. Empty from a pre-bootId agent; consumers treat "" as unknown, never
	// as a mismatch (ADR-0005 Decision 3).
	BootID string    `json:"bootId,omitempty"`
	Ts     time.Time `json:"ts"`
}

// StorageInfo describes the node's persistent data partition
// (/var/lib/rasputin — the only writable storage on an appliance, where "/"
// is read-only squashfs). Snapshotted by the agent at startup: the values
// change materially only across a boot (the one-time growpart), so register
// cadence is the right freshness; live fill level is in the disk_* metrics.
type StorageInfo struct {
	// PersistentTotalBytes / PersistentFreeBytes are a statfs of the
	// persistent filesystem. A ~512 MiB total on a large disk is the
	// signature of a failed/skipped growpart (the historically silent
	// failure this field exists to surface).
	PersistentTotalBytes uint64 `json:"persistentTotalBytes"`
	PersistentFreeBytes  uint64 `json:"persistentFreeBytes"`
	// Growpart is the outcome keyword from the newest line of the
	// rasputin-os breadcrumb log (/var/lib/rasputin/growpart.log):
	// grown | already-full | deferred-trial | skipped | failed.
	// "" when the log is absent (pre-breadcrumb image, or dev).
	Growpart string `json:"growpart,omitempty"`
}

// HeartbeatEvt is published on rasputin.node.<id>.heartbeat every ~10s. Kept
// deliberately small — heartbeats add up.
type HeartbeatEvt struct {
	NodeID       string    `json:"nodeId"`
	Uptime       string    `json:"uptime"`
	AgentVersion string    `json:"agentVersion"`
	Ts           time.Time `json:"ts"`
}

// InventoryChangeType enumerates the change events the api emits on
// rasputin.inventory.<nodeId>.<change>.
type InventoryChangeType string

const (
	InventoryAdded   InventoryChangeType = "added"
	InventoryOnline  InventoryChangeType = "online"
	InventoryStale   InventoryChangeType = "stale"
	InventoryOffline InventoryChangeType = "offline"
	InventoryUpdated InventoryChangeType = "updated"
	InventoryRemoved InventoryChangeType = "removed"
)

// InventoryChangeEvt is the payload published by the api on the inventory
// change subject. The full Node is included so subscribers don't have to
// re-fetch.
type InventoryChangeEvt struct {
	Change InventoryChangeType `json:"change"`
	Node   Node                `json:"node"`
	Ts     time.Time           `json:"ts"`
}

// Node is the api's view of an agent — the projection that gets returned
// from /api/nodes and embedded in InventoryChangeEvt.
type Node struct {
	ID           string   `json:"id"`
	Role         NodeRole `json:"role"`
	Hostname     string   `json:"hostname"`
	AgentVersion string   `json:"agentVersion"`
	ImageVersion string   `json:"imageVersion"`
	// Architecture is the node's CPU arch ("amd64" | "arm64"); "" if a pre-arch
	// agent never reported it. Surfaced in the UI and used to match the right
	// OS bundle on deploy.
	Architecture string `json:"architecture,omitempty"`
	// LANIP is the node's LAN IPv4, agent-reported on NodeRegisteredEvt (ADR-0004
	// §8). "" until a LANIP-reporting agent registers. What the CP nameserver
	// resolves this node's name (and its apps' names) to.
	LANIP        string         `json:"lanIP,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	// Storage is the latest agent-reported persistent-partition snapshot;
	// nil until a storage-reporting agent registers.
	Storage   *StorageInfo `json:"storage,omitempty"`
	FirstSeen time.Time    `json:"firstSeen"`
	LastSeen  time.Time    `json:"lastSeen"`
	Status    NodeStatus   `json:"status"`
}
