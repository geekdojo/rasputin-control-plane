package proto

import (
	"fmt"
	"time"
)

// MeshIntentKind enumerates the supported mesh intent types. v0 deliberately
// models only the two intent shapes that map cleanly to user-facing concepts;
// the long tail of Headscale's HuJSON policy surface passes through to
// Headplane untouched (see wiki design/control-plane/mesh.md §3).
type MeshIntentKind string

const (
	IntentPreAuthKey  MeshIntentKind = "preauth_key"
	IntentSubnetRoute MeshIntentKind = "subnet_route"
)

// AllMeshIntentKinds is the validation list for incoming POSTs.
var AllMeshIntentKinds = []MeshIntentKind{IntentPreAuthKey, IntentSubnetRoute}

// ValidMeshIntentKind reports whether k is one of the supported kinds.
func ValidMeshIntentKind(k MeshIntentKind) bool {
	for _, ok := range AllMeshIntentKinds {
		if ok == k {
			return true
		}
	}
	return false
}

// PreAuthKeySpec describes a single Headscale pre-auth key intent. The
// resolved key string is persisted on the intent row (hs_value) after
// apply — Headscale will not return the plaintext on subsequent reads.
type PreAuthKeySpec struct {
	User       string   `json:"user"`                 // Headscale user; defaults to "rasputin-operator" in v0
	Reusable   bool     `json:"reusable"`             // default false; single-use is safer
	Ephemeral  bool     `json:"ephemeral"`            // ephemeral nodes auto-expire on disconnect; useful for user devices on transient networks
	ExpiresIn  string   `json:"expiresIn"`            // duration string like "24h"; default 24h
	Tags       []string `json:"tags,omitempty"`       // ACL tags assigned at registration; defaults ["tag:user-device"]
	DeviceHint string   `json:"deviceHint,omitempty"` // human label shown to the user ("Rasputin Terminal")
}

// SubnetRouteSpec describes one route advertisement. NodeID is a Rasputin
// inventory id; the api translates it to a Headscale node id at apply
// time. CIDR is what the node will `--advertise-routes`.
type SubnetRouteSpec struct {
	NodeID string `json:"nodeId"`
	CIDR   string `json:"cidr"`
}

// MeshEnrollCmd is sent on rasputin.node.<id>.cmd.mesh.enroll. The agent
// runs `tailscale up --login-server=<loginServer> --auth-key=<authKey>`,
// optionally advertising routes.
type MeshEnrollCmd struct {
	LoginServer     string   `json:"loginServer"`
	AuthKey         string   `json:"authKey"`
	Hostname        string   `json:"hostname,omitempty"`
	AdvertiseRoutes []string `json:"advertiseRoutes,omitempty"`
	AcceptDNS       bool     `json:"acceptDns"`
	AcceptRoutes    bool     `json:"acceptRoutes"`
}

// MeshEnrollAck reports the post-enrollment tailscale state.
type MeshEnrollAck struct {
	OK        bool     `json:"ok"`
	TailnetID string   `json:"tailnetId,omitempty"` // Headscale node id, if the agent could resolve it
	TailnetIP string   `json:"tailnetIp,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
	Routes    []string `json:"routes,omitempty"`
	Backend   string   `json:"backend"` // "tailscale" or "mock"
	Detail    string   `json:"detail,omitempty"`
}

// MeshLeaveCmd asks the agent to leave the tailnet (tailscale logout +
// tailscale down). Used during decommission.
type MeshLeaveCmd struct{}

type MeshLeaveAck struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// MeshStatusCmd asks the agent for its current tailscale status. Result
// includes tailnet IP, peer count, whether the daemon is up. Read-only.
type MeshStatusCmd struct{}

type MeshStatusAck struct {
	OK        bool     `json:"ok"`
	Enrolled  bool     `json:"enrolled"`
	TailnetID string   `json:"tailnetId,omitempty"`
	TailnetIP string   `json:"tailnetIp,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
	Routes    []string `json:"routes,omitempty"`
	PeerCount int      `json:"peerCount,omitempty"`
	Backend   string   `json:"backend"`
	Detail    string   `json:"detail,omitempty"`
}

// MeshChangeType enumerates the change events the api publishes on
// rasputin.mesh.<scope>.<change>. Scope is either a node id (for enrollment
// events) or "global" (for tailnet-wide state transitions).
type MeshChangeType string

const (
	MeshApplied        MeshChangeType = "applied"
	MeshInSync         MeshChangeType = "in_sync"
	MeshDrift          MeshChangeType = "drift"
	MeshReconciled     MeshChangeType = "reconciled"
	MeshNodeEnrolled   MeshChangeType = "node_enrolled"
	MeshNodeLeft       MeshChangeType = "node_left"
	MeshKeyCreated     MeshChangeType = "key_created"
	MeshKeyExpired     MeshChangeType = "key_expired"
	MeshUserDeviceSeen MeshChangeType = "user_device_seen"
)

// MeshChangeEvt is the payload published on each lifecycle transition.
type MeshChangeEvt struct {
	Scope        string         `json:"scope"` // node id or "global"
	Change       MeshChangeType `json:"change"`
	IntentHash   string         `json:"intentHash,omitempty"`
	ObservedHash string         `json:"observedHash,omitempty"`
	Detail       string         `json:"detail,omitempty"`
	NodeID       string         `json:"nodeId,omitempty"`
	TailnetID    string         `json:"tailnetId,omitempty"`
	Ts           time.Time      `json:"ts"`
}

// ----- Subject helpers ----------------------------------------------------

// MeshEnrollSubject returns the cmd subject for enrolling nodeID.
func MeshEnrollSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "mesh.enroll")
}

// MeshLeaveSubject returns the cmd subject for leaving the tailnet on nodeID.
func MeshLeaveSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "mesh.leave")
}

// MeshStatusSubject returns the cmd subject for tailnet status on nodeID.
func MeshStatusSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "mesh.status")
}

// MeshChangeSubject returns the publish subject for a mesh change.
// scope is either a node id (for per-node events) or "global" (for tailnet
// state-level events like applied / in_sync / drift).
func MeshChangeSubject(scope string, change MeshChangeType) string {
	return fmt.Sprintf("rasputin.mesh.%s.%s", scope, string(change))
}

// AllMeshChangesFilter is the wildcard the UI uses to receive every mesh
// change event over a WebSocket bridge.
const AllMeshChangesFilter = "rasputin.mesh.>"
