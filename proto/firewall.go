package proto

import (
	"fmt"
	"time"
)

// FirewallIntentKind enumerates the supported firewall intent types.
// Only port_forward is implemented in v0; the others are reserved.
type FirewallIntentKind string

const (
	IntentPortForward FirewallIntentKind = "port_forward"
	// Reserved for future:
	// IntentWGPeer        FirewallIntentKind = "wg_peer"
	// IntentVLAN          FirewallIntentKind = "vlan"
	// IntentFirewallRule  FirewallIntentKind = "firewall_rule"
)

// AllFirewallIntentKinds lists supported intent kinds for validation.
var AllFirewallIntentKinds = []FirewallIntentKind{IntentPortForward}

// ValidFirewallIntentKind reports whether k is one of the supported kinds.
func ValidFirewallIntentKind(k FirewallIntentKind) bool {
	for _, ok := range AllFirewallIntentKinds {
		if ok == k {
			return true
		}
	}
	return false
}

// PortForwardProto enumerates supported port-forward protocols.
type PortForwardProto string

const (
	ProtoTCP    PortForwardProto = "tcp"
	ProtoUDP    PortForwardProto = "udp"
	ProtoTCPUDP PortForwardProto = "tcpudp"
)

// PortForwardSpec describes a single port-forward intent.
type PortForwardSpec struct {
	WanPort  int              `json:"wanPort"`
	LanHost  string           `json:"lanHost"` // IP or DNS-resolvable name on LAN
	LanPort  int              `json:"lanPort"`
	Protocol PortForwardProto `json:"protocol"`
	Comment  string           `json:"comment,omitempty"`
}

// FirewallApplyCmd is the request body the api sends on
// rasputin.node.<id>.cmd.firewall.apply. The agent applies the compiled UCI
// state and returns FirewallApplyAck.
type FirewallApplyCmd struct {
	// State is the compiled UCI representation of all enabled intents.
	// The shape mirrors OpenWrt UCI: { "<config>": { "<section_type>": [ {...}, ... ] } }
	State map[string]any `json:"state"`
	// IntentHash is what the api computed for State; the agent should report
	// it back on success so the api can confirm the round-trip.
	IntentHash string `json:"intentHash"`
}

// FirewallApplyAck is the synchronous reply from the agent's apply handler.
type FirewallApplyAck struct {
	OK   bool   `json:"ok"`
	Hash string `json:"hash"` // SHA-256 of the canonicalized applied state
}

// FirewallGetCmd is sent on rasputin.node.<id>.cmd.firewall.get. The agent
// returns FirewallGetAck describing the currently observed state.
type FirewallGetCmd struct{}

// FirewallGetAck is the synchronous reply from the agent's get handler.
type FirewallGetAck struct {
	State map[string]any `json:"state"`
	Hash  string         `json:"hash"`
}

// FirewallChangeType enumerates the change events the api publishes on
// rasputin.firewall.<nodeId>.<change>.
type FirewallChangeType string

const (
	FirewallApplied    FirewallChangeType = "applied"
	FirewallDrift      FirewallChangeType = "drift"
	FirewallInSync     FirewallChangeType = "in_sync"
	FirewallReconciled FirewallChangeType = "reconciled"
)

// FirewallChangeEvt is the payload published when the api detects an apply,
// reconcile, or drift transition on a firewall node.
type FirewallChangeEvt struct {
	NodeID       string             `json:"nodeId"`
	Change       FirewallChangeType `json:"change"`
	IntentHash   string             `json:"intentHash,omitempty"`
	ObservedHash string             `json:"observedHash,omitempty"`
	Ts           time.Time          `json:"ts"`
}

// FirewallApplySubject returns the cmd subject for an apply on nodeID.
func FirewallApplySubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "firewall.apply")
}

// FirewallGetSubject returns the cmd subject for a state-get on nodeID.
func FirewallGetSubject(nodeID string) string {
	return NodeCmdSubject(nodeID, "firewall.get")
}

// FirewallChangeSubject returns the publish subject for a firewall change.
func FirewallChangeSubject(nodeID string, change FirewallChangeType) string {
	return fmt.Sprintf("rasputin.firewall.%s.%s", nodeID, string(change))
}

// AllFirewallChangesFilter is the wildcard the UI uses to receive every
// firewall change event over a WebSocket bridge.
const AllFirewallChangesFilter = "rasputin.firewall.>"
