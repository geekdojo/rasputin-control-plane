package proto

import (
	"fmt"
	"time"
)

// FirewallIntentKind enumerates the supported firewall intent types.
type FirewallIntentKind string

const (
	IntentPortForward  FirewallIntentKind = "port_forward"
	IntentFirewallRule FirewallIntentKind = "firewall_rule"
	IntentWANConfig    FirewallIntentKind = "wan_config"
	// Reserved for future:
	// IntentWGPeer FirewallIntentKind = "wg_peer"
	// IntentVLAN   FirewallIntentKind = "vlan"
)

// AllFirewallIntentKinds lists supported intent kinds for validation.
var AllFirewallIntentKinds = []FirewallIntentKind{IntentPortForward, IntentFirewallRule, IntentWANConfig}

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

// FirewallRuleProto enumerates supported protocols for a firewall rule. "any"
// matches everything (compiled to UCI "all"); "tcpudp" is expanded into the
// UCI form "tcp udp" at compile time.
type FirewallRuleProto string

const (
	RuleProtoTCP    FirewallRuleProto = "tcp"
	RuleProtoUDP    FirewallRuleProto = "udp"
	RuleProtoTCPUDP FirewallRuleProto = "tcpudp"
	RuleProtoICMP   FirewallRuleProto = "icmp"
	RuleProtoAny    FirewallRuleProto = "any"
)

// FirewallRuleTarget enumerates supported actions for a firewall rule.
type FirewallRuleTarget string

const (
	RuleTargetAccept FirewallRuleTarget = "accept"
	RuleTargetReject FirewallRuleTarget = "reject"
	RuleTargetDrop   FirewallRuleTarget = "drop"
)

// WANProto enumerates supported WAN-interface protocols.
type WANProto string

const (
	WANProtoDHCP   WANProto = "dhcp"
	WANProtoStatic WANProto = "static"
	WANProtoPppoe  WANProto = "pppoe"
)

// WANConfigSpec describes a single WAN-interface configuration. Multiple
// configs can coexist in the table — the operator might keep an "ISP A" and
// "ISP B" profile around — but **at most one** is ever Enabled at a time
// (enforced by the api at create / update / toggle time). 0 enabled is the
// explicit "kill outbound" path: Compile emits `network.wan.proto = "none"`.
//
// The physical interface (`ifname`) is intentionally NOT part of the spec.
// It's hardware-role-specific (eth0 on the Phase 2 RPi 5 firewall, eth1 on
// the Phase 3 N100 + i226-V firewall) and lives in the agent's preconfigured
// UCI `wan` interface section. The compiler only overrides the proto-specific
// option keys, leaving ifname untouched.
//
// Field presence is gated by Proto — see validateIntentSpec for the contract.
type WANConfigSpec struct {
	Proto WANProto `json:"proto"`
	// DHCP — Hostname is optional client-id hint passed to the upstream
	// DHCP server.
	Hostname string `json:"hostname,omitempty"`
	// Static — IP is in CIDR form (e.g. "203.0.113.5/24"); Gateway is a
	// bare address; DNS is 0+ resolver addresses.
	IP      string   `json:"ip,omitempty"`
	Gateway string   `json:"gateway,omitempty"`
	DNS     []string `json:"dns,omitempty"`
	// PPPoE — Username + Secret required; Service optional (some ISPs
	// require a specific service-name tag).
	Username string `json:"username,omitempty"`
	Secret   string `json:"secret,omitempty"`
	Service  string `json:"service,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// FirewallRuleSpec describes a generic zone-based accept/drop rule.
//
// Src is a zone name (e.g. "wan", "lan", "iot") and is required. Dest names
// the destination zone; an empty Dest compiles to OpenWrt's INPUT chain
// (traffic terminating at the firewall itself).
//
// SrcIP / DestIP accept either a single IP ("10.0.0.5") or a CIDR
// ("10.0.0.0/24"). SrcPort / DestPort accept a single port ("443") or a
// range ("8000-8100"). All four are optional; an unset field is "any".
type FirewallRuleSpec struct {
	Src      string             `json:"src"`
	Dest     string             `json:"dest,omitempty"`
	SrcIP    string             `json:"srcIp,omitempty"`
	SrcPort  string             `json:"srcPort,omitempty"`
	DestIP   string             `json:"destIp,omitempty"`
	DestPort string             `json:"destPort,omitempty"`
	Proto    FirewallRuleProto  `json:"proto,omitempty"`
	Target   FirewallRuleTarget `json:"target"`
	Log      bool               `json:"log,omitempty"`
	Comment  string             `json:"comment,omitempty"`
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
