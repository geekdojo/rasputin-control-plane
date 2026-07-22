package proto

import (
	"encoding/json"
	"fmt"
	"time"
)

// The bmc-targets capability (design/control-plane/bmc.md §2a): a BMC-host
// agent's registration advertises the node-ids whose BMC serial lines it
// can physically reach. CapabilityBMCTargets tags the host in
// capabilities[]; the list itself rides in metadata under
// MetadataBMCTargets. MetadataBMCConfigHash echoes the applied
// settings-config hash so the api can re-push after a miss or reflash,
// and MetadataBMCConfigPinned marks a host whose selection is pinned by
// RASPUTIN_BMC_BACKEND env (bmc-settings.md §4–5). proto owns all the
// names so the agent that publishes and the api/UI that gate can't drift.
const (
	CapabilityBMCTargets    = "bmc-targets"
	MetadataBMCTargets      = "bmcTargets"
	MetadataBMCConfigHash   = "bmcConfigHash"
	MetadataBMCConfigPinned = "bmcConfigPinned"
)

// BMCBackendInfo describes one supported BMC backend for the Settings
// picker (bmc-settings.md §2, S-1). The UI renders this served list —
// never a hardcoded copy. "None" is not a backend; it is the absence of
// a selection (hard off).
type BMCBackendInfo struct {
	Kind   string `json:"kind"`
	Label  string `json:"label"`
	Status string `json:"status"` // BMCBackendAvailable | BMCBackendPlanned
}

const (
	BMCBackendAvailable = "available"
	BMCBackendPlanned   = "planned"
)

// SupportedBMCBackends is the platform's backend registry. Every
// "available" kind must have a factory in the agent's bmc registry —
// asserted by a drift test on the agent side (proto cannot import the
// agent without a cycle).
var SupportedBMCBackends = []BMCBackendInfo{
	{Kind: "bitscope", Label: "BitScope CB04B blade rack", Status: BMCBackendAvailable},
	{Kind: "mock", Label: "Mock (development)", Status: BMCBackendAvailable},
	{Kind: "turingpi", Label: "Turing Pi", Status: BMCBackendPlanned},
	{Kind: "rasputin", Label: "Rasputin chassis", Status: BMCBackendPlanned},
}

// AvailableBMCBackend reports whether kind is a supported, available
// backend selection.
func AvailableBMCBackend(kind string) bool {
	for _, b := range SupportedBMCBackends {
		if b.Kind == kind && b.Status == BMCBackendAvailable {
			return true
		}
	}
	return false
}

// BMCConfigureCmd delivers the cluster's BMC selection to the host agent
// (bmc-settings.md §4). Kind "none" clears the selection: the agent
// deletes its persisted config, tears down handlers, and re-registers
// with no advertisement. Config is the per-kind blob from settings,
// carried verbatim; ConfigHash is computed api-side and echoed by the
// agent (opaque to it).
type BMCConfigureCmd struct {
	Kind       string          `json:"kind"`
	Config     json.RawMessage `json:"config,omitempty"`
	ConfigHash string          `json:"configHash"`
}

// BMCConfigureAck is the typed reply. A pinned host answers
// OK:false with a detail naming the pin — never a timeout.
type BMCConfigureAck struct {
	OK         bool   `json:"ok"`
	ConfigHash string `json:"configHash,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// BMCConfigureSubject returns the cmd subject that delivers the BMC
// selection to the host agent.
func BMCConfigureSubject(bmcHostID string) string {
	return NodeCmdSubject(bmcHostID, "bmc.configure")
}

// NodeBMCTargets returns the node's advertised BMC target list, nil if it
// advertises none. Metadata values arrive as []string in-process but as
// []any after a JSON decode round-trip (the api's store path) — both
// shapes are handled; non-string entries are dropped.
func NodeBMCTargets(n *Node) []string {
	if n == nil || n.Metadata == nil {
		return nil
	}
	switch v := n.Metadata[MetadataBMCTargets].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// BMCPowerVerb enumerates the power operations a BMC supports.
//
// Routing note: BMC commands target a specific node, but they're delivered
// to the agent that *owns* the BMC bus (in MVS, the controlplane node's
// agent). That agent's BMC backend translates the verb + target into the
// right hardware op. Routing through the target node directly is wrong —
// if the target is powered off, its agent isn't running.
type BMCPowerVerb string

const (
	BMCPowerOn    BMCPowerVerb = "on"
	BMCPowerOff   BMCPowerVerb = "off"
	BMCPowerCycle BMCPowerVerb = "cycle"
	BMCPowerReset BMCPowerVerb = "reset"
	BMCPowerQuery BMCPowerVerb = "status"
)

// AllBMCPowerVerbs is the validation list for incoming POSTs.
var AllBMCPowerVerbs = []BMCPowerVerb{
	BMCPowerOn, BMCPowerOff, BMCPowerCycle, BMCPowerReset, BMCPowerQuery,
}

// ValidBMCPowerVerb reports whether v is one of AllBMCPowerVerbs.
func ValidBMCPowerVerb(v BMCPowerVerb) bool {
	for _, ok := range AllBMCPowerVerbs {
		if ok == v {
			return true
		}
	}
	return false
}

// BMCPowerState is what the BMC reports after (or independently of) a verb.
type BMCPowerState string

const (
	BMCStateOn      BMCPowerState = "on"
	BMCStateOff     BMCPowerState = "off"
	BMCStateUnknown BMCPowerState = "unknown"
)

// BMCPowerCmd is the request body the api sends on
// rasputin.node.<bmcHostID>.cmd.bmc.<verb>. TargetNodeID is the node whose
// power is being controlled — not the node receiving the command.
type BMCPowerCmd struct {
	TargetNodeID string `json:"targetNodeId"`
}

// BMCPowerAck is the synchronous reply from the BMC agent.
type BMCPowerAck struct {
	OK     bool          `json:"ok"`
	State  BMCPowerState `json:"state"`
	Detail string        `json:"detail,omitempty"`
}

// BMCSOLOpenCmd is sent on rasputin.node.<bmcHostID>.cmd.bmc.sol.open. The
// agent opens the target node's serial port (or its mock equivalent) and
// starts pumping bytes to/from the api over the session subjects.
type BMCSOLOpenCmd struct {
	TargetNodeID string `json:"targetNodeId"`
	SessionID    string `json:"sessionId"`
}

// BMCSOLOpenAck reports whether the session was established.
type BMCSOLOpenAck struct {
	OK        bool   `json:"ok"`
	SessionID string `json:"sessionId"`
	Backend   string `json:"backend"` // "ipmi" / "redfish" / "mock"
	Detail    string `json:"detail,omitempty"`
}

// BMCSOLCloseCmd tears down a SOL session.
type BMCSOLCloseCmd struct {
	SessionID string `json:"sessionId"`
}

type BMCSOLCloseAck struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// BMCSOLDataEvt is the byte stream payload published on the SOL data
// subjects (.in for api→agent, .out for agent→api). Data is base64-safe
// when it transits JSON; agents and the api should treat it as opaque.
type BMCSOLDataEvt struct {
	SessionID string    `json:"sessionId"`
	Data      string    `json:"data"` // raw bytes, JSON-encoded as a string
	Ts        time.Time `json:"ts"`
}

// BMCChangeType enumerates the lifecycle events the api publishes on
// rasputin.bmc.<targetNodeID>.<change>. Subscribed by the UI for live
// state pills (powered on/off banner) and the audit-log surface.
type BMCChangeType string

const (
	BMCPoweredOn  BMCChangeType = "powered_on"
	BMCPoweredOff BMCChangeType = "powered_off"
	BMCCycled     BMCChangeType = "cycled"
	BMCResetSent  BMCChangeType = "reset_sent"
	BMCSOLOpened  BMCChangeType = "sol_opened"
	BMCSOLClosed  BMCChangeType = "sol_closed"
)

// BMCChangeEvt is the payload published on each lifecycle transition.
type BMCChangeEvt struct {
	TargetNodeID string        `json:"targetNodeId"`
	Change       BMCChangeType `json:"change"`
	State        BMCPowerState `json:"state,omitempty"`
	SessionID    string        `json:"sessionId,omitempty"`
	Detail       string        `json:"detail,omitempty"`
	Ts           time.Time     `json:"ts"`
}

// ----- Subject helpers ----------------------------------------------------

// BMCPowerSubject returns the cmd subject for a power verb on the BMC
// host. The target node is in the body, not the subject — same reasoning
// as the verb routing above.
func BMCPowerSubject(bmcHostID string, verb BMCPowerVerb) string {
	return NodeCmdSubject(bmcHostID, "bmc.power."+string(verb))
}

// BMCSOLOpenSubject returns the cmd subject for opening a SOL session on
// the BMC host.
func BMCSOLOpenSubject(bmcHostID string) string {
	return NodeCmdSubject(bmcHostID, "bmc.sol.open")
}

// BMCSOLCloseSubject returns the cmd subject for closing a SOL session.
func BMCSOLCloseSubject(bmcHostID string) string {
	return NodeCmdSubject(bmcHostID, "bmc.sol.close")
}

// BMCSOLInSubject is the api→agent byte stream for a session. The api
// publishes; the agent subscribes.
func BMCSOLInSubject(sessionID string) string {
	return fmt.Sprintf("rasputin.bmc.sol.%s.in", sessionID)
}

// BMCSOLOutSubject is the agent→api byte stream for a session. The agent
// publishes; the api subscribes.
func BMCSOLOutSubject(sessionID string) string {
	return fmt.Sprintf("rasputin.bmc.sol.%s.out", sessionID)
}

// BMCChangeSubject returns the publish subject for a BMC change event.
func BMCChangeSubject(targetNodeID string, change BMCChangeType) string {
	return fmt.Sprintf("rasputin.bmc.%s.%s", targetNodeID, string(change))
}

// AllBMCChangesFilter matches every BMC change event. Used by the UI
// WebSocket bridge for live power-state pills.
const AllBMCChangesFilter = "rasputin.bmc.*.*"
