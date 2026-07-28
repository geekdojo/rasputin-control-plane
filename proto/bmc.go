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
	MetadataBMCCapabilities = "bmcCapabilities"
	MetadataBMCConfigHash   = "bmcConfigHash"
	MetadataBMCConfigPinned = "bmcConfigPinned"
)

// ── Per-target capabilities ──────────────────────────────────────────────
//
// bmc-targets originally answered one question: which nodes can this host
// reach. That was enough while every backend could do everything. It is
// not enough now — the turingpi driver does power and reset but cannot
// offer a usable console, and a single reachability flag would render a
// CONSOLE button that fails on click (exactly what bmc.md §2a forbids).
//
// So reachability grows into a capability set per node. Different BMC
// controllers have genuinely different abilities, and the model has to be
// able to say so.
//
// ROLLOUT: MetadataBMCTargets keeps carrying the plain node-id list and
// MetadataBMCCapabilities is added alongside it. An agent older than this
// change advertises only the list, and NodeBMCCapabilities then treats it
// as "legacy: everything", which is what those backends could in fact do.
// The controlplane and its nodes update independently, so both directions
// of a rolling update have to keep working.

// BMC capability names. A backend advertises the subset it can honour for
// a given node.
const (
	BMCCapPower   = "power"   // on/off/status
	BMCCapReset   = "reset"   // hard reset
	BMCCapConsole = "console" // serial-over-LAN
)

// LegacyBMCCaps is what a target advertised without an explicit
// capability set is assumed to support — everything, matching the
// behaviour of the backends that shipped before capabilities existed.
var LegacyBMCCaps = []string{BMCCapPower, BMCCapReset, BMCCapConsole}

// Console fidelity. A polled, command-granular console (turingpi) cannot
// do character-mode input, and it drops output between polls; the UI
// needs to be able to say so rather than silently disappoint.
const (
	BMCConsoleCharacter = "character" // raw keypresses, ANSI, password masking
	BMCConsoleLine      = "line"      // one line per write, no raw mode
)

// BMCConsoleInfo describes the console a backend can actually provide.
// Nil when the target has no BMCCapConsole.
type BMCConsoleInfo struct {
	Mode string `json:"mode"` // BMCConsoleCharacter | BMCConsoleLine
	// Lossy marks a console whose output can be dropped — a polled ring
	// buffer overwrites bytes the client has not read yet, so boot
	// capture is best-effort rather than guaranteed.
	Lossy bool `json:"lossy,omitempty"`
}

// BMCTarget is one node a BMC host can reach, and what it can do for it.
type BMCTarget struct {
	NodeID  string          `json:"nodeId"`
	Caps    []string        `json:"caps"`
	Console *BMCConsoleInfo `json:"console,omitempty"`
}

// HasCap reports whether the target advertises cap.
func (t BMCTarget) HasCap(cap string) bool {
	for _, c := range t.Caps {
		if c == cap {
			return true
		}
	}
	return false
}

// BMCTargetIDs projects the node-ids, for the legacy MetadataBMCTargets
// list that ships alongside the capability set.
func BMCTargetIDs(targets []BMCTarget) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.NodeID)
	}
	return out
}

// NodeBMCCapabilities returns the node's advertised per-target
// capabilities. When the host advertises only the legacy list (an agent
// older than this change), each target is synthesised with
// LegacyBMCCaps — those backends really could do all three.
//
// Metadata arrives as concrete types in-process and as []any/map[string]any
// after a JSON round-trip (the api's store path); both are handled.
func NodeBMCCapabilities(n *Node) []BMCTarget {
	if n == nil || n.Metadata == nil {
		return nil
	}
	if raw, ok := n.Metadata[MetadataBMCCapabilities]; ok {
		if targets := decodeBMCTargets(raw); len(targets) > 0 {
			return targets
		}
	}
	// Legacy fallback.
	ids := NodeBMCTargets(n)
	if len(ids) == 0 {
		return nil
	}
	out := make([]BMCTarget, 0, len(ids))
	for _, id := range ids {
		out = append(out, BMCTarget{
			NodeID:  id,
			Caps:    append([]string(nil), LegacyBMCCaps...),
			Console: &BMCConsoleInfo{Mode: BMCConsoleCharacter},
		})
	}
	return out
}

func decodeBMCTargets(raw any) []BMCTarget {
	switch v := raw.(type) {
	case []BMCTarget:
		return v
	case []any:
		out := make([]BMCTarget, 0, len(v))
		for _, e := range v {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			id, _ := m["nodeId"].(string)
			if id == "" {
				continue
			}
			t := BMCTarget{NodeID: id}
			if caps, ok := m["caps"].([]any); ok {
				for _, c := range caps {
					if s, ok := c.(string); ok {
						t.Caps = append(t.Caps, s)
					}
				}
			}
			if c, ok := m["console"].(map[string]any); ok {
				mode, _ := c["mode"].(string)
				lossy, _ := c["lossy"].(bool)
				t.Console = &BMCConsoleInfo{Mode: mode, Lossy: lossy}
			}
			out = append(out, t)
		}
		return out
	}
	return nil
}

// NodeBMCTargetFor returns the capability entry a host advertises for
// target, and whether it was found.
func NodeBMCTargetFor(host *Node, target string) (BMCTarget, bool) {
	for _, t := range NodeBMCCapabilities(host) {
		if t.NodeID == target {
			return t, true
		}
	}
	return BMCTarget{}, false
}

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
	{Kind: "turingpi", Label: "Turing Pi 2 / 2.5 (network BMC)", Status: BMCBackendAvailable},
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
	// BMCStatusChecked is a read-only observation: a status query (an
	// explicit one, or the seed sweep after a host advertises targets)
	// recorded fresh state without commanding anything.
	BMCStatusChecked BMCChangeType = "status_checked"
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
//
// Session subjects live inside the BMC host's node scope, not a global
// rasputin.bmc.sol.* namespace: the bus-auth minted permissions only let
// an agent subscribe under its own cmd scope and publish under its own
// node scope, so a global subject is a permissions violation on an
// enforced bus (bench find, 2026-07-26). In-scope subjects also mean
// only the host that owns the session can carry its byte stream.
func BMCSOLInSubject(bmcHostID, sessionID string) string {
	return NodeCmdSubject(bmcHostID, "bmc.sol."+sessionID+".in")
}

// BMCSOLOutSubject is the agent→api byte stream for a session. The agent
// publishes; the api subscribes. Host-scoped like BMCSOLInSubject.
func BMCSOLOutSubject(bmcHostID, sessionID string) string {
	return NodeEvtSubject(bmcHostID, "bmc.sol."+sessionID+".out")
}

// BMCChangeSubject returns the publish subject for a BMC change event.
func BMCChangeSubject(targetNodeID string, change BMCChangeType) string {
	return fmt.Sprintf("rasputin.bmc.%s.%s", targetNodeID, string(change))
}

// AllBMCChangesFilter matches every BMC change event. Used by the UI
// WebSocket bridge for live power-state pills.
const AllBMCChangesFilter = "rasputin.bmc.*.*"
