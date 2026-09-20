// Package cutover answers one question, for one fact at a time: has EVERY
// registered node reported it?
//
// The migration plan's rule is that a cutover waits on a checkable fact and
// never on a date (methodology §7). A server-side tightening — deleting the
// agent's environment token fallback, deleting the chain-verified HTTPS routes
// — is allowed to fire only once every node in inventory has said it no longer
// needs the old path. The nodes say it in registration metadata (proto
// MetadataTokenSource, MetadataHTTPSPinned), the api records it on the node
// row, and this package turns those rows into the yes/no the step reads.
//
// Three readings, kept apart on purpose, because they send an operator to
// three different places:
//
//   - the node reported what the cutover wants — done;
//   - the node reported something else — it is still to migrate, and its own
//     report says how;
//   - the node reported nothing. That splits again on the key's
//     metadataMinAgentVersion floor: an agent below the floor COULD NOT report
//     it ("update the node"), and an agent at or above it should have and did
//     not ("this node did not say", a fault).
//
// Unreported is never read as satisfied, whichever reading it falls under.
// That is the fail-closed direction every one of these cutovers runs in: the
// cost of waiting is a step that ships late, and the cost of guessing is a
// fielded node that stops joining.
package cutover

import (
	"fmt"
	"sort"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// NodeState is one node's standing against one fact.
type NodeState struct {
	NodeID       string           `json:"nodeId"`
	Role         proto.NodeRole   `json:"role,omitempty"`
	Status       proto.NodeStatus `json:"status,omitempty"`
	AgentVersion string           `json:"agentVersion,omitempty"`
	// Reported is true when the node's registration carried the key with a
	// value this api understands.
	Reported bool `json:"reported"`
	// Value is what it reported, rendered for display ("file", "env",
	// "true", "false"). Empty when Reported is false.
	Value string `json:"value,omitempty"`
	// Satisfied is Reported AND the value the cutover wants.
	Satisfied bool `json:"satisfied"`
	// AgentPredatesKey says the node's reported agent version is older than
	// the first release that reports this key, so "unreported" means "could
	// not", not "did not". Only meaningful when Reported is false.
	AgentPredatesKey bool `json:"agentPredatesKey,omitempty"`
}

// State is the whole fleet's standing against one fact.
type State struct {
	// Key is the registration-metadata key (proto.Metadata*).
	Key string `json:"key"`
	// Want is the value every node must report, rendered as Value is.
	Want string `json:"want"`
	// Floor is the key's metadataMinAgentVersion, "" when proto records none.
	Floor string `json:"floor,omitempty"`
	// Nodes is every node in inventory, sorted by id.
	Nodes []NodeState `json:"nodes"`
	// Satisfied is true when every node in Nodes is satisfied. An EMPTY
	// inventory is not satisfied: a control plane with no nodes has not
	// proved anything about the fleet, and a cutover that read "no
	// counter-examples" as "go" would fire in exactly the window where
	// inventory has not loaded yet.
	Satisfied bool `json:"satisfied"`
	// Blockers is one sentence per node that is not satisfied, in Nodes
	// order, for an operator to read.
	Blockers []string `json:"blockers"`
}

// reader pulls one key out of a node's metadata and renders it. reported is
// false for an absent key or a value the decoder does not recognise.
type reader func(metadata map[string]any) (value string, reported bool)

// TokenOnFile reports whether every node reads its bus join token from a file
// (proto.TokenSourceFile) rather than from the environment. It is the gate on
// deleting the agent's RASPUTIN_CP_JOIN_TOKEN fallback (§7 4.1).
func TokenOnFile(nodes []*proto.Node) State {
	return evaluate(proto.MetadataTokenSource, proto.TokenSourceFile, nodes,
		func(m map[string]any) (string, bool) { return proto.TokenSourceOf(m) },
		func(n NodeState) string {
			switch n.Value {
			case proto.TokenSourceEnv:
				return fmt.Sprintf("%s reads its join token from %s, not from a file", n.NodeID, "RASPUTIN_CP_JOIN_TOKEN")
			case proto.TokenSourceNone:
				return fmt.Sprintf("%s reports no join token at all", n.NodeID)
			}
			return ""
		})
}

// HTTPSPinned reports whether every node's HTTPS clients to the api verify the
// control plane by the bus pin (proto.MetadataHTTPSPinned). It is one of the
// three facts the plaintext-ladder deletion waits on (§7 6.5).
func HTTPSPinned(nodes []*proto.Node) State {
	return evaluate(proto.MetadataHTTPSPinned, "true", nodes,
		func(m map[string]any) (string, bool) {
			pinned, reported := proto.HTTPSPinnedOf(m)
			if !reported {
				return "", false
			}
			if pinned {
				return "true", true
			}
			return "false", true
		},
		func(n NodeState) string {
			return fmt.Sprintf("%s reports its HTTPS clients to the api are not pinned", n.NodeID)
		})
}

// evaluate is the shared body. describe renders the blocker sentence for a
// node that REPORTED something other than want; the unreported sentences are
// the same for every fact and are written here.
func evaluate(key, want string, nodes []*proto.Node, read reader, describe func(NodeState) string) State {
	st := State{Key: key, Want: want, Nodes: []NodeState{}, Blockers: []string{}}
	st.Floor, _ = proto.MetadataMinAgentVersion(key)
	for _, n := range nodes {
		if n == nil {
			continue
		}
		s := NodeState{NodeID: n.ID, Role: n.Role, Status: n.Status, AgentVersion: n.AgentVersion}
		s.Value, s.Reported = read(n.Metadata)
		s.Satisfied = s.Reported && s.Value == want
		if !s.Reported {
			s.AgentPredatesKey = agentPredatesKey(n.AgentVersion, key)
		}
		st.Nodes = append(st.Nodes, s)
	}
	sort.Slice(st.Nodes, func(i, j int) bool { return st.Nodes[i].NodeID < st.Nodes[j].NodeID })
	for _, s := range st.Nodes {
		if s.Satisfied {
			continue
		}
		switch {
		case s.Reported:
			if line := describe(s); line != "" {
				st.Blockers = append(st.Blockers, line)
			} else {
				st.Blockers = append(st.Blockers, fmt.Sprintf("%s reports %s=%q, and the cutover needs %q", s.NodeID, key, s.Value, want))
			}
		case s.AgentPredatesKey:
			st.Blockers = append(st.Blockers, fmt.Sprintf(
				"the agent on %s is %s, which predates the %s report — it needs %s or newer; update the node",
				s.NodeID, agentVersionOrUnknown(s.AgentVersion), key, st.Floor))
		default:
			st.Blockers = append(st.Blockers, fmt.Sprintf(
				"%s has not reported %s, and its agent (%s) is new enough to",
				s.NodeID, key, agentVersionOrUnknown(s.AgentVersion)))
		}
	}
	st.Satisfied = len(st.Nodes) > 0 && len(st.Blockers) == 0
	return st
}

func agentVersionOrUnknown(v string) string {
	if strings.TrimSpace(v) == "" {
		return "version unknown"
	}
	return v
}

// agentPredatesKey reports whether agentVersion is older than the first
// release that reports key. An unknown floor or an unparseable version is
// false: the api does not call an agent too old when it cannot read what the
// agent said, and the node still counts as a blocker either way — it simply
// reads as "did not" rather than "could not".
func agentPredatesKey(agentVersion, key string) bool {
	floor, ok := proto.MetadataMinAgentVersion(key)
	if !ok {
		return false
	}
	v := strings.TrimPrefix(strings.TrimSpace(agentVersion), "v")
	if v == "" {
		return false
	}
	c, err := releases.Compare(releases.SchemeCalVer, v, floor)
	return err == nil && c < 0
}
