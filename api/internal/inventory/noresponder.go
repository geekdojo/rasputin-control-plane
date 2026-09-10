package inventory

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Why a node-scoped request drew no responder.
//
// NATS answers a request nobody is subscribed to with ErrNoResponders, and
// every node-scoped verb the api sends can draw it. What it means depends on
// two facts inventory already holds — the node's presence and the agent
// version it reported at registration — and a call site that renders it
// without consulting them says something false whenever the node is online.
// On e3bench (2026-09-04) a compute node running agent 2026.08.4-dev.130 was
// reported OFFLINE by a backup run's fan-out and as having "no container
// runtime" by the orphaned-volumes list; it was online with Docker fine, and
// its agent simply had no subscription for storage.backup_stage_volume or
// docker.volumes.list, both of which shipped later.
//
// ExplainNoResponder is the one place that reading lives, so every site that
// sends a node-scoped request and gets silence tells the same story: the
// node is offline; the node is online but its agent predates the verb (with
// the release that answers it, from proto.VerbMinAgentVersion); or the node
// is online, its agent is new enough, and it still did not answer — which
// is a fault, and is named as one rather than folded into either of the
// others.

// Silence is which of those readings applies.
type Silence int

const (
	// SilenceNodeUnknown: inventory has no row for the node the subject
	// names, so nothing is known about it.
	SilenceNodeUnknown Silence = iota
	// SilenceOffline: the node is not on the bus — its presence is stale,
	// offline, or off-bus (lapsed heartbeat, mesh device online; Status says
	// which, and String names the off-bus case as such).
	SilenceOffline
	// SilenceOldAgent: the node is online, and its agent reported a version
	// below the first release that answers the verb.
	SilenceOldAgent
	// SilenceUnexplained: the node is online and its agent should answer the
	// verb — its version is at or above the floor, or the verb has no
	// recorded floor, or the agent never reported a version — and it did
	// not. A fault, not a version gap.
	SilenceUnexplained
)

// NoResponder is the reading of one silent request, and String is the
// sentence a manifest, a job feed or an API error carries for it.
type NoResponder struct {
	NodeID string
	// Verb is the dotted cmd verb the subject carried ("" if the subject was
	// not a cmd subject at all).
	Verb string
	Kind Silence
	// Status is the node's computed presence (DeriveStatus); "" when the
	// node is unknown.
	Status proto.NodeStatus
	// MeshLastSeen is the mesh device's last-seen when Status is
	// StatusOffBus — the evidence that the machine is reachable; nil
	// otherwise.
	MeshLastSeen *time.Time
	// AgentVersion is what the node reported, bare CalVer; "" if it never
	// reported one.
	AgentVersion string
	// MinVersion is the first agent release that answers Verb, bare CalVer;
	// "" when proto records none for it.
	MinVersion string
	// Err is set when inventory itself could not be read.
	Err error
	// Now is the clock String renders MeshLastSeen against, and the only
	// place this type reads a clock at all. Nil means time.Now, so a
	// zero-value NoResponder — every one production builds — renders
	// exactly what it always has. A test sets it to pin the elapsed time
	// the off-bus sentence prints: humanAgo's sub-minute bucket counts
	// whole seconds, so a reading rendered a second after its fixture was
	// built says "21s ago" where the fixture said 20. Store.SetNow stamps
	// it on the readings Store.ExplainNoResponder returns, which is how a
	// caller in another package reaches it.
	Now func() time.Time
}

// now is Now, or the wall clock when no clock was injected.
func (n NoResponder) now() time.Time {
	if n.Now != nil {
		return n.Now()
	}
	return time.Now()
}

// ExplainNoResponder reads the silence on subject — a subject built by
// proto.NodeCmdSubject — against node, inventory's row for the node it
// names, or nil when there is none.
func ExplainNoResponder(node *proto.Node, subject string) NoResponder {
	nodeID, verb, ok := proto.CmdSubjectVerb(subject)
	if !ok {
		nodeID, verb = "", subject
	}
	if node != nil && node.ID != "" {
		nodeID = node.ID
	}
	n := NoResponder{NodeID: nodeID, Verb: verb}
	if min, ok := proto.VerbMinAgentVersion(verb); ok {
		n.MinVersion = min
	}
	if node == nil {
		n.Kind = SilenceNodeUnknown
		return n
	}
	n.AgentVersion = strings.TrimPrefix(strings.TrimSpace(node.AgentVersion), "v")
	n.Status = DeriveStatus(node.LastSeen, node.Mesh)
	if n.Status != proto.StatusOnline {
		n.Kind = SilenceOffline
		if n.Status == proto.StatusOffBus && node.Mesh != nil {
			n.MeshLastSeen = node.Mesh.LastSeen
		}
		return n
	}
	n.Kind = SilenceUnexplained
	if n.MinVersion != "" && n.AgentVersion != "" {
		// An unparseable version is left Unexplained: the api cannot say the
		// agent is too old when it cannot read what the agent said.
		if c, err := releases.Compare(releases.SchemeCalVer, n.AgentVersion, n.MinVersion); err == nil && c < 0 {
			n.Kind = SilenceOldAgent
		}
	}
	return n
}

// SetNow wires the clock the readings from this store render elapsed times
// against — the off-bus sentence's "(seen 20s ago)". Nil (what production
// leaves it) is time.Now. Set before the reader runs, as SetMeshLookup is;
// it exists so a caller in another package — the storage fan-out's tests
// hold the store and nothing else — can pin that string.
func (s *Store) SetNow(fn func() time.Time) { s.now = fn }

// ExplainNoResponder is ExplainNoResponder against this store's row for the
// node the subject names, joined with its mesh membership (presence.go) so a
// node that is off the bus but on the mesh is named as such.
func (s *Store) ExplainNoResponder(ctx context.Context, subject string) NoResponder {
	nodeID, _, _ := proto.CmdSubjectVerb(subject)
	node, err := s.Get(ctx, nodeID)
	if err != nil {
		n := ExplainNoResponder(nil, subject)
		n.Err = err
		n.Now = s.now
		return n
	}
	if node != nil {
		s.Presence(ctx, []*proto.Node{node})
	}
	n := ExplainNoResponder(node, subject)
	n.Now = s.now
	return n
}

// Online reports whether the reading is of a node that IS on the bus — the
// two cases in which "offline" would be the wrong word.
func (n NoResponder) Online() bool {
	return n.Kind == SilenceOldAgent || n.Kind == SilenceUnexplained
}

func (n NoResponder) String() string {
	switch n.Kind {
	case SilenceOldAgent:
		return fmt.Sprintf("node %s is online but its agent (%s) predates %s; update the node to ≥ %s",
			n.NodeID, vtag(n.AgentVersion), n.Verb, vtag(n.MinVersion))
	case SilenceUnexplained:
		switch {
		case n.AgentVersion == "" && n.MinVersion != "":
			return fmt.Sprintf("node %s is online but never reported an agent version, and nothing answered %s (first answered by agent %s)",
				n.NodeID, n.Verb, vtag(n.MinVersion))
		case n.AgentVersion == "":
			return fmt.Sprintf("node %s is online but never reported an agent version, and nothing answered %s", n.NodeID, n.Verb)
		case n.MinVersion != "":
			return fmt.Sprintf("node %s is online and its agent (%s) should answer %s (first answered by agent %s) and did not",
				n.NodeID, vtag(n.AgentVersion), n.Verb, vtag(n.MinVersion))
		default:
			return fmt.Sprintf("node %s is online and its agent (%s) did not answer %s; no minimum agent version is recorded for that verb",
				n.NodeID, vtag(n.AgentVersion), n.Verb)
		}
	case SilenceOffline:
		if n.Status == proto.StatusOffBus {
			seen := ""
			if n.MeshLastSeen != nil {
				seen = fmt.Sprintf(" (seen %s ago)", humanAgo(n.now().Sub(*n.MeshLastSeen)))
			}
			return fmt.Sprintf("node %s is OFF BUS (on mesh): reachable over the mesh%s but its agent is not on the bus, so nothing answered %s; restart the agent or check its log",
				n.NodeID, seen, n.Verb)
		}
		return fmt.Sprintf("node %s is %s: no agent on it answered %s", n.NodeID, n.Status, n.Verb)
	default:
		if n.Err != nil {
			return fmt.Sprintf("node %s could not be looked up in inventory (%v), and no agent answered %s", n.NodeID, n.Err, n.Verb)
		}
		return fmt.Sprintf("node %s is not in inventory, and no agent answered %s", n.NodeID, n.Verb)
	}
}

// humanAgo renders an elapsed duration coarsely — "40s", "3m", "3h", "2d" —
// for the off-bus sentence. Coarse on purpose: the reader needs "seconds" vs
// "hours", not a stopwatch.
func humanAgo(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// vtag renders a bare CalVer the way the release is named.
func vtag(v string) string {
	return "v" + strings.TrimPrefix(v, "v")
}
