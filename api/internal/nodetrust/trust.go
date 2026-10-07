// Package nodetrust delivers the node trust bundle — the controlplane CA, plus
// the operator's CA when Headscale is theirs — to every node, and reads what
// each node reports it trusts.
//
// Trust is not a mesh concern. The agent's own HTTPS clients (bundle
// download, backup transfer, restore fetch) verify the api against this
// bundle whether or not the node is on the tailnet, so it travels on a verb of
// its own, trust.install, and trust.converge sends it to every online node
// whose reported fingerprint differs from the api's. Mesh enrollment does not
// matter to either.
//
// Derived from data, not from an event: every agent reports the fingerprint
// of the bundle it holds on every registration (proto
// MetadataTrustFingerprint), and an identity restore that swaps the CA under
// enrolled nodes (e3bench 2026-09-04) is converged the same way as any other
// drift. A node whose agent has not reported a fingerprint is left alone: the
// api does not guess what a node trusts.
//
// An agent that predates trust.install draws no responder. Those are left to
// the mesh: mesh.enroll still carries the bundle for them, and the mesh
// reconcile's converge_trust re-delivers it to them, and only them.
package nodetrust

import (
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// NodeTrustState is how a node's reported fingerprint compares with the api's
// current bundle.
type NodeTrustState string

const (
	// TrustCurrent: the node reports the fingerprint of the api's bundle.
	TrustCurrent NodeTrustState = "current"
	// TrustStale: the node reports a different fingerprint, "none", or
	// "reload-pending"; trust.converge sends it the bundle.
	TrustStale NodeTrustState = "stale"
	// TrustUnreported: the node's agent has reported no fingerprint. Older
	// agent, or not registered since the field shipped. Left alone.
	TrustUnreported NodeTrustState = "unreported"
)

// NodeTrust is one node's trust reading.
type NodeTrust struct {
	NodeID string         `json:"nodeId"`
	State  NodeTrustState `json:"state"`
	// Fingerprint is what the node reported (proto.TrustFingerprint of its
	// bundle, "none", or "reload-pending"); "" when unreported. A
	// fingerprint, never a PEM.
	Fingerprint string `json:"fingerprint,omitempty"`
	// AgentPredatesField says the node's reported agent version is older
	// than the release that reports the fingerprint (proto
	// MetadataMinAgentVersion), so "unreported" means "cannot", not "did
	// not". Only meaningful when State is TrustUnreported.
	AgentPredatesField bool `json:"agentPredatesField,omitempty"`
}

// ReportedFingerprint is the fingerprint n's agent reported under
// proto.MetadataTrustFingerprint, or "" when it reported none.
func ReportedFingerprint(n *proto.Node) string {
	if n == nil || n.Metadata == nil {
		return ""
	}
	fp, _ := n.Metadata[proto.MetadataTrustFingerprint].(string)
	return strings.TrimSpace(fp)
}

// StateFor reads n against want, the api's current bundle fingerprint. An
// empty want has nothing to compare against and reads every node as current.
func StateFor(want string, n *proto.Node) NodeTrust {
	t := NodeTrust{NodeID: n.ID, Fingerprint: ReportedFingerprint(n)}
	switch {
	case want == "":
		t.State = TrustCurrent
	case t.Fingerprint == "":
		t.State = TrustUnreported
		if floor, ok := proto.MetadataMinAgentVersion(proto.MetadataTrustFingerprint); ok {
			t.AgentPredatesField = inventory.AgentPredates(n.AgentVersion, floor)
		}
	case t.Fingerprint == want:
		t.State = TrustCurrent
	default:
		t.State = TrustStale
	}
	return t
}

// ConvergeResult is what one convergence pass found and did — trust.converge's
// result, the legacy converge_trust step's, and what the restore report
// records (storage.TrustRedeliveryRecord). Fingerprints only, never PEMs.
type ConvergeResult struct {
	// CAFingerprint is the api's current bundle. "" when none is configured,
	// in which case nothing below is populated.
	CAFingerprint string `json:"caFingerprint,omitempty"`
	// Redelivered is every node this pass installed the bundle on.
	Redelivered []string `json:"redelivered"`
	// Stale is every node whose fingerprint differs — Redelivered plus those
	// held back (Skipped says why).
	Stale []string `json:"stale"`
	// Current is every node reporting the api's fingerprint.
	Current []string `json:"current"`
	// Unreported is every node whose agent has reported no fingerprint. Left
	// alone; named so the gap is visible.
	Unreported []string `json:"unreported"`
	// Skipped counts stale nodes held back, by reason. "legacy_agent" is a
	// node whose agent predates trust.install, left to the mesh bridge.
	Skipped map[string]int `json:"skipped,omitempty"`
}

// NewConvergeResult is an empty result for fingerprint, with every list
// non-nil so it marshals as [] rather than null.
func NewConvergeResult(fingerprint string) ConvergeResult {
	return ConvergeResult{
		CAFingerprint: fingerprint,
		Redelivered:   []string{}, Stale: []string{}, Current: []string{}, Unreported: []string{},
		Skipped: map[string]int{},
	}
}
