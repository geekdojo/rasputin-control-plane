package mesh

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Trust convergence: the CA a node holds must be the CA the api holds.
//
// The mesh CA reaches a node exactly once, inside mesh.enroll, and until this
// step nothing compared what a node kept with what the api now has. An
// identity restore (#291 phase 1) is the case that made the gap visible on
// e3bench, 2026-09-04: a wiped controlplane minted a fresh CA at 04:18, auto-
// enrolled compute1 with it at 04:20, and at 04:47 the restore put the
// ORIGINAL CA back. The api's HTTPS leaf was re-minted under the original;
// compute1 still trusted the fresh one; every node→api TLS client on it
// (backup transfer, bundle download, restore egress) failed with
// "certificate signed by unknown authority", and no product path existed to
// fix it — converge_enrollment enrolls only nodes with no device row, and the
// UI offers nothing for an enrolled node.
//
// Derived from data, not from the restore event: every agent reports the
// fingerprint of the bundle it holds on every registration (proto
// MetadataMeshCAFingerprint), this step compares each enrolled node's report
// with the api's own on every mesh.reconcile tick, and any node that differs
// gets mesh.enroll_node again. The agent side already handles a re-delivery
// correctly — installMeshCA is a no-op when the bundle is unchanged and
// restarts tailscaled when it changed — and re-registering an already-
// registered node with a fresh pre-auth key updates the node Headscale has
// rather than creating another (headscale 0.28 HandleNodeFromPreAuthKey:
// same machine key + same user → NodeKey/Hostinfo/AuthKey refreshed in place,
// IPs kept). A node whose agent has not reported a fingerprint is left alone:
// the api does not guess what a node trusts.

// NodeTrustState is how a node's reported mesh-CA fingerprint compares with
// the api's current mesh CA.
type NodeTrustState string

const (
	// TrustCurrent: the node reports the fingerprint of the api's mesh CA.
	TrustCurrent NodeTrustState = "current"
	// TrustStale: the node reports a different fingerprint (or "none"); the
	// reconcile re-delivers the CA.
	TrustStale NodeTrustState = "stale"
	// TrustUnreported: the node's agent has reported no fingerprint. Older
	// agent, or not registered since the field shipped. Left alone.
	TrustUnreported NodeTrustState = "unreported"
)

// NodeTrust is one node's trust reading.
type NodeTrust struct {
	NodeID string         `json:"nodeId"`
	State  NodeTrustState `json:"state"`
	// Fingerprint is what the node reported (proto.MeshCAFingerprint of its
	// bundle, or "none"); "" when unreported. A fingerprint, never a PEM.
	Fingerprint string `json:"fingerprint,omitempty"`
	// AgentPredatesField says the node's reported agent version is older
	// than the release that reports the fingerprint (proto
	// MetadataMinAgentVersion), so "unreported" means "cannot", not "did
	// not". Only meaningful when State is TrustUnreported.
	AgentPredatesField bool `json:"agentPredatesField,omitempty"`
}

// ReportedCAFingerprint is the fingerprint n's agent reported under
// proto.MetadataMeshCAFingerprint, or "" when it reported none.
func ReportedCAFingerprint(n *proto.Node) string {
	if n == nil || n.Metadata == nil {
		return ""
	}
	fp, _ := n.Metadata[proto.MetadataMeshCAFingerprint].(string)
	return strings.TrimSpace(fp)
}

// NodeTrustFor reads n against want, the api's current mesh-CA fingerprint.
// An empty want (no mesh CA configured: mock mesh, plain-HTTP dev, external
// Headscale with a public cert) has nothing to compare against and reads
// every node as current — there is no CA to deliver.
func NodeTrustFor(want string, n *proto.Node) NodeTrust {
	t := NodeTrust{NodeID: n.ID, Fingerprint: ReportedCAFingerprint(n)}
	switch {
	case want == "":
		t.State = TrustCurrent
	case t.Fingerprint == "":
		t.State = TrustUnreported
		t.AgentPredatesField = agentPredatesField(n.AgentVersion, proto.MetadataMeshCAFingerprint)
	case t.Fingerprint == want:
		t.State = TrustCurrent
	default:
		t.State = TrustStale
	}
	return t
}

// agentPredatesField reports whether agentVersion is older than the first
// release that reports key. Unknown floor or unparseable version → false:
// the api cannot call an agent too old when it cannot read what it said.
func agentPredatesField(agentVersion, key string) bool {
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

// MeshCAFingerprint is proto.MeshCAFingerprint of the CA the api ships in
// mesh.enroll (Config.MeshCAPEM), or "" when it ships none.
func (s *Service) MeshCAFingerprint() string { return s.caFingerprint }

// TrustConvergeResult is the converge_trust step's result, and what the
// restore report records of the reconcile it kicked (RestoreReport
// TrustRedelivery).
type TrustConvergeResult struct {
	// CAFingerprint is the api's current mesh CA. "" when none is configured,
	// in which case nothing below is populated.
	CAFingerprint string `json:"caFingerprint,omitempty"`
	// Redelivered is every enrolled node this pass submitted mesh.enroll_node
	// for because its reported fingerprint differed.
	Redelivered []string `json:"redelivered"`
	// Stale is every enrolled node whose fingerprint differs — Redelivered
	// plus those a guard (offline, in-flight, backoff, recent delivery) held
	// back this pass.
	Stale []string `json:"stale"`
	// Current is every enrolled node reporting the api's fingerprint.
	Current []string `json:"current"`
	// Unreported is every enrolled node whose agent has reported no
	// fingerprint. Left alone; named so the gap is visible.
	Unreported []string `json:"unreported"`
	// Skipped counts stale nodes held back, by reason.
	Skipped map[string]int `json:"skipped,omitempty"`
}

// trustRedeliverCooldown is how long converge_trust waits after a SUCCEEDED
// re-delivery before delivering to the same still-stale node again. After a
// successful enroll the agent re-registers with its new fingerprint within a
// second, so a node still reading stale ten minutes later has lost that
// registration (or the enroll landed a CA that is not the one the api holds
// — which the dispatch log names). Either way another delivery is safe (the
// agent no-ops an unchanged bundle) and cheap; this only keeps the ledger
// from filling with a job every tick for a node that cannot converge.
const trustRedeliverCooldown = 10 * time.Minute

// enrollGuards is the one pass over recent mesh.enroll_node jobs that both
// converge steps read: nodes with an enroll queued or running, each node's
// newest terminal job, and each node's streak of consecutive failures
// (newest-first, ending at the first terminal job that is not a failure, so
// a node that once succeeded starts its backoff over).
type enrollGuards struct {
	inflight            map[string]bool
	lastTerminal        map[string]*jobs.Job
	consecutiveFailures map[string]int
}

func loadEnrollGuards(sc *jobs.StepCtx, jstore *jobs.Store) (*enrollGuards, error) {
	recent, err := jstore.ListJobsByKind(sc.Ctx, "mesh.enroll_node", 200)
	if err != nil {
		return nil, fmt.Errorf("list enroll jobs: %w", err)
	}
	g := &enrollGuards{
		inflight:            map[string]bool{},
		lastTerminal:        map[string]*jobs.Job{},
		consecutiveFailures: map[string]int{},
	}
	streakEnded := map[string]bool{}
	for _, j := range recent {
		var spec EnrollSpec
		if json.Unmarshal(j.Spec, &spec) != nil || spec.NodeID == "" {
			continue
		}
		switch j.Status {
		case jobs.StatusQueued, jobs.StatusRunning:
			g.inflight[spec.NodeID] = true
		default:
			if _, seen := g.lastTerminal[spec.NodeID]; !seen {
				g.lastTerminal[spec.NodeID] = j
			}
			if !streakEnded[spec.NodeID] {
				if j.Status == jobs.StatusFailed {
					g.consecutiveFailures[spec.NodeID]++
				} else {
					streakEnded[spec.NodeID] = true
				}
			}
		}
	}
	return g, nil
}

// inBackoff reports whether nodeID's newest enroll failed inside its
// exponential retry window (enrollRetryBackoff).
func (g *enrollGuards) inBackoff(nodeID string) bool {
	last := g.lastTerminal[nodeID]
	return last != nil && last.Status == jobs.StatusFailed &&
		time.Since(last.CreatedAt) < enrollRetryBackoff(g.consecutiveFailures[nodeID])
}

// deliveredRecently reports whether nodeID's newest enroll SUCCEEDED inside
// trustRedeliverCooldown.
func (g *enrollGuards) deliveredRecently(nodeID string) bool {
	last := g.lastTerminal[nodeID]
	if last == nil || last.Status != jobs.StatusSucceeded {
		return false
	}
	at := last.CreatedAt
	if last.FinishedAt != nil {
		at = *last.FinishedAt
	}
	return time.Since(at) < trustRedeliverCooldown
}

// reconcileConvergeTrust re-delivers the mesh CA to every enrolled node whose
// reported fingerprint differs from the api's. See the package note above.
//
// A node qualifies when it:
//
//   - has a rasputin device row in mesh_devices (fetch_observed just synced
//     that table from Headscale) — it is enrolled; the unenrolled are
//     converge_enrollment's,
//   - has reported a fingerprint (proto MetadataMeshCAFingerprint) that is
//     not the api's — "none" counts: a node that trusts nothing is stale,
//   - is online (an enroll RPC to an offline agent burns the dispatch
//     timeout; it converges when it comes back — its fingerprint is in
//     inventory either way),
//   - has no enroll job queued or running,
//   - is outside enrollRetryBackoff of its last failed enroll, and outside
//     trustRedeliverCooldown of its last successful one.
//
// Every role is eligible, the controlplane included: it self-enrols at
// setup, but its own tailscaled trusts the same bundle file, and after a
// restore it is as stale as any other node (the loopback login server in
// enrollDispatch handles it).
func reconcileConvergeTrust(svc *Service, inv *inventory.Store, jstore *jobs.Store, runner *jobs.Runner) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		res := TrustConvergeResult{
			CAFingerprint: svc.MeshCAFingerprint(),
			Redelivered:   []string{}, Stale: []string{}, Current: []string{}, Unreported: []string{},
			Skipped: map[string]int{},
		}
		if res.CAFingerprint == "" {
			sc.Log("info", "trust: no mesh CA is shipped to nodes in this configuration — nothing to converge")
			return json.Marshal(res)
		}
		nodes, err := inv.List(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("list inventory: %w", err)
		}
		devices, err := svc.store.ListDevices(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("list devices: %w", err)
		}
		enrolled := make(map[string]bool, len(devices))
		for _, d := range devices {
			if d.Kind == "rasputin" && d.RasputinNodeID != "" {
				enrolled[d.RasputinNodeID] = true
			}
		}
		guards, err := loadEnrollGuards(sc, jstore)
		if err != nil {
			return nil, err
		}

		var predates []string
		for _, n := range nodes {
			if !enrolled[n.ID] {
				continue
			}
			t := NodeTrustFor(res.CAFingerprint, n)
			switch t.State {
			case TrustCurrent:
				res.Current = append(res.Current, n.ID)
				continue
			case TrustUnreported:
				res.Unreported = append(res.Unreported, n.ID)
				if t.AgentPredatesField {
					predates = append(predates, n.ID)
				}
				continue
			}
			res.Stale = append(res.Stale, n.ID)
			switch {
			case inventory.ComputeStatus(n.LastSeen) != proto.StatusOnline:
				res.Skipped["offline"]++
				continue
			case guards.inflight[n.ID]:
				res.Skipped["inflight"]++
				continue
			case guards.inBackoff(n.ID):
				res.Skipped["backoff"]++
				continue
			case guards.deliveredRecently(n.ID):
				res.Skipped["delivered_recently"]++
				continue
			}
			spec, _ := json.Marshal(EnrollSpec{NodeID: n.ID})
			if _, err := runner.Submit(sc.Ctx, "mesh.enroll_node", spec, "converge-trust"); err != nil {
				sc.Log("warn", fmt.Sprintf("trust: submit re-delivery for %s: %v", n.ID, err))
				res.Skipped["submit_error"]++
				continue
			}
			sc.Log("info", fmt.Sprintf("trust: %s trusts %s, api holds %s — re-delivering the mesh CA",
				n.ID, proto.ShortFingerprint(t.Fingerprint), proto.ShortFingerprint(res.CAFingerprint)))
			res.Redelivered = append(res.Redelivered, n.ID)
		}
		sort.Strings(res.Redelivered)
		sort.Strings(res.Stale)
		sort.Strings(res.Current)
		sort.Strings(res.Unreported)

		switch {
		case len(res.Redelivered) > 0:
			sc.Log("info", fmt.Sprintf("trust: re-delivering the mesh CA (%s) to %d node(s): %s",
				proto.ShortFingerprint(res.CAFingerprint), len(res.Redelivered), strings.Join(res.Redelivered, ", ")))
		case len(res.Stale) > 0:
			sc.Log("info", fmt.Sprintf("trust: %d stale node(s) not re-delivered this pass (skipped: %v)", len(res.Stale), res.Skipped))
		default:
			sc.Log("info", fmt.Sprintf("trust: %d enrolled node(s) hold the current mesh CA", len(res.Current)))
		}
		if len(res.Unreported) > 0 {
			msg := fmt.Sprintf("trust: %d enrolled node(s) have not reported what they trust and are left alone: %s",
				len(res.Unreported), strings.Join(res.Unreported, ", "))
			if len(predates) > 0 {
				if floor, ok := proto.MetadataMinAgentVersion(proto.MetadataMeshCAFingerprint); ok {
					msg += fmt.Sprintf(" (agent predates %s on %s — update the node to have it report)", floor, strings.Join(predates, ", "))
				}
			}
			sc.Log("warn", msg)
		}
		return json.Marshal(res)
	}
}
