package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/nodetrust"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Trust delivery, from the mesh's side.
//
// The node trust bundle reaches a node on its own verb, trust.install, through
// nodetrust (api/internal/nodetrust), and the mesh only consumes it: enroll
// delivers trust before it mints a key, because tailscaled must trust
// Headscale's leaf before `tailscale up` can dial it.
//
// Two bridges remain for agents that predate trust.install, and only for
// them. mesh.enroll carries the bundle (proto.MeshEnrollCmd
// .LegacyTrustBundlePEM), and converge_trust below re-delivers it to an
// enrolled old agent by re-running mesh.enroll_node — the path every node used
// before (e3bench 2026-09-04: a restore swapped the CA under compute1, and this
// re-delivery is what converged it). The agent side handles a re-delivery
// correctly: an unchanged bundle is a no-op, a changed one restarts tailscaled,
// and re-registering with a fresh pre-auth key updates the node Headscale has
// rather than creating another (headscale 0.28 HandleNodeFromPreAuthKey).

// TrustDeliverer installs the node trust bundle on one node (nodetrust
// .Service.Deliver). nodetrust.ErrAgentPredatesVerb means the node's agent
// is too old for the verb and must be given the bundle in mesh.enroll.
type TrustDeliverer interface {
	Deliver(ctx context.Context, req nodetrust.Requester, nodeID string) (proto.TrustInstallAck, error)
}

// TrustFingerprinter is the api's bundle fingerprint (nodetrust
// .Service.Fingerprint).
type TrustFingerprinter interface {
	Fingerprint() string
}

// trustFingerprint is the api's bundle fingerprint, or "" when this mesh was
// built without trust.
func (s *Service) trustFingerprint() string {
	if s.cfg.TrustFingerprint == nil {
		return ""
	}
	return s.cfg.TrustFingerprint.Fingerprint()
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

// reconcileConvergeTrust re-delivers the trust bundle, by mesh.enroll_node, to
// every enrolled node whose agent predates trust.install and whose reported
// fingerprint differs from the api's. A node whose agent answers
// trust.install is trust.converge's and is not looked at here. See the note
// above.
//
// A node qualifies when it:
//
//   - runs an agent below the trust.install floor (proto.VerbMinAgentVersion),
//   - has a rasputin device row in mesh_devices (fetch_observed just synced
//     that table from Headscale) — it is enrolled; the unenrolled are
//     converge_enrollment's,
//   - has reported a fingerprint (proto MetadataTrustFingerprint) that is
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
		res := nodetrust.NewConvergeResult(svc.trustFingerprint())
		if res.CAFingerprint == "" {
			sc.Log("info", "trust: no trust bundle is delivered in this configuration — nothing to converge")
			return json.Marshal(res)
		}
		floor, _ := proto.VerbMinAgentVersion(proto.TrustInstallVerb)
		// This list is a DATA read, not a membership decision: what the pass
		// needs from each node is the trust fingerprint its agent reported,
		// which lives in the node row's metadata and not in the node registry
		// (geekdojo-brain#585). The membership decision it makes — is this
		// node enrolled? — comes from the mesh device table below.
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
		boundDev, _ := BoundDevices(devices)
		guards, err := loadEnrollGuards(sc, jstore)
		if err != nil {
			return nil, err
		}

		var predates []string
		for _, n := range nodes {
			if !enrolled[n.ID] || !inventory.AgentPredates(n.AgentVersion, floor) {
				continue
			}
			t := nodetrust.StateFor(res.CAFingerprint, n)
			switch t.State {
			case nodetrust.TrustCurrent:
				res.Current = append(res.Current, n.ID)
				continue
			case nodetrust.TrustUnreported:
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
			d := boundDev[n.ID]
			if d == nil {
				// Bound to more than one device: re-delivering would re-enrol
				// with routes read off a guess. Left for the duplicate to be
				// resolved (push_routes and app DNS name it).
				res.Skipped["duplicate_binding"]++
				continue
			}
			// Re-delivery re-runs `tailscale up --reset`; name the routes the
			// node advertises now so the reset keeps them.
			routes, _ := ReenrolRoutes(sc.Ctx, svc, n.ID, d, nil)
			spec := EnrollSpec{NodeID: n.ID, AdvertiseRoutes: routes}
			if _, err := runner.Submit(sc.Ctx, "mesh.enroll_node", spec, "converge-trust"); err != nil {
				sc.Log("warn", fmt.Sprintf("trust: submit re-delivery for %s: %v", n.ID, err))
				res.Skipped["submit_error"]++
				continue
			}
			sc.Log("info", fmt.Sprintf("trust: %s trusts %s, api holds %s — re-delivering the trust bundle",
				n.ID, proto.ShortFingerprint(t.Fingerprint), proto.ShortFingerprint(res.CAFingerprint)))
			res.Redelivered = append(res.Redelivered, n.ID)
		}
		sort.Strings(res.Redelivered)
		sort.Strings(res.Stale)
		sort.Strings(res.Current)
		sort.Strings(res.Unreported)

		switch {
		case len(res.Redelivered) > 0:
			sc.Log("info", fmt.Sprintf("trust: re-delivering the trust bundle (%s) to %d legacy-agent node(s): %s",
				proto.ShortFingerprint(res.CAFingerprint), len(res.Redelivered), strings.Join(res.Redelivered, ", ")))
		case len(res.Stale) > 0:
			sc.Log("info", fmt.Sprintf("trust: %d stale node(s) not re-delivered this pass (skipped: %v)", len(res.Stale), res.Skipped))
		default:
			sc.Log("info", fmt.Sprintf("trust: %d enrolled legacy-agent node(s) hold the current trust bundle", len(res.Current)))
		}
		if len(res.Unreported) > 0 {
			msg := fmt.Sprintf("trust: %d enrolled node(s) have not reported what they trust and are left alone: %s",
				len(res.Unreported), strings.Join(res.Unreported, ", "))
			if len(predates) > 0 {
				if floor, ok := proto.MetadataMinAgentVersion(proto.MetadataTrustFingerprint); ok {
					msg += fmt.Sprintf(" (agent predates %s on %s — update the node to have it report)", floor, strings.Join(predates, ", "))
				}
			}
			sc.Log("warn", msg)
		}
		return json.Marshal(res)
	}
}
