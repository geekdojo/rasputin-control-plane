package mesh

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// meshNodeTag is the Tailscale/Headscale ACL tag the control plane stamps on
// every node it enrolls (the enroll saga mints the preauth key with it). It is
// the authoritative, control-plane-set marker of "this machine is a Rasputin
// node" — distinct from RASPUTIN_NODE_ID/ROLE, which live in the control-plane
// DB and never reach Headscale. Reconcile classifies devices by this tag, not
// by guessing from the hostname.
const meshNodeTag = "tag:rasputin-node"

// ----- mesh.apply --------------------------------------------------------

// ApplyWorkflow reconciles the api's intent set forward into Headscale.
//
//  1. compile     — turn intents into canonical state + hash
//  2. push_routes — for each subnet_route intent, look up the node's
//     Headscale id (via mesh_devices) and call SetNodeRoutes
//  3. record      — persist intent_hash + last_applied
//
// It mints no pre-auth keys. A user-device key is minted by POST
// /api/mesh/keys, which shows its value once; a node's enrolment key is
// minted inside mesh.enroll_node's dispatch step. A key minted here would be
// one nobody asked for and nobody is shown.
func ApplyWorkflow(svc *Service, inv *inventory.Store, nc *nats.Conn) jobs.Workflow {
	return jobs.Workflow{
		Kind: "mesh.apply",
		Steps: []jobs.WorkflowStep{
			{Name: "compile", Timeout: 2 * time.Second, Do: applyCompile(svc)},
			{Name: "push_routes", Timeout: 30 * time.Second, Do: applyPushRoutes(svc, inv)},
			{Name: "record", Timeout: 2 * time.Second, Do: applyRecord(svc, nc)},
		},
	}
}

func applyCompile(svc *Service) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		intents, err := svc.store.ListIntents(sc.Ctx)
		if err != nil {
			return nil, err
		}
		state, hash, err := Compile(intents)
		if err != nil {
			return nil, fmt.Errorf("compile: %w", err)
		}
		enabled := 0
		for _, i := range intents {
			if i.Enabled {
				enabled++
			}
		}
		sc.Log("info", fmt.Sprintf("compiled %d enabled intent(s), hash=%s", enabled, short(hash)))
		return json.Marshal(map[string]any{"hash": hash, "state": state, "intentCount": enabled})
	}
}

func applyPushRoutes(svc *Service, inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		intents, err := svc.store.ListIntentsByKind(sc.Ctx, string(proto.IntentSubnetRoute))
		if err != nil {
			return nil, err
		}
		// Group CIDRs by node id so we make one SetNodeRoutes call per node.
		byNode := map[string][]string{}
		for _, i := range intents {
			if !i.Enabled {
				continue
			}
			var spec proto.SubnetRouteSpec
			if err := json.Unmarshal(i.Spec, &spec); err != nil {
				return nil, fmt.Errorf("intent %s: %w", i.ID, err)
			}
			byNode[spec.NodeID] = append(byNode[spec.NodeID], spec.CIDR)
		}
		if len(byNode) == 0 {
			return json.Marshal(map[string]int{"applied": 0})
		}

		// Resolve Rasputin node id → Headscale node id via mesh_devices.
		devices, err := svc.store.ListDevices(sc.Ctx)
		if err != nil {
			return nil, err
		}
		bound, dup := BoundDevices(devices)

		applied := 0
		var refused []string
		for nodeID, cidrs := range byNode {
			if ids, ok := dup[nodeID]; ok {
				// Approving routes on one of several devices bound to the
				// node would be a guess about which one is the node.
				msg := (&DuplicateBindingError{NodeID: nodeID, HSIDs: ids}).Error() + "; its subnet routes are not approved until that is resolved"
				sc.Log("error", msg)
				log.Print(msg)
				refused = append(refused, nodeID)
				continue
			}
			d, ok := bound[nodeID]
			if !ok {
				// Node not yet enrolled in the tailnet; skip without
				// failing. The next mesh.apply after enrollment will pick
				// this up. Note in the log so the operator sees why.
				sc.Log("warn", fmt.Sprintf("subnet route for %s skipped: node not yet enrolled in tailnet", nodeID))
				_ = inv // inventory lookup deferred; nodeID is the kept reference
				continue
			}
			sort.Strings(cidrs)
			if err := svc.Client().SetNodeRoutes(sc.Ctx, d.HSID, cidrs); err != nil {
				return nil, fmt.Errorf("set routes on %s: %w", nodeID, err)
			}
			sc.Log("info", fmt.Sprintf("approved routes on %s: %v", nodeID, cidrs))
			applied++
		}
		sort.Strings(refused)
		return json.Marshal(map[string]any{"applied": applied, "refusedDuplicateBinding": refused})
	}
}

func applyRecord(svc *Service, nc *nats.Conn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		intents, err := svc.store.ListIntents(sc.Ctx)
		if err != nil {
			return nil, err
		}
		_, hash, err := Compile(intents)
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		if err := svc.store.UpdateAfterApply(sc.Ctx, hash, now); err != nil {
			log.Printf("mesh: persist apply state: %v", err)
		}
		publishChange(nc, proto.MeshChangeEvt{
			Scope:      "global",
			Change:     proto.MeshApplied,
			IntentHash: hash,
			Ts:         now,
		})
		sc.Log("info", fmt.Sprintf("applied: hash=%s", short(hash)))
		return json.Marshal(map[string]string{"hash": hash})
	}
}

// ----- mesh.reconcile -----------------------------------------------------

// AutoEnrollRoles are the node roles the control plane enrolls into the mesh
// automatically — once at first registration (the onNodeAdded hook in main)
// and convergently on every reconcile tick (converge_enrollment below). The
// controlplane self-enrolls during setup (POST /api/setup/mesh); user devices
// are never auto-enrolled.
var AutoEnrollRoles = []proto.NodeRole{proto.RoleFirewall, proto.RoleCompute, proto.RoleStorage}

// Retry pacing for converge_enrollment after a FAILED enroll.
//
// A flat 30-minute cooldown used to live here. Its purpose was sound — stop a
// persistently broken agent producing a failed job every reconcile tick — but
// it was tuned entirely for permanent failure and charged the same penalty to
// a TRANSIENT one. The transient case is not hypothetical: a freshly flashed
// node reboots for `growpart` on first boot, and the control plane enrolls the
// instant the node registers, so the FIRST attempt lands mid-reboot and
// `systemctl restart tailscaled` fails. Measured on the bench 2026-08-03: the
// node self-corrected in ~30 seconds and then sat outside the mesh for
// 33.7 minutes, showing a red FAILED job and a missing mesh device the whole
// time. An operator reasonably concludes the cluster is broken and starts
// debugging something that was going to fix itself.
//
// Exponential backoff instead: quick early retries for the transient case,
// converging on the old ceiling for the permanent one, so nothing regresses.
// Retrying is cheap — the dispatch step expires its preauth key when it ends,
// so a failed attempt leaves no state to clean up.
//
// NOTE the real floor is the reconcile interval, not enrollRetryBase:
// converge_enrollment only runs on a mesh.reconcile tick (default 5m,
// RASPUTIN_MESH_RECONCILE_INTERVAL). So sub-5m delays mean "eligible at the
// next tick" — first retry lands within ~5 minutes rather than ~30.
const (
	enrollRetryBase = 30 * time.Second
	enrollRetryMax  = 30 * time.Minute
)

// enrollRetryBackoff is how long to wait after the Nth consecutive failed
// enroll before trying again: 30s, 1m, 2m, 4m … capped at 30m. A success
// resets the count, so a node that recovers is not penalised for its history.
func enrollRetryBackoff(consecutiveFailures int) time.Duration {
	if consecutiveFailures < 1 {
		return 0
	}
	d := enrollRetryBase
	for i := 1; i < consecutiveFailures; i++ {
		if d >= enrollRetryMax {
			break
		}
		d *= 2
	}
	return min(d, enrollRetryMax)
}

// ReconcileWorkflow pulls Headscale's live state, derives an observed
// hash, compares to intent_hash, and emits drift / in_sync. It then
// converges mesh membership: any managed node in inventory that isn't
// enrolled gets a mesh.enroll_node job submitted.
func ReconcileWorkflow(svc *Service, inv *inventory.Store, jstore *jobs.Store, runner *jobs.Runner, nc *nats.Conn) jobs.Workflow {
	return jobs.Workflow{
		Kind: "mesh.reconcile",
		Steps: []jobs.WorkflowStep{
			{Name: "fetch_observed", Timeout: 30 * time.Second, Do: reconcileFetch(svc, nc)},
			{Name: "compare", Timeout: 2 * time.Second, Do: reconcileCompare(svc, nc)},
			{Name: "converge_enrollment", Timeout: 10 * time.Second, Do: reconcileConvergeEnrollment(svc, inv, jstore, runner)},
			{Name: "converge_trust", Timeout: 10 * time.Second, Do: reconcileConvergeTrust(svc, inv, jstore, runner)},
			{Name: "reconcile_app_dns", Timeout: 10 * time.Second, Do: reconcileAppDNS(svc)},
		},
	}
}

// reconcileAppDNS re-renders the tailnet app-name projection into Headscale's
// extra_records on every mesh.reconcile tick (ADR-0004 §9) — the topology-driven
// backstop that catches app or enrollment changes.
func reconcileAppDNS(svc *Service) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		if err := svc.ReconcileAppDNS(sc.Ctx); err != nil {
			return nil, err
		}
		return nil, nil
	}
}

func reconcileFetch(svc *Service, nc *nats.Conn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		keys, err := svc.Client().ListPreAuthKeys(sc.Ctx, "")
		if err != nil {
			return nil, fmt.Errorf("list keys: %w", err)
		}
		nodes, err := svc.Client().ListNodes(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("list nodes: %w", err)
		}

		// Sync the mesh_devices table with Headscale's view of reality.
		//
		// Which Rasputin node a device IS comes only from the enrol: the
		// record step stores the Headscale node id the enrolled agent
		// reported, against the node it enrolled. Reconcile carries that
		// binding forward by Headscale id and never derives one — not from
		// the hostname, which the device chooses, and not from a tag, which
		// says only what kind of key admitted it. A meshNodeTag device with
		// no recorded binding is listed as a Rasputin-kind device bound to no
		// node; converge_enrollment then enrols the node, and the enrol
		// records the binding. Anything untagged and unbound is a user device
		// (e.g. a laptop added on the Keys tab).
		recorded, err := svc.store.ListDevices(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("list recorded devices: %w", err)
		}
		boundByHSID := make(map[string]string, len(recorded))
		for _, d := range recorded {
			if d.Kind == "rasputin" && d.RasputinNodeID != "" {
				boundByHSID[d.HSID] = d.RasputinNodeID
			}
		}
		for _, n := range nodes {
			kind := "user"
			rasp := boundByHSID[n.ID]
			if rasp != "" || slices.Contains(n.Tags, meshNodeTag) {
				kind = "rasputin"
			}
			_ = svc.store.UpsertDevice(sc.Ctx, &Device{
				HSID:             n.ID,
				User:             n.User,
				Hostname:         n.Hostname,
				TailnetIP:        n.IPv4,
				Tags:             n.Tags,
				AdvertisedRoutes: n.AdvertisedRoutes,
				RasputinNodeID:   rasp,
				Kind:             kind,
				FirstSeen:        n.RegisteredAt,
				LastSeen:         n.LastSeen,
				Online:           n.Online,
			})
		}

		// Build an observed state map mirroring Compile's shape.
		obsKeys := make([]map[string]string, 0, len(keys))
		for _, k := range keys {
			if k.Used || time.Now().After(k.Expiration) {
				continue
			}
			tags := append([]string{}, k.Tags...)
			sort.Strings(tags)
			obsKeys = append(obsKeys, map[string]string{
				"user":      k.User,
				"reusable":  fmt.Sprintf("%t", k.Reusable),
				"ephemeral": fmt.Sprintf("%t", k.Ephemeral),
				"tags":      joinComma(tags),
			})
		}
		sort.Slice(obsKeys, func(a, b int) bool { return obsKeys[a]["user"] < obsKeys[b]["user"] })

		obsRoutes := make([]map[string]string, 0)
		for _, n := range nodes {
			for _, c := range n.ApprovedRoutes {
				obsRoutes = append(obsRoutes, map[string]string{
					"nodeId": n.Hostname,
					"cidr":   c,
				})
			}
		}
		sort.Slice(obsRoutes, func(a, b int) bool {
			if obsRoutes[a]["nodeId"] != obsRoutes[b]["nodeId"] {
				return obsRoutes[a]["nodeId"] < obsRoutes[b]["nodeId"]
			}
			return obsRoutes[a]["cidr"] < obsRoutes[b]["cidr"]
		})

		obs := map[string]any{
			"preauth_keys":  obsKeys,
			"subnet_routes": obsRoutes,
		}
		hash, err := HashObserved(obs)
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		if err := svc.store.UpdateAfterReconcile(sc.Ctx, hash, now); err != nil {
			log.Printf("mesh: persist reconcile state: %v", err)
		}
		publishChange(nc, proto.MeshChangeEvt{
			Scope:        "global",
			Change:       proto.MeshReconciled,
			ObservedHash: hash,
			Ts:           now,
		})
		sc.Log("info", fmt.Sprintf("observed hash=%s (%d keys, %d nodes)", short(hash), len(keys), len(nodes)))
		return json.Marshal(map[string]any{"hash": hash, "keys": len(keys), "nodes": len(nodes)})
	}
}

func reconcileCompare(svc *Service, nc *nats.Conn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		state, err := svc.store.GetState(sc.Ctx)
		if err != nil {
			return nil, err
		}
		if state.IntentHash == "" {
			// We haven't applied yet. Not drift; just unstarted.
			sc.Log("info", "no apply has run yet — skipping drift comparison")
			return json.Marshal(map[string]any{"drift": false, "unstarted": true})
		}
		now := time.Now().UTC()
		change := proto.MeshInSync
		if state.Drift {
			change = proto.MeshDrift
			sc.Log("warn", fmt.Sprintf("DRIFT: intent=%s observed=%s",
				short(state.IntentHash), short(state.ObservedHash)))
		} else {
			sc.Log("info", "in sync with intent")
		}
		publishChange(nc, proto.MeshChangeEvt{
			Scope:        "global",
			Change:       change,
			IntentHash:   state.IntentHash,
			ObservedHash: state.ObservedHash,
			Ts:           now,
		})
		return json.Marshal(map[string]any{
			"drift":        state.Drift,
			"intentHash":   state.IntentHash,
			"observedHash": state.ObservedHash,
		})
	}
}

// reconcileConvergeEnrollment makes mesh membership a converged invariant
// rather than a fire-once event. The onNodeAdded hook enrolls a node exactly
// once, at its FIRST inventory registration — so a node that registered
// before Headscale finished bring-up, or whose enroll job failed, stayed out
// of the mesh forever with no retry (found on rasputin-local 2026-07-12:
// 21 of 23 computes unenrolled because the fleet first-registered during
// initial cluster bring-up). This step runs every reconcile tick and submits
// mesh.enroll_node for any inventory node in AutoEnrollRoles that:
//
//   - has no rasputin device row in mesh_devices (fetch_observed just synced
//     that table from Headscale, so it reflects live mesh membership),
//   - is currently online (an enroll RPC to an offline agent just burns the
//     dispatch timeout; the node converges when it comes back),
//   - has no enroll job already queued or running, and
//   - isn't inside enrollRetryBackoff of its last failed attempt (30s after
//     the first failure, doubling to a 30m cap; a success resets the streak).
func reconcileConvergeEnrollment(svc *Service, inv *inventory.Store, jstore *jobs.Store, runner *jobs.Runner) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		// The node set comes from the api's one in-memory node registry, not
		// the nodes table (geekdojo-brain#585): id, role and last-seen are
		// every fact this pass needs about a node, and the registry holds all
		// three. Nothing here hydrates a row.
		nodes := inv.Registry().Members()
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

		// One pass over recent enroll jobs (newest first) gives both guards:
		// nodes with an in-flight enroll and each node's newest terminal job
		// (with its failure streak). Shared with converge_trust.
		guards, err := loadEnrollGuards(sc, jstore)
		if err != nil {
			return nil, err
		}

		var submitted []string
		var records []EnrolRecord // read lazily: only a node about to be enrolled needs them
		skipped := map[string]int{}
		for _, n := range nodes {
			if !slices.Contains(AutoEnrollRoles, n.Role) || enrolled[n.ID] {
				continue
			}
			if inventory.ComputeStatus(n.LastSeen) != proto.StatusOnline {
				skipped["offline"]++
				continue
			}
			if guards.inflight[n.ID] {
				skipped["inflight"]++
				continue
			}
			if guards.inBackoff(n.ID) {
				skipped["backoff"]++
				continue
			}
			// No device is bound to this node, so the routes come from its
			// last enrol or its subnet_route intents (ReenrolRoutes): an
			// automatic enrol must not reset away a route the node advertises.
			if records == nil {
				if records, err = (JobsLedger{Store: jstore}).Records(sc.Ctx); err != nil {
					sc.Log("warn", fmt.Sprintf("converge: read enrol records for routes: %v", err))
					records = []EnrolRecord{}
				}
			}
			routes, source := ReenrolRoutes(sc.Ctx, svc, n.ID, nil, records)
			if len(routes) > 0 {
				sc.Log("info", fmt.Sprintf("converge: %s re-enrols advertising %s (from %s)", n.ID, strings.Join(routes, ", "), source))
			}
			spec, _ := json.Marshal(EnrollSpec{NodeID: n.ID, AdvertiseRoutes: routes})
			if _, err := runner.Submit(sc.Ctx, "mesh.enroll_node", spec, "auto-enroll"); err != nil {
				// A single bad submit shouldn't fail the whole reconcile.
				sc.Log("warn", fmt.Sprintf("converge: submit enroll for %s: %v", n.ID, err))
				skipped["submit_error"]++
				continue
			}
			submitted = append(submitted, n.ID)
		}

		if len(submitted) > 0 {
			sc.Log("info", fmt.Sprintf("converge: enrolling %d unenrolled node(s): %s",
				len(submitted), strings.Join(submitted, ", ")))
		} else if len(skipped) > 0 {
			sc.Log("info", fmt.Sprintf("converge: no enrolls submitted (skipped: %v)", skipped))
		}
		return json.Marshal(map[string]any{"submitted": submitted, "skipped": skipped})
	}
}

// ----- mesh.enroll_node ---------------------------------------------------

// EnrollSpec is the spec body for a node enrollment job.
type EnrollSpec struct {
	NodeID          string   `json:"nodeId"`
	AdvertiseRoutes []string `json:"advertiseRoutes,omitempty"`
}

// enrollDispatchTimeout bounds the dispatch step: the agent's whole enroll
// budget (proto.MeshEnrollWork — mesh CA install, tailscaled restart,
// `tailscale up`) plus the bus round trip and a queued ack. The api must
// LOSE this race on purpose. An agent that used its whole budget answers
// with a real verdict — which command it was in, for how long, what
// tailscaled says — and an api that gave up first replaced that with
// "enroll rpc: context deadline exceeded" and left the agent's ack to die in
// an inbox nobody was reading. Both clocks were 30 s when e3bench-compute1's
// first login was killed (geekdojo/geekdojo-brain#402).
const enrollDispatchTimeout = proto.MeshEnrollWork + 30*time.Second

// EnrollNodeWorkflow NATSes a single-use preauth key to the target node's
// agent, waits for the agent's MeshEnrollAck, and writes the resulting
// Headscale node id back into mesh_devices.
//
//  0. validate — refuse a spec `tailscale up` would refuse, or one whose
//     node is not registered, before a key is minted or the agent touched.
//  1. dispatch — mint the node's enrolment key (PreAuthNode), RPC the
//     agent's mesh.enroll handler with the key + URL, and expire the key
//     when the step ends, whatever its outcome. The key exists only for the
//     life of this step and is never written to a step result.
//  2. record   — persist the device under the Headscale node id the enrol
//     reported, publish node_enrolled.
func EnrollNodeWorkflow(svc *Service, inv *inventory.Store, nc *nats.Conn) jobs.Workflow {
	return jobs.Workflow{
		Kind: "mesh.enroll_node",
		Steps: []jobs.WorkflowStep{
			{Name: "validate", Timeout: 5 * time.Second, Do: enrollValidate(inv)},
			{Name: "dispatch", Timeout: enrollDispatchTimeout, Do: enrollDispatch(svc, inv)},
			{Name: "record", Timeout: 5 * time.Second, Do: enrollRecord(svc, nc)},
		},
	}
}

// enrollSession is the state carried across steps: each step returns the
// re-marshaled session as its step result, and the next step reads it back
// via StepCtx.PriorResults (falling back to the job spec for the first
// step). It is NOT carried via the spec — the runner hands every step the
// original job spec unchanged.
//
// It carries no key value. Step results are persisted in the job ledger, so
// the enrolment key is minted, sent and expired inside the dispatch step and
// only its Headscale id (not a credential) is recorded.
type enrollSession struct {
	EnrollSpec
	KeyID string `json:"keyId"`
	HSID  string `json:"hsId"`
	HSIP  string `json:"hsIp"`
}

func parseEnrollSession(raw json.RawMessage) (*enrollSession, error) {
	var s enrollSession
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("invalid spec: %w", err)
	}
	if s.NodeID == "" {
		return nil, errors.New("nodeId is required")
	}
	// Every step parses through here, so no step addresses a bus subject or a
	// Headscale hostname built from an id that is not a single DNS label. The
	// spec may arrive from the jobs endpoint as submitted, so the saga checks
	// it as if the HTTP handler did not exist.
	if !busauth.ValidNodeID(s.NodeID) {
		return nil, fmt.Errorf("invalid nodeId %q: %s", s.NodeID, busauth.NodeIDRule)
	}
	return &s, nil
}

// enrollSessionFrom resumes the session from priorStep's result when
// present, else from the job spec (first step, or a step re-run after an
// api restart where prior results were lost — the latter fails later with
// a clear error rather than silently proceeding with empty fields).
func enrollSessionFrom(sc *jobs.StepCtx, priorStep string) (*enrollSession, error) {
	if raw, ok := sc.PriorResults[priorStep]; ok && len(raw) > 0 {
		return parseEnrollSession(raw)
	}
	return parseEnrollSession(sc.Spec)
}

// enrollValidate fails the job on a spec the agent's `tailscale up` would
// fail on anyway — but here, before a preauth key is minted and before the
// agent has installed the mesh CA and restarted tailscaled for nothing.
// Today that is an advertised route that is not a canonical network
// (192.168.1.149/24 for 192.168.1.0/24; e3bench-compute1 2026-09-04, where
// the enroll-defaults suggestion itself carried the host form). The
// operator's value is refused with the canonical form named, never
// rewritten: a route someone typed is theirs to correct. The auto-enroll
// paths (the onNodeAdded hook, converge_enrollment, converge_trust and the
// setup wizard's self-enroll) submit no routes and pass through untouched.
//
// It also refuses a node that is not in inventory: an enroll targets an
// onboarded node, and nothing downstream should mint a key for, or dispatch to,
// an id no node registered under. Without inventory the check cannot be made,
// so the step fails rather than skipping it.
func enrollValidate(inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		s, err := parseEnrollSession(sc.Spec)
		if err != nil {
			return nil, err
		}
		if err := ValidateAdvertiseRoutes(s.AdvertiseRoutes); err != nil {
			return nil, err
		}
		if inv == nil {
			return nil, errors.New("inventory unavailable: cannot confirm the enroll target is a registered node")
		}
		// Membership comes from the api's one in-memory node registry, not a
		// database read (geekdojo-brain#585). The same question as before —
		// is this id a node? — asked of the one list instead of the nodes
		// table.
		if !inv.Registry().IsMember(s.NodeID) {
			return nil, fmt.Errorf("node %s is not registered", s.NodeID)
		}
		if len(s.AdvertiseRoutes) > 0 {
			sc.Log("info", fmt.Sprintf("advertising %s from %s", strings.Join(s.AdvertiseRoutes, ", "), s.NodeID))
		}
		return json.Marshal(s)
	}
}

func enrollDispatch(svc *Service, inv *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		s, err := enrollSessionFrom(sc, "validate")
		if err != nil {
			return nil, err
		}
		// The control plane reaches Headscale on ITSELF. Enrolling it against
		// the cluster's public name makes its own tailscaled resolve
		// <cluster>.local to get there, and mDNS answers that with every
		// address the box has — including docker-bridge and link-local ones.
		// Dialling an fe80:: without a zone index errors outright, so the
		// control plane spends ~2m20s off its own mesh after each reboot before
		// it retries into a usable address (measured twice on e3bench,
		// geekdojo/geekdojo-brain#202).
		//
		// Loopback removes the name from that path entirely. The mesh leaf
		// already carries 127.0.0.1 in its SANs (see supervisor_docker.go
		// ensureLeaf), and Headscale accepts a client dialling a URL that
		// differs from its configured server_url — verified on e3bench
		// 2026-08-30, the client stays on it rather than being redirected.
		//
		// Enrolment-time only, deliberately. Changing an already-enrolled
		// node's control URL needs `tailscale up --force-reauth`, which mints a
		// NEW registration: the node gets a new tailnet IP and leaves a
		// duplicate Headscale entry that nothing prunes automatically. Not
		// worth forcing on existing clusters for a transient, self-healing,
		// LAN-invisible delay — they pick this up when next re-provisioned.
		loginServer := svc.cfg.LoginServer
		if isControlPlaneNode(sc.Ctx, inv, s.NodeID) {
			loginServer = loopbackLoginServer(svc.cfg.LoginServer)
			if loginServer != svc.cfg.LoginServer {
				sc.Log("info", fmt.Sprintf("%s is the control plane — enrolling against %s so its own tailscaled needs no name resolution", s.NodeID, loginServer))
			}
		}
		key, err := svc.MintPreAuthKey(sc.Ctx, PreAuthNode, PreAuthKeyRequest{})
		if err != nil {
			return nil, fmt.Errorf("mint key: %w", err)
		}
		s.KeyID = key.ID
		sc.Log("info", fmt.Sprintf("minted enrollment key %s for %s", short(key.ID), s.NodeID))
		// The key's life is this step. Expire it on every way out — an ack,
		// a rejection, a timeout, a bad ack — so a single-use key that was
		// sent but not consumed does not stay valid for its safety-net TTL.
		defer expireEnrolKey(sc, svc, s.NodeID, key.ID)

		cmd, _ := json.Marshal(proto.MeshEnrollCmd{
			LoginServer:     loginServer,
			AuthKey:         key.Value,
			Hostname:        s.NodeID,
			AdvertiseRoutes: s.AdvertiseRoutes,
			AcceptDNS:       true,
			AcceptRoutes:    true,
			// Ship the Mesh CA so the node trusts the self-hosted Headscale's
			// HTTPS leaf before tailscaled dials it. Nil/empty in mock + HTTP
			// dev and when Headscale is externally managed with a public cert.
			MeshCAPEM: svc.cfg.MeshCAPEM,
		})
		sc.Log("info", fmt.Sprintf("dispatching mesh.enroll to %s", s.NodeID))
		subject := proto.MeshEnrollSubject(s.NodeID)
		sent := time.Now()
		msg, err := sc.NATS.RequestWithContext(sc.Ctx, subject, cmd)
		if err != nil {
			return nil, enrollDispatchError(sc.Ctx, inv, s.NodeID, subject, err, time.Since(sent))
		}
		var ack proto.MeshEnrollAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("decode ack: %w", err)
		}
		if !ack.OK {
			return nil, enrollRejected(sc.Ctx, inv, s.NodeID, ack)
		}
		s.HSID = ack.TailnetID
		s.HSIP = ack.TailnetIP

		// In mock mode the agent has no Headscale to register with, so the
		// api gets to do it on the agent's behalf: tell the mock client
		// that this node is now in the tailnet. Skipped silently in real
		// mode (when ack.TailnetID is already populated by Headscale).
		if mock, ok := svc.Client().(*MockClient); ok && s.HSID == "" {
			node := HSNode{
				User:             svc.cfg.DefaultUser,
				Hostname:         s.NodeID,
				GivenName:        s.NodeID,
				IPv4:             "100.64.0." + fmt.Sprintf("%d", 1+(simpleHash(s.NodeID)%240)),
				Tags:             []string{meshNodeTag},
				AdvertisedRoutes: s.AdvertiseRoutes,
				ApprovedRoutes:   s.AdvertiseRoutes,
			}
			if err := mock.UpsertMockNode(node); err != nil {
				return nil, fmt.Errorf("mock register: %w", err)
			}
			// re-fetch to grab the generated id
			for _, n := range mockNodesByHostname(mock, s.NodeID) {
				s.HSID = n.ID
				s.HSIP = n.IPv4
				break
			}
		}

		sc.Log("info", fmt.Sprintf("agent enrolled (hsId=%s ip=%s backend=%s)",
			short(s.HSID), s.HSIP, ack.Backend))
		// What the node trusts now, against what was sent. A mismatch here
		// is a real fault (the agent installed something other than what it
		// was handed); a pre-fingerprint agent reports nothing and is not
		// called out for it.
		if want := svc.MeshCAFingerprint(); want != "" && ack.TrustFingerprint != "" {
			if ack.TrustFingerprint == want {
				sc.Log("info", fmt.Sprintf("%s now trusts mesh CA %s", s.NodeID, proto.ShortFingerprint(want)))
			} else {
				sc.Log("warn", fmt.Sprintf("%s reports trusting %s after enroll, but the api delivered %s",
					s.NodeID, proto.ShortFingerprint(ack.TrustFingerprint), proto.ShortFingerprint(want)))
			}
		}
		return json.Marshal(s)
	}
}

// enrolKeyExpireTimeout bounds the one Headscale call that expires an
// enrolment key as the dispatch step ends. It runs on a context detached
// from the step's, because the step's may already be done (a dispatch that
// timed out is exactly the case that most needs the key expired).
const enrolKeyExpireTimeout = 10 * time.Second

// expireEnrolKey expires the enrolment key minted by this dispatch step. A
// failure is logged, never turned into the step's result: the enrol itself
// succeeded or failed on its own terms, and the key's short expiry
// (nodeEnrolKeyExpiry) is the safety net for exactly this miss.
func expireEnrolKey(sc *jobs.StepCtx, svc *Service, nodeID, keyID string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(sc.Ctx), enrolKeyExpireTimeout)
	defer cancel()
	if err := svc.Client().ExpirePreAuthKey(ctx, keyID); err != nil {
		sc.Log("warn", fmt.Sprintf("could not expire enrollment key %s for %s (it lapses on its own within %s): %v",
			short(keyID), nodeID, nodeEnrolKeyExpiry, err))
		return
	}
	sc.Log("info", fmt.Sprintf("expired enrollment key %s for %s", short(keyID), nodeID))
}

// enrollDispatchError is the step error for an enroll RPC that returned no
// ack — the line the job feed carries, written so an operator does not need
// the agent log. A timeout says it timed out, after how long, and what the
// agent on the other end was budgeted; the dispatch step waits longer than
// that budget (enrollDispatchTimeout), so an agent that is honouring it has
// answered by now, and the honest readings of its silence are the two
// named. A silence with no responder is read against inventory (offline,
// old agent, real fault) when inventory is at hand. Either way the job
// fails, and converge_enrollment's backoff retries it on a later tick.
func enrollDispatchError(ctx context.Context, inv *inventory.Store, nodeID, subject string, err error, waited time.Duration) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("dispatch timed out after %s with no ack from %s: its agent is budgeted %s for the enroll (mesh CA install, tailscaled restart, tailscale up) and should have answered by now — either it was still running tailscale up past that budget, or it went away mid-enroll, or its ack was lost on the bus; the next reconcile pass retries after backoff",
			waited.Round(time.Second), nodeID, proto.MeshEnrollWork)
	case errors.Is(err, nats.ErrNoResponders) && inv != nil:
		return fmt.Errorf("enroll rpc: %s", inv.ExplainNoResponder(ctx, subject))
	}
	return fmt.Errorf("enroll rpc: %w", err)
}

// enrollRejected is the step error for a negative ack. An agent that
// predates proto.MeshEnrollDeadlineMinAgentVersion reports a deadline kill
// of `tailscale up` only as `tailscale up: signal: killed (stderr=)` — its
// own 30 s deadline firing while the CLI waited on the login, with nothing
// printed — so the saga reads that shape for what it is and names the
// release that fixes it. A newer agent names the kill itself and is relayed
// verbatim; so is a newer agent's bare signal, which is then a real kill
// from outside (an OOM, say) and not this bug wearing a new coat.
func enrollRejected(ctx context.Context, inv *inventory.Store, nodeID string, ack proto.MeshEnrollAck) error {
	if !strings.Contains(ack.Detail, "signal: killed") || strings.Contains(ack.Detail, "enroll deadline") {
		return fmt.Errorf("agent rejected enroll: %s", ack.Detail)
	}
	version := nodeAgentVersion(ctx, inv, nodeID)
	if version != "" {
		if c, err := releases.Compare(releases.SchemeCalVer, version, proto.MeshEnrollDeadlineMinAgentVersion); err == nil && c >= 0 {
			return fmt.Errorf("agent rejected enroll: %s", ack.Detail)
		}
	}
	who := "an agent that reported no version"
	if version != "" {
		who = fmt.Sprintf("agent %s", version)
	}
	return fmt.Errorf("agent's tailscale up was killed while it waited on the login: %s answered only %q, which is the shape of that agent's own 30s enroll deadline (it predates %s, which names the kill and gives the enroll %s) — update the node; the next reconcile pass retries after backoff",
		who, ack.Detail, proto.MeshEnrollDeadlineMinAgentVersion, proto.MeshEnrollWork)
}

// nodeAgentVersion is the bare CalVer the node reported at registration, or
// "" when inventory is absent, the node unknown, or nothing was reported.
func nodeAgentVersion(ctx context.Context, inv *inventory.Store, nodeID string) string {
	if inv == nil || nodeID == "" {
		return ""
	}
	n, err := inv.Get(ctx, nodeID)
	if err != nil || n == nil {
		return ""
	}
	return strings.TrimPrefix(strings.TrimSpace(n.AgentVersion), "v")
}

// isControlPlaneNode reports whether nodeID is this cluster's control plane.
// A lookup failure answers false: the cluster's normal login server is always
// correct, just occasionally slow for the control plane, so an unknown role
// degrades to the existing behaviour rather than to something novel.
func isControlPlaneNode(ctx context.Context, inv *inventory.Store, nodeID string) bool {
	if inv == nil || nodeID == "" {
		return false
	}
	n, err := inv.Get(ctx, nodeID)
	if err != nil || n == nil {
		return false
	}
	return n.Role == proto.RoleControlPlane
}

// loopbackLoginServer rewrites a login server URL to point at loopback,
// preserving scheme and port. Returns the input unchanged if it cannot be
// parsed or carries no host — the caller then enrols against the cluster name
// exactly as before, which works, so there is nothing to gain by failing here.
func loopbackLoginServer(loginServer string) string {
	u, err := url.Parse(loginServer)
	if err != nil || u.Host == "" {
		return loginServer
	}
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort("127.0.0.1", port)
	} else {
		u.Host = "127.0.0.1"
	}
	return u.String()
}

func enrollRecord(svc *Service, nc *nats.Conn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		s, err := enrollSessionFrom(sc, "dispatch")
		if err != nil {
			return nil, err
		}
		if s.HSID == "" {
			return nil, errors.New("no tailnet id returned by agent or mock")
		}
		now := time.Now().UTC()
		// The enrol is the one thing that binds a device to a node. A device
		// previously bound to this node (a re-registered machine) is unbound
		// in the same write, and pruned from Headscale just below.
		unbound, err := svc.store.BindDevice(sc.Ctx, &Device{
			HSID:             s.HSID,
			User:             svc.cfg.DefaultUser,
			Hostname:         s.NodeID,
			TailnetIP:        s.HSIP,
			Tags:             []string{meshNodeTag},
			AdvertisedRoutes: s.AdvertiseRoutes,
			RasputinNodeID:   s.NodeID,
			Kind:             "rasputin",
			FirstSeen:        now,
			LastSeen:         now,
		}, sc.JobID)
		if err != nil {
			return nil, fmt.Errorf("bind device: %w", err)
		}
		for _, id := range unbound {
			sc.Log("info", fmt.Sprintf("%s: device %s is no longer bound to it (now %s)", s.NodeID, short(id), short(s.HSID)))
		}
		pruneSupersededRegistrations(sc, svc, s.NodeID, s.HSID)
		publishChange(nc, proto.MeshChangeEvt{
			Scope:     s.NodeID,
			Change:    proto.MeshNodeEnrolled,
			NodeID:    s.NodeID,
			TailnetID: s.HSID,
			Ts:        now,
		})
		sc.Log("info", fmt.Sprintf("%s enrolled in tailnet as %s", s.NodeID, short(s.HSID)))
		return json.Marshal(s)
	}
}

// pruneSupersededRegistrations removes, from Headscale and mesh_devices, any
// OTHER Rasputin-tagged registration carrying nodeID's hostname once nodeID
// has enrolled as hsID.
//
// Re-enrolling a node whose tailscaled state survived updates the node
// Headscale already has (same machine key, same user — headscale 0.28
// HandleNodeFromPreAuthKey refreshes it in place). But a node whose
// tailscaled state is gone — a re-flashed box, or the controlplane itself
// after a restore put back a Headscale database that remembers the machine
// it was before the re-flash — presents a NEW machine key, and Headscale
// registers a second node under the same hostname. The old one never
// connects again; fetch_observed would otherwise sync it into mesh_devices
// beside the live one, both claiming the same RasputinNodeID. Same for a
// `--force-reauth` re-registration, which enrollDispatch's comment notes
// nothing pruned.
//
// Guarded by the live registration being FOUND in Headscale's list under
// hsID: if the id the agent reported does not match Headscale's id format,
// nothing is pruned, because "everything but the live one" cannot be told
// apart from "everything". Best-effort: a failure here is logged, never
// fails the enroll.
func pruneSupersededRegistrations(sc *jobs.StepCtx, svc *Service, nodeID, hsID string) {
	nodes, err := svc.Client().ListNodes(sc.Ctx)
	if err != nil {
		sc.Log("warn", fmt.Sprintf("%s: could not list Headscale nodes to prune superseded registrations: %v", nodeID, err))
		return
	}
	live := false
	var ghosts []HSNode
	for _, n := range nodes {
		if n.Hostname != nodeID || !slices.Contains(n.Tags, meshNodeTag) {
			continue
		}
		if n.ID == hsID {
			live = true
			continue
		}
		ghosts = append(ghosts, n)
	}
	if !live || len(ghosts) == 0 {
		return
	}
	for _, g := range ghosts {
		if err := svc.Client().DeleteNode(sc.Ctx, g.ID); err != nil {
			sc.Log("warn", fmt.Sprintf("%s: superseded registration %s (ip %s) could not be removed from Headscale: %v", nodeID, short(g.ID), g.IPv4, err))
			continue
		}
		if err := svc.store.DeleteDevice(sc.Ctx, g.ID); err != nil && !errors.Is(err, sql.ErrNoRows) {
			sc.Log("warn", fmt.Sprintf("%s: superseded device row %s: %v", nodeID, short(g.ID), err))
		}
		sc.Log("info", fmt.Sprintf("%s: removed superseded Headscale registration %s (ip %s) — the node re-registered with a new machine key as %s",
			nodeID, short(g.ID), g.IPv4, short(hsID)))
	}
}

// ----- helpers ------------------------------------------------------------

func mockNodesByHostname(mc *MockClient, hostname string) []HSNode {
	nodes, _ := mc.ListNodes(context.TODO())
	var out []HSNode
	for _, n := range nodes {
		if n.Hostname == hostname {
			out = append(out, n)
		}
	}
	return out
}

// simpleHash is a small djb2 used only to generate visually-distinct mock
// IPs from a node id. Not security-relevant.
func simpleHash(s string) int {
	h := 5381
	for _, c := range s {
		h = (h * 33) + int(c)
	}
	if h < 0 {
		h = -h
	}
	return h
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func publishChange(nc *nats.Conn, ev proto.MeshChangeEvt) {
	payload, err := json.Marshal(ev)
	if err != nil {
		log.Printf("mesh: marshal change: %v", err)
		return
	}
	scope := ev.Scope
	if scope == "" {
		scope = "global"
	}
	if err := nc.Publish(proto.MeshChangeSubject(scope, ev.Change), payload); err != nil {
		log.Printf("mesh: publish change: %v", err)
	}
}
