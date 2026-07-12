package mesh

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
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
//  2. push_keys   — create any pre-auth keys that don't exist on the
//     Headscale side yet; write the resulting hs_id +
//     plaintext back onto the intent row
//  3. push_routes — for each subnet_route intent, look up the node's
//     Headscale id (via mesh_devices) and call SetNodeRoutes
//  4. record      — persist intent_hash + last_applied
func ApplyWorkflow(svc *Service, inv *inventory.Store, nc *nats.Conn) jobs.Workflow {
	return jobs.Workflow{
		Kind: "mesh.apply",
		Steps: []jobs.WorkflowStep{
			{Name: "compile", Timeout: 2 * time.Second, Do: applyCompile(svc)},
			{Name: "push_keys", Timeout: 30 * time.Second, Do: applyPushKeys(svc)},
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

func applyPushKeys(svc *Service) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		intents, err := svc.store.ListIntentsByKind(sc.Ctx, string(proto.IntentPreAuthKey))
		if err != nil {
			return nil, err
		}
		created := 0
		for _, i := range intents {
			if !i.Enabled {
				continue
			}
			if i.HSID != "" {
				continue // already minted
			}
			var spec proto.PreAuthKeySpec
			if err := json.Unmarshal(i.Spec, &spec); err != nil {
				return nil, fmt.Errorf("intent %s: %w", i.ID, err)
			}
			user := spec.User
			if user == "" {
				user = svc.cfg.DefaultUser
			}
			expiry := time.Now().Add(parseExpiry(spec.ExpiresIn))
			id, value, err := svc.Client().CreatePreAuthKey(sc.Ctx, CreatePreAuthKeyInput{
				User:      user,
				Reusable:  spec.Reusable,
				Ephemeral: spec.Ephemeral,
				Expiry:    expiry,
				Tags:      spec.Tags,
			})
			if err != nil {
				return nil, fmt.Errorf("create key for intent %s: %w", i.ID, err)
			}
			if err := svc.store.SetIntentHSRef(sc.Ctx, i.ID, id, value); err != nil {
				return nil, fmt.Errorf("persist hs ref for %s: %w", i.ID, err)
			}
			sc.Log("info", fmt.Sprintf("minted preauth key %s (user=%s, tags=%v)", short(id), user, spec.Tags))
			created++
		}
		return json.Marshal(map[string]int{"created": created})
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
		hsByRasp := map[string]string{}
		for _, d := range devices {
			if d.RasputinNodeID != "" {
				hsByRasp[d.RasputinNodeID] = d.HSID
			}
		}

		applied := 0
		for nodeID, cidrs := range byNode {
			hsID, ok := hsByRasp[nodeID]
			if !ok {
				// Node not yet enrolled in the tailnet; skip without
				// failing. The next mesh.apply after enrollment will pick
				// this up. Note in the log so the operator sees why.
				sc.Log("warn", fmt.Sprintf("subnet route for %s skipped: node not yet enrolled in tailnet", nodeID))
				_ = inv // inventory lookup deferred; nodeID is the kept reference
				continue
			}
			sort.Strings(cidrs)
			if err := svc.Client().SetNodeRoutes(sc.Ctx, hsID, cidrs); err != nil {
				return nil, fmt.Errorf("set routes on %s: %w", nodeID, err)
			}
			sc.Log("info", fmt.Sprintf("approved routes on %s: %v", nodeID, cidrs))
			applied++
		}
		return json.Marshal(map[string]int{"applied": applied})
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

// enrollRetryCooldown is how long converge_enrollment waits after a FAILED
// enroll attempt before retrying that node, so a persistently broken agent
// produces a failed job every ~cooldown instead of every reconcile tick.
const enrollRetryCooldown = 30 * time.Minute

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
		},
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
		// Classify by the meshNodeTag the control plane stamps on every node it
		// enrolls — a DIRECT match on a marker we set, not a guess from the
		// hostname. (A Rasputin node id like "bench-controlplane1" matches no
		// hostname prefix, and re-deriving from the hostname would clobber the
		// authoritative kind/RasputinNodeID the enroll saga recorded — it did,
		// downgrading enrolled nodes to "user" every reconcile, bench
		// 2026-06-18.) A tagged node's hostname is its RASPUTIN_NODE_ID by
		// construction (the agent sets the tailscale hostname to the node id on
		// enroll). Anything untagged is a user device (e.g. a laptop added on
		// the Keys tab).
		for _, n := range nodes {
			kind := "user"
			rasp := ""
			if slices.Contains(n.Tags, meshNodeTag) {
				kind = "rasputin"
				rasp = n.Hostname
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
//   - isn't inside enrollRetryCooldown of its last failed attempt.
func reconcileConvergeEnrollment(svc *Service, inv *inventory.Store, jstore *jobs.Store, runner *jobs.Runner) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
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

		// One pass over recent enroll jobs (newest first) gives both guards:
		// nodes with an in-flight enroll and each node's newest terminal job.
		recent, err := jstore.ListJobsByKind(sc.Ctx, "mesh.enroll_node", 200)
		if err != nil {
			return nil, fmt.Errorf("list enroll jobs: %w", err)
		}
		inflight := map[string]bool{}
		lastTerminal := map[string]*jobs.Job{}
		for _, j := range recent {
			var spec EnrollSpec
			if json.Unmarshal(j.Spec, &spec) != nil || spec.NodeID == "" {
				continue
			}
			switch j.Status {
			case jobs.StatusQueued, jobs.StatusRunning:
				inflight[spec.NodeID] = true
			default:
				if _, seen := lastTerminal[spec.NodeID]; !seen {
					lastTerminal[spec.NodeID] = j
				}
			}
		}

		var submitted []string
		skipped := map[string]int{}
		for _, n := range nodes {
			if !slices.Contains(AutoEnrollRoles, n.Role) || enrolled[n.ID] {
				continue
			}
			if inventory.ComputeStatus(n.LastSeen) != proto.StatusOnline {
				skipped["offline"]++
				continue
			}
			if inflight[n.ID] {
				skipped["inflight"]++
				continue
			}
			if last := lastTerminal[n.ID]; last != nil && last.Status == jobs.StatusFailed &&
				time.Since(last.CreatedAt) < enrollRetryCooldown {
				skipped["cooldown"]++
				continue
			}
			spec, _ := json.Marshal(EnrollSpec{NodeID: n.ID})
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

// EnrollNodeWorkflow mints an ephemeral preauth key, NATSes it to the
// target node's agent, waits for the agent's MeshEnrollAck, and writes
// the resulting Headscale node id back into mesh_devices.
//
//  1. mint_key — CreatePreAuthKey for the rasputin-operator user
//     with the Rasputin tag.
//  2. dispatch — RPC the agent's mesh.enroll handler with the key + URL.
//  3. record   — persist the device, publish node_enrolled.
func EnrollNodeWorkflow(svc *Service, inv *inventory.Store, nc *nats.Conn) jobs.Workflow {
	return jobs.Workflow{
		Kind: "mesh.enroll_node",
		Steps: []jobs.WorkflowStep{
			{Name: "mint_key", Timeout: 10 * time.Second, Do: enrollMintKey(svc)},
			{Name: "dispatch", Timeout: 30 * time.Second, Do: enrollDispatch(svc, inv)},
			{Name: "record", Timeout: 5 * time.Second, Do: enrollRecord(svc, nc)},
		},
	}
}

// enrollSession is the state carried across steps: each step returns the
// re-marshaled session as its step result, and the next step reads it back
// via StepCtx.PriorResults (falling back to the job spec for the first
// step). It is NOT carried via the spec — the runner hands every step the
// original job spec unchanged, which is exactly the bug that shipped in v0:
// dispatch re-parsed the spec, never saw mint_key's KeyValue, and the agent
// rejected the enroll with "empty auth key" (caught on the first Mu wizard
// run, 2026-06-12).
type enrollSession struct {
	EnrollSpec
	KeyID    string `json:"keyId"`
	KeyValue string `json:"keyValue"`
	HSID     string `json:"hsId"`
	HSIP     string `json:"hsIp"`
}

func parseEnrollSession(raw json.RawMessage) (*enrollSession, error) {
	var s enrollSession
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("invalid spec: %w", err)
	}
	if s.NodeID == "" {
		return nil, errors.New("nodeId is required")
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

func enrollMintKey(svc *Service) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		s, err := parseEnrollSession(sc.Spec)
		if err != nil {
			return nil, err
		}
		id, value, err := svc.Client().CreatePreAuthKey(sc.Ctx, CreatePreAuthKeyInput{
			User:      svc.cfg.DefaultUser,
			Reusable:  false,
			Ephemeral: false,
			Expiry:    time.Now().Add(10 * time.Minute),
			Tags:      []string{meshNodeTag},
		})
		if err != nil {
			return nil, fmt.Errorf("mint key: %w", err)
		}
		s.KeyID = id
		s.KeyValue = value
		sc.Log("info", fmt.Sprintf("minted enrollment key %s for %s", short(id), s.NodeID))
		return json.Marshal(s)
	}
}

func enrollDispatch(svc *Service, _ *inventory.Store) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		s, err := enrollSessionFrom(sc, "mint_key")
		if err != nil {
			return nil, err
		}
		if s.KeyValue == "" {
			return nil, errors.New("no auth key from mint_key step (saga state lost?)")
		}
		cmd, _ := json.Marshal(proto.MeshEnrollCmd{
			LoginServer:     svc.cfg.LoginServer,
			AuthKey:         s.KeyValue,
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
		msg, err := sc.NATS.RequestWithContext(sc.Ctx, proto.MeshEnrollSubject(s.NodeID), cmd)
		if err != nil {
			return nil, fmt.Errorf("enroll rpc: %w", err)
		}
		var ack proto.MeshEnrollAck
		if err := json.Unmarshal(msg.Data, &ack); err != nil {
			return nil, fmt.Errorf("decode ack: %w", err)
		}
		if !ack.OK {
			return nil, fmt.Errorf("agent rejected enroll: %s", ack.Detail)
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
		return json.Marshal(s)
	}
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
		if err := svc.store.UpsertDevice(sc.Ctx, &Device{
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
		}); err != nil {
			return nil, fmt.Errorf("upsert device: %w", err)
		}
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

// ----- helpers ------------------------------------------------------------

func mockNodesByHostname(mc *MockClient, hostname string) []HSNode {
	nodes, _ := mc.ListNodes(nil)
	var out []HSNode
	for _, n := range nodes {
		if n.Hostname == hostname {
			out = append(out, n)
		}
	}
	return out
}

// parseExpiry maps a duration string like "24h" to a time.Duration. Falls
// back to 24h on parse error.
func parseExpiry(s string) time.Duration {
	if s == "" {
		return 24 * time.Hour
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 24 * time.Hour
	}
	return d
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
