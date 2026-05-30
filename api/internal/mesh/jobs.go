package mesh

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

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
			id, value, err := svc.client.CreatePreAuthKey(sc.Ctx, CreatePreAuthKeyInput{
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
			if err := svc.client.SetNodeRoutes(sc.Ctx, hsID, cidrs); err != nil {
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

// ReconcileWorkflow pulls Headscale's live state, derives an observed
// hash, compares to intent_hash, and emits drift / in_sync.
func ReconcileWorkflow(svc *Service, nc *nats.Conn) jobs.Workflow {
	return jobs.Workflow{
		Kind: "mesh.reconcile",
		Steps: []jobs.WorkflowStep{
			{Name: "fetch_observed", Timeout: 30 * time.Second, Do: reconcileFetch(svc, nc)},
			{Name: "compare", Timeout: 2 * time.Second, Do: reconcileCompare(svc, nc)},
		},
	}
}

func reconcileFetch(svc *Service, nc *nats.Conn) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		keys, err := svc.client.ListPreAuthKeys(sc.Ctx, "")
		if err != nil {
			return nil, fmt.Errorf("list keys: %w", err)
		}
		nodes, err := svc.client.ListNodes(sc.Ctx)
		if err != nil {
			return nil, fmt.Errorf("list nodes: %w", err)
		}

		// Sync the mesh_devices table with Headscale's view of reality.
		// Rasputin nodes are correlated by Hostname == NodeID (the agent
		// publishes its node id as the tailscale hostname during enroll).
		for _, n := range nodes {
			kind := "user"
			rasp := ""
			if matchesRasputinHostname(n.Hostname) {
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

// enrollSession is the state carried across steps via the spec — we
// re-marshal the spec at each step to pass forward.
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

func enrollMintKey(svc *Service) jobs.DoFn {
	return func(sc *jobs.StepCtx) (json.RawMessage, error) {
		s, err := parseEnrollSession(sc.Spec)
		if err != nil {
			return nil, err
		}
		id, value, err := svc.client.CreatePreAuthKey(sc.Ctx, CreatePreAuthKeyInput{
			User:      svc.cfg.DefaultUser,
			Reusable:  false,
			Ephemeral: false,
			Expiry:    time.Now().Add(10 * time.Minute),
			Tags:      []string{"tag:rasputin-node"},
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
		s, err := parseEnrollSession(sc.Spec)
		if err != nil {
			return nil, err
		}
		cmd, _ := json.Marshal(proto.MeshEnrollCmd{
			LoginServer:     svc.cfg.LoginServer,
			AuthKey:         s.KeyValue,
			Hostname:        s.NodeID,
			AdvertiseRoutes: s.AdvertiseRoutes,
			AcceptDNS:       true,
			AcceptRoutes:    true,
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
		if mock, ok := svc.client.(*MockClient); ok && s.HSID == "" {
			node := HSNode{
				User:             svc.cfg.DefaultUser,
				Hostname:         s.NodeID,
				GivenName:        s.NodeID,
				IPv4:             "100.64.0." + fmt.Sprintf("%d", 1+(simpleHash(s.NodeID)%240)),
				Tags:             []string{"tag:rasputin-node"},
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
		s, err := parseEnrollSession(sc.Spec)
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
			Tags:             []string{"tag:rasputin-node"},
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

// matchesRasputinHostname returns true if the hostname matches a Rasputin
// inventory node id format. v0 heuristic: starts with "node-" or any
// Rasputin role prefix. Real correlation happens via the explicit
// EnrollNodeWorkflow's record step; this is for reconcile cases where we
// see a node we didn't enroll ourselves (post-reset, manual re-enroll).
func matchesRasputinHostname(hostname string) bool {
	if hostname == "" {
		return false
	}
	for _, p := range []string{"node-", "rasp-", "fw-", "cp-"} {
		if len(hostname) > len(p) && hostname[:len(p)] == p {
			return true
		}
	}
	return false
}

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
