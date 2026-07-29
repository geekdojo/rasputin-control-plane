package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// GET /api/bmc/backends — the supported-backends list the Settings
// picker renders (bmc-settings.md S-1). Served, never UI-hardcoded.
func (s *Server) handleBMCBackends(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, proto.SupportedBMCBackends)
}

// bmcConfigView is the sanitized selection state for the Settings UI.
// The bitscope unlock sequence is write-only: never echoed, surfaced
// only as unlockSet.
type bmcConfigView struct {
	Backend    string          `json:"backend"` // "" = off
	HostNodeID string          `json:"hostNodeId,omitempty"`
	Config     json.RawMessage `json:"config,omitempty"`
	PinnedNode string          `json:"pinnedNode,omitempty"`
}

// GET /api/bmc/config — current selection from settings + the env-pin
// state from inventory.
func (s *Server) handleBMCGetConfig(w http.ResponseWriter, r *http.Request) {
	st := s.setup.Store()
	view := bmcConfigView{}
	var err error
	if view.Backend, err = st.Get(r.Context(), setup.KeyBMCBackend); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if view.HostNodeID, err = st.Get(r.Context(), setup.KeyBMCHostNode); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	raw, err := st.Get(r.Context(), setup.KeyBMCConfig)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if raw != "" {
		view.Config = sanitizeBMCConfig(view.Backend, raw)
	}
	// A backend's credential lives under its own settings key (never in
	// bmc.config); surface only whether one is stored, so the form can
	// show "leave blank to keep" instead of a blank that means "unset".
	if cred, ok := bmc.CredentialFor(view.Backend); ok {
		if v, cerr := st.Get(r.Context(), cred.SettingsKey); cerr == nil && v != "" {
			view.Config = setCredentialSet(view.Config, cred.Field)
		}
	}
	// A pinned host anywhere renders the whole section read-only.
	if nodes, err := s.inv.List(r.Context()); err == nil {
		for _, n := range nodes {
			if n.Metadata != nil {
				if pinned, ok := n.Metadata[proto.MetadataBMCConfigPinned].(bool); ok && pinned {
					view.PinnedNode = n.ID
					break
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, view)
}

// sanitizeBMCConfig strips write-only fields before a config leaves the
// api. Stored configs no longer contain the unlock (it has its own
// settings key), so this is defense-in-depth against any legacy or
// hand-edited value.
func sanitizeBMCConfig(kind, raw string) json.RawMessage {
	cred, ok := bmc.CredentialFor(kind)
	if !ok {
		return json.RawMessage(raw)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil
	}
	if v, vok := m[cred.Field].(string); vok && v != "" {
		m[cred.Field+"Set"] = true
	}
	delete(m, cred.Field)
	out, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return out
}

// setUnlockSet annotates a config view with unlockSet: true.
func setCredentialSet(raw json.RawMessage, field string) json.RawMessage {
	m := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &m); err != nil {
			return raw
		}
	}
	m[field+"Set"] = true
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

// POST /api/bmc/config — validate, then submit a bmc.configure job.
// Settings are written by the job's record step (after a successful
// push), so a refused push changes nothing.
func (s *Server) handleBMCSetConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind       string          `json:"kind"`
		HostNodeID string          `json:"hostNodeId"`
		Config     json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad body: "+err.Error())
		return
	}
	if req.Kind == "" {
		req.Kind = "none"
	}
	st := s.setup.Store()
	if req.HostNodeID == "" {
		// Deconfigure targets whichever host currently holds the config.
		req.HostNodeID, _ = st.Get(r.Context(), setup.KeyBMCHostNode)
	}
	if req.HostNodeID == "" {
		writeError(w, http.StatusBadRequest, "hostNodeId is required")
		return
	}
	// Write-only unlock (security review, CP #34): a typed unlock goes
	// straight to its own settings key and is STRIPPED from the config —
	// job specs and step results are served unredacted by the jobs API,
	// so no secret may enter them. An empty incoming unlock keeps the
	// stored one; the push step injects it bus-side at dispatch time.
	secret := ""
	if cred, ok := bmc.CredentialFor(req.Kind); ok {
		var serr error
		req.Config, serr = storeAndStripCredential(r.Context(), st, cred, req.Config)
		if serr != nil {
			writeError(w, http.StatusBadRequest, serr.Error())
			return
		}
		secret, _ = st.Get(r.Context(), cred.SettingsKey)
	}
	if err := bmc.ValidateSelection(r.Context(), s.inv, req.Kind, req.Config); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	spec, _ := json.Marshal(bmc.ConfigureSpec{
		Kind:       req.Kind,
		HostNodeID: req.HostNodeID,
		Config:     req.Config,
		ConfigHash: bmc.ConfigHash(req.Kind, req.Config, secret),
	})
	j, err := s.runner.Submit(r.Context(), "bmc.configure", spec, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// POST /api/bmc/probe
// Body: {"kind":"turingpi","endpoint":"optional"}
//
// Asks the BMC-host agent to look for a board and capture the
// certificate it presents (bmc-settings §7a). Runs with no credentials
// and before any backend is configured — that is the point: it is what
// lets Settings offer discovery instead of a blank form asking for an IP
// and a fingerprint the operator would have to go and read themselves.
//
// Routed through the host agent rather than dialled from here because
// mDNS is link-local: the well-known name resolves from a node on the
// chassis's segment, which the host agent is and the api may not be.
func (s *Server) handleBMCProbe(w http.ResponseWriter, r *http.Request) {
	st := s.setup.Store()
	var req proto.BMCProbeCmd
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	host, err := st.Get(r.Context(), setup.KeyBMCHostNode)
	if err != nil || host == "" {
		writeError(w, http.StatusBadRequest, "no BMC host node configured — pick one before probing")
		return
	}
	body, _ := json.Marshal(req)
	msg, err := s.nc.Request(proto.BMCProbeSubject(host), body, 25*time.Second)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("probe rpc to %s: %v", host, err))
		return
	}
	var res proto.BMCProbeResult
	if uerr := json.Unmarshal(msg.Data, &res); uerr != nil {
		writeError(w, http.StatusBadGateway, "probe returned an unreadable reply")
		return
	}
	// The agent reads what each slot calls itself; only the api can say
	// which Rasputin node that is. Split that way because the agent has
	// no inventory and the api has no board.
	s.matchProbeSlots(r.Context(), &res)
	writeJSON(w, http.StatusOK, res)
}

// matchProbeSlots turns each slot's self-reported hostname into a
// Rasputin node id, so the operator confirms a filled-in map instead of
// composing one.
//
// A hostname is only a hint, never an assertion — it is whatever the
// node's getty happens to print. So this matches conservatively and
// leaves NodeID empty rather than guessing:
//
//   - exact node-id match, or exact hostname match, wins
//   - anything ambiguous or unrecognised is left blank with a reason
//
// The controlplane is the case that reliably does not match: it sets a
// transient hostname of "rasputin" regardless of its node-id, so it will
// always fall through to the dropdown. That is expected, and worth
// saying in the row rather than looking like a failure.
func (s *Server) matchProbeSlots(ctx context.Context, res *proto.BMCProbeResult) {
	if len(res.Slots) == 0 {
		return
	}
	nodes, err := s.inv.List(ctx)
	if err != nil {
		return
	}
	matchProbeSlotsAgainst(res.Slots, nodes)
}

// matchProbeSlotsAgainst is the pure half, so the matching rules can be
// tested without a Server or a board.
func matchProbeSlotsAgainst(slots []proto.BMCProbeSlot, nodes []*proto.Node) {
	byID := make(map[string]string, len(nodes))
	byHost := make(map[string]string, len(nodes))
	hostDup := map[string]bool{}
	for _, n := range nodes {
		byID[strings.ToLower(n.ID)] = n.ID
		if h := strings.ToLower(strings.TrimSpace(n.Hostname)); h != "" {
			if _, seen := byHost[h]; seen {
				hostDup[h] = true
			}
			byHost[h] = n.ID
		}
	}
	for i := range slots {
		sl := &slots[i]
		h := strings.ToLower(strings.TrimSpace(sl.Hostname))
		if h == "" {
			continue
		}
		if id, ok := byID[h]; ok {
			sl.NodeID = id
			continue
		}
		if id, ok := byHost[h]; ok && !hostDup[h] {
			sl.NodeID = id
			continue
		}
		if hostDup[h] {
			sl.Detail = fmt.Sprintf("more than one node answers to %q — choose which one this slot is", sl.Hostname)
			continue
		}
		sl.Detail = fmt.Sprintf("this slot calls itself %q, which is not a node Rasputin knows — choose it yourself, or leave the slot unmapped", sl.Hostname)
	}
}

// storeAndStripCredential persists a newly-typed credential under its own
// settings key and returns the config with every trace of it removed —
// the returned blob is what lands in the job spec and audit trail, so it
// must be safe to serve unredacted. An absent/empty value keeps the
// stored secret unchanged, which is what lets the form show a blank
// password field without wiping the saved one.
func storeAndStripCredential(ctx context.Context, st *setup.Store, cred bmc.CredentialField, incoming json.RawMessage) (json.RawMessage, error) {
	in := map[string]any{}
	if len(incoming) > 0 {
		if err := json.Unmarshal(incoming, &in); err != nil {
			return nil, fmt.Errorf("bmc config: %w", err)
		}
	}
	if v, ok := in[cred.Field].(string); ok && v != "" {
		if err := st.Set(ctx, cred.SettingsKey, v); err != nil {
			return nil, fmt.Errorf("store credential: %w", err)
		}
	}
	delete(in, cred.Field)
	delete(in, cred.Field+"Set")
	out, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// POST /api/bmc/{nodeId}/power/{verb}
// Body: none. Returns the kicked-off job.
func (s *Server) handleBMCPower(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("nodeId")
	verb := proto.BMCPowerVerb(r.PathValue("verb"))
	if !proto.ValidBMCPowerVerb(verb) {
		writeError(w, http.StatusBadRequest, "unsupported verb")
		return
	}
	spec, _ := json.Marshal(bmc.Spec{TargetNodeID: nodeID, Verb: verb})
	j, err := s.runner.Submit(r.Context(), "bmc.power", spec, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// GET /api/bmc/{nodeId}/status — read-only view of last-known state.
// Does not RPC the BMC; use POST .../power/status to refresh from hardware.
func (s *Server) handleBMCStatus(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("nodeId")
	state, err := s.bmc.Store().Get(r.Context(), nodeID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if state == nil {
		// Never queried — return a zero-value envelope rather than 404 so
		// the UI can render the row without special-casing.
		state = &bmc.NodeState{
			TargetNodeID: nodeID,
			PowerState:   proto.BMCStateUnknown,
		}
	}
	writeJSON(w, http.StatusOK, state)
}

// GET /api/bmc — list every known BMC state row.
func (s *Server) handleListBMCStates(w http.ResponseWriter, r *http.Request) {
	rows, err := s.bmc.Store().List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []*bmc.NodeState{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// GET /ws/bmc/{nodeId}/sol — open a serial-over-LAN WebSocket. Bidirectional:
// the UI reads bytes from the agent's serial port and writes bytes back.
//
// Flow:
//  1. Accept the WS.
//  2. SessionManager.Open() RPCs the BMC host agent's bmc.sol.open handler
//     and subscribes to the .out subject (where the agent publishes serial
//     bytes from the device).
//  3. Two goroutines run concurrently:
//     - readLoop: WS → session.Write() → NATS .in subject
//     - writeLoop: session.Out → WS frames
//  4. When either side closes, the other goroutine sees ctx.Done() and we
//     SessionManager.Close() which RPCs bmc.sol.close.
func (s *Server) handleBMCSOL(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("nodeId")
	// Per-node, per-capability gate (bmc.md §2a): refuse before accepting
	// the WS when the BMC host has no serial path to this target — or has
	// one it cannot offer as a console. A backend that drives power but
	// not console (turingpi) must not get a session it can only fail.
	if err := s.bmc.TargetSupports(r.Context(), s.inv, nodeID, proto.BMCCapConsole); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // dev cross-origin, same as bridgeSubject
	})
	if err != nil {
		log.Printf("ws bmc.sol: accept: %v", err)
		return
	}
	defer c.Close(websocket.StatusInternalError, "")

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	sess, err := s.bmcSessions.Open(ctx, nodeID)
	if err != nil {
		_ = c.Write(ctx, websocket.MessageText, []byte("\r\n*** sol open failed: "+err.Error()+"\r\n"))
		c.Close(websocket.StatusInternalError, "sol open failed")
		return
	}
	defer sess.Close(context.Background())

	// Banner: tell the UI we're connected so the page isn't visually dead
	// while the mock backend's first canned line is in flight.
	_ = c.Write(ctx, websocket.MessageText,
		[]byte("*** sol session "+sess.ID[:12]+" open ("+sess.Backend+")\r\n"))

	// WS → session
	go func() {
		defer cancel()
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			if writeErr := sess.Write(data); writeErr != nil {
				log.Printf("ws bmc.sol: session write: %v", writeErr)
				return
			}
		}
	}()

	// session.Out → WS
	pings := time.NewTicker(30 * time.Second)
	defer pings.Stop()
	for {
		select {
		case <-ctx.Done():
			c.Close(websocket.StatusNormalClosure, "")
			return
		case <-pings.C:
			pingCtx, pcancel := context.WithTimeout(ctx, 5*time.Second)
			err := c.Ping(pingCtx)
			pcancel()
			if err != nil {
				return
			}
		case b := <-sess.Out:
			writeCtx, wcancel := context.WithTimeout(ctx, 5*time.Second)
			err := c.Write(writeCtx, websocket.MessageText, b)
			wcancel()
			if err != nil {
				return
			}
		case <-sess.Closed():
			c.Close(websocket.StatusNormalClosure, "session closed")
			return
		}
	}
}
