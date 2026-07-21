package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
	// The unlock lives under its own settings key (never in bmc.config);
	// surface only its presence.
	if view.Backend == "bitscope" {
		if u, uerr := st.Get(r.Context(), setup.KeyBMCBitscopeUnlock); uerr == nil && u != "" {
			view.Config = setUnlockSet(view.Config)
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
	if kind != "bitscope" {
		return json.RawMessage(raw)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil
	}
	if v, ok := m["unlock"].(string); ok && v != "" {
		m["unlockSet"] = true
	}
	delete(m, "unlock")
	out, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return out
}

// setUnlockSet annotates a config view with unlockSet: true.
func setUnlockSet(raw json.RawMessage) json.RawMessage {
	m := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &m); err != nil {
			return raw
		}
	}
	m["unlockSet"] = true
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
	unlock := ""
	if req.Kind == "bitscope" {
		var uerr error
		req.Config, uerr = storeAndStripUnlock(r.Context(), st, req.Config)
		if uerr != nil {
			writeError(w, http.StatusBadRequest, uerr.Error())
			return
		}
		unlock, _ = st.Get(r.Context(), setup.KeyBMCBitscopeUnlock)
	}
	if err := bmc.ValidateSelection(r.Context(), s.inv, req.Kind, req.Config); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	spec, _ := json.Marshal(bmc.ConfigureSpec{
		Kind:       req.Kind,
		HostNodeID: req.HostNodeID,
		Config:     req.Config,
		ConfigHash: bmc.ConfigHash(req.Kind, req.Config, unlock),
	})
	j, err := s.runner.Submit(r.Context(), "bmc.configure", spec, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// storeAndStripUnlock persists a newly-typed bitscope unlock under its
// own settings key and returns the config with every unlock-related
// field removed — the returned blob is safe for the job audit trail.
// An absent/empty unlock keeps the stored secret unchanged.
func storeAndStripUnlock(ctx context.Context, st *setup.Store, incoming json.RawMessage) (json.RawMessage, error) {
	in := map[string]any{}
	if len(incoming) > 0 {
		if err := json.Unmarshal(incoming, &in); err != nil {
			return nil, fmt.Errorf("bitscope config: %w", err)
		}
	}
	if v, ok := in["unlock"].(string); ok && v != "" {
		if err := st.Set(ctx, setup.KeyBMCBitscopeUnlock, v); err != nil {
			return nil, fmt.Errorf("store unlock: %w", err)
		}
	}
	delete(in, "unlock")
	delete(in, "unlockSet")
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
	// Per-node gate (bmc.md §2a): refuse before accepting the WS when the
	// BMC host has no serial path to this target.
	if err := s.bmc.TargetReachable(r.Context(), s.inv, nodeID); err != nil {
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
