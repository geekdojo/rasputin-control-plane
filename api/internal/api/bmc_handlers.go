package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

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
//       - readLoop: WS → session.Write() → NATS .in subject
//       - writeLoop: session.Out → WS frames
//  4. When either side closes, the other goroutine sees ctx.Done() and we
//     SessionManager.Close() which RPCs bmc.sol.close.
func (s *Server) handleBMCSOL(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("nodeId")
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
