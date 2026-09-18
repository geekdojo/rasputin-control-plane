package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Bus join-token management. The plaintext token is returned exactly once at
// mint time (like mesh preauth keys); thereafter only secret-free metadata is
// listable. One token is not revocable at all: the one the api minted for this
// controlplane's own agent, which the list marks `selfAgent` (#140). Agents present a token as NATS username=node-id, password=token;
// the auth-callout responder validates it. See internal/busauth.

func (s *Server) handleListBusTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.busTokens.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tokens == nil {
		tokens = []busauth.TokenInfo{}
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (s *Server) handleMintBusToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label  string `json:"label"`
		NodeID string `json:"nodeId"` // required: the node id the token is bound to
	}
	// Body is optional; ignore decode errors on an empty body.
	_ = json.NewDecoder(r.Body).Decode(&body)

	// Every token is bound to one node (geekdojo-brain#423): there is no
	// unbound mint, because an unbound token authenticated as whatever node id
	// the connecting client chose. The id must also be one the bus will accept
	// as a username; a token bound to anything else could never authenticate.
	// Rejected, not normalized, so the id the operator sees is the id the node
	// presents.
	if body.NodeID == "" {
		writeError(w, http.StatusBadRequest, "nodeId is required: every join token is bound to the node id it will authenticate as")
		return
	}
	if !busauth.ValidNodeID(body.NodeID) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid nodeId %q: %s", body.NodeID, busauth.NodeIDRule))
		return
	}

	// Cluster-size cap (proto.MaxClusterNodes): refuse a mint that would
	// commit a NEW prospective node past the cap. Committed = live nodes +
	// pending enrollments (bound, unrevoked tokens whose node hasn't
	// registered). A re-mint for an id that's already live or pending is a
	// token replacement, not growth, and is always allowed.
	// Registration is the backstop for anything that slips past this.
	grows, used, err := s.mintGrowsCluster(r.Context(), body.NodeID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if grows && used >= proto.MaxClusterNodes {
		writeError(w, http.StatusConflict, fmt.Sprintf(
			"cluster is at the %d-node cap (%d nodes + pending enrollments); remove a node or revoke a pending token first",
			proto.MaxClusterNodes, used))
		return
	}

	plaintext, id, err := s.busTokens.MintBound(r.Context(), body.Label, body.NodeID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// token is returned ONCE — the operator seeds it into the node and it's
	// unrecoverable afterward. busPin rides along so the seed the UI renders
	// from this response carries RASPUTIN_BUS_PIN (#448) — the same response,
	// so a seed can never pair a token with a pin fetched at another moment.
	writeJSON(w, http.StatusCreated, map[string]string{
		"id":     id,
		"label":  body.Label,
		"nodeId": body.NodeID,
		"token":  plaintext,
		"busPin": s.busPin(),
	})
}

// mintGrowsCluster reports whether minting a token bound to nodeID would
// commit a new prospective node, and
// returns the committed count: live nodes plus distinct pending enrollments
// (bound, unrevoked tokens whose node id isn't in inventory). Mirrors the
// UI's pending-bay accounting so the API and the wizard agree on "full".
func (s *Server) mintGrowsCluster(ctx context.Context, nodeID string) (grows bool, used int, err error) {
	nodes, err := s.inv.List(ctx)
	if err != nil {
		return false, 0, err
	}
	live := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		live[n.ID] = true
	}
	tokens, err := s.busTokens.List(ctx)
	if err != nil {
		return false, 0, err
	}
	pending := make(map[string]bool)
	for _, t := range tokens {
		if t.RevokedAt != nil || t.NodeID == nil || *t.NodeID == "" {
			continue
		}
		if !live[*t.NodeID] {
			pending[*t.NodeID] = true
		}
	}
	used = len(nodes) + len(pending)
	grows = !live[nodeID] && !pending[nodeID]
	return grows, used, nil
}

func (s *Server) handleRevokeBusToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing token id")
		return
	}
	disconnected, err := s.busTokens.Revoke(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "no live token with that id")
			return
		}
		// The controlplane's own agent token (geekdojo-brain#140). 409, not
		// 403: the request is well-formed and the caller is authorised — the
		// state of this particular token is what makes it refusable, and the
		// same conflict answers the UI's "cancel this pending enrollment",
		// which is this route too. The message says what to do instead.
		if errors.Is(err, busauth.ErrSelfAgentToken) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Revoke also closed every live bus session the token authenticated
	// (certificates.md §4.2(1)). Say how many: an operator revoking a token in
	// response to a compromise needs to know whether a live session was cut,
	// and "0" is a real answer (the node was offline) rather than a silence.
	if disconnected > 0 {
		log.Printf("rasputin-api: revoked bus token %q and closed %d live bus connection(s)", id, disconnected)
	}
	writeJSON(w, http.StatusOK, revokeBusTokenResponse{ID: id, Disconnected: disconnected})
}

// revokeBusTokenResponse is DELETE /api/bus/tokens/{id}'s reply.
type revokeBusTokenResponse struct {
	ID string `json:"id"`
	// Disconnected is how many live bus connections authenticated with the
	// token were closed by the revoke. Their reconnects are refused.
	Disconnected int `json:"disconnected"`
}
