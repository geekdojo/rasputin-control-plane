package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
)

// Bus join-token management. The plaintext token is returned exactly once at
// mint time (like mesh preauth keys); thereafter only secret-free metadata is
// listable. Agents present a token as NATS username=node-id, password=token;
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
		Label string `json:"label"`
	}
	// Body is optional; ignore decode errors on an empty body.
	_ = json.NewDecoder(r.Body).Decode(&body)

	plaintext, id, err := s.busTokens.Mint(r.Context(), body.Label)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// token is returned ONCE — the operator seeds it into the node and it's
	// unrecoverable afterward.
	writeJSON(w, http.StatusCreated, map[string]string{
		"id":    id,
		"label": body.Label,
		"token": plaintext,
	})
}

func (s *Server) handleRevokeBusToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing token id")
		return
	}
	if err := s.busTokens.Revoke(r.Context(), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "no live token with that id")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
