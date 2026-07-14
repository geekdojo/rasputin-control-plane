package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
)

// Operator SSH keys — the cluster-remembered public key(s) the Add-node
// wizard prefills its SSH KEY field from, so the operator isn't re-asked on
// every enrollment. Public-key material only. See setup/operatorkeys.go for
// the storage semantics (unset vs explicit-empty, forward-only rotation).

// GET /api/enroll/operator-keys
// Response: { "keys": ["ssh-ed25519 AAAA… you@laptop", …], "captured": true }
// "captured" false means the setting has never been set (nothing to prefill,
// and the wizard should offer to remember whatever the operator enters).
func (s *Server) handleGetOperatorKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.setup.OperatorSSHKeys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	captured := keys != nil
	if keys == nil {
		keys = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys, "captured": captured})
}

// PUT /api/enroll/operator-keys
// Body: { "keys": ["ssh-ed25519 AAAA…", …] } — replaces the list (empty is
// a valid explicit choice and disables prefill without ever re-seeding).
// 400 on a line that isn't an OpenSSH public key.
func (s *Server) handlePutOperatorKeys(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Keys []string `json:"keys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Keys == nil {
		writeError(w, http.StatusBadRequest, "body must carry a \"keys\" array (empty allowed)")
		return
	}
	keys, err := s.setup.SetOperatorSSHKeys(r.Context(), req.Keys)
	if err != nil {
		if errors.Is(err, setup.ErrInvalidSSHKey) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys, "captured": true})
}
