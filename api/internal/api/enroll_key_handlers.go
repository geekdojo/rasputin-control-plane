package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
)

// Operator SSH key — the one public key the Add-node wizard prefills its SSH
// KEY field from, so the operator isn't re-asked on every enrollment. It is
// written into the seeds of nodes enrolled from now on and changes nothing on
// nodes already enrolled. Public-key material only. See setup/operatorkeys.go
// for the storage semantics (unset vs cleared, legacy multi-key values).

// operatorKeyResponse is the wire shape of GET and PUT.
//
//   - key: the key the wizard prefills; "" when none is saved.
//   - captured: false only while the setting has never been set (the wizard
//     then remembers whatever the operator enters on the next enrollment).
//   - ignoredKeys: extra keys left in a legacy multi-key value. They have no
//     effect; the next PUT drops them. Always 0 in a PUT response.
type operatorKeyResponse struct {
	Key         string `json:"key"`
	Captured    bool   `json:"captured"`
	IgnoredKeys int    `json:"ignoredKeys"`
}

// GET /api/enroll/operator-key
// Response: { "key": "ssh-ed25519 AAAA… you@laptop", "captured": true, "ignoredKeys": 0 }
func (s *Server) handleGetOperatorKey(w http.ResponseWriter, r *http.Request) {
	k, err := s.setup.OperatorSSHKey(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, operatorKeyResponse{Key: k.Key, Captured: k.Captured, IgnoredKeys: k.IgnoredKeys})
}

// PUT /api/enroll/operator-key
// Body: { "key": "ssh-ed25519 AAAA…" } replaces the key; { "key": "" } clears
// it (an explicit "no prefill" that the startup capture never overwrites).
// Either way the stored value holds at most this one key afterwards.
// 400 on a missing "key" field or a line that isn't an OpenSSH public key.
func (s *Server) handlePutOperatorKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key *string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Key == nil {
		writeError(w, http.StatusBadRequest, "body must carry a \"key\" string (empty clears it)")
		return
	}
	key, err := s.setup.SetOperatorSSHKey(r.Context(), *req.Key)
	if err != nil {
		if errors.Is(err, setup.ErrInvalidSSHKey) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, operatorKeyResponse{Key: key, Captured: true})
}
