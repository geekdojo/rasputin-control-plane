package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
)

// GET /api/setup/state — **unauthenticated** so the wizard can drive the
// very first passkey registration. Doesn't leak anything sensitive: just
// the operator-chosen install name + boolean step state. The trust-pem
// path isn't exposed either.
func (s *Server) handleSetupState(w http.ResponseWriter, r *http.Request) {
	state, err := s.setup.GetState(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, state)
}

// POST /api/setup/install-name
// Body: { "name": "rasputin-home" }
// Authenticated. Idempotent — operators can rename later from the wizard.
func (s *Server) handleSetupInstallName(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if err := s.setup.SetInstallName(r.Context(), req.Name); err != nil {
		if errors.Is(err, setup.ErrInstallNameEmpty) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	state, _ := s.setup.GetState(r.Context())
	writeJSON(w, http.StatusOK, state)
}

// POST /api/setup/mesh
// Body: none. Kicks off mesh.enroll_node for this api's self node.
// Authenticated. Refuses if RASPUTIN_SELF_NODE_ID isn't configured —
// without it we can't address the agent at all.
func (s *Server) handleSetupMesh(w http.ResponseWriter, r *http.Request) {
	selfID := s.setup.SelfNodeID()
	if selfID == "" {
		writeError(w, http.StatusPreconditionFailed,
			"RASPUTIN_SELF_NODE_ID is not configured on the api process; cannot enroll without it")
		return
	}
	spec, _ := json.Marshal(mesh.EnrollSpec{NodeID: selfID})
	j, err := s.runner.Submit(r.Context(), "mesh.enroll_node", spec, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// POST /api/setup/complete — marks the wizard finished. Returns 412 if a
// required step isn't satisfied.
func (s *Server) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	state, err := s.setup.GetState(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, st := range state.Steps {
		if st.Required && !st.Done {
			writeError(w, http.StatusPreconditionFailed,
				"required step not complete: "+st.Title)
			return
		}
	}
	if err := s.setup.MarkCompleted(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	state, _ = s.setup.GetState(r.Context())
	writeJSON(w, http.StatusOK, state)
}
