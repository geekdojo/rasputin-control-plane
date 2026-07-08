package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/oklog/ulid/v2"
)

// GET /api/apps
func (s *Server) handleListApps(w http.ResponseWriter, r *http.Request) {
	out, err := s.apps.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out == nil {
		out = []*apps.App{}
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/apps
// Body: { "name": "minecraft", "composeYaml": "...", "targetNode": "node-dev" }
func (s *Server) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		ComposeYAML string `json:"composeYaml"`
		TargetNode  string `json:"targetNode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.TargetNode = strings.TrimSpace(req.TargetNode)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if !validAppName(req.Name) {
		writeError(w, http.StatusBadRequest, "name must be 1-32 chars of [a-zA-Z0-9_-]")
		return
	}
	if strings.TrimSpace(req.ComposeYAML) == "" {
		writeError(w, http.StatusBadRequest, "composeYaml is required")
		return
	}
	if req.TargetNode == "" {
		writeError(w, http.StatusBadRequest, "targetNode is required")
		return
	}

	// Validate target node exists.
	node, err := s.inv.Get(r.Context(), req.TargetNode)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if node == nil {
		writeError(w, http.StatusBadRequest, "target node not registered")
		return
	}
	if node.Role != proto.RoleCompute && node.Role != proto.RoleControlPlane {
		writeError(w, http.StatusBadRequest,
			"target node role must be compute or controlplane")
		return
	}

	if existing, _ := s.apps.GetByName(r.Context(), req.Name); existing != nil {
		writeError(w, http.StatusConflict, "an app with that name already exists")
		return
	}

	now := time.Now().UTC()
	app := &apps.App{
		ID:          ulid.Make().String(),
		Name:        req.Name,
		ComposeYAML: req.ComposeYAML,
		TargetNode:  req.TargetNode,
		LastStatus:  proto.AppStatusStopped,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.apps.Create(r.Context(), app); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, app)
}

// GET /api/apps/{id}
func (s *Server) handleGetApp(w http.ResponseWriter, r *http.Request) {
	app, err := s.apps.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if app == nil {
		writeError(w, http.StatusNotFound, "app not found")
		return
	}
	writeJSON(w, http.StatusOK, app)
}

// DELETE /api/apps/{id}
// Runs the app.delete saga: stop the running deployment on the target node
// (docker compose down) THEN remove the api's record — so delete actually tears
// the containers down instead of orphaning them. Async, like deploy/stop:
// returns the job; the row disappears on the `deleted` change event once the
// stop completes. On a reachable node the stop must succeed or the delete fails
// (the record stays); on an unreachable node it removes the record with a
// logged warning.
func (s *Server) handleDeleteApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if existing, _ := s.apps.Get(r.Context(), id); existing == nil {
		writeError(w, http.StatusNotFound, "app not found")
		return
	}
	spec, _ := json.Marshal(apps.DeleteSpec{AppID: id})
	j, err := s.runner.Submit(r.Context(), "app.delete", spec, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// POST /api/apps/{id}/deploy
func (s *Server) handleDeployApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	spec, _ := json.Marshal(map[string]string{"appId": id})
	j, err := s.runner.Submit(r.Context(), "app.deploy", spec, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// POST /api/apps/{id}/stop
func (s *Server) handleStopApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	spec, _ := json.Marshal(map[string]string{"appId": id})
	j, err := s.runner.Submit(r.Context(), "app.stop", spec, creator(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

func validAppName(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}
