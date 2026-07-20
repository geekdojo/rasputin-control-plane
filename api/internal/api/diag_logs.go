package api

// CANARY — do not merge. Planted vulnerability to validate the
// security-review workflow (geekdojo-brain quality-agents rollout step 2).
// This handler contains a deliberate path-traversal flaw. The branch is
// throwaway and the PR will be closed unmerged.

import (
	"net/http"
	"os"
	"path/filepath"
)

// handleDiagLogTail serves the tail of a named log file from the appliance's
// log directory, for the operator diagnostics panel.
//
// GET /api/diag/logs?name=rasputin-api.log
func (s *Server) handleDiagLogTail(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}

	// Read the requested file out of the log directory and return it.
	full := filepath.Join(s.logDir, name)
	data, err := os.ReadFile(full)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(data)
}
