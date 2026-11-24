package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/jobs
// Body: { "kind": "diag.ping", "spec": { "nodeId": "node-dev" } }
func (s *Server) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind string          `json:"kind"`
		Spec json.RawMessage `json:"spec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Kind == "" {
		writeError(w, http.StatusBadRequest, "kind is required")
		return
	}
	// The job records the account that submitted it: a step acting on their
	// behalf (app.delete's store deletes) records them (#783, #1001).
	// The runner decides whether this person may start this kind: a kind
	// only the system starts, or one the kind table refuses them, is refused
	// before any job exists (#978, #1001).
	j, err := s.runner.SubmitOperatorSpec(r.Context(), req.Kind, req.Spec, submitter(r))
	if errors.Is(err, jobs.ErrSystemKind) {
		s.writeCodedError(w, r, http.StatusForbidden, codeJobSystemOnly,
			"This job runs only when the system starts it.", slog.String("kind", req.Kind))
		return
	}
	if err != nil {
		s.writeSubmitError(w, r, req.Kind, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, j)
}

// GET /api/jobs?limit=50&parentId=<id>
// parentId, if set, returns only the children of that job (ordered by
// created_at ascending). Without it, returns the most-recent N jobs of
// any kind.
func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	if parentID := r.URL.Query().Get("parentId"); parentID != "" {
		children, err := s.store.ListChildJobs(r.Context(), parentID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, children)
		return
	}
	limit := atoiOr(r.URL.Query().Get("limit"), 50)
	// `kind` was accepted-and-ignored until 2026-08-15: a caller filtering for
	// system.update got the newest job of ANY kind and no indication it had been
	// dropped, which reads as a confident answer to a question that was never
	// asked. A silently-ignored filter is worse than an unsupported one.
	if kind := r.URL.Query().Get("kind"); kind != "" {
		jobs, err := s.store.ListJobsByKind(r.Context(), kind, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, jobs)
		return
	}
	jobs, err := s.store.ListJobs(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, jobs)
}

// GET /api/jobs/{id}
func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	j, err := s.store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if j == nil {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	writeJSON(w, http.StatusOK, j)
}

// GET /api/jobs/{id}/steps
func (s *Server) handleListSteps(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	steps, err := s.store.ListSteps(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, steps)
}

// GET /api/jobs/{id}/events
func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	events, err := s.store.ListEvents(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// GET /api/nodes
func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.inv.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Status and mesh are one derivation (inventory.ApplyMesh): a node whose
	// heartbeat lapsed while its mesh device is online is off-bus, not
	// offline, and the row carries the mesh block that says so.
	inventory.ApplyMesh(nodes, s.meshMembership(r.Context()))
	writeJSON(w, http.StatusOK, nodes)
}

// GET /api/nodes/{id}
func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := s.inv.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n == nil {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	inventory.ApplyMesh([]*proto.Node{n}, s.meshMembership(r.Context()))
	writeJSON(w, http.StatusOK, n)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// submitter is the request's person as a job's submitter, or the zero
// Submitter, which the runner refuses, when the request carries no person.
// Every job a request submits for its person passes exactly this
// (specargs_test.go pins it), so no handler picks its own submitter.
func submitter(r *http.Request) authz.Submitter {
	if p, ok := auth.PrincipalFrom(r.Context()); ok {
		return p.Submitter()
	}
	return authz.Submitter{}
}

// subOf is the request's person's account id, for a record or log line of
// who asked, or "" when the request carries no person. Never the name.
func subOf(r *http.Request) string {
	if p, ok := auth.PrincipalFrom(r.Context()); ok {
		return p.Sub
	}
	return ""
}

// writeSubmitError answers a refused job submit for kind: the kind table's
// answer when refusedSubmit has one, else status with the error.
func (s *Server) writeSubmitError(w http.ResponseWriter, r *http.Request, kind string, status int, err error) {
	if s.refusedSubmit(w, r, kind, err) {
		return
	}
	writeError(w, status, err.Error())
}

// refusedSubmit answers err when the runner's authorization produced it, and
// reports whether it did. A *authz.KindRefusal is 403 with "job_" + its code
// and its sentence, under a WARN refusal record carrying the kind and never
// the spec, the target or the person. A check that could not finish
// (authz.ErrCheckFailed) or a runner that runs only the system's jobs
// (jobs.ErrNotSystem) is 500 job_check_failed, under one ERROR record.
func (s *Server) refusedSubmit(w http.ResponseWriter, r *http.Request, kind string, err error) bool {
	var kr *authz.KindRefusal
	switch {
	case errors.As(err, &kr):
		s.writeCodedError(w, r, http.StatusForbidden, "job_"+kr.Code, kr.Sentence, slog.String("kind", kind))
		return true
	case errors.Is(err, authz.ErrCheckFailed), errors.Is(err, jobs.ErrNotSystem):
		id := s.newCorrelationID()
		s.log.LogAttrs(r.Context(), slog.LevelError, "api: job check failed",
			slog.String("correlation_id", id), slog.String("route", r.Pattern),
			slog.String("kind", kind), slog.String("err", err.Error()))
		writeCodedBody(w, http.StatusInternalServerError, codeJobCheckFailed,
			"The job couldn't be checked, so it wasn't started.", id)
		return true
	}
	return false
}

func atoiOr(s string, def int) int {
	if s == "" {
		return def
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return def
		}
		n = n*10 + int(r-'0')
	}
	if n <= 0 {
		return def
	}
	return n
}
