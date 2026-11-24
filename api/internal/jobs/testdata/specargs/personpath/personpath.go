// Package personpath is a fixture for specargs_test.go: a person-path
// package whose handlers reach the runner's system path, beside one clean
// SubmitFor and one allowed system consequence.
package personpath

import (
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// Server holds the runner, as package api's does.
type Server struct{ runner *jobs.Runner }

func submitter(*http.Request) authz.Submitter { return authz.Submitter{} }

// Clean submits for the request's person.
func (s *Server) Clean(r *http.Request) {
	_, _ = s.runner.SubmitFor(r.Context(), submitter(r), "k", nil, nil)
}

// systemConsequence is the allowed system path.
func (s *Server) systemConsequence(r *http.Request) {
	_, _ = s.runner.Submit(r.Context(), "k", nil, "consequence")
}

// Handler is a person's request reaching the system path.
func (s *Server) Handler(r *http.Request) {
	_, _ = s.runner.Submit(r.Context(), "k", nil, "user")
}

// Prepared is a person's request reaching the system path with a prepare.
func (s *Server) Prepared(r *http.Request) {
	_, _ = s.runner.SubmitPrepared(r.Context(), "k", nil, "user", nil)
}
