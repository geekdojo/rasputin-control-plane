// Package systemsubmitter is a fixture for specargs_test.go: a person-path
// handler that builds its own Submitter instead of passing submitter(r),
// and uses of the constructors no package may call.
package systemsubmitter

import (
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// Server holds the runner, as package api's does.
type Server struct{ runner *jobs.Runner }

// The fixture's submitter, never called, so the package type-checks the way
// package api does.
func submitter(*http.Request) authz.Submitter { return authz.Submitter{} }

var _ = submitter

// AsSystem passes the system to SubmitFor.
func (s *Server) AsSystem(r *http.Request) {
	_, _ = s.runner.SubmitFor(r.Context(), authz.SystemSubmitter("user"), "k", nil, nil)
}

// AsPerson builds a person itself.
func (s *Server) AsPerson(r *http.Request) {
	_, _ = s.runner.SubmitFor(r.Context(), authz.Person(authz.Subject{Sub: "x"}), "k", nil, nil)
}

// Constructors no package may build yet.
func Constructors() (authz.Submitter, authz.Submitter) {
	a := authz.RepairSession()
	b := authz.BridgeGrant("x")
	return a, b
}
