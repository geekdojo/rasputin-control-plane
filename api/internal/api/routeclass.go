package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
)

// Route classes (geekdojo/geekdojo-brain#1002; identity-authz.md §3.2).
//
// Every session route is registered through gate with a routeRule: the value
// gate records is the value the router enforces, so there is no second list
// to drift from it. The router authenticates (RequireSession) and declares
// what the route needs; authz decides (Set.Permits, Set.PermitsKindRoute).
// No handler decides access.

// ruleKind is what a routeRule checks. The zero value is no rule and is
// refused.
type ruleKind int

const (
	ruleNone ruleKind = iota
	// ruleNeed checks a Requirement: view, control under a capability, or
	// self.
	ruleNeed
	// ruleJob checks the route floor of every kind the route submits.
	ruleJob
	// ruleAnyJob is POST /api/jobs: the request names its own kind, so the
	// router checks Self and the runner decides the kind.
	ruleAnyJob
)

// routeRule is what a session route needs before its handler runs.
type routeRule struct {
	kind  ruleKind
	need  authz.Requirement
	kinds []string
}

// needs is a view, control or self route.
func needs(r authz.Requirement) routeRule { return routeRule{kind: ruleNeed, need: r} }

// job is a route that submits jobs of kinds. Its floor is each kind's
// (authz.Set.PermitsKindRoute); the runner still decides each job.
func job(kinds ...string) routeRule { return routeRule{kind: ruleJob, kinds: kinds} }

// anyJob is POST /api/jobs, whose kind is the request's own: its floor is
// Self, and the runner decides the kind.
func anyJob() routeRule { return routeRule{kind: ruleAnyJob} }

// label is the rule as text, for the refusal record's need field and the
// route table test: view, control:<capability>, self, job:<k1>,<k2>, anyjob,
// or none.
func (r routeRule) label() string {
	switch r.kind {
	case ruleNeed:
		switch r.need.Class {
		case authz.ClassView:
			return "view"
		case authz.ClassControl:
			return "control:" + string(r.need.Capability)
		case authz.ClassSelf:
			return "self"
		}
	case ruleJob:
		return "job:" + strings.Join(r.kinds, ",")
	case ruleAnyJob:
		return "anyjob"
	}
	return "none"
}

// errRouteNotPermitted is a refusal that is not a Job kind's.
var errRouteNotPermitted = errors.New("api: route not permitted")

// check decides caps against r: nil, a *authz.KindRefusal for a Job route
// whose floor refuses, or errRouteNotPermitted. The zero rule and a Job rule
// with no kinds are refused (ERR-CLOSED).
func (r routeRule) check(caps authz.Set) error {
	switch r.kind {
	case ruleNeed:
		if caps.Permits(r.need) {
			return nil
		}
	case ruleJob:
		if len(r.kinds) == 0 {
			return errRouteNotPermitted
		}
		for _, k := range r.kinds {
			if err := caps.PermitsKindRoute(k); err != nil {
				return err
			}
		}
		return nil
	case ruleAnyJob:
		if caps.Permits(authz.NeedSelf()) {
			return nil
		}
	}
	return errRouteNotPermitted
}

// codeRouteNotPermittedMsg is the sentence a route refusal answers with.
const codeRouteNotPermittedMsg = "You don't have permission to do this."

// gate registers h at pattern behind the session and rule, and records rule
// on mux. It is the only way a session route is registered.
func (s *Server) gate(mux *routeMux, pattern string, rule routeRule, h http.Handler) {
	mux.HandleRule(pattern, rule, s.auth.RequireSession(s.authorize(rule, h)))
}

// authorize runs next only when the session's principal meets rule. A
// request with no principal holds nothing. A Job route's refusal answers as
// the runner would (refusedSubmit: 403 "job_" + code, the kind table's
// sentence); any other is 403 route_not_permitted. Either way one WARN
// refusal record is written under the correlation id, with the route pattern
// and never the path, the body or the person.
func (s *Server) authorize(rule routeRule, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var caps authz.Set
		if p, ok := auth.PrincipalFrom(r.Context()); ok {
			caps = p.Capabilities()
		}
		err := rule.check(caps)
		if err == nil {
			next.ServeHTTP(w, r)
			return
		}
		if s.refusedSubmit(w, r, strings.Join(rule.kinds, ","), err) {
			return
		}
		s.writeCodedError(w, r, http.StatusForbidden, codeRouteNotPermitted, codeRouteNotPermittedMsg,
			slog.String("need", rule.label()))
	})
}
