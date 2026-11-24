package api

import "net/http"

// routeMux is an http.ServeMux that remembers every pattern registered on it.
//
// It exists so tests can enumerate the routes a handler ACTUALLY serves —
// the route-enumeration auth test (routes_auth_test.go) requests every one of
// them without a session — instead of checking a hand-copied list that drifts
// the day someone adds a route. It changes nothing about routing: each call is
// forwarded to the embedded ServeMux unchanged, so the patterns it records are
// exactly the ones the mux matches on.
//
// It also records each session route's routeRule (HandleRule, through
// Server.gate) and each pattern the sign-in registrar gave it
// (signinRegistrar), so the route-class matrix (routes_matrix_test.go) reads
// the classes off the same mux the server routes with
// (geekdojo/geekdojo-brain#1002).
type routeMux struct {
	*http.ServeMux
	patterns []string
	rules    map[string]routeRule
	signin   map[string]bool
}

func newRouteMux() *routeMux { return &routeMux{ServeMux: http.NewServeMux()} }

// Handle registers handler for pattern and records the pattern.
func (m *routeMux) Handle(pattern string, handler http.Handler) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.Handle(pattern, handler)
}

// HandleFunc registers handler for pattern and records the pattern.
func (m *routeMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.HandleFunc(pattern, handler)
}

// HandleRule registers handler for pattern and records the pattern and its
// rule. Server.gate is its caller; handler already enforces rule.
func (m *routeMux) HandleRule(pattern string, rule routeRule, handler http.Handler) {
	if m.rules == nil {
		m.rules = map[string]routeRule{}
	}
	m.rules[pattern] = rule
	m.Handle(pattern, handler)
}

// Rule returns the rule recorded for pattern, and false when none was.
func (m *routeMux) Rule(pattern string) (routeRule, bool) {
	r, ok := m.rules[pattern]
	return r, ok
}

// SigninPatterns returns every pattern the sign-in registrar recorded.
func (m *routeMux) SigninPatterns() map[string]bool {
	out := make(map[string]bool, len(m.signin))
	for p := range m.signin {
		out[p] = true
	}
	return out
}

// Patterns returns every pattern registered so far, in registration order.
func (m *routeMux) Patterns() []string {
	return append([]string(nil), m.patterns...)
}

// signinRegistrar is the mux auth.RegisterRoutes registers on: it records
// each pattern as a sign-in pattern and registers it raw. Every sign-in
// pattern must be an open route or a pinned sign-in session route, so a route
// auth adds later is not exempt from the route classes
// (geekdojo/geekdojo-brain#1002, F-1002-01).
type signinRegistrar struct{ *routeMux }

// HandleFunc records pattern as a sign-in pattern and registers it.
func (r signinRegistrar) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	if r.signin == nil {
		r.signin = map[string]bool{}
	}
	r.signin[pattern] = true
	r.routeMux.HandleFunc(pattern, handler)
}
