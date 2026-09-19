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
type routeMux struct {
	*http.ServeMux
	patterns []string
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

// Patterns returns every pattern registered so far, in registration order.
func (m *routeMux) Patterns() []string {
	return append([]string(nil), m.patterns...)
}
