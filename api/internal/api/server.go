package api

import (
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Server bundles the HTTP handlers for the api.
type Server struct {
	store   *jobs.Store
	runner  *jobs.Runner
	inv     *inventory.Store
	fw      *firewall.Store
	metrics *metrics.Store
	auth    *auth.Service
	nc      *nats.Conn
}

// NewServer constructs an api Server. The auth service is mandatory; if you
// want the api to run without auth (e.g. for early dev), pass a Service
// configured with an "allow-all" middleware in a future refactor — for v0
// auth is always on.
func NewServer(
	store *jobs.Store,
	runner *jobs.Runner,
	inv *inventory.Store,
	fw *firewall.Store,
	mtr *metrics.Store,
	authSvc *auth.Service,
	nc *nats.Conn,
) *Server {
	return &Server{store: store, runner: runner, inv: inv, fw: fw, metrics: mtr, auth: authSvc, nc: nc}
}

// Handler returns the root http.Handler with all routes wired.
//
// Route protection:
//   - /healthz and /api/auth/* are open.
//   - everything else requires a valid session cookie.
//   - WebSocket endpoints (/ws/*) receive the cookie on upgrade and are
//     gated by the same middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Open
	mux.HandleFunc("GET /healthz", s.handleHealth)
	s.auth.RegisterRoutes(mux)

	// Authenticated
	reqd := s.auth.RequireSessionFunc

	mux.HandleFunc("POST /api/jobs", reqd(s.handleCreateJob))
	mux.HandleFunc("GET /api/jobs", reqd(s.handleListJobs))
	mux.HandleFunc("GET /api/jobs/{id}", reqd(s.handleGetJob))
	mux.HandleFunc("GET /api/jobs/{id}/steps", reqd(s.handleListSteps))
	mux.HandleFunc("GET /api/jobs/{id}/events", reqd(s.handleListEvents))

	mux.HandleFunc("GET /api/nodes", reqd(s.handleListNodes))
	mux.HandleFunc("GET /api/nodes/{id}", reqd(s.handleGetNode))

	mux.HandleFunc("GET /api/metrics/{id}", reqd(s.handleGetMetrics))

	mux.HandleFunc("GET /api/firewall/intents", reqd(s.handleListIntents))
	mux.HandleFunc("POST /api/firewall/intents", reqd(s.handleCreateIntent))
	mux.HandleFunc("PATCH /api/firewall/intents/{id}", reqd(s.handleUpdateIntent))
	mux.HandleFunc("DELETE /api/firewall/intents/{id}", reqd(s.handleDeleteIntent))
	mux.HandleFunc("GET /api/firewall/state", reqd(s.handleGetFirewallState))
	mux.HandleFunc("POST /api/firewall/apply", reqd(s.handleApplyFirewall))
	mux.HandleFunc("POST /api/firewall/reconcile", reqd(s.handleReconcileFirewall))

	mux.HandleFunc("GET /ws/jobs", reqd(s.bridgeSubject(proto.AllJobsFilter)))
	mux.HandleFunc("GET /ws/inventory", reqd(s.bridgeSubject(proto.AllInventoryFilter)))
	mux.HandleFunc("GET /ws/firewall", reqd(s.bridgeSubject(proto.AllFirewallChangesFilter)))

	return withCORS(mux)
}

// withCORS is dev-only: allows the Next.js dev server on :3000 to talk to
// the api on :8080. With cookies in play we must echo the request Origin
// explicitly (the wildcard "*" is incompatible with credentials).
func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}
