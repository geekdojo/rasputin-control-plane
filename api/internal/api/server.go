package api

import (
	"net/http"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Server bundles the HTTP handlers for the api.
type Server struct {
	store  *jobs.Store
	runner *jobs.Runner
	inv    *inventory.Store
	nc     *nats.Conn
}

// NewServer constructs an api Server.
func NewServer(store *jobs.Store, runner *jobs.Runner, inv *inventory.Store, nc *nats.Conn) *Server {
	return &Server{store: store, runner: runner, inv: inv, nc: nc}
}

// Handler returns the root http.Handler with all routes wired.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)

	mux.HandleFunc("POST /api/jobs", s.handleCreateJob)
	mux.HandleFunc("GET /api/jobs", s.handleListJobs)
	mux.HandleFunc("GET /api/jobs/{id}", s.handleGetJob)
	mux.HandleFunc("GET /api/jobs/{id}/steps", s.handleListSteps)
	mux.HandleFunc("GET /api/jobs/{id}/events", s.handleListEvents)

	mux.HandleFunc("GET /api/nodes", s.handleListNodes)
	mux.HandleFunc("GET /api/nodes/{id}", s.handleGetNode)

	mux.HandleFunc("GET /ws/jobs", s.bridgeSubject(proto.AllJobsFilter))
	mux.HandleFunc("GET /ws/inventory", s.bridgeSubject(proto.AllInventoryFilter))

	return withCORS(mux)
}

// withCORS is dev-only: allows the Next.js dev server on :3000 to talk to
// the api on :8080. Production reverse-proxies both behind one origin.
func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}
