package api

import (
	"net/http"
	"os"

	"github.com/geekdojo/rasputin-control-plane/api/internal/alerts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Server bundles the HTTP handlers for the api.
type Server struct {
	store               *jobs.Store
	runner              *jobs.Runner
	inv                 *inventory.Store
	invSvc              *inventory.Service
	fw                  *firewall.Store
	apps                *apps.Store
	metrics             *metrics.Store
	updater             *updater.Store
	updaterVerifier     *updater.Verifier
	bundleDir           string
	trustDir            string
	mesh                *mesh.Service
	bmc                 *bmc.Service
	bmcSessions         *bmc.SessionManager
	setup               *setup.Service
	alerts              *alerts.Service
	alertsWebhookSecret string
	auth                *auth.Service
	obs                 *obs.Status
	nc                  *nats.Conn
	uiDir               string
}

// SetAlertsService overrides the default aggregator-only alerts service
// with one that has a persistence store + nats conn wired. main.go
// calls this when RASPUTIN_OBS_ENABLED=1 and the persisted store opens
// successfully.
func (s *Server) SetAlertsService(svc *alerts.Service) { s.alerts = svc }

// SetAlertsWebhookSecret turns on shared-secret auth for
// POST /api/alerts/webhook. Empty disables the check (dev mode).
func (s *Server) SetAlertsWebhookSecret(secret string) { s.alertsWebhookSecret = secret }

// NewServer constructs an api Server. The auth service is mandatory; if you
// want the api to run without auth (e.g. for early dev), pass a Service
// configured with an "allow-all" middleware in a future refactor — for v0
// auth is always on.
func NewServer(
	store *jobs.Store,
	runner *jobs.Runner,
	inv *inventory.Store,
	invSvc *inventory.Service,
	fw *firewall.Store,
	appsStore *apps.Store,
	mtr *metrics.Store,
	updaterStore *updater.Store,
	updaterVerifier *updater.Verifier,
	bundleDir string,
	trustDir string,
	meshSvc *mesh.Service,
	bmcSvc *bmc.Service,
	setupSvc *setup.Service,
	authSvc *auth.Service,
	obsStatus *obs.Status,
	nc *nats.Conn,
) *Server {
	if obsStatus == nil {
		// Always-non-nil so handler can call Snapshot without guarding.
		// A nil-input Status returns Enabled=false snapshots — exactly
		// the right "obs is off" semantics.
		obsStatus = obs.NewStatus(nil, nil, nil)
	}
	return &Server{
		store: store, runner: runner, inv: inv, invSvc: invSvc, fw: fw, apps: appsStore,
		metrics: mtr, updater: updaterStore, updaterVerifier: updaterVerifier,
		bundleDir: bundleDir, trustDir: trustDir, mesh: meshSvc,
		bmc: bmcSvc, bmcSessions: bmc.NewSessionManager(bmcSvc),
		setup: setupSvc,
		// alerts aggregates the subsystem stores AND, when an alerts
		// store + nats.Conn are wired, merges in vmalert-driven
		// persisted alerts via the webhook receiver. Dev wiring passes
		// nil for both; production passes them through main.go.
		alerts: alerts.New(inv, store, appsStore, setupSvc, nil, nc),
		auth:   authSvc, obs: obsStatus, nc: nc,
	}
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
	// GET /api/setup/state is intentionally unauthenticated — the wizard
	// runs before any passkey exists and needs to read step state to know
	// which form to show first. The response carries no secrets.
	mux.HandleFunc("GET /api/setup/state", s.handleSetupState)

	// Authenticated
	reqd := s.auth.RequireSessionFunc

	mux.HandleFunc("POST /api/jobs", reqd(s.handleCreateJob))
	mux.HandleFunc("GET /api/jobs", reqd(s.handleListJobs))
	mux.HandleFunc("GET /api/jobs/{id}", reqd(s.handleGetJob))
	mux.HandleFunc("GET /api/jobs/{id}/steps", reqd(s.handleListSteps))
	mux.HandleFunc("GET /api/jobs/{id}/events", reqd(s.handleListEvents))

	mux.HandleFunc("GET /api/nodes", reqd(s.handleListNodes))
	mux.HandleFunc("GET /api/nodes/{id}", reqd(s.handleGetNode))
	mux.HandleFunc("GET /api/nodes/{id}/removal-impact", reqd(s.handleGetNodeRemovalImpact))
	mux.HandleFunc("DELETE /api/nodes/{id}", reqd(s.handleDeleteNode))

	mux.HandleFunc("GET /api/metrics/{id}", reqd(s.handleGetMetrics))

	mux.HandleFunc("GET /api/firewall/intents", reqd(s.handleListIntents))
	mux.HandleFunc("POST /api/firewall/intents", reqd(s.handleCreateIntent))
	mux.HandleFunc("PATCH /api/firewall/intents/{id}", reqd(s.handleUpdateIntent))
	mux.HandleFunc("DELETE /api/firewall/intents/{id}", reqd(s.handleDeleteIntent))
	mux.HandleFunc("GET /api/firewall/state", reqd(s.handleGetFirewallState))
	mux.HandleFunc("POST /api/firewall/apply", reqd(s.handleApplyFirewall))
	mux.HandleFunc("POST /api/firewall/reconcile", reqd(s.handleReconcileFirewall))

	mux.HandleFunc("GET /api/apps", reqd(s.handleListApps))
	mux.HandleFunc("POST /api/apps", reqd(s.handleCreateApp))
	mux.HandleFunc("GET /api/apps/{id}", reqd(s.handleGetApp))
	mux.HandleFunc("DELETE /api/apps/{id}", reqd(s.handleDeleteApp))
	mux.HandleFunc("POST /api/apps/{id}/deploy", reqd(s.handleDeployApp))
	mux.HandleFunc("POST /api/apps/{id}/stop", reqd(s.handleStopApp))

	// Bundle bytes are content-addressed: the SHA-256 in the path is the
	// capability. Agents have no session cookie in v0; the tailnet is
	// the network boundary. List / upload / delete still require auth
	// because they read or mutate the bundle catalog. (v1 adds per-node
	// mTLS so the agent can authenticate; see updates.md.)
	mux.HandleFunc("GET /api/bundles", reqd(s.handleListBundles))
	mux.HandleFunc("POST /api/bundles", reqd(s.handleUploadBundle))
	mux.HandleFunc("GET /api/bundles/{sha}", s.handleGetBundle) // unauthenticated
	mux.HandleFunc("DELETE /api/bundles/{sha}", reqd(s.handleDeleteBundle))
	mux.HandleFunc("POST /api/updates", reqd(s.handleCreateUpdate))
	mux.HandleFunc("POST /api/updates/system", reqd(s.handleCreateSystemUpdate))
	mux.HandleFunc("GET /api/updates", reqd(s.handleListUpdates))

	mux.HandleFunc("GET /api/mesh/state", reqd(s.handleMeshState))
	mux.HandleFunc("GET /api/mesh/devices", reqd(s.handleListMeshDevices))
	mux.HandleFunc("DELETE /api/mesh/devices/{hsId}", reqd(s.handleDeleteMeshDevice))
	mux.HandleFunc("GET /api/mesh/keys", reqd(s.handleListMeshKeys))
	mux.HandleFunc("POST /api/mesh/keys", reqd(s.handleCreateMeshKey))
	mux.HandleFunc("PATCH /api/mesh/keys/{id}", reqd(s.handleUpdateMeshKey))
	mux.HandleFunc("DELETE /api/mesh/keys/{id}", reqd(s.handleDeleteMeshKey))
	mux.HandleFunc("GET /api/mesh/routes", reqd(s.handleListMeshRoutes))
	mux.HandleFunc("POST /api/mesh/routes", reqd(s.handleCreateMeshRoute))
	mux.HandleFunc("PATCH /api/mesh/routes/{id}", reqd(s.handleUpdateMeshRoute))
	mux.HandleFunc("DELETE /api/mesh/routes/{id}", reqd(s.handleDeleteMeshRoute))
	mux.HandleFunc("POST /api/mesh/apply", reqd(s.handleMeshApply))
	mux.HandleFunc("POST /api/mesh/reconcile", reqd(s.handleMeshReconcile))
	mux.HandleFunc("POST /api/mesh/enroll/{nodeId}", reqd(s.handleMeshEnrollNode))
	mux.HandleFunc("GET /api/mesh/enroll-defaults/{nodeId}", reqd(s.handleMeshEnrollDefaults))
	mux.HandleFunc("GET /api/mesh/ios-profile", reqd(s.handleMeshIOSProfile))

	mux.HandleFunc("POST /api/setup/install-name", reqd(s.handleSetupInstallName))
	mux.HandleFunc("POST /api/setup/mesh", reqd(s.handleSetupMesh))
	mux.HandleFunc("POST /api/setup/complete", reqd(s.handleSetupComplete))

	mux.HandleFunc("GET /api/bmc", reqd(s.handleListBMCStates))
	mux.HandleFunc("GET /api/bmc/{nodeId}/status", reqd(s.handleBMCStatus))
	mux.HandleFunc("POST /api/bmc/{nodeId}/power/{verb}", reqd(s.handleBMCPower))
	mux.HandleFunc("GET /ws/bmc/{nodeId}/sol", reqd(s.handleBMCSOL))

	mux.HandleFunc("GET /api/alerts", reqd(s.handleListAlerts))
	mux.HandleFunc("POST /api/alerts/{id}/ack", reqd(s.handleAlertAck))
	mux.HandleFunc("POST /api/alerts/{id}/dismiss", reqd(s.handleAlertDismiss))
	// Webhook is intentionally NOT behind reqd — vmalert can't carry a
	// session cookie. Auth is the optional shared secret in
	// X-Webhook-Secret (RASPUTIN_ALERTS_WEBHOOK_SECRET).
	mux.HandleFunc("POST /api/alerts/webhook", s.handleAlertWebhook)

	mux.HandleFunc("GET /api/obs/status", reqd(s.handleObsStatus))
	mux.HandleFunc("GET /api/obs/logs", reqd(s.handleObsLogs))
	mux.HandleFunc("GET /api/obs/series", reqd(s.handleObsSeries))
	mux.HandleFunc("GET /api/obs/containers", reqd(s.handleObsContainers))

	// /observability/* is the auth-proxy in front of Grafana. The
	// trailing slash matters — Go's ServeMux uses it as the prefix
	// match marker. Method-less because Grafana speaks GET/POST/PUT
	// (panel saves) and we forward all of them.
	mux.Handle("/observability/", s.auth.RequireSession(http.HandlerFunc(s.handleObservabilityProxy)))

	mux.HandleFunc("GET /ws/jobs", reqd(s.bridgeSubject(proto.AllJobsFilter)))
	mux.HandleFunc("GET /ws/inventory", reqd(s.bridgeSubject(proto.AllInventoryFilter)))
	mux.HandleFunc("GET /ws/firewall", reqd(s.bridgeSubject(proto.AllFirewallChangesFilter)))
	mux.HandleFunc("GET /ws/apps", reqd(s.bridgeSubject(proto.AllAppsFilter)))
	mux.HandleFunc("GET /ws/updates", reqd(s.bridgeSubject(proto.AllUpdatesFilter)))
	mux.HandleFunc("GET /ws/updates/system", reqd(s.bridgeSubject(proto.AllSystemUpdatesFilter)))
	mux.HandleFunc("GET /ws/mesh", reqd(s.bridgeSubject(proto.AllMeshChangesFilter)))
	mux.HandleFunc("GET /ws/bmc", reqd(s.bridgeSubject(proto.AllBMCChangesFilter)))
	mux.HandleFunc("GET /ws/alerts", reqd(s.bridgeSubject(proto.AlertsChangesSubject)))

	// Web UI: the mux fallback. "/" is the least-specific pattern, so every
	// /api, /ws, /healthz and /observability route above wins; only paths
	// nothing else claims reach the static export. Method-less on purpose:
	// "GET /" would *conflict* with the method-less "/observability/"
	// prefix route (Go 1.22 ServeMux rules) — the handler enforces
	// GET/HEAD itself. See SetUIDir.
	if s.uiDir != "" {
		mux.Handle("/", uiHandler{fsys: os.DirFS(s.uiDir)})
	}

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
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}
