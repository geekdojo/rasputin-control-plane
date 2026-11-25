package api

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/geekdojo/rasputin-control-plane/api/internal/accounts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/alerts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/authz"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/api/internal/breakglass"
	"github.com/geekdojo/rasputin-control-plane/api/internal/busauth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalog"
	"github.com/geekdojo/rasputin-control-plane/api/internal/catalogsync"
	"github.com/geekdojo/rasputin-control-plane/api/internal/console"
	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/api/internal/identity/move"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/obs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/storage"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/backupxfer"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Server bundles the HTTP handlers for the api.
type Server struct {
	// operatorSecrets serves GET/PUT /api/apps/{id}/secrets
	// (geekdojo/geekdojo-brain#604).
	operatorSecrets operatorSecretsService
	// nodeApps removes a removed node's apps and their secrets
	// (geekdojo/geekdojo-brain#783).
	nodeApps nodeAppRemover
	// bmcCSR signs a Super4C BMC's certificate request for POST
	// /api/bmc/csr (geekdojo/geekdojo-brain#1065).
	bmcCSR          bmcCSRSigner
	store           *jobs.Store
	runner          *jobs.Runner
	inv             *inventory.Store
	invSvc          *inventory.Service
	fw              *firewall.Store
	fwState         firewallState
	apps            *apps.Store
	catalog         *catalog.Catalog
	catalogStore    *catalogsync.Store
	catalogPoller   *catalogsync.Poller
	metrics         *metrics.Store
	updater         *updater.Store
	updaterVerifier *updater.Verifier
	backup          *storage.Store
	backupIngest    *backupxfer.Ingest
	// restore is the first-run restore surface (design/storage.md §4.5,
	// #291); nil keeps its routes at 503. restoreRestart is what a prepared
	// restore calls to have the process exit and come back on the restored
	// identity — main.go's shutdown, so the unit restarts it.
	restore        *storage.RestoreConfig
	restoreRestart func()
	// appRestore and restoreEgress are the app-volume restore surface
	// (design/storage.md §4.5 phase 2, #291); nil keeps their routes at 503.
	appRestore    *storage.RestoreAppConfig
	restoreEgress *storage.RestoreEgress
	bundleDir     string
	trustDir      string
	mesh          *mesh.Service
	// nodeTrust is the api's node trust bundle, for the devices view's
	// trust reading (SetNodeTrust); nil reads every node as current.
	nodeTrust   trustFingerprinter
	bmc         *bmc.Service
	bmcSessions *bmc.SessionManager
	setup       *setup.Service
	// console is the console root password store (#587). nil keeps its
	// routes at 503.
	console *console.Store
	alerts  *alerts.Service
	// backupStates is the per-app backup derivation the /api/apps rows carry
	// as `backup` (design/storage.md §4.4, #298); nil omits the field.
	backupStates *storage.BackupStates
	auth         *auth.Service
	// resetter decides an administrator's password reset
	// (geekdojo/geekdojo-brain#992); nil answers 503 identity_not_ready.
	resetter resetChecker
	// accountRequests decides every account change
	// (geekdojo/geekdojo-brain#994); nil answers 503 identity_not_ready.
	accountRequests AccountRequester
	// waiting counts the accounts waiting for access
	// (geekdojo/geekdojo-brain#990), set under keycloak only.
	waiting   WaitingCounter
	obs       *obs.Status
	busTokens *busauth.Store
	nc        *nats.Conn
	uiDir     string
	// releaseSource discovers the latest releases from the public channel
	// (Check for Updates). nil when not configured — the endpoints then
	// return 503. releaseChannel is the default channel ("stable" | "dev").
	releaseSource  releases.Source
	releaseChannel string
	// releaseDownloadBase is the asset host (https://github.com) used to resolve
	// the public flashable node image for GET /api/cluster/node-image (the
	// one-command flasher); overridable for tests. The OS source repo itself
	// comes from the releases registry (ADR-0002).
	releaseDownloadBase string
	// applyDNSForwarding reconciles the CP nameserver's AA-11 forwarding stub
	// from the persisted setting and returns the effective upstream. nil when the
	// nameserver isn't running (RASPUTIN_DNS=off). Wired by main after NewServer.
	applyDNSForwarding func(context.Context) (effectiveUpstream string, fellBack bool, err error)
	// hostLANInfo returns the control plane's LAN IP + MAC for the DHCP-reservation
	// guidance surfaced in the DNS-forwarding view (AA-11). nil until main wires it.
	hostLANInfo func() (ip string, mac string)
	// rotateAppLeaf re-mints an app's TLS leaf when its SANs drift, so a LAN
	// exposure change (#197) takes effect immediately instead of waiting for
	// the rotation sweep. nil when there is no controlplane CA (dev, or a cluster that
	// never enrolled) — the exposure flip still persists and still changes DNS;
	// only the proxy half waits.
	rotateAppLeaf apps.LeafRotator
	// composeStash holds custom composes submitted to PUT
	// /api/apps/{id}/compose until their app.edit job ends (#410).
	composeStash *apps.ComposeStash
	// selfNodeID is the node hosting this api. Read from the same env the saga's
	// SystemUpdateConfig is built from, so the plan preview excludes the
	// controlplane exactly as the real cascade does. Empty off-appliance.
	selfNodeID string
	// bus is the bus TLS state: the live pin, or which file failed and why
	// (geekdojo/geekdojo-brain#517). Never nil: NewServer refuses one.
	bus BusState
	// log is the injected structured logger the handlers this change wrote
	// log through (writeCodedError). Never nil.
	log *slog.Logger
	// newCorrelationID yields the id a coded error carries in its body and
	// its log entry. Never nil.
	newCorrelationID func() string
	// nodeGate is the node listener's admission gate, set by WireObsIngest.
	// It decides the caller's identity and admission at the handshake and
	// again on every request, from memory (obs_ingest_conns.go). nil means
	// the listener was never wired, and the handlers refuse everything:
	// fail closed.
	nodeGate *ingestConns
	// repair is the break-glass service (SetRepair,
	// geekdojo/geekdojo-brain#321); nil keeps the repair routes at 401 and
	// 503.
	repair repairService
}

// SetReleaseSource wires the update-channel source used by
// POST /api/updates/check and /api/updates/pull. channel is the default
// release channel. main.go calls this at startup.
func (s *Server) SetReleaseSource(src releases.Source, channel string) {
	s.releaseSource = src
	if channel != "" {
		s.releaseChannel = channel
	}
}

// SetReleaseDownloadBase wires the asset host used to resolve a new node's
// flashable image (GET /api/cluster/node-image); the OS source repo itself
// comes from the releases registry. main.go calls this at startup; tests point
// it at a fake asset server.
func (s *Server) SetReleaseDownloadBase(downloadBase string) {
	s.releaseDownloadBase = downloadBase
}

// SetAppLeafRotator wires the per-app TLS-leaf rotator so PATCH /api/apps/{id}
// can apply a LAN-exposure change to the proxy immediately. main.go calls this
// with the same closure the rotation workflow uses, so the two cannot drift.
func (s *Server) SetAppLeafRotator(rotate apps.LeafRotator) { s.rotateAppLeaf = rotate }

// SetComposeStash wires where PUT /api/apps/{id}/compose holds a submitted
// compose for its app.edit job. It must be the stash apps.EditWorkflow was
// registered with, or the job finds nothing to install. Unset, custom compose
// edits answer 503.
func (s *Server) SetComposeStash(stash *apps.ComposeStash) { s.composeStash = stash }

// SetBackupStore wires the backup_targets ledger (design/storage.md §4.8) so
// the /api/backup routes can read it. Wired by main after NewServer rather than
// as a twentieth constructor argument, the same way the alerts service and the
// release source are. Leaving it nil is a supported state: the target routes
// then answer 503, which is the honest answer for an api built without the
// store.
func (s *Server) SetBackupStore(st *storage.Store) { s.backup = st }

// SetBackupIngest mounts the backup transport's ingest endpoint — the SAME
// *Ingest the backup.run workflow mints credentials through, so a credential
// is verifiable by exactly the endpoint that receives it.
func (s *Server) SetBackupIngest(in *backupxfer.Ingest) { s.backupIngest = in }

// SetBackupStates wires the per-app backup derivation so every /api/apps row
// says where the app stands against its backup cadence. Wired by main beside
// the alerts service that reads the same derivation.
func (s *Server) SetBackupStates(b *storage.BackupStates) { s.backupStates = b }

// SetAlertsService overrides the default aggregator-only alerts service
// with one that has a persistence store + nats conn wired. main.go
// calls this when RASPUTIN_OBS_ENABLED=1 and the persisted store opens
// successfully.
func (s *Server) SetAlertsService(svc *alerts.Service) { s.alerts = svc }

// BMCSessions exposes the SoL session manager so main can wire the
// bmc.configure workflow to the same instance the WS handler uses.
func (s *Server) BMCSessions() *bmc.SessionManager { return s.bmcSessions }

// SetDNSForwardingApplier wires the AA-11 reconcile hook (main → nameserver),
// kept plain-typed so this package doesn't import nameserver.
func (s *Server) SetDNSForwardingApplier(fn func(context.Context) (string, bool, error)) {
	s.applyDNSForwarding = fn
}

// SetHostLANInfo wires the control plane's LAN IP + MAC provider (main →
// interface lookup), surfaced in the DNS-forwarding view for the reservation
// recommendation.
func (s *Server) SetHostLANInfo(fn func() (ip string, mac string)) {
	s.hostLANInfo = fn
}

// NewServer constructs an api Server. The auth service is mandatory; if you
// want the api to run without auth (e.g. for early dev), pass a Service
// configured with an "allow-all" middleware in a future refactor — for v0
// auth is always on.
//
// fwState, bus, operatorSecrets, nodeApps, bmcCSR, logger and newCorrelationID are required,
// and NewServer returns an error rather than a Server that would fail on its
// first use: fwState is the firewall service the state route reads, bus is
// the bus TLS state (bustls.Available or bustls.Unavailable), operatorSecrets
// the business service behind the operator secret routes
// (geekdojo/geekdojo-brain#604), nodeApps what removes a removed node's apps
// and their secrets (geekdojo/geekdojo-brain#783), bmcCSR what signs a Super4C
// BMC's certificate request (geekdojo/geekdojo-brain#1065), logger the process logger, and
// newCorrelationID the source of the id a coded error carries.
func NewServer(
	store *jobs.Store,
	runner *jobs.Runner,
	inv *inventory.Store,
	invSvc *inventory.Service,
	fw *firewall.Store,
	fwState firewallState,
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
	busTokens *busauth.Store,
	nc *nats.Conn,
	bus BusState,
	operatorSecrets operatorSecretsService,
	nodeApps nodeAppRemover,
	bmcCSR bmcCSRSigner,
	logger *slog.Logger,
	newCorrelationID func() string,
) (*Server, error) {
	switch {
	case fwState == nil:
		return nil, errors.New("api: NewServer: a firewall state service is required")
	case bus == nil:
		return nil, errors.New("api: NewServer: a BusState is required")
	case operatorSecrets == nil:
		return nil, errors.New("api: NewServer: an operator secrets service is required")
	case nodeApps == nil:
		return nil, errors.New("api: NewServer: a node app remover is required")
	case bmcCSR == nil:
		return nil, errors.New("api: NewServer: a BMC certificate request signer is required")
	case logger == nil:
		return nil, errors.New("api: NewServer: a logger is required")
	case newCorrelationID == nil:
		return nil, errors.New("api: NewServer: a correlation id generator is required")
	}
	if obsStatus == nil {
		// Always-non-nil so handler can call Snapshot without guarding.
		// A nil-input Status returns Enabled=false snapshots — exactly
		// the right "obs is off" semantics.
		obsStatus = obs.NewStatus(nil, nil, nil)
	}
	return &Server{
		store: store, runner: runner, inv: inv, invSvc: invSvc, fw: fw, fwState: fwState, apps: appsStore,
		// The catalog is embedded, read-only content — MustLoad panics on an
		// invalid tile (a build defect in our own content), the same contract
		// as template.Must. catalog_test.go gates this in CI.
		catalog: catalog.MustLoad(),
		metrics: mtr, updater: updaterStore, updaterVerifier: updaterVerifier,
		bundleDir: bundleDir, trustDir: trustDir, mesh: meshSvc,
		bmc: bmcSvc, bmcSessions: bmc.NewSessionManager(bmcSvc),
		setup: setupSvc,
		// alerts aggregates the subsystem stores AND, when an alerts
		// store + nats.Conn are wired, merges in the vmalert-driven
		// persisted alerts. Dev wiring passes nil for both; production
		// passes them through main.go.
		alerts: alerts.New(inv, store, appsStore, setupSvc, nil, nc, false),
		auth:   authSvc, obs: obsStatus, busTokens: busTokens, nc: nc,
		// Mirrors the saga's SystemUpdateConfig.SelfNodeID (main.go reads the
		// same env). Threading it as a 19th constructor arg would touch every
		// caller for a process-wide constant; reading it here keeps the one
		// source without disturbing the signature.
		selfNodeID: os.Getenv("RASPUTIN_SELF_NODE_ID"),
		bus:        bus, operatorSecrets: operatorSecrets, nodeApps: nodeApps, bmcCSR: bmcCSR, log: logger, newCorrelationID: newCorrelationID,
	}, nil
}

// Handler returns the root http.Handler with all routes wired.
//
// Route protection:
//   - /healthz, /api/auth/*, GET /api/setup/state and the CA-download
//     endpoints (GET /mesh-ca.pem, GET /mesh-ca.crt, GET /api/mesh/ios-profile)
//     are open.
//   - everything else requires a valid session cookie.
//   - WebSocket endpoints (/ws/*) receive the cookie on upgrade and are
//     gated by the same middleware.
//
// Origin policy: one allowlist, s.auth.Origins() (the WebAuthn RP origins),
// decides CORS (withCORS), cross-origin protection for unsafe methods
// (http.CrossOriginProtection), the WebSocket upgrade (wsAcceptOptions) and
// the Origin check in auth.RequireSession.
//
// Every response also carries the security headers (securityHeaders): the
// outermost wrapper, so a CORS preflight, a refusal or a 401 gets them too.
func (s *Server) Handler() http.Handler {
	origins := s.auth.Origins()
	return securityHeaders(withCORS(origins, crossOriginProtection(origins, s.routes())))
}

// routes registers every route Handler serves on a recording mux. It is split
// from Handler so the route-enumeration auth test can read the patterns off
// the same mux the server routes with — there is no second list to keep in
// sync.
func (s *Server) routes() *routeMux {
	mux := newRouteMux()

	// Open
	mux.HandleFunc("GET /healthz", s.handleHealth)
	// The sign-in routes: each is an open route or a pinned sign-in session
	// route (routes_matrix_test.go, signinSessionRoutes).
	s.auth.RegisterRoutes(signinRegistrar{mux})
	// GET /api/setup/state is intentionally unauthenticated — the wizard
	// runs before any passkey exists and needs to read step state to know
	// which form to show first. The response carries no secrets.
	mux.HandleFunc("GET /api/setup/state", s.handleSetupState)
	// CA-download endpoints are intentionally unauthenticated: the controlplane CA
	// public cert is not a secret, and first-run has no users yet — the
	// operator must be able to install the CA before the first passkey
	// ceremony can happen over HTTPS. See the handlers' comments.
	mux.HandleFunc("GET /api/mesh/ios-profile", s.handleMeshIOSProfile)
	mux.HandleFunc("GET /mesh-ca.pem", s.handleMeshCAPEM)
	// Same bytes, Windows-installable envelope — see handleMeshCACRT.
	mux.HandleFunc("GET /mesh-ca.crt", s.handleMeshCACRT)
	// The one-command node flasher runs on a laptop (no session) and is
	// secret-free; these endpoints are intentionally open. flash.sh is a static
	// script; the *-image endpoints return only the public image URL + checksum
	// (node-image = the cluster's OS image; firewall-image = the latest firewall
	// image, which enrolls over SSH rather than via flash.sh).
	mux.HandleFunc("GET /flash.sh", s.handleGetFlashScript)
	mux.HandleFunc("GET /api/cluster/node-image", s.handleClusterNodeImage)
	mux.HandleFunc("GET /api/cluster/firewall-image", s.handleClusterFirewallImage)
	// Restore-before-first-boot (design/storage.md §4.5, #291) is open by
	// necessity — a re-flashed controlplane has no users to authenticate —
	// and gated by the fact that defines first-run: both routes answer 409
	// the moment an operator exists. See restore_handlers.go.
	mux.HandleFunc("GET /api/restore/candidates", s.handleListRestoreCandidates)
	mux.HandleFunc("POST /api/restore", s.handleRestore)
	// Break-glass (geekdojo/geekdojo-brain#321; repair_handlers.go): the
	// repair code is the authentication of its redemption, and the ways to
	// make one carry no secret. Both are open by necessity: sign-in is what
	// is broken.
	mux.HandleFunc("POST /api/auth/break-glass", s.handleBreakGlass)
	mux.HandleFunc("GET /api/repair/ways", s.handleRepairWays)

	// Authenticated. Every session route is registered through gate with its
	// class (routeclass.go, geekdojo/geekdojo-brain#1002): view, control
	// under a capability, self, or the floor of the Job kinds it submits.
	// The router refuses a person who lacks it before the handler runs, and
	// routes_matrix_test.go holds the table every class here is checked
	// against.
	gate := func(pattern string, rule routeRule, h http.HandlerFunc) { s.gate(mux, pattern, rule, h) }

	// The break-glass repair session's routes (geekdojo/geekdojo-brain#321):
	// its own session, and what it may do. Every route below them refuses
	// it.
	gate("GET /api/repair/state", repairNeeds(), s.handleRepairState)
	gate("POST /api/repair/end", repairNeeds(), s.handleRepairEnd)
	gate("POST /api/repair/restart", repairJob(breakglass.RestartKind), s.handleRepairRestart)
	gate("POST /api/repair/reset", repairJob(accounts.RepairResetKind), s.handleRepairReset)
	gate("POST /api/repair/move", repairJob(move.Kind), s.handleRepairMove)

	gate("POST /api/jobs", anyJob(), s.handleCreateJob)
	gate("POST /api/accounts/{id}/reset-password", needs(authz.NeedControl(authz.IAM)), s.handleResetPassword)
	// A person adds a sign-in method to their own account (#1150).
	gate("POST /api/me/sign-in-methods", needs(authz.NeedSelf()), s.handleAddSignInMethod)
	// Every account change (#994): the request names its kind, so the
	// router checks Self and the runner decides the kind.
	gate("POST /api/accounts/jobs", anyJob(), s.handleAccountJob)
	gate("GET /api/accounts/waiting", needs(authz.AccountsRead()), s.handleWaiting)
	gate("GET /api/jobs", needs(authz.NeedView()), s.handleListJobs)
	gate("GET /api/jobs/{id}", needs(authz.NeedView()), s.handleGetJob)
	gate("GET /api/jobs/{id}/steps", needs(authz.NeedView()), s.handleListSteps)
	gate("GET /api/jobs/{id}/events", needs(authz.NeedView()), s.handleListEvents)

	gate("GET /api/nodes", needs(authz.NeedView()), s.handleListNodes)
	gate("GET /api/nodes/{id}", needs(authz.NeedView()), s.handleGetNode)
	gate("GET /api/nodes/{id}/removal-impact", needs(authz.NeedView()), s.handleGetNodeRemovalImpact)
	gate("DELETE /api/nodes/{id}", needs(authz.NeedControl(authz.Nodes)), s.handleDeleteNode)

	gate("GET /api/metrics/{id}", needs(authz.NeedView()), s.handleGetMetrics)

	gate("GET /api/firewall/intents", needs(authz.NeedView()), s.handleListIntents)
	gate("POST /api/firewall/intents", needs(authz.NeedControl(authz.Firewall)), s.handleCreateIntent)
	gate("PATCH /api/firewall/intents/{id}", needs(authz.NeedControl(authz.Firewall)), s.handleUpdateIntent)
	gate("DELETE /api/firewall/intents/{id}", needs(authz.NeedControl(authz.Firewall)), s.handleDeleteIntent)
	gate("GET /api/firewall/state", needs(authz.NeedView()), s.handleGetFirewallState)
	gate("POST /api/firewall/apply", job("firewall.apply"), s.handleApplyFirewall)
	gate("POST /api/firewall/reconcile", job("firewall.reconcile"), s.handleReconcileFirewall)

	gate("GET /api/apps", needs(authz.NeedView()), s.handleListApps)
	gate("POST /api/apps", needs(authz.NeedControl(authz.AppsHost)), s.handleCreateApp)
	gate("GET /api/apps/{id}", needs(authz.NeedView()), s.handleGetApp)
	gate("PATCH /api/apps/{id}", needs(authz.NeedControl(authz.Apps)), s.handleUpdateApp)
	gate("DELETE /api/apps/{id}", job("app.delete"), s.handleDeleteApp)
	gate("POST /api/apps/{id}/deploy", job("app.deploy"), s.handleDeployApp)
	gate("POST /api/apps/{id}/stop", job("app.stop"), s.handleStopApp)
	// The app's compose, as a resource: upgrade, custom edit and re-apply by
	// hash (geekdojo/geekdojo-brain#410). It replaced POST .../upgrade and
	// POST .../revert, which no release ever carried.
	gate("PUT /api/apps/{id}/compose", job("app.upgrade", "app.edit", "app.revert"), s.handlePutAppCompose)
	// geekdojo/geekdojo-brain#399: the uninstall prompt's facts, and the path
	// for volumes earlier uninstalls left behind.
	gate("GET /api/apps/{id}/volumes", needs(authz.NeedView()), s.handleAppVolumes)
	// geekdojo/geekdojo-brain#291 phase 2: restore one app's data from a
	// backup generation. Explicit, per app, operator-initiated.
	gate("GET /api/apps/{id}/restore-sources", needs(authz.NeedView()), s.handleAppRestoreSources)
	gate("POST /api/apps/{id}/restore", job(storage.RestoreAppJobKind), s.handleAppRestore)
	// geekdojo/geekdojo-brain#604: the app's owner-supplied secrets,
	// write-only. GET reports which are set; PUT sets one.
	gate("GET /api/apps/{id}/secrets", needs(authz.NeedView()), s.handleListOperatorSecrets)
	gate("PUT /api/apps/{id}/secrets/{name}", needs(authz.NeedControl(authz.Secrets)), s.handlePutOperatorSecret)
	gate("GET /api/volumes/orphans", needs(authz.NeedView()), s.handleListOrphanVolumes)
	gate("POST /api/volumes/orphans/reclaim", needs(authz.NeedControl(authz.Apps)), s.handleReclaimOrphanVolumes)
	gate("GET /api/catalog", needs(authz.NeedView()), s.handleListCatalog)
	// Registered BEFORE the {id} route for readability; Go's mux prefers the
	// more specific pattern regardless, and "_status" cannot be a tile id.
	gate("GET /api/catalog/_status", needs(authz.NeedView()), s.handleCatalogStatus)
	gate("POST /api/catalog/_refresh", needs(authz.NeedControl(authz.Apps)), s.handleCatalogRefresh)
	gate("GET /api/catalog/{id}", needs(authz.NeedView()), s.handleGetCatalogTile)
	gate("POST /api/catalog/{id}/install", needs(authz.NeedControl(authz.Apps)), s.handleInstallCatalogTile)

	// Bundle bytes are content-addressed: the SHA-256 in the path is the
	// capability. Agents have no session cookie in v0; the tailnet is
	// the network boundary. List / upload / delete still require auth
	// because they read or mutate the bundle catalog. (v1 adds per-node
	// mTLS so the agent can authenticate; see updates.md.)
	gate("GET /api/bundles", needs(authz.NeedView()), s.handleListBundles)
	gate("POST /api/bundles", needs(authz.NeedControl(authz.Updates)), s.handleUploadBundle)
	mux.HandleFunc("GET /api/bundles/{sha}", s.handleGetBundle)        // unauthenticated
	mux.HandleFunc("GET /api/bundles/{sha}/sig", s.handleGetBundleSig) // unauthenticated
	gate("DELETE /api/bundles/{sha}", needs(authz.NeedControl(authz.Updates)), s.handleDeleteBundle)
	gate("POST /api/updates", job("node.update"), s.handleCreateUpdate)
	gate("POST /api/updates/system", job("system.update"), s.handleCreateSystemUpdate)
	gate("POST /api/updates/system/plan", needs(authz.NeedControl(authz.Updates)), s.handleSystemUpdatePlan)
	gate("GET /api/updates", needs(authz.NeedView()), s.handleListUpdates)
	gate("POST /api/updates/check", needs(authz.NeedControl(authz.Updates)), s.handleCheckUpdates)
	gate("POST /api/updates/pull", needs(authz.NeedControl(authz.Updates)), s.handlePullUpdate)

	// Backup targets (design/storage.md §4.8). GET candidates is a read-only
	// agent RPC the picker calls before any job exists; POST targets submits
	// the backup.target.claim saga, which is the only path that formats a disk.
	gate("GET /api/backup/candidates", needs(authz.NeedView()), s.handleListBackupCandidates)
	gate("GET /api/backup/targets", needs(authz.NeedView()), s.handleListBackupTargets)
	gate("POST /api/backup/targets", job(storage.ClaimJobKind), s.handleClaimBackupTarget)

	// Backup RUNS (design/storage.md §4.1). GET runs is the ledger, failures
	// included — §4.4 wants a failed backup visible, not absent. POST runs is
	// the on-demand "Back up now", which submits the same saga with the same
	// refusals as the weekly schedule. The schedule routes are §4.1's
	// "overridable per installation".
	// The backup INGEST and restore EGRESS endpoints are not on this
	// listener: a node moves members only on the node listener, by its
	// registered agent key (obsIngestRoutes).
	gate("GET /api/backup/runs", needs(authz.NeedView()), s.handleListBackupRuns)
	gate("POST /api/backup/runs", job(storage.RunJobKind), s.handleStartBackupRun)
	gate("GET /api/backup/restores", needs(authz.NeedView()), s.handleListRestores)
	gate("GET /api/backup/schedule", needs(authz.NeedView()), s.handleGetBackupSchedule)
	gate("PUT /api/backup/schedule", needs(authz.NeedControl(authz.System)), s.handleSetBackupSchedule)

	gate("GET /api/mesh/state", needs(authz.NeedView()), s.handleMeshState)
	gate("GET /api/mesh/devices", needs(authz.NeedView()), s.handleListMeshDevices)
	gate("DELETE /api/mesh/devices/{hsId}", needs(authz.NeedControl(authz.Mesh)), s.handleDeleteMeshDevice)
	gate("GET /api/mesh/keys", needs(authz.NeedControl(authz.Mesh)), s.handleListMeshKeys)
	gate("POST /api/mesh/keys", needs(authz.NeedControl(authz.Mesh)), s.handleCreateMeshKey)
	gate("PATCH /api/mesh/keys/{id}", needs(authz.NeedControl(authz.Mesh)), s.handleUpdateMeshKey)
	gate("DELETE /api/mesh/keys/{id}", needs(authz.NeedControl(authz.Mesh)), s.handleDeleteMeshKey)
	gate("GET /api/mesh/routes", needs(authz.NeedView()), s.handleListMeshRoutes)
	gate("POST /api/mesh/routes", needs(authz.NeedControl(authz.Mesh)), s.handleCreateMeshRoute)
	gate("PATCH /api/mesh/routes/{id}", needs(authz.NeedControl(authz.Mesh)), s.handleUpdateMeshRoute)
	gate("DELETE /api/mesh/routes/{id}", needs(authz.NeedControl(authz.Mesh)), s.handleDeleteMeshRoute)
	gate("POST /api/mesh/apply", job("mesh.apply"), s.handleMeshApply)
	gate("POST /api/mesh/reconcile", job("mesh.reconcile"), s.handleMeshReconcile)
	gate("POST /api/mesh/enroll/{nodeId}", job("mesh.enroll_node"), s.handleMeshEnrollNode)
	gate("GET /api/mesh/enroll-defaults/{nodeId}", needs(authz.NeedView()), s.handleMeshEnrollDefaults)

	// Bus join tokens — the per-node credential agents present to the
	// auth-callout. Authed (an operator mints/revokes them).
	gate("GET /api/bus/tokens", needs(authz.NeedView()), s.handleListBusTokens)
	gate("POST /api/bus/tokens", needs(authz.NeedControl(authz.Nodes)), s.handleMintBusToken)
	gate("DELETE /api/bus/tokens/{id}", needs(authz.NeedControl(authz.Nodes)), s.handleRevokeBusToken)
	// Bus TLS: read-only status of the automatic mode ladder and the pin (#448).
	gate("GET /api/bus/tls", needs(authz.NeedView()), s.handleGetBusTLS)

	gate("POST /api/setup/install-name", needs(authz.NeedControl(authz.System)), s.handleSetupInstallName)
	gate("POST /api/setup/mode", needs(authz.NeedControl(authz.Firewall)), s.handleSetupMode)
	gate("POST /api/setup/mesh", job("mesh.enroll_node"), s.handleSetupMesh)
	gate("POST /api/setup/complete", needs(authz.NeedControl(authz.System)), s.handleSetupComplete)

	gate("GET /api/settings/dns-forwarding", needs(authz.NeedView()), s.handleGetDNSForwarding)
	gate("POST /api/settings/dns-forwarding", needs(authz.NeedControl(authz.System)), s.handleSetDNSForwarding)

	// Operator SSH key — the one key the Add-node wizard prefills (public-key
	// material; authed because it's operator configuration).
	gate("GET /api/enroll/operator-key", needs(authz.NeedView()), s.handleGetOperatorKey)
	gate("PUT /api/enroll/operator-key", needs(authz.NeedControl(authz.Nodes)), s.handlePutOperatorKey)

	// Console root password (#587): chosen in the first-run wizard, changed
	// from Settings, applied to every node by console.root_push. Authed —
	// the wizard registers the operator's passkey before this step. The GET
	// never returns the hash; see console_handlers.go.
	gate("GET /api/console/root-password", needs(authz.NeedView()), s.handleGetConsoleRootPassword)
	gate("PUT /api/console/root-password", needs(authz.NeedControl(authz.Nodes)), s.handlePutConsoleRootPassword)
	gate("POST /api/console/root-password/push", job(console.PushKind), s.handlePushConsoleRootPassword)

	gate("GET /api/bmc", needs(authz.NeedView()), s.handleListBMCStates)
	gate("GET /api/bmc/backends", needs(authz.NeedView()), s.handleBMCBackends)
	gate("GET /api/bmc/config", needs(authz.NeedView()), s.handleBMCGetConfig)
	gate("POST /api/bmc/config", needs(authz.NeedControl(authz.BMC)), s.handleBMCSetConfig)
	gate("POST /api/bmc/probe", needs(authz.NeedControl(authz.BMC)), s.handleBMCProbe)
	gate("POST /api/bmc/csr", needs(authz.NeedControl(authz.BMC)), s.handleBMCSignCSR)
	gate("GET /api/bmc/{nodeId}/status", needs(authz.NeedView()), s.handleBMCStatus)
	gate("POST /api/bmc/{nodeId}/power/{verb}", job("bmc.power"), s.handleBMCPower)
	gate("GET /ws/bmc/{nodeId}/sol", needs(authz.NeedControl(authz.BMC)), s.handleBMCSOL)

	gate("GET /api/alerts", needs(authz.NeedView()), s.handleListAlerts)
	gate("POST /api/alerts/{id}/ack", needs(authz.NeedControl(authz.System)), s.handleAlertAck)
	gate("POST /api/alerts/{id}/dismiss", needs(authz.NeedControl(authz.System)), s.handleAlertDismiss)

	gate("GET /api/obs/status", needs(authz.NeedView()), s.handleObsStatus)
	gate("GET /api/obs/logs", needs(authz.NeedView()), s.handleObsLogs)
	gate("GET /api/obs/series", needs(authz.NeedView()), s.handleObsSeries)
	gate("GET /api/obs/containers", needs(authz.NeedView()), s.handleObsContainers)
	// The write half of the obs surface. Both are async (they return a
	// job) — a cold enable pulls ~500 MB. See obs/jobs.go.
	gate("POST /api/obs/enable", job("obs.enable"), s.handleObsEnable)
	gate("POST /api/obs/disable", job("obs.disable"), s.handleObsDisable)

	// /observability/* is the auth-proxy in front of Grafana. The
	// trailing slash matters — Go's ServeMux uses it as the prefix
	// match marker. Method-less because Grafana speaks GET/POST/PUT
	// (panel saves) and we forward all of them.
	// sameOriginFraming is the one relaxation of the frame-ancestors 'none'
	// every other response carries; see its comment.
	gate("/observability/", needs(authz.NeedView()), sameOriginFraming(http.HandlerFunc(s.handleObservabilityProxy)).ServeHTTP)

	gate("GET /ws/jobs", needs(authz.NeedView()), s.bridgeSubject(proto.AllJobsFilter))
	gate("GET /ws/inventory", needs(authz.NeedView()), s.bridgeSubject(proto.AllInventoryFilter))
	gate("GET /ws/firewall", needs(authz.NeedView()), s.bridgeSubject(proto.AllFirewallChangesFilter))
	gate("GET /ws/apps", needs(authz.NeedView()), s.bridgeSubject(proto.AllAppsFilter))
	gate("GET /ws/updates", needs(authz.NeedView()), s.bridgeSubject(proto.AllUpdatesFilter))
	gate("GET /ws/updates/system", needs(authz.NeedView()), s.bridgeSubject(proto.AllSystemUpdatesFilter))
	gate("GET /ws/mesh", needs(authz.NeedView()), s.bridgeSubject(proto.AllMeshChangesFilter))
	gate("GET /ws/bmc", needs(authz.NeedView()), s.bridgeSubject(proto.AllBMCChangesFilter))
	gate("GET /ws/alerts", needs(authz.NeedView()), s.bridgeSubject(proto.AlertsChangesSubject))

	// Web UI: the mux fallback. "/" is the least-specific pattern, so every
	// /api, /ws, /healthz and /observability route above wins; only paths
	// nothing else claims reach the static export. Method-less on purpose:
	// "GET /" would *conflict* with the method-less "/observability/"
	// prefix route (Go 1.22 ServeMux rules) — the handler enforces
	// GET/HEAD itself. See SetUIDir.
	if s.uiDir != "" {
		mux.Handle("/", uiHandler{fsys: os.DirFS(s.uiDir)})
	}

	return mux
}

// withCORS answers CORS for the origins on the allowlist and for no others.
// On an appliance the allowlist is the cluster's own origin, so nothing is
// allowed cross-origin; a dev run's allowlist carries the Next dev server
// (:3000), which calls the api on :8080 with credentials. With cookies in
// play the allowed Origin is echoed explicitly (the wildcard "*" is
// incompatible with credentials).
//
// A preflight from an origin not on the list is refused outright; any other
// request from one is served without CORS headers, so the browser withholds
// the response from the calling page. What the request may change is decided
// further in: crossOriginProtection for unsafe methods, RequireSession for
// every gated route.
func withCORS(origins *auth.OriginAllowlist, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := origin != "" && origins.Allows(origin)
		if origin != "" {
			w.Header().Add("Vary", "Origin")
		}
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}
		if r.Method == http.MethodOptions {
			if origin != "" && !allowed {
				writeError(w, http.StatusForbidden, "origin not allowed")
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// crossOriginProtection refuses a cross-origin request with an unsafe method
// (anything but GET, HEAD and OPTIONS) unless it comes from an origin on the
// allowlist. It covers the routes RequireSession does not gate — the auth
// ceremonies, first-run restore — as well as the gated ones. Requests from
// non-browser clients carry neither Origin nor Sec-Fetch-Site and pass.
func crossOriginProtection(origins *auth.OriginAllowlist, h http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	for _, o := range origins.Origins() {
		// Normalized origins are exactly the scheme://host[:port] form this
		// takes, so an error here is a bug; the origin then stays untrusted,
		// which is the closed direction.
		if err := cop.AddTrustedOrigin(o); err != nil {
			log.Printf("api: cross-origin protection: trusted origin %q refused: %v", o, err)
		}
	}
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusForbidden, "cross-origin request refused")
	}))
	return cop.Handler(h)
}
