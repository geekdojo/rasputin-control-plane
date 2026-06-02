package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/auth"
	"github.com/geekdojo/rasputin-control-plane/api/internal/bmc"
	"github.com/geekdojo/rasputin-control-plane/api/internal/firewall"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/mesh"
	"github.com/geekdojo/rasputin-control-plane/api/internal/metrics"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/updater"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// ============================================================================
// Embedded NATS
// ============================================================================

func embeddedNATS(t *testing.T) *nats.Conn {
	t.Helper()
	opts := &server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true}
	ns, err := server.NewServer(opts)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(2 * time.Second) {
		t.Fatal("nats not ready")
	}
	t.Cleanup(func() {
		ns.Shutdown()
		ns.WaitForShutdown()
	})
	nc, err := nats.Connect("", nats.InProcessServer(ns))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { nc.Close() })
	return nc
}

// ============================================================================
// Fixture — builds a complete Server with file-backed stores
// ============================================================================

type apiFixture struct {
	ctx          context.Context
	dir          string
	srv          *Server
	handler      http.Handler
	authSvc      *auth.Service
	authStore    *auth.Store
	authSession  *auth.Session
	authUser     *auth.User
	jobsStore    *jobs.Store
	runner       *jobs.Runner
	inv          *inventory.Store
	fw           *firewall.Store
	appsStore    *apps.Store
	metricsStore *metrics.Store
	updStore     *updater.Store
	verifier     *updater.Verifier
	bundleDir    string
	mesh         *mesh.Service
	meshFake     *fakeMeshClient
	bmcSvc       *bmc.Service
	setupSvc     *setup.Service
	nc           *nats.Conn
	hasUsers     bool
}

// fakeMeshClient is a minimal in-memory mesh Client implementation just
// good enough for the API tests to exercise mesh-related handlers without
// going through the real Headscale REST layer.
type fakeMeshClient struct {
	users       map[string]bool
	keys        map[string]mesh.HSPreAuthKey
	nodes       map[string]mesh.HSNode
	createCalls int
	createErr   error
}

func newFakeMeshClient() *fakeMeshClient {
	return &fakeMeshClient{
		users: map[string]bool{},
		keys:  map[string]mesh.HSPreAuthKey{},
		nodes: map[string]mesh.HSNode{},
	}
}

func (f *fakeMeshClient) Backend() string                              { return "fake" }
func (f *fakeMeshClient) EnsureUser(_ context.Context, n string) error { f.users[n] = true; return nil }
func (f *fakeMeshClient) ExpirePreAuthKey(_ context.Context, _ string) error {
	return nil
}
func (f *fakeMeshClient) ListPreAuthKeys(_ context.Context, _ string) ([]mesh.HSPreAuthKey, error) {
	return nil, nil
}
func (f *fakeMeshClient) ListNodes(_ context.Context) ([]mesh.HSNode, error) {
	out := make([]mesh.HSNode, 0, len(f.nodes))
	for _, n := range f.nodes {
		out = append(out, n)
	}
	return out, nil
}
func (f *fakeMeshClient) SetNodeRoutes(_ context.Context, _ string, _ []string) error { return nil }
func (f *fakeMeshClient) DeleteNode(_ context.Context, nodeID string) error {
	delete(f.nodes, nodeID)
	return nil
}
func (f *fakeMeshClient) CreatePreAuthKey(_ context.Context, in mesh.CreatePreAuthKeyInput) (string, string, error) {
	f.createCalls++
	if f.createErr != nil {
		return "", "", f.createErr
	}
	return "hsid-" + in.User, "plain-" + in.User, nil
}

func newAPIFixture(t *testing.T) *apiFixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	nc := embeddedNATS(t)

	open := func(name string) string { return filepath.Join(dir, name) }

	invStore, err := inventory.OpenStore(ctx, open("inv.db"))
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	t.Cleanup(func() { _ = invStore.Close() })

	jobStore, err := jobs.OpenStore(ctx, open("jobs.db"))
	if err != nil {
		t.Fatalf("jobs: %v", err)
	}
	t.Cleanup(func() { _ = jobStore.Close() })

	appStore, err := apps.OpenStore(ctx, open("apps.db"))
	if err != nil {
		t.Fatalf("apps: %v", err)
	}
	t.Cleanup(func() { _ = appStore.Close() })

	fwStore, err := firewall.OpenStore(ctx, open("fw.db"))
	if err != nil {
		t.Fatalf("fw: %v", err)
	}
	t.Cleanup(func() { _ = fwStore.Close() })

	mtrStore, err := metrics.OpenStore(ctx, open("metrics.db"))
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	t.Cleanup(func() { _ = mtrStore.Close() })

	updStore, err := updater.OpenStore(ctx, open("updater.db"))
	if err != nil {
		t.Fatalf("updater: %v", err)
	}
	t.Cleanup(func() { _ = updStore.Close() })

	authStore, err := auth.OpenStore(ctx, open("auth.db"))
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	t.Cleanup(func() { _ = authStore.Close() })

	bmcStore, err := bmc.OpenStore(ctx, open("bmc.db"))
	if err != nil {
		t.Fatalf("bmc: %v", err)
	}
	t.Cleanup(func() { _ = bmcStore.Close() })

	meshStore, err := mesh.OpenStore(ctx, open("mesh.db"))
	if err != nil {
		t.Fatalf("mesh: %v", err)
	}
	t.Cleanup(func() { _ = meshStore.Close() })

	setupStore, err := setup.OpenStore(ctx, open("setup.db"))
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Cleanup(func() { _ = setupStore.Close() })

	f := &apiFixture{
		ctx:          ctx,
		dir:          dir,
		nc:           nc,
		authStore:    authStore,
		jobsStore:    jobStore,
		inv:          invStore,
		fw:           fwStore,
		appsStore:    appStore,
		metricsStore: mtrStore,
		updStore:     updStore,
	}
	probes := setup.Probes{
		HasUsers: func(_ context.Context) (bool, error) { return f.hasUsers, nil },
	}
	setupSvc := setup.NewService(setupStore, probes, "self-node")

	authSvc, err := auth.NewService(authStore, auth.Config{
		RPDisplayName: "Test", RPID: "localhost",
		RPOrigins: []string{"http://localhost:3000"},
	})
	if err != nil {
		t.Fatalf("auth NewService: %v", err)
	}
	meshClient := newFakeMeshClient()
	meshSvc := mesh.NewService(mesh.Config{}, meshStore, meshClient, mesh.NewNoopSupervisor())
	bmcSvc := bmc.NewService(bmc.Config{HostNodeID: "self-node"}, bmcStore, nc)

	bundleDir := filepath.Join(dir, "bundles")
	verifier, err := updater.NewVerifier(dir)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	runner := jobs.NewRunner(jobStore, nc)

	trustDir := dir
	srv := NewServer(jobStore, runner, invStore, fwStore, appStore,
		mtrStore, updStore, verifier, bundleDir, trustDir,
		meshSvc, bmcSvc, setupSvc, authSvc, nc)

	f.srv = srv
	f.handler = srv.Handler()
	f.authSvc = authSvc
	f.runner = runner
	f.verifier = verifier
	f.bundleDir = bundleDir
	f.mesh = meshSvc
	f.meshFake = meshClient
	f.bmcSvc = bmcSvc
	f.setupSvc = setupSvc
	return f
}

// authenticate mints a user + a fresh session and returns the cookie so test
// requests can satisfy RequireSession.
func (f *apiFixture) authenticate(t *testing.T) *http.Cookie {
	t.Helper()
	// auth.makeUser is private to auth; instead create a user via the public
	// store API and then create a session.
	u := &auth.User{
		ID:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Name:        "alice",
		DisplayName: "Alice",
		CreatedAt:   time.Now().UTC(),
	}
	if err := f.authStore.CreateUser(f.ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	now := time.Now().UTC()
	sess := &auth.Session{
		Token:        "test-cookie-token",
		UserID:       u.ID,
		CreatedAt:    now,
		ExpiresAt:    now.Add(time.Hour),
		LastActiveAt: now,
	}
	if err := f.authStore.CreateSession(f.ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	f.authUser = u
	f.authSession = sess
	f.hasUsers = true
	return &http.Cookie{Name: "rasputin-session", Value: sess.Token}
}

// do performs a request through the server's Handler with the given cookie
// attached. Returns the recorded response.
func (f *apiFixture) do(t *testing.T, method, path string, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader interface{ Read([]byte) (int, error) }
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	var req *http.Request
	if bodyReader == nil {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	return w
}

// ============================================================================
// Health (open)
// ============================================================================

func TestHandleHealth(t *testing.T) {
	f := newAPIFixture(t)
	w := f.do(t, http.MethodGet, "/healthz", "", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Errorf("body: %s", w.Body.String())
	}
}

// ============================================================================
// Auth gating
// ============================================================================

func TestRouteRequiresAuth(t *testing.T) {
	f := newAPIFixture(t)
	w := f.do(t, http.MethodGet, "/api/jobs", "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestSetupState_OpenEndpoint(t *testing.T) {
	f := newAPIFixture(t)
	w := f.do(t, http.MethodGet, "/api/setup/state", "", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

// ============================================================================
// Jobs handlers
// ============================================================================

func TestHandleListJobs_Empty(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/jobs", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestHandleListJobs_ParentFilter(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/jobs?parentId=ghost", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleCreateJob_BadJSON(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/jobs", "{bad", c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateJob_MissingKind(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/jobs", `{"spec":{}}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateJob_UnknownKind(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/jobs", `{"kind":"no.such.kind"}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleGetJob_NotFound(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/jobs/ghost", "", c)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestHandleListSteps_Empty(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/jobs/x/steps", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleListEvents_Empty(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/jobs/x/events", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

// ============================================================================
// Nodes handlers
// ============================================================================

func TestHandleListNodes_Empty(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/nodes", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleListNodes_Populated(t *testing.T) {
	f := newAPIFixture(t)
	_ = f.inv.Insert(f.ctx, &proto.Node{
		ID: "node-1", Role: proto.RoleCompute, Hostname: "node-1",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	})
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/nodes", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var nodes []*proto.Node
	_ = json.Unmarshal(w.Body.Bytes(), &nodes)
	if len(nodes) != 1 {
		t.Errorf("nodes: %d", len(nodes))
	}
	if nodes[0].Status == "" {
		t.Errorf("Status should be populated by handler, got empty")
	}
}

func TestHandleGetNode_NotFound(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/nodes/ghost", "", c)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestHandleGetNode_Found(t *testing.T) {
	f := newAPIFixture(t)
	_ = f.inv.Insert(f.ctx, &proto.Node{
		ID: "node-1", Role: proto.RoleCompute, Hostname: "x",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	})
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/nodes/node-1", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

// ============================================================================
// Apps handlers
// ============================================================================

func TestHandleListApps_Empty(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/apps", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleCreateApp_BadJSON(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/apps", "{bad", c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateApp_MissingFields(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	for _, body := range []string{
		`{}`,
		`{"name":"x"}`,
		`{"name":"x","composeYaml":"y"}`,
	} {
		w := f.do(t, http.MethodPost, "/api/apps", body, c)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body=%s want 400, got %d", body, w.Code)
		}
	}
}

func TestHandleCreateApp_InvalidName(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/apps",
		`{"name":"has space","composeYaml":"x","targetNode":"node-1"}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateApp_TargetNotFound(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/apps",
		`{"name":"x","composeYaml":"y","targetNode":"ghost"}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateApp_TargetWrongRole(t *testing.T) {
	f := newAPIFixture(t)
	_ = f.inv.Insert(f.ctx, &proto.Node{
		ID: "node-fw", Role: proto.RoleFirewall, Hostname: "fw",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	})
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/apps",
		`{"name":"x","composeYaml":"y","targetNode":"node-fw"}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateApp_Success(t *testing.T) {
	f := newAPIFixture(t)
	_ = f.inv.Insert(f.ctx, &proto.Node{
		ID: "node-1", Role: proto.RoleCompute, Hostname: "x",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	})
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/apps",
		`{"name":"minecraft","composeYaml":"services: {}","targetNode":"node-1"}`, c)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestHandleCreateApp_DuplicateName(t *testing.T) {
	f := newAPIFixture(t)
	_ = f.inv.Insert(f.ctx, &proto.Node{
		ID: "node-1", Role: proto.RoleCompute, Hostname: "x",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	})
	c := f.authenticate(t)
	body := `{"name":"dupe","composeYaml":"services: {}","targetNode":"node-1"}`
	_ = f.do(t, http.MethodPost, "/api/apps", body, c)
	w := f.do(t, http.MethodPost, "/api/apps", body, c)
	if w.Code != http.StatusConflict {
		t.Errorf("want 409, got %d", w.Code)
	}
}

func TestHandleGetApp_NotFound(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/apps/ghost", "", c)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestHandleDeleteApp_NotFound(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodDelete, "/api/apps/ghost", "", c)
	// Delete returns 404 only when the apps store returns sql.ErrNoRows;
	// otherwise it succeeds (idempotent). Either is acceptable.
	if w.Code != http.StatusNotFound && w.Code != http.StatusNoContent {
		t.Errorf("want 404 or 204, got %d", w.Code)
	}
}

func TestHandleDeployApp_UnknownKind(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/apps/x/deploy", "", c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 (unknown workflow), got %d", w.Code)
	}
}

func TestHandleStopApp_UnknownKind(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/apps/x/stop", "", c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 (unknown workflow), got %d", w.Code)
	}
}

// ============================================================================
// validAppName
// ============================================================================

func TestValidAppName(t *testing.T) {
	cases := map[string]bool{
		"a":                     true,
		"minecraft":             true,
		"my_app-1":              true,
		"":                      false,
		"with space":            false,
		strings.Repeat("a", 33): false,
	}
	for n, want := range cases {
		if got := validAppName(n); got != want {
			t.Errorf("validAppName(%q) = %v, want %v", n, got, want)
		}
	}
}

// ============================================================================
// Firewall handlers
// ============================================================================

func TestHandleListIntents_Empty(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/firewall/intents", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleCreateIntent_BadJSON(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/firewall/intents", "{bad", c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateIntent_MissingName(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/firewall/intents", `{"kind":"port_forward"}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateIntent_UnknownKind(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/firewall/intents",
		`{"kind":"sorcery","name":"x","spec":{}}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateIntent_BadSpec(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	body := `{"kind":"port_forward","name":"x","spec":{"wanPort":0,"lanPort":1,"lanHost":"h"}}`
	w := f.do(t, http.MethodPost, "/api/firewall/intents", body, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateIntent_Success(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	body := `{"kind":"port_forward","name":"minecraft","spec":{"wanPort":25565,"lanPort":25565,"lanHost":"10.0.0.5","protocol":"tcp"}}`
	w := f.do(t, http.MethodPost, "/api/firewall/intents", body, c)
	if w.Code != http.StatusCreated {
		t.Errorf("want 201, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestHandleUpdateIntent_NotFound(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPatch, "/api/firewall/intents/ghost", `{}`, c)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestHandleDeleteIntent_NotFound(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodDelete, "/api/firewall/intents/ghost", "", c)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestHandleGetFirewallState_Empty(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/firewall/state", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleApplyFirewall_UnknownKind(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/firewall/apply", "", c)
	// No workflow registered → 400.
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleReconcileFirewall_UnknownKind(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/firewall/reconcile", "", c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// ============================================================================
// validateIntentSpec
// ============================================================================

func TestValidateIntentSpec(t *testing.T) {
	good := []byte(`{"wanPort":1,"lanPort":2,"lanHost":"h","protocol":"tcp"}`)
	if err := validateIntentSpec("port_forward", good); err != nil {
		t.Errorf("good spec: %v", err)
	}
	cases := [][]byte{
		[]byte(`{not json`),
		[]byte(`{"wanPort":0,"lanPort":1,"lanHost":"h"}`),
		[]byte(`{"wanPort":1,"lanPort":99999,"lanHost":"h"}`),
		[]byte(`{"wanPort":1,"lanPort":1,"lanHost":""}`),
		[]byte(`{"wanPort":1,"lanPort":1,"lanHost":"h","protocol":"sctp"}`),
	}
	for i, raw := range cases {
		if err := validateIntentSpec("port_forward", raw); err == nil {
			t.Errorf("case %d: want error", i)
		}
	}
	// Unknown kind returns "unsupported intent kind" via fall-through.
	if err := validateIntentSpec("sorcery", []byte(`{}`)); err == nil {
		t.Error("want error for unknown kind")
	}
}

// ============================================================================
// Metrics handler
// ============================================================================

func TestHandleGetMetrics_Empty(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/metrics/node-1", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleGetMetrics_WithFilter(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet,
		"/api/metrics/node-1?range=24h&metric=cpu_percent,mem_used_bytes", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestParseRange(t *testing.T) {
	cases := map[string]time.Duration{
		"":     time.Hour,
		"1h":   time.Hour,
		"5m":   5 * time.Minute,
		"15m":  15 * time.Minute,
		"6h":   6 * time.Hour,
		"24h":  24 * time.Hour,
		"junk": time.Hour,
	}
	for in, want := range cases {
		if got := parseRange(in); got != want {
			t.Errorf("parseRange(%q) = %v, want %v", in, got, want)
		}
	}
}

// ============================================================================
// Bundles / Updates handlers
// ============================================================================

func TestHandleListBundles_Empty(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/bundles", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleGetBundle_BadSha(t *testing.T) {
	f := newAPIFixture(t)
	w := f.do(t, http.MethodGet, "/api/bundles/zzz", "", nil) // open endpoint
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleGetBundle_NotFound(t *testing.T) {
	f := newAPIFixture(t)
	w := f.do(t, http.MethodGet, "/api/bundles/"+strings.Repeat("a", 64), "", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestHandleDeleteBundle_NotFound(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodDelete, "/api/bundles/"+strings.Repeat("a", 64), "", c)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestLooksLikeSHA256(t *testing.T) {
	cases := map[string]bool{
		strings.Repeat("a", 64): true,
		strings.Repeat("F", 64): true,
		strings.Repeat("a", 63): false,
		"":                      false,
		strings.Repeat("z", 64): false,
	}
	for in, want := range cases {
		if got := looksLikeSHA256(in); got != want {
			t.Errorf("looksLikeSHA256(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestHandleListUpdates_Empty(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/updates", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleCreateUpdate_BadJSON(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/updates", "{bad", c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateUpdate_MissingFields(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/updates", `{}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateSystemUpdate_MissingSha(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/updates/system", `{}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleUploadBundle_TooLarge(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	req := httptest.NewRequest(http.MethodPost, "/api/bundles", strings.NewReader(""))
	req.AddCookie(c)
	req.ContentLength = 1<<30 + 1 // just over the limit
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("want 413, got %d", w.Code)
	}
}

// ============================================================================
// BMC handlers
// ============================================================================

func TestHandleListBMCStates_Empty(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/bmc", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleBMCStatus_DefaultUnknown(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/bmc/never-queried/status", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "unknown") {
		t.Errorf("want unknown in body, got %s", w.Body.String())
	}
}

func TestHandleBMCPower_BadVerb(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/bmc/n/power/explode", "", c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleBMCPower_UnknownKind(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/bmc/n/power/on", "", c)
	// bmc.power workflow not registered with this runner → 400.
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// ============================================================================
// Mesh handlers
// ============================================================================

func TestHandleMeshState(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/mesh/state", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

// When HeadplaneURL isn't configured the field is omitted entirely so
// the UI can hide the sibling-tab link with a simple presence check.
func TestHandleMeshState_OmitsHeadplaneURLWhenUnset(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/mesh/state", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "headplaneUrl") {
		t.Errorf("headplaneUrl should be omitted when not set; body=%s", w.Body.String())
	}
}

// When configured, the URL is round-tripped verbatim so the UI can
// build a sibling-tab link without any normalization on the backend.
func TestHandleMeshState_SurfacesHeadplaneURL(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	// Mutate the service config in place — the fixture builds the
	// service with zero values, and the config is held by pointer-free
	// value, but the Service exposes Config() (by-value) which we can't
	// mutate. So we build a parallel server with the URL set.
	hpURL := "http://headplane.lan:3000"
	meshSvc := mesh.NewService(mesh.Config{
		LoginServer:  "http://mesh.local",
		DefaultUser:  "rasputin-operator",
		HeadplaneURL: hpURL,
	}, f.mesh.Store(), f.meshFake, mesh.NewNoopSupervisor())
	srv := NewServer(f.jobsStore, f.runner, f.inv, f.fw, f.appsStore,
		f.metricsStore, f.updStore, f.verifier, f.bundleDir, f.srv.trustDir,
		meshSvc, f.bmcSvc, f.setupSvc, f.authSvc, f.nc)
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/mesh/state", nil)
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"headplaneUrl":"`+hpURL+`"`) {
		t.Errorf("body missing headplane URL: %s", rec.Body.String())
	}
}

func TestHandleListMeshDevices_Empty(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/mesh/devices", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleDeleteMeshDevice_NotFound(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodDelete, "/api/mesh/devices/ghost", "", c)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

// --- /api/mesh/enroll-defaults/{nodeId} -----------------------------------

func TestHandleMeshEnrollDefaults_PrefillsFromAgentMetadata(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "node-5", Role: proto.RoleCompute, Hostname: "node-5",
		Metadata:  map[string]any{"primaryLanCidr": "192.168.50.0/24"},
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv.Insert: %v", err)
	}
	w := f.do(t, http.MethodGet, "/api/mesh/enroll-defaults/node-5", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		NodeID          string   `json:"nodeId"`
		AdvertiseRoutes []string `json:"advertiseRoutes"`
		PrimaryLanCidr  string   `json:"primaryLanCidr"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.NodeID != "node-5" {
		t.Errorf("nodeId: %q", resp.NodeID)
	}
	if resp.PrimaryLanCidr != "192.168.50.0/24" {
		t.Errorf("primaryLanCidr: %q", resp.PrimaryLanCidr)
	}
	if len(resp.AdvertiseRoutes) != 1 || resp.AdvertiseRoutes[0] != "192.168.50.0/24" {
		t.Errorf("advertiseRoutes: %v", resp.AdvertiseRoutes)
	}
}

func TestHandleMeshEnrollDefaults_NoCIDRReturnsEmptyArray(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	if err := f.inv.Insert(f.ctx, &proto.Node{
		ID: "node-6", Role: proto.RoleCompute, Hostname: "node-6",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv.Insert: %v", err)
	}
	w := f.do(t, http.MethodGet, "/api/mesh/enroll-defaults/node-6", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	// JSON should have advertiseRoutes:[] (not null) so the UI can iterate.
	if !strings.Contains(w.Body.String(), `"advertiseRoutes":[]`) {
		t.Errorf("want empty array, got body=%s", w.Body.String())
	}
}

func TestHandleMeshEnrollDefaults_NotFound(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/mesh/enroll-defaults/missing", "", c)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

// --- /api/mesh/ios-profile -------------------------------------------------

func TestHandleMeshIOSProfile_Missing404(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/mesh/ios-profile", "", c)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404 when root-ca.pem absent, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestHandleMeshIOSProfile_ServesAppleAspenConfig(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	// Drop a fresh self-signed cert at <trustDir>/mesh-ca.pem (the Mesh
	// TLS CA — NOT root-ca.pem; that's the bundle-signing root which is
	// the wrong CA for the trust-Headscale use case).
	certPEM := freshSelfSignedCertForAPI(t)
	caPath := filepath.Join(f.srv.trustDir, mesh.MeshCAFileName)
	if err := os.WriteFile(caPath, certPEM, 0o644); err != nil {
		t.Fatalf("write mesh-ca.pem: %v", err)
	}
	w := f.do(t, http.MethodGet, "/api/mesh/ios-profile", "", c)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "application/x-apple-aspen-config" {
		t.Errorf("content-type: %q", got)
	}
	if got := w.Header().Get("Content-Disposition"); got == "" {
		t.Error("content-disposition missing — iOS Safari won't trigger install prompt")
	}
	if !strings.Contains(w.Body.String(), "com.apple.security.root") {
		t.Errorf("body missing root payload type:\n%s", w.Body.String())
	}
}

// freshSelfSignedCertForAPI mirrors the mesh-package test helper but
// duplicated here to avoid an internal export just for the test.
func freshSelfSignedCertForAPI(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Rasputin API Test CA"},
		NotBefore:             time.Now().Add(-time.Hour).UTC(),
		NotAfter:              time.Now().Add(24 * time.Hour).UTC(),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Verify the handler removes the node from Headscale before dropping the
// local cache row. Without this, a "deleted" device would re-appear on
// the next reconcile.
func TestHandleDeleteMeshDevice_RemovesFromHeadscale(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	ctx := context.Background()

	// Seed both the local cache and the fake Headscale.
	f.meshFake.nodes["hs-77"] = mesh.HSNode{ID: "hs-77", User: "alice", Hostname: "alice-laptop"}
	if err := f.mesh.Store().UpsertDevice(ctx, &mesh.Device{
		HSID: "hs-77", User: "alice", Hostname: "alice-laptop", Kind: "user",
		FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	w := f.do(t, http.MethodDelete, "/api/mesh/devices/hs-77", "", c)
	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d body=%s", w.Code, w.Body.String())
	}
	if _, ok := f.meshFake.nodes["hs-77"]; ok {
		t.Error("Headscale-side node was NOT removed")
	}
	rows, err := f.mesh.Store().ListDevices(ctx)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	for _, d := range rows {
		if d.HSID == "hs-77" {
			t.Error("local cache row was NOT removed")
		}
	}
}

func TestHandleListMeshKeys_Empty(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/mesh/keys", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleCreateMeshKey_BadJSON(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/mesh/keys", "{bad", c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateMeshKey_MissingName(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/mesh/keys", `{}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateMeshKey_Success(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/mesh/keys",
		`{"name":"my laptop","reusable":false,"ephemeral":false}`, c)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d body=%s", w.Code, w.Body.String())
	}
	if f.meshFake.createCalls != 1 {
		t.Errorf("CreatePreAuthKey calls: want 1, got %d", f.meshFake.createCalls)
	}
}

func TestHandleDeleteMeshKey_NotFound(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodDelete, "/api/mesh/keys/ghost", "", c)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestHandleListMeshRoutes_Empty(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/mesh/routes", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleCreateMeshRoute_BadJSON(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/mesh/routes", "{bad", c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateMeshRoute_MissingFields(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/mesh/routes", `{"name":"x"}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateMeshRoute_Success(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	body := `{"name":"lan","nodeId":"node-fw","cidr":"10.0.0.0/24"}`
	w := f.do(t, http.MethodPost, "/api/mesh/routes", body, c)
	if w.Code != http.StatusCreated {
		t.Errorf("want 201, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestHandleDeleteMeshRoute_NotFound(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodDelete, "/api/mesh/routes/ghost", "", c)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestHandleMeshApply_UnknownKind(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/mesh/apply", "", c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleMeshReconcile_UnknownKind(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/mesh/reconcile", "", c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleMeshEnroll_UnknownKind(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/mesh/enroll/node-x", "", c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// ============================================================================
// Setup handlers (authenticated)
// ============================================================================

func TestHandleSetupInstallName_Empty(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/setup/install-name", `{}`, c)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 (empty name), got %d", w.Code)
	}
}

func TestHandleSetupInstallName_Success(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/setup/install-name", `{"name":"Test"}`, c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestHandleSetupMesh_UnknownWorkflow(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/setup/mesh", "", c)
	// mesh.enroll_node workflow isn't registered → 400.
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleSetupComplete_RequiredStepIncomplete(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodPost, "/api/setup/complete", "", c)
	// The first-passkey step is unsatisfied until we mark hasUsers=true,
	// AND install name must be set.
	if w.Code != http.StatusPreconditionFailed {
		t.Errorf("want 412, got %d body=%s", w.Code, w.Body.String())
	}
}

// ============================================================================
// Alerts
// ============================================================================

func TestHandleListAlerts_Default(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	w := f.do(t, http.MethodGet, "/api/alerts", "", c)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

// ============================================================================
// CORS preflight
// ============================================================================

func TestCORS_PreflightReturnsNoContent(t *testing.T) {
	f := newAPIFixture(t)
	req := httptest.NewRequest(http.MethodOptions, "/api/jobs", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("want 204, got %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("ACAO: %q", got)
	}
}

func TestCORS_NoOriginPassesThrough(t *testing.T) {
	f := newAPIFixture(t)
	w := f.do(t, http.MethodGet, "/healthz", "", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

// ============================================================================
// atoiOr (handlers.go pure helper)
// ============================================================================

func TestAtoiOr(t *testing.T) {
	cases := []struct {
		in   string
		def  int
		want int
	}{
		{"", 50, 50},
		{"12", 50, 12},
		{"abc", 50, 50},
		{"-5", 50, 50},
		{"0", 50, 50},
	}
	for _, tc := range cases {
		if got := atoiOr(tc.in, tc.def); got != tc.want {
			t.Errorf("atoiOr(%q,%d) = %d, want %d", tc.in, tc.def, got, tc.want)
		}
	}
}

// ============================================================================
// creator + parseDurationOr
// ============================================================================

func TestCreator(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if creator(r) == "" {
		t.Error("want non-empty creator")
	}
}

func TestParseDurationOr(t *testing.T) {
	if got := parseDurationOr("5m", time.Hour); got != 5*time.Minute {
		t.Errorf("5m: %v", got)
	}
	if got := parseDurationOr("", time.Hour); got != time.Hour {
		t.Errorf("default: %v", got)
	}
	if got := parseDurationOr("-1h", time.Hour); got != time.Hour {
		t.Errorf("negative defaults: %v", got)
	}
}

// ============================================================================
// writeJSON / writeError pass-through
// ============================================================================

func TestWriteJSON_SetsContentType(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"a": "b"})
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type: %q", got)
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusTeapot, "msg")
	if w.Code != http.StatusTeapot {
		t.Errorf("status: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "msg") {
		t.Errorf("body: %s", w.Body.String())
	}
}
