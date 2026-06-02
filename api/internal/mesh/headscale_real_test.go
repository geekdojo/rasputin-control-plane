package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// fakeHeadscale — minimal in-memory Headscale REST stand-in
// ============================================================================

// fakeHeadscale serves enough of the v0.28.x REST surface for RealClient
// tests: users, pre-auth keys, nodes, plus auth-header enforcement and a
// per-route error injector.
type fakeHeadscale struct {
	t        *testing.T
	apiKey   string
	srv      *httptest.Server
	requests atomic.Int64

	mu          sync.Mutex
	users       map[string]string                // name -> id
	nextUserID  int
	keys        map[string]fakeKey               // id -> key
	nextKeyID   int
	nodes       map[string]fakeNode              // id -> node
	failRoute   map[string]int                   // "METHOD PATH" -> status
	missingAuth bool                             // record whether any unauthed call slipped in

	// hooks captures every request method+path in arrival order — tests
	// use this to assert call sequencing (e.g. ListUsers happens BEFORE
	// CreateUser inside EnsureUser).
	hooks []string
}

type fakeKey struct {
	ID         string
	User       string
	Key        string
	Reusable   bool
	Ephemeral  bool
	Used       bool
	Expiration time.Time
	CreatedAt  time.Time
	ACLTags    []string
	Expired    bool
}

type fakeNode struct {
	ID              string
	Name            string
	User            string
	IPAddresses     []string
	Tags            []string
	AvailableRoutes []string
	ApprovedRoutes  []string
	LastSeen        time.Time
}

func newFakeHeadscale(t *testing.T) *fakeHeadscale {
	t.Helper()
	fh := &fakeHeadscale{
		t:         t,
		apiKey:    "hskey-auth-test-secret",
		users:     map[string]string{},
		keys:      map[string]fakeKey{},
		nodes:     map[string]fakeNode{},
		failRoute: map[string]int{},
	}
	fh.srv = httptest.NewServer(http.HandlerFunc(fh.handle))
	t.Cleanup(fh.srv.Close)
	return fh
}

func (f *fakeHeadscale) baseURL() string { return f.srv.URL }

func (f *fakeHeadscale) failNext(method, path string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failRoute[method+" "+path] = status
}

func (f *fakeHeadscale) snapshotHooks() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.hooks))
	copy(out, f.hooks)
	return out
}

func (f *fakeHeadscale) seedUser(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.users[name]; ok {
		return id
	}
	f.nextUserID++
	id := fmt.Sprintf("%d", f.nextUserID)
	f.users[name] = id
	return id
}

func (f *fakeHeadscale) seedNode(n fakeNode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n.ID == "" {
		f.t.Fatalf("seedNode: empty id")
	}
	f.nodes[n.ID] = n
}

func (f *fakeHeadscale) handle(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)

	if got := r.Header.Get("Authorization"); got != "Bearer "+f.apiKey {
		f.mu.Lock()
		f.missingAuth = true
		f.mu.Unlock()
		http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	f.mu.Lock()
	f.hooks = append(f.hooks, r.Method+" "+r.URL.Path)
	if code, ok := f.failRoute[r.Method+" "+r.URL.Path]; ok {
		delete(f.failRoute, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		http.Error(w, fmt.Sprintf(`{"message":"injected fail %d"}`, code), code)
		return
	}
	f.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user":
		f.handleListUsers(w)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/user":
		f.handleCreateUser(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/preauthkey":
		f.handleListPreAuthKeys(w)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/preauthkey":
		f.handleCreatePreAuthKey(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/preauthkey/expire":
		f.handleExpirePreAuthKey(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/node":
		f.handleListNodes(w)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/node/") && strings.HasSuffix(r.URL.Path, "/approve_routes"):
		f.handleApproveRoutes(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/node/"):
		f.handleDeleteNode(w, r)
	default:
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	}
}

func (f *fakeHeadscale) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	// Path: /api/v1/node/{id}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, `{"message":"bad path"}`, http.StatusBadRequest)
		return
	}
	nodeID := parts[4]
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.nodes[nodeID]; !ok {
		http.Error(w, `{"message":"node not found"}`, http.StatusNotFound)
		return
	}
	delete(f.nodes, nodeID)
	writeJSON(w, map[string]any{})
}

func (f *fakeHeadscale) handleListUsers(w http.ResponseWriter) {
	f.mu.Lock()
	users := make([]map[string]string, 0, len(f.users))
	for name, id := range f.users {
		users = append(users, map[string]string{"id": id, "name": name})
	}
	f.mu.Unlock()
	writeJSON(w, map[string]any{"users": users})
}

func (f *fakeHeadscale) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"message":"bad request"}`, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	if _, exists := f.users[body.Name]; exists {
		f.mu.Unlock()
		http.Error(w, `{"message":"user already exists"}`, http.StatusConflict)
		return
	}
	f.nextUserID++
	id := fmt.Sprintf("%d", f.nextUserID)
	f.users[body.Name] = id
	f.mu.Unlock()
	writeJSON(w, map[string]any{
		"user": map[string]any{"id": id, "name": body.Name, "createdAt": time.Now().UTC()},
	})
}

func (f *fakeHeadscale) handleCreatePreAuthKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		User       string    `json:"user"`
		Reusable   bool      `json:"reusable"`
		Ephemeral  bool      `json:"ephemeral"`
		Expiration time.Time `json:"expiration"`
		ACLTags    []string  `json:"aclTags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"message":"bad request"}`, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// Validate the user-id actually exists — catches RealClient bugs that
	// would otherwise be silently ignored by a permissive fake.
	var userName string
	for name, id := range f.users {
		if id == body.User {
			userName = name
			break
		}
	}
	if userName == "" {
		http.Error(w, `{"message":"user id not found"}`, http.StatusBadRequest)
		return
	}
	f.nextKeyID++
	id := fmt.Sprintf("%d", f.nextKeyID)
	plaintext := "hskey-auth-real-" + id
	f.keys[id] = fakeKey{
		ID: id, User: userName, Key: plaintext,
		Reusable: body.Reusable, Ephemeral: body.Ephemeral,
		Expiration: body.Expiration, CreatedAt: time.Now().UTC(),
		ACLTags: append([]string(nil), body.ACLTags...),
	}
	writeJSON(w, map[string]any{
		"preAuthKey": map[string]any{
			"id":         id,
			"key":        plaintext,
			"user":       map[string]string{"id": body.User, "name": userName},
			"reusable":   body.Reusable,
			"ephemeral":  body.Ephemeral,
			"used":       false,
			"expiration": body.Expiration,
			"createdAt":  time.Now().UTC(),
			"aclTags":    body.ACLTags,
		},
	})
}

func (f *fakeHeadscale) handleExpirePreAuthKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"message":"bad request"}`, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[body.ID]
	if !ok {
		http.Error(w, `{"message":"key not found"}`, http.StatusNotFound)
		return
	}
	k.Expired = true
	k.Expiration = time.Now().Add(-time.Second).UTC()
	f.keys[body.ID] = k
	writeJSON(w, map[string]any{})
}

func (f *fakeHeadscale) handleListPreAuthKeys(w http.ResponseWriter) {
	f.mu.Lock()
	keys := make([]map[string]any, 0, len(f.keys))
	for _, k := range f.keys {
		userID := f.users[k.User]
		// Plaintext omitted on List, matching real Headscale.
		keys = append(keys, map[string]any{
			"id":         k.ID,
			"key":        "",
			"user":       map[string]string{"id": userID, "name": k.User},
			"reusable":   k.Reusable,
			"ephemeral":  k.Ephemeral,
			"used":       k.Used,
			"expiration": k.Expiration,
			"createdAt":  k.CreatedAt,
			"aclTags":    k.ACLTags,
		})
	}
	f.mu.Unlock()
	writeJSON(w, map[string]any{"preAuthKeys": keys})
}

func (f *fakeHeadscale) handleListNodes(w http.ResponseWriter) {
	f.mu.Lock()
	nodes := make([]map[string]any, 0, len(f.nodes))
	for _, n := range f.nodes {
		userID := f.users[n.User]
		nodes = append(nodes, map[string]any{
			"id":              n.ID,
			"name":            n.Name,
			"ipAddresses":     n.IPAddresses,
			"lastSeen":        n.LastSeen,
			"online":          true,
			"approvedRoutes":  n.ApprovedRoutes,
			"availableRoutes": n.AvailableRoutes,
			"tags":            n.Tags,
			"user":            map[string]string{"id": userID, "name": n.User},
		})
	}
	f.mu.Unlock()
	writeJSON(w, map[string]any{"nodes": nodes})
}

func (f *fakeHeadscale) handleApproveRoutes(w http.ResponseWriter, r *http.Request) {
	// Path: /api/v1/node/{id}/approve_routes
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 {
		http.Error(w, `{"message":"bad path"}`, http.StatusBadRequest)
		return
	}
	nodeID := parts[4]
	var body struct {
		Routes []string `json:"routes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"message":"bad request"}`, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.nodes[nodeID]
	if !ok {
		http.Error(w, `{"message":"node not found"}`, http.StatusNotFound)
		return
	}
	n.ApprovedRoutes = append([]string(nil), body.Routes...)
	f.nodes[nodeID] = n
	writeJSON(w, map[string]any{
		"node": map[string]any{"id": nodeID, "approvedRoutes": n.ApprovedRoutes},
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ============================================================================
// RealClient tests
// ============================================================================

func newRealClientForFake(t *testing.T, fh *fakeHeadscale) *RealClient {
	t.Helper()
	c, err := NewRealClient(RealClientConfig{
		BaseURL: fh.baseURL(),
		APIKey:  fh.apiKey,
	})
	if err != nil {
		t.Fatalf("NewRealClient: %v", err)
	}
	return c
}

func TestRealClient_NewRealClient_ValidatesInputs(t *testing.T) {
	if _, err := NewRealClient(RealClientConfig{APIKey: "x"}); err == nil {
		t.Error("expected error for empty BaseURL")
	}
	if _, err := NewRealClient(RealClientConfig{BaseURL: "http://x"}); err == nil {
		t.Error("expected error for empty APIKey")
	}
}

func TestRealClient_Backend(t *testing.T) {
	fh := newFakeHeadscale(t)
	c := newRealClientForFake(t, fh)
	if c.Backend() != "headscale" {
		t.Errorf("backend: got %q, want %q", c.Backend(), "headscale")
	}
}

func TestRealClient_AuthHeaderRequired(t *testing.T) {
	fh := newFakeHeadscale(t)
	c, err := NewRealClient(RealClientConfig{BaseURL: fh.baseURL(), APIKey: "wrong-key"})
	if err != nil {
		t.Fatalf("NewRealClient: %v", err)
	}
	err = c.EnsureUser(context.Background(), "alice")
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusUnauthorized {
		t.Fatalf("want 401 HTTPError, got %v", err)
	}
}

func TestRealClient_EnsureUser_CreatesWhenMissing(t *testing.T) {
	fh := newFakeHeadscale(t)
	c := newRealClientForFake(t, fh)

	if err := c.EnsureUser(context.Background(), "rasputin-operator"); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	hooks := fh.snapshotHooks()
	wantPrefix := []string{"GET /api/v1/user", "POST /api/v1/user"}
	if len(hooks) != 2 || hooks[0] != wantPrefix[0] || hooks[1] != wantPrefix[1] {
		t.Errorf("call sequence: got %v, want %v (list-then-create)", hooks, wantPrefix)
	}
	if id, ok := c.cachedUserID("rasputin-operator"); !ok || id == "" {
		t.Errorf("cache miss after EnsureUser; got id=%q ok=%v", id, ok)
	}
}

func TestRealClient_EnsureUser_NoCreateWhenAlreadyExists(t *testing.T) {
	fh := newFakeHeadscale(t)
	fh.seedUser("rasputin-operator")
	c := newRealClientForFake(t, fh)

	if err := c.EnsureUser(context.Background(), "rasputin-operator"); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	hooks := fh.snapshotHooks()
	if len(hooks) != 1 || hooks[0] != "GET /api/v1/user" {
		t.Errorf("expected single GET list, got %v", hooks)
	}
}

func TestRealClient_EnsureUser_CachesAcrossCalls(t *testing.T) {
	fh := newFakeHeadscale(t)
	c := newRealClientForFake(t, fh)
	ctx := context.Background()

	if err := c.EnsureUser(ctx, "alice"); err != nil {
		t.Fatalf("EnsureUser 1: %v", err)
	}
	beforeReqs := fh.requests.Load()
	if err := c.EnsureUser(ctx, "alice"); err != nil {
		t.Fatalf("EnsureUser 2: %v", err)
	}
	if got := fh.requests.Load(); got != beforeReqs {
		t.Errorf("cached EnsureUser should be a no-op; HTTP requests went %d -> %d", beforeReqs, got)
	}
}

// Race: two concurrent creators both see "doesn't exist" from the initial
// list step; one wins the POST, the other receives 409 and must recover by
// re-listing to discover the now-existing user. We simulate this by wrapping
// the fake's handler so the FIRST list returns empty, the POST seeds the
// user behind the scenes AND returns 409, then a follow-up list finds it.
func TestRealClient_EnsureUser_HandlesAlreadyExistsRace(t *testing.T) {
	fh := newFakeHeadscale(t)
	var (
		listCalls int32
		postCalls int32
	)
	prev := fh.srv.Config.Handler
	fh.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/user":
			if atomic.AddInt32(&listCalls, 1) == 1 {
				// First list: pretend nobody is there.
				w.Header().Set("Authorization-Echo", r.Header.Get("Authorization"))
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"users":[]}`))
				return
			}
			prev.ServeHTTP(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/user":
			atomic.AddInt32(&postCalls, 1)
			// "Racing creator already wrote the user" — seed then 409.
			fh.seedUser("alice")
			http.Error(w, `{"message":"user already exists"}`, http.StatusConflict)
		default:
			prev.ServeHTTP(w, r)
		}
	})

	c := newRealClientForFake(t, fh)
	if err := c.EnsureUser(context.Background(), "alice"); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	if got := atomic.LoadInt32(&listCalls); got != 2 {
		t.Errorf("expected 2 list calls (initial-empty + recovery), got %d", got)
	}
	if got := atomic.LoadInt32(&postCalls); got != 1 {
		t.Errorf("expected 1 POST call, got %d", got)
	}
	if id, ok := c.cachedUserID("alice"); !ok || id == "" {
		t.Errorf("cache should be populated after 409 recovery; got id=%q ok=%v", id, ok)
	}
}

func TestRealClient_CreatePreAuthKey_ResolvesUserToID(t *testing.T) {
	fh := newFakeHeadscale(t)
	c := newRealClientForFake(t, fh)
	ctx := context.Background()
	if err := c.EnsureUser(ctx, "rasputin-operator"); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	id, value, err := c.CreatePreAuthKey(ctx, CreatePreAuthKeyInput{
		User:     "rasputin-operator",
		Reusable: false,
		Expiry:   time.Now().Add(24 * time.Hour),
		Tags:     []string{"tag:user-device"},
	})
	if err != nil {
		t.Fatalf("CreatePreAuthKey: %v", err)
	}
	if id == "" || value == "" {
		t.Errorf("want id+value populated, got id=%q value=%q", id, value)
	}
	if !strings.HasPrefix(value, "hskey-auth-real-") {
		t.Errorf("plaintext key shape: got %q", value)
	}
}

// Expiry zero -> Headscale-default; should NOT serialize an explicit field.
func TestRealClient_CreatePreAuthKey_OmitsZeroExpiry(t *testing.T) {
	fh := newFakeHeadscale(t)
	c := newRealClientForFake(t, fh)
	ctx := context.Background()
	if err := c.EnsureUser(ctx, "alice"); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	// Intercept the POST body by wrapping the fake handler.
	var seenBody string
	prev := fh.srv.Config.Handler
	fh.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/preauthkey" {
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			seenBody = string(buf[:n])
			// Reset body for the real handler.
			r.Body = nopReadCloser{strings.NewReader(seenBody)}
		}
		prev.ServeHTTP(w, r)
	})

	_, _, err := c.CreatePreAuthKey(ctx, CreatePreAuthKeyInput{
		User:     "alice",
		Reusable: true,
	})
	if err != nil {
		t.Fatalf("CreatePreAuthKey: %v", err)
	}
	if strings.Contains(seenBody, "expiration") {
		t.Errorf("zero Expiry should be omitted from JSON; body was %s", seenBody)
	}
}

func TestRealClient_ExpirePreAuthKey(t *testing.T) {
	fh := newFakeHeadscale(t)
	c := newRealClientForFake(t, fh)
	ctx := context.Background()
	if err := c.EnsureUser(ctx, "alice"); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	id, _, err := c.CreatePreAuthKey(ctx, CreatePreAuthKeyInput{User: "alice", Expiry: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("CreatePreAuthKey: %v", err)
	}
	if err := c.ExpirePreAuthKey(ctx, id); err != nil {
		t.Fatalf("ExpirePreAuthKey: %v", err)
	}
	fh.mu.Lock()
	got := fh.keys[id].Expired
	fh.mu.Unlock()
	if !got {
		t.Errorf("expected key %s to be expired", id)
	}
}

func TestRealClient_ExpirePreAuthKey_RejectsEmptyID(t *testing.T) {
	fh := newFakeHeadscale(t)
	c := newRealClientForFake(t, fh)
	if err := c.ExpirePreAuthKey(context.Background(), ""); err == nil {
		t.Error("expected error for empty id")
	}
}

func TestRealClient_ListPreAuthKeys_FiltersByUserClientSide(t *testing.T) {
	fh := newFakeHeadscale(t)
	c := newRealClientForFake(t, fh)
	ctx := context.Background()
	if err := c.EnsureUser(ctx, "alice"); err != nil {
		t.Fatalf("EnsureUser alice: %v", err)
	}
	if err := c.EnsureUser(ctx, "bob"); err != nil {
		t.Fatalf("EnsureUser bob: %v", err)
	}
	if _, _, err := c.CreatePreAuthKey(ctx, CreatePreAuthKeyInput{User: "alice", Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("create alice key: %v", err)
	}
	if _, _, err := c.CreatePreAuthKey(ctx, CreatePreAuthKeyInput{User: "bob", Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("create bob key: %v", err)
	}

	all, err := c.ListPreAuthKeys(ctx, "")
	if err != nil {
		t.Fatalf("ListPreAuthKeys all: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("want 2 keys (all), got %d", len(all))
	}
	aliceOnly, err := c.ListPreAuthKeys(ctx, "alice")
	if err != nil {
		t.Fatalf("ListPreAuthKeys alice: %v", err)
	}
	if len(aliceOnly) != 1 || aliceOnly[0].User != "alice" {
		t.Errorf("want 1 alice key, got %+v", aliceOnly)
	}
	// Real Headscale strips plaintext on List; we should faithfully forward.
	if aliceOnly[0].Plaintext != "" {
		t.Errorf("expected empty plaintext on List, got %q", aliceOnly[0].Plaintext)
	}
}

func TestRealClient_ListNodes(t *testing.T) {
	fh := newFakeHeadscale(t)
	uid := fh.seedUser("alice")
	fh.seedNode(fakeNode{
		ID: "7", Name: "alice-laptop", User: "alice",
		IPAddresses:     []string{"100.64.0.5", "fd7a:115c:a1e0::5"},
		Tags:            []string{"tag:user-device"},
		AvailableRoutes: []string{"192.168.1.0/24"},
		ApprovedRoutes:  []string{"192.168.1.0/24"},
		LastSeen:        time.Now().Add(-5 * time.Minute).UTC(),
	})
	c := newRealClientForFake(t, fh)

	nodes, err := c.ListNodes(context.Background())
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}
	n := nodes[0]
	if n.ID != "7" || n.Hostname != "alice-laptop" || n.User != "alice" {
		t.Errorf("node identity: %+v", n)
	}
	if n.IPv4 != "100.64.0.5" {
		t.Errorf("ipv4: got %q want 100.64.0.5", n.IPv4)
	}
	if n.IPv6 != "fd7a:115c:a1e0::5" {
		t.Errorf("ipv6: got %q want fd7a:115c:a1e0::5", n.IPv6)
	}
	if len(n.AdvertisedRoutes) != 1 || n.AdvertisedRoutes[0] != "192.168.1.0/24" {
		t.Errorf("advertised routes: %v", n.AdvertisedRoutes)
	}
	_ = uid
}

func TestRealClient_SetNodeRoutes(t *testing.T) {
	fh := newFakeHeadscale(t)
	fh.seedUser("alice")
	fh.seedNode(fakeNode{ID: "7", Name: "alice-laptop", User: "alice"})
	c := newRealClientForFake(t, fh)

	err := c.SetNodeRoutes(context.Background(), "7", []string{"10.0.0.0/24", "192.168.5.0/24"})
	if err != nil {
		t.Fatalf("SetNodeRoutes: %v", err)
	}
	fh.mu.Lock()
	got := fh.nodes["7"].ApprovedRoutes
	fh.mu.Unlock()
	if len(got) != 2 || got[0] != "10.0.0.0/24" || got[1] != "192.168.5.0/24" {
		t.Errorf("approved routes: got %v", got)
	}
}

func TestRealClient_SetNodeRoutes_NotFound(t *testing.T) {
	fh := newFakeHeadscale(t)
	c := newRealClientForFake(t, fh)
	err := c.SetNodeRoutes(context.Background(), "missing", []string{"10.0.0.0/24"})
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusNotFound {
		t.Errorf("want 404 HTTPError, got %v", err)
	}
}

func TestRealClient_DeleteNode_Success(t *testing.T) {
	fh := newFakeHeadscale(t)
	fh.seedUser("alice")
	fh.seedNode(fakeNode{ID: "7", Name: "alice-laptop", User: "alice"})
	c := newRealClientForFake(t, fh)

	if err := c.DeleteNode(context.Background(), "7"); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	fh.mu.Lock()
	_, present := fh.nodes["7"]
	fh.mu.Unlock()
	if present {
		t.Error("node still present after delete")
	}
}

// "Already gone" must resolve to nil so callers can clean up a stale
// local cache row whose Headscale counterpart was already removed.
func TestRealClient_DeleteNode_IdempotentOn404(t *testing.T) {
	fh := newFakeHeadscale(t)
	c := newRealClientForFake(t, fh)
	if err := c.DeleteNode(context.Background(), "ghost"); err != nil {
		t.Errorf("expected nil for missing node (idempotent), got %v", err)
	}
}

// And for the v0.28 quirk: Headscale uses HTTP 400 + gRPC NotFound for
// "no longer exists" in some paths. DeleteNode normalizes that too.
func TestRealClient_DeleteNode_IdempotentOn400NotExist(t *testing.T) {
	fh := newFakeHeadscale(t)
	// Pre-program the route so the DELETE returns 400 with a body that
	// looks like Headscale's "node no longer exists" message.
	fh.failNext(http.MethodDelete, "/api/v1/node/99", http.StatusBadRequest)
	c := newRealClientForFake(t, fh)
	// Without the body-content match the test fake's failNext returns the
	// generic injected payload, so we override the response to mimic
	// Headscale's actual 400 shape.
	prev := fh.srv.Config.Handler
	fh.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/api/v1/node/99" {
			if got := r.Header.Get("Authorization"); got != "Bearer "+fh.apiKey {
				http.Error(w, `unauth`, http.StatusUnauthorized)
				return
			}
			http.Error(w, `{"code":5,"message":"node no longer exists in NodeStore: 99","details":[]}`, http.StatusBadRequest)
			return
		}
		prev.ServeHTTP(w, r)
	})
	if err := c.DeleteNode(context.Background(), "99"); err != nil {
		t.Errorf("expected nil for HTTP 400 not-exist (idempotent), got %v", err)
	}
}

func TestRealClient_DeleteNode_RejectsEmptyID(t *testing.T) {
	fh := newFakeHeadscale(t)
	c := newRealClientForFake(t, fh)
	if err := c.DeleteNode(context.Background(), ""); err == nil {
		t.Error("expected error for empty nodeID")
	}
}

func TestRealClient_HTTPError_Wraps(t *testing.T) {
	fh := newFakeHeadscale(t)
	fh.failNext(http.MethodGet, "/api/v1/user", http.StatusInternalServerError)
	c := newRealClientForFake(t, fh)
	err := c.EnsureUser(context.Background(), "alice")
	var he *HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("want *HTTPError, got %T %v", err, err)
	}
	if he.Status != http.StatusInternalServerError {
		t.Errorf("status: got %d want 500", he.Status)
	}
	if !strings.Contains(he.Error(), "/api/v1/user") {
		t.Errorf("error should mention path; got %q", he.Error())
	}
}

func TestRealClient_IsAlreadyExists(t *testing.T) {
	if IsAlreadyExists(nil) {
		t.Error("nil err must not be already-exists")
	}
	if IsAlreadyExists(errors.New("plain")) {
		t.Error("plain err must not be already-exists")
	}
	if !IsAlreadyExists(&HTTPError{Status: http.StatusConflict}) {
		t.Error("409 should be already-exists")
	}
	if !IsAlreadyExists(&HTTPError{Status: http.StatusBadRequest, Body: "user ALREADY EXISTS"}) {
		t.Error("400 + body match should be already-exists")
	}
	if IsAlreadyExists(&HTTPError{Status: http.StatusBadRequest, Body: "missing field"}) {
		t.Error("400 without body match should NOT be already-exists")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type nopReadCloser struct {
	*strings.Reader
}

func (nopReadCloser) Close() error { return nil }
