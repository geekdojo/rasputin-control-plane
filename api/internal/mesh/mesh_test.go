package mesh

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// ============================================================================
// Fakes
// ============================================================================

// fakeClient is a fully in-memory Client implementation. We don't reuse
// MockClient because that's file-backed; this one is simpler and gives the
// test direct visibility into what the Service asked for.
type fakeClient struct {
	mu              sync.Mutex
	users           map[string]bool
	keys            map[string]HSPreAuthKey
	nodes           map[string]HSNode
	createCalls     int
	expireCalls     int
	setRoutesCalls  int
	ensureUserCalls int
	deleteNodeCalls int

	createKeyErr  error
	listNodesErr  error
	listKeysErr   error
	setRoutesErr  error
	ensureUserErr error
	deleteNodeErr error
}

func newFakeClient() *fakeClient {
	return &fakeClient{
		users: map[string]bool{},
		keys:  map[string]HSPreAuthKey{},
		nodes: map[string]HSNode{},
	}
}

func (f *fakeClient) Backend() string { return "fake" }

func (f *fakeClient) EnsureUser(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureUserCalls++
	if f.ensureUserErr != nil {
		return f.ensureUserErr
	}
	f.users[name] = true
	return nil
}

func (f *fakeClient) CreatePreAuthKey(_ context.Context, in CreatePreAuthKeyInput) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls++
	if f.createKeyErr != nil {
		return "", "", f.createKeyErr
	}
	id := "key-" + in.User + "-" + time.Now().UTC().Format("150405.000000")
	value := "plain-" + id
	f.keys[id] = HSPreAuthKey{
		ID: id, User: in.User, Reusable: in.Reusable, Ephemeral: in.Ephemeral,
		Tags: append([]string{}, in.Tags...), Expiration: in.Expiry,
		CreatedAt: time.Now().UTC(),
	}
	return id, value, nil
}

func (f *fakeClient) ExpirePreAuthKey(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expireCalls++
	k, ok := f.keys[id]
	if !ok {
		return nil
	}
	k.Expiration = time.Now().Add(-time.Second).UTC()
	f.keys[id] = k
	return nil
}

func (f *fakeClient) ListPreAuthKeys(_ context.Context, user string) ([]HSPreAuthKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listKeysErr != nil {
		return nil, f.listKeysErr
	}
	var out []HSPreAuthKey
	for _, k := range f.keys {
		if user != "" && k.User != user {
			continue
		}
		out = append(out, k)
	}
	return out, nil
}

func (f *fakeClient) ListNodes(_ context.Context) ([]HSNode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listNodesErr != nil {
		return nil, f.listNodesErr
	}
	out := make([]HSNode, 0, len(f.nodes))
	for _, n := range f.nodes {
		out = append(out, n)
	}
	return out, nil
}

func (f *fakeClient) SetNodeRoutes(_ context.Context, nodeID string, cidrs []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setRoutesCalls++
	if f.setRoutesErr != nil {
		return f.setRoutesErr
	}
	n, ok := f.nodes[nodeID]
	if !ok {
		f.nodes[nodeID] = HSNode{ID: nodeID, ApprovedRoutes: append([]string{}, cidrs...)}
		return nil
	}
	n.ApprovedRoutes = append([]string{}, cidrs...)
	f.nodes[nodeID] = n
	return nil
}

func (f *fakeClient) DeleteNode(_ context.Context, nodeID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteNodeCalls++
	if f.deleteNodeErr != nil {
		return f.deleteNodeErr
	}
	delete(f.nodes, nodeID)
	return nil
}

// failingSupervisor is used to test the Start error path.
type failingSupervisor struct{ err error }

func (s *failingSupervisor) Start(context.Context) error           { return s.err }
func (s *failingSupervisor) Stop(context.Context) error            { return nil }
func (s *failingSupervisor) Healthy(context.Context) (bool, error) { return true, nil }

// ============================================================================
// embedded NATS (publish only — Service jobs use it for change events)
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
// Fixture
// ============================================================================

type meshFixture struct {
	ctx    context.Context
	store  *Store
	nc     *nats.Conn
	client *fakeClient
	svc    *Service
}

func newMeshFixture(t *testing.T) *meshFixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := OpenStore(ctx, filepath.Join(dir, "mesh.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	nc := embeddedNATS(t)
	client := newFakeClient()
	svc := NewService(Config{}, st, client, NewNoopSupervisor())
	return &meshFixture{ctx: ctx, store: st, nc: nc, client: client, svc: svc}
}

// stepCtx packages a spec into a StepCtx the saga steps consume.
func stepCtx(ctx context.Context, nc *nats.Conn, spec any) *jobs.StepCtx {
	raw, _ := json.Marshal(spec)
	return &jobs.StepCtx{
		Ctx:   ctx,
		JobID: "test-job",
		Spec:  raw,
		NATS:  nc,
		Log:   func(string, string) {},
	}
}

// ============================================================================
// Compile
// ============================================================================

func TestCompile_EmptyIntents(t *testing.T) {
	state, hash, err := Compile(nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if hash == "" {
		t.Error("want non-empty hash")
	}
	keys, _ := state["preauth_keys"].([]map[string]string)
	routes, _ := state["subnet_routes"].([]map[string]string)
	if len(keys) != 0 || len(routes) != 0 {
		t.Errorf("want both empty: keys=%v routes=%v", keys, routes)
	}
}

func TestCompile_DeterministicHash(t *testing.T) {
	intents := []*Intent{
		{ID: "1", Kind: string(proto.IntentPreAuthKey), Name: "alpha", Enabled: true,
			Spec: mustMarshal(t, proto.PreAuthKeySpec{User: "u", ExpiresIn: "24h", Tags: []string{"tag:b", "tag:a"}})},
		{ID: "2", Kind: string(proto.IntentSubnetRoute), Name: "lan", Enabled: true,
			Spec: mustMarshal(t, proto.SubnetRouteSpec{NodeID: "n1", CIDR: "10.0.0.0/24"})},
	}
	_, h1, _ := Compile(intents)
	_, h2, _ := Compile(intents)
	if h1 != h2 {
		t.Errorf("hash not stable: %s vs %s", h1, h2)
	}
}

func TestCompile_DisabledIntentsExcluded(t *testing.T) {
	enabled := []*Intent{
		{ID: "1", Kind: string(proto.IntentPreAuthKey), Name: "x", Enabled: true,
			Spec: mustMarshal(t, proto.PreAuthKeySpec{User: "u", ExpiresIn: "24h"})},
	}
	disabled := []*Intent{
		{ID: "1", Kind: string(proto.IntentPreAuthKey), Name: "x", Enabled: false,
			Spec: mustMarshal(t, proto.PreAuthKeySpec{User: "u", ExpiresIn: "24h"})},
	}
	_, hEnabled, _ := Compile(enabled)
	_, hDisabled, _ := Compile(disabled)
	if hEnabled == hDisabled {
		t.Error("disabled intent should not contribute to hash")
	}
}

func TestCompile_BadSpecErrors(t *testing.T) {
	intents := []*Intent{
		{ID: "x", Kind: string(proto.IntentPreAuthKey), Enabled: true, Spec: []byte("{not json")},
	}
	if _, _, err := Compile(intents); err == nil {
		t.Error("want error for bad PreAuthKey spec")
	}
	intents2 := []*Intent{
		{ID: "y", Kind: string(proto.IntentSubnetRoute), Enabled: true, Spec: []byte("{nope")},
	}
	if _, _, err := Compile(intents2); err == nil {
		t.Error("want error for bad SubnetRoute spec")
	}
}

func TestHashObserved(t *testing.T) {
	h, err := HashObserved(map[string]any{"a": "b"})
	if err != nil {
		t.Fatalf("HashObserved: %v", err)
	}
	if h == "" {
		t.Error("want non-empty hash")
	}
}

func TestJoinComma(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"a"}, "a"},
		{[]string{"a", "b", "c"}, "a,b,c"},
	}
	for _, c := range cases {
		if got := joinComma(c.in); got != c.want {
			t.Errorf("joinComma(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func mustMarshal(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// ============================================================================
// Store: intents
// ============================================================================

func TestStore_CreateAndGetIntent(t *testing.T) {
	f := newMeshFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	in := &Intent{
		ID: "i1", Kind: "preauth_key", Name: "x",
		Enabled:   true,
		Spec:      json.RawMessage(`{"user":"u"}`),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := f.store.CreateIntent(f.ctx, in); err != nil {
		t.Fatalf("CreateIntent: %v", err)
	}
	got, err := f.store.GetIntent(f.ctx, "i1")
	if err != nil {
		t.Fatalf("GetIntent: %v", err)
	}
	if got == nil || got.Name != "x" {
		t.Errorf("not found / wrong: %+v", got)
	}
	if !got.Enabled {
		t.Error("Enabled bit lost")
	}
}

func TestStore_GetIntent_NotFound(t *testing.T) {
	f := newMeshFixture(t)
	got, err := f.store.GetIntent(f.ctx, "no")
	if err != nil {
		t.Fatalf("GetIntent: %v", err)
	}
	if got != nil {
		t.Errorf("want nil, got %+v", got)
	}
}

func TestStore_SetIntentHSRef(t *testing.T) {
	f := newMeshFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	in := &Intent{ID: "i1", Kind: "preauth_key", Name: "x", Spec: json.RawMessage(`{}`), CreatedAt: now, UpdatedAt: now}
	_ = f.store.CreateIntent(f.ctx, in)
	if err := f.store.SetIntentHSRef(f.ctx, "i1", "hsid", "value"); err != nil {
		t.Fatalf("SetIntentHSRef: %v", err)
	}
	got, _ := f.store.GetIntent(f.ctx, "i1")
	if got.HSID != "hsid" || got.HSValue != "value" {
		t.Errorf("HS ref: %+v", got)
	}
}

func TestStore_DeleteIntent(t *testing.T) {
	f := newMeshFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	_ = f.store.CreateIntent(f.ctx, &Intent{ID: "i1", Kind: "x", Name: "x", Spec: json.RawMessage(`{}`), CreatedAt: now, UpdatedAt: now})
	if err := f.store.DeleteIntent(f.ctx, "i1"); err != nil {
		t.Fatalf("DeleteIntent: %v", err)
	}
	if err := f.store.DeleteIntent(f.ctx, "i1"); err == nil {
		t.Error("expected error on double delete")
	}
}

func TestStore_ListIntents(t *testing.T) {
	f := newMeshFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	_ = f.store.CreateIntent(f.ctx, &Intent{ID: "a", Kind: "preauth_key", Name: "a",
		Spec: json.RawMessage(`{}`), CreatedAt: now, UpdatedAt: now})
	_ = f.store.CreateIntent(f.ctx, &Intent{ID: "b", Kind: "subnet_route", Name: "b",
		Spec: json.RawMessage(`{}`), CreatedAt: now.Add(time.Second), UpdatedAt: now.Add(time.Second)})

	all, err := f.store.ListIntents(f.ctx)
	if err != nil {
		t.Fatalf("ListIntents: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("want 2, got %d", len(all))
	}
}

func TestStore_ListIntentsByKind(t *testing.T) {
	f := newMeshFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	_ = f.store.CreateIntent(f.ctx, &Intent{ID: "a", Kind: "preauth_key", Name: "a",
		Spec: json.RawMessage(`{}`), CreatedAt: now, UpdatedAt: now})
	_ = f.store.CreateIntent(f.ctx, &Intent{ID: "b", Kind: "subnet_route", Name: "b",
		Spec: json.RawMessage(`{}`), CreatedAt: now, UpdatedAt: now})

	keys, err := f.store.ListIntentsByKind(f.ctx, "preauth_key")
	if err != nil {
		t.Fatalf("ListIntentsByKind: %v", err)
	}
	if len(keys) != 1 || keys[0].ID != "a" {
		t.Errorf("filter: %+v", keys)
	}
}

// ============================================================================
// Store: state
// ============================================================================

func TestStore_GetState_EmptyRow(t *testing.T) {
	f := newMeshFixture(t)
	st, err := f.store.GetState(f.ctx)
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if st.IntentHash != "" || st.ObservedHash != "" {
		t.Errorf("expected empty state, got %+v", st)
	}
	if st.Drift {
		t.Error("Drift should be false when both hashes empty")
	}
}

func TestStore_UpdateAfterApply(t *testing.T) {
	f := newMeshFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := f.store.UpdateAfterApply(f.ctx, "hash-1", now); err != nil {
		t.Fatalf("UpdateAfterApply: %v", err)
	}
	st, _ := f.store.GetState(f.ctx)
	if st.IntentHash != "hash-1" {
		t.Errorf("IntentHash: %q", st.IntentHash)
	}
	if st.LastApplied == nil || !st.LastApplied.Equal(now) {
		t.Errorf("LastApplied: %v", st.LastApplied)
	}
	if st.Drift {
		t.Error("after apply: observed = intent, no drift")
	}
}

func TestStore_UpdateAfterReconcile_Drift(t *testing.T) {
	f := newMeshFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	_ = f.store.UpdateAfterApply(f.ctx, "intent-A", now)
	_ = f.store.UpdateAfterReconcile(f.ctx, "observed-B", now)
	st, _ := f.store.GetState(f.ctx)
	if !st.Drift {
		t.Errorf("expected drift: %+v", st)
	}
	if st.LastReconciled == nil {
		t.Error("LastReconciled missing")
	}
}

// ============================================================================
// Store: devices
// ============================================================================

func TestStore_UpsertAndListDevices(t *testing.T) {
	f := newMeshFixture(t)
	d := &Device{
		HSID: "hs-1", User: "u", Hostname: "rasp-1", TailnetIP: "100.64.0.1",
		Tags: []string{"tag:rasputin-node"}, AdvertisedRoutes: []string{"10.0.0.0/24"},
		RasputinNodeID: "rasp-1", Kind: "rasputin",
	}
	if err := f.store.UpsertDevice(f.ctx, d); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	all, err := f.store.ListDevices(f.ctx)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(all) != 1 || all[0].Hostname != "rasp-1" {
		t.Fatalf("ListDevices: %+v", all)
	}
	if len(all[0].Tags) != 1 || all[0].Tags[0] != "tag:rasputin-node" {
		t.Errorf("tags round-trip: %+v", all[0].Tags)
	}
}

func TestStore_DeleteDevice(t *testing.T) {
	f := newMeshFixture(t)
	d := &Device{HSID: "hs-1", User: "u", Hostname: "x", Kind: "user"}
	_ = f.store.UpsertDevice(f.ctx, d)
	if err := f.store.DeleteDevice(f.ctx, "hs-1"); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}
	if err := f.store.DeleteDevice(f.ctx, "hs-1"); err == nil {
		t.Error("want error on double delete")
	}
}

// ============================================================================
// Service: Start / Stop / EnsureUser
// ============================================================================

func TestService_DefaultsApplied(t *testing.T) {
	f := newMeshFixture(t)
	if f.svc.cfg.DefaultUser == "" {
		t.Error("DefaultUser default not applied")
	}
	if f.svc.cfg.ReconcileInterval == 0 {
		t.Error("ReconcileInterval default not applied")
	}
}

func TestService_StartCallsEnsureUser(t *testing.T) {
	f := newMeshFixture(t)
	if err := f.svc.Start(f.ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if f.client.ensureUserCalls != 1 {
		t.Errorf("EnsureUser calls: want 1, got %d", f.client.ensureUserCalls)
	}
	f.svc.Stop()
}

func TestService_Start_SupervisorErrPropagates(t *testing.T) {
	f := newMeshFixture(t)
	svc := NewService(Config{}, f.store, f.client, &failingSupervisor{err: errFake})
	if err := svc.Start(f.ctx); err == nil {
		t.Error("want error from supervisor")
	}
}

var errFake = fakeErr("boom")

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

func TestService_Accessors(t *testing.T) {
	f := newMeshFixture(t)
	if f.svc.Config().DefaultUser == "" {
		t.Error("Config() missing default user")
	}
	if f.svc.Client() != f.client {
		t.Error("Client accessor mismatch")
	}
	if f.svc.Store() != f.store {
		t.Error("Store accessor mismatch")
	}
}

// ============================================================================
// NoopSupervisor
// ============================================================================

func TestNoopSupervisor_StartHealthyStop(t *testing.T) {
	s := NewNoopSupervisor()
	if err := s.Start(context.Background()); err != nil {
		t.Errorf("Start: %v", err)
	}
	// Second start is a no-op log.
	if err := s.Start(context.Background()); err != nil {
		t.Errorf("Start (second): %v", err)
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Errorf("Stop: %v", err)
	}
	ok, err := s.Healthy(context.Background())
	if err != nil {
		t.Errorf("Healthy: %v", err)
	}
	if !ok {
		t.Error("want healthy=true")
	}
}

// ============================================================================
// applyCompile / applyPushKeys / applyPushRoutes / applyRecord
// ============================================================================

func TestApplyCompile_EmptyStore(t *testing.T) {
	f := newMeshFixture(t)
	step := applyCompile(f.svc)
	out, err := step(stepCtx(f.ctx, f.nc, struct{}{}))
	if err != nil {
		t.Fatalf("applyCompile: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected output")
	}
}

func TestApplyPushKeys_MintsForUnsetIntents(t *testing.T) {
	f := newMeshFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	intent := &Intent{
		ID: "k1", Kind: string(proto.IntentPreAuthKey), Name: "primary",
		Enabled:   true,
		Spec:      mustMarshal(t, proto.PreAuthKeySpec{User: "u1", ExpiresIn: "24h"}),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := f.store.CreateIntent(f.ctx, intent); err != nil {
		t.Fatalf("CreateIntent: %v", err)
	}
	step := applyPushKeys(f.svc)
	if _, err := step(stepCtx(f.ctx, f.nc, struct{}{})); err != nil {
		t.Fatalf("applyPushKeys: %v", err)
	}
	if f.client.createCalls != 1 {
		t.Errorf("CreateKey calls: want 1, got %d", f.client.createCalls)
	}
	got, _ := f.store.GetIntent(f.ctx, "k1")
	if got.HSID == "" || got.HSValue == "" {
		t.Errorf("HS ref not persisted: %+v", got)
	}
}

func TestApplyPushKeys_SkipsExistingKeys(t *testing.T) {
	f := newMeshFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	intent := &Intent{
		ID: "k1", Kind: string(proto.IntentPreAuthKey), Name: "primary",
		Enabled: true,
		Spec:    mustMarshal(t, proto.PreAuthKeySpec{User: "u1", ExpiresIn: "24h"}),
		HSID:    "existing", HSValue: "existing-value",
		CreatedAt: now, UpdatedAt: now,
	}
	_ = f.store.CreateIntent(f.ctx, intent)
	step := applyPushKeys(f.svc)
	if _, err := step(stepCtx(f.ctx, f.nc, struct{}{})); err != nil {
		t.Fatalf("applyPushKeys: %v", err)
	}
	if f.client.createCalls != 0 {
		t.Errorf("should skip already-minted: %d calls", f.client.createCalls)
	}
}

func TestApplyPushRoutes_SkipsUnenrolledNode(t *testing.T) {
	f := newMeshFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	_ = f.store.CreateIntent(f.ctx, &Intent{
		ID: "r1", Kind: string(proto.IntentSubnetRoute), Name: "lan",
		Enabled:   true,
		Spec:      mustMarshal(t, proto.SubnetRouteSpec{NodeID: "n1", CIDR: "10.0.0.0/24"}),
		CreatedAt: now, UpdatedAt: now,
	})
	// No device with rasputin_node_id=n1 → skip.
	step := applyPushRoutes(f.svc, nil)
	if _, err := step(stepCtx(f.ctx, f.nc, struct{}{})); err != nil {
		t.Fatalf("applyPushRoutes: %v", err)
	}
	if f.client.setRoutesCalls != 0 {
		t.Errorf("expected 0 setroute calls, got %d", f.client.setRoutesCalls)
	}
}

func TestApplyPushRoutes_AppliesWhenDevicePresent(t *testing.T) {
	f := newMeshFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	_ = f.store.CreateIntent(f.ctx, &Intent{
		ID: "r1", Kind: string(proto.IntentSubnetRoute), Name: "lan",
		Enabled:   true,
		Spec:      mustMarshal(t, proto.SubnetRouteSpec{NodeID: "n1", CIDR: "10.0.0.0/24"}),
		CreatedAt: now, UpdatedAt: now,
	})
	// Pre-register the device with the Rasputin ID.
	_ = f.store.UpsertDevice(f.ctx, &Device{
		HSID: "hs-n1", User: "u", Hostname: "n1",
		RasputinNodeID: "n1", Kind: "rasputin",
	})
	step := applyPushRoutes(f.svc, nil)
	if _, err := step(stepCtx(f.ctx, f.nc, struct{}{})); err != nil {
		t.Fatalf("applyPushRoutes: %v", err)
	}
	if f.client.setRoutesCalls != 1 {
		t.Errorf("setroute calls: %d", f.client.setRoutesCalls)
	}
}

func TestApplyPushRoutes_NoIntents(t *testing.T) {
	f := newMeshFixture(t)
	step := applyPushRoutes(f.svc, nil)
	if _, err := step(stepCtx(f.ctx, f.nc, struct{}{})); err != nil {
		t.Fatalf("applyPushRoutes: %v", err)
	}
}

func TestApplyRecord_PersistsHash(t *testing.T) {
	f := newMeshFixture(t)
	step := applyRecord(f.svc, f.nc)
	if _, err := step(stepCtx(f.ctx, f.nc, struct{}{})); err != nil {
		t.Fatalf("applyRecord: %v", err)
	}
	st, _ := f.store.GetState(f.ctx)
	if st.IntentHash == "" {
		t.Error("IntentHash not persisted")
	}
}

// ============================================================================
// reconcileFetch / reconcileCompare
// ============================================================================

func TestReconcileFetch_PullsHeadscaleState(t *testing.T) {
	f := newMeshFixture(t)
	// Seed fake client with one node so the reconcile populates mesh_devices.
	f.client.mu.Lock()
	f.client.nodes["hs-1"] = HSNode{
		ID: "hs-1", User: "u", Hostname: "rasp-1",
		IPv4:             "100.64.0.1",
		AdvertisedRoutes: []string{"10.0.0.0/24"},
		LastSeen:         time.Now().UTC(),
		RegisteredAt:     time.Now().UTC(),
	}
	f.client.mu.Unlock()
	step := reconcileFetch(f.svc, f.nc)
	if _, err := step(stepCtx(f.ctx, f.nc, struct{}{})); err != nil {
		t.Fatalf("reconcileFetch: %v", err)
	}
	st, _ := f.store.GetState(f.ctx)
	if st.ObservedHash == "" {
		t.Error("ObservedHash not persisted")
	}
	devices, _ := f.store.ListDevices(f.ctx)
	if len(devices) != 1 {
		t.Errorf("device sync: want 1, got %d", len(devices))
	}
}

func TestReconcileCompare_UnstartedState(t *testing.T) {
	f := newMeshFixture(t)
	// No apply has run → IntentHash is empty.
	step := reconcileCompare(f.svc, f.nc)
	out, err := step(stepCtx(f.ctx, f.nc, struct{}{}))
	if err != nil {
		t.Fatalf("reconcileCompare: %v", err)
	}
	var resp map[string]any
	_ = json.Unmarshal(out, &resp)
	if resp["unstarted"] != true {
		t.Errorf("unstarted: %+v", resp)
	}
}

func TestReconcileCompare_InSync(t *testing.T) {
	f := newMeshFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	_ = f.store.UpdateAfterApply(f.ctx, "h", now)
	step := reconcileCompare(f.svc, f.nc)
	out, err := step(stepCtx(f.ctx, f.nc, struct{}{}))
	if err != nil {
		t.Fatalf("reconcileCompare: %v", err)
	}
	var resp map[string]any
	_ = json.Unmarshal(out, &resp)
	if resp["drift"] == true {
		t.Errorf("expected no drift: %+v", resp)
	}
}

func TestReconcileCompare_DriftSurfaces(t *testing.T) {
	f := newMeshFixture(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	_ = f.store.UpdateAfterApply(f.ctx, "intent-A", now)
	_ = f.store.UpdateAfterReconcile(f.ctx, "observed-B", now)
	step := reconcileCompare(f.svc, f.nc)
	out, _ := step(stepCtx(f.ctx, f.nc, struct{}{}))
	var resp map[string]any
	_ = json.Unmarshal(out, &resp)
	if resp["drift"] != true {
		t.Errorf("want drift=true, got %+v", resp)
	}
}

// ============================================================================
// Workflows: constructor smoke
// ============================================================================

func TestWorkflowConstructors_Kinds(t *testing.T) {
	f := newMeshFixture(t)
	if wf := ApplyWorkflow(f.svc, nil, f.nc); wf.Kind != "mesh.apply" {
		t.Errorf("ApplyWorkflow.Kind = %q", wf.Kind)
	}
	if wf := ReconcileWorkflow(f.svc, f.nc); wf.Kind != "mesh.reconcile" {
		t.Errorf("ReconcileWorkflow.Kind = %q", wf.Kind)
	}
	if wf := EnrollNodeWorkflow(f.svc, nil, f.nc); wf.Kind != "mesh.enroll_node" {
		t.Errorf("EnrollNodeWorkflow.Kind = %q", wf.Kind)
	}
}

// ============================================================================
// Misc helpers
// ============================================================================

func TestParseExpiry(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 24 * time.Hour},
		{"5m", 5 * time.Minute},
		{"not a duration", 24 * time.Hour},
		{"-1h", 24 * time.Hour},
	}
	for _, tc := range cases {
		if got := parseExpiry(tc.in); got != tc.want {
			t.Errorf("parseExpiry(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSimpleHash_StableNonNegative(t *testing.T) {
	a := simpleHash("foo")
	b := simpleHash("foo")
	if a != b {
		t.Errorf("not stable: %d vs %d", a, b)
	}
	if a < 0 {
		t.Errorf("negative: %d", a)
	}
}

func TestShort_Mesh(t *testing.T) {
	if got := short("0123456789abcd"); got != "0123456789ab" {
		t.Errorf("short long: %q", got)
	}
	if got := short("abc"); got != "abc" {
		t.Errorf("short short: %q", got)
	}
}

func TestMatchesRasputinHostname(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"node-1", true},
		{"rasp-1", true},
		{"fw-edge", true},
		{"cp-main", true},
		{"foo", false},
		{"", false},
		{"node", false}, // exactly len(prefix), no body
	}
	for _, tc := range cases {
		if got := matchesRasputinHostname(tc.in); got != tc.want {
			t.Errorf("matchesRasputinHostname(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestPublishChange_Mesh(t *testing.T) {
	f := newMeshFixture(t)
	sub, _ := f.nc.SubscribeSync(proto.MeshChangeSubject("global", proto.MeshApplied))
	publishChange(f.nc, proto.MeshChangeEvt{
		Scope: "global", Change: proto.MeshApplied, Ts: time.Now().UTC(),
	})
	if _, err := sub.NextMsg(time.Second); err != nil {
		t.Errorf("publish didn't land: %v", err)
	}
}

func TestPublishChange_DefaultsScope(t *testing.T) {
	f := newMeshFixture(t)
	sub, _ := f.nc.SubscribeSync(proto.MeshChangeSubject("global", proto.MeshApplied))
	// Scope empty → falls back to "global".
	publishChange(f.nc, proto.MeshChangeEvt{Change: proto.MeshApplied, Ts: time.Now().UTC()})
	if _, err := sub.NextMsg(time.Second); err != nil {
		t.Errorf("publish didn't land: %v", err)
	}
}

func TestMsRoundTrip_Mesh(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	if got := fromMs(ms(now)); !got.Equal(now) {
		t.Errorf("round-trip: %v vs %v", now, got)
	}
}

func TestBoolToInt_Mesh(t *testing.T) {
	if boolToInt(true) != 1 || boolToInt(false) != 0 {
		t.Error("boolToInt")
	}
}

// ============================================================================
// MockClient (the in-repo file-backed implementation)
// ============================================================================

func TestMockClient_BasicFlow(t *testing.T) {
	dir := t.TempDir()
	mc, err := NewMockClient(dir)
	if err != nil {
		t.Fatalf("NewMockClient: %v", err)
	}
	if mc.Backend() != "mock" {
		t.Errorf("Backend: %q", mc.Backend())
	}
	ctx := context.Background()
	if err := mc.EnsureUser(ctx, "alice"); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	// Idempotent.
	if err := mc.EnsureUser(ctx, "alice"); err != nil {
		t.Fatalf("EnsureUser repeat: %v", err)
	}

	id, value, err := mc.CreatePreAuthKey(ctx, CreatePreAuthKeyInput{
		User: "alice", Reusable: true, Tags: []string{"b", "a"},
		Expiry: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreatePreAuthKey: %v", err)
	}
	if id == "" || value == "" {
		t.Errorf("empty id/value: %q %q", id, value)
	}

	keys, err := mc.ListPreAuthKeys(ctx, "alice")
	if err != nil {
		t.Fatalf("ListPreAuthKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("want 1 key, got %d", len(keys))
	}
	// Tags sorted ascending.
	if len(keys[0].Tags) != 2 || keys[0].Tags[0] != "a" || keys[0].Tags[1] != "b" {
		t.Errorf("tags not sorted: %+v", keys[0].Tags)
	}

	// Filter by other user → empty.
	other, _ := mc.ListPreAuthKeys(ctx, "nobody")
	if len(other) != 0 {
		t.Errorf("user filter leak: %+v", other)
	}

	if err := mc.ExpirePreAuthKey(ctx, id); err != nil {
		t.Fatalf("ExpirePreAuthKey: %v", err)
	}
	expiredKeys, _ := mc.ListPreAuthKeys(ctx, "")
	if !time.Now().After(expiredKeys[0].Expiration) {
		t.Errorf("not expired: %v", expiredKeys[0].Expiration)
	}
}

func TestMockClient_ExpireUnknownKey(t *testing.T) {
	mc, _ := NewMockClient(t.TempDir())
	if err := mc.ExpirePreAuthKey(context.Background(), "no-such-key"); err == nil {
		t.Error("want error for unknown key")
	}
}

func TestMockClient_NodesAndRoutes(t *testing.T) {
	mc, _ := NewMockClient(t.TempDir())
	if err := mc.UpsertMockNode(HSNode{User: "u", Hostname: "node-1"}); err != nil {
		t.Fatalf("UpsertMockNode: %v", err)
	}
	nodes, err := mc.ListNodes(context.Background())
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}
	if nodes[0].ID == "" {
		t.Error("UpsertMockNode should have derived a stable id")
	}

	if err := mc.SetNodeRoutes(context.Background(), nodes[0].ID, []string{"10.0.0.0/24", "192.168.1.0/24"}); err != nil {
		t.Fatalf("SetNodeRoutes: %v", err)
	}
	updated, _ := mc.ListNodes(context.Background())
	if len(updated[0].ApprovedRoutes) != 2 {
		t.Errorf("ApprovedRoutes: %+v", updated[0].ApprovedRoutes)
	}
}

func TestMockClient_SetRoutesUnknownNode(t *testing.T) {
	mc, _ := NewMockClient(t.TempDir())
	if err := mc.SetNodeRoutes(context.Background(), "no-such-node", []string{"10.0.0.0/24"}); err == nil {
		t.Error("want error for unknown node")
	}
}

func TestMockClient_PersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	mc1, _ := NewMockClient(dir)
	_ = mc1.EnsureUser(context.Background(), "alice")
	_, _, _ = mc1.CreatePreAuthKey(context.Background(), CreatePreAuthKeyInput{
		User: "alice", Expiry: time.Now().Add(time.Hour),
	})

	mc2, err := NewMockClient(dir)
	if err != nil {
		t.Fatalf("NewMockClient (reopen): %v", err)
	}
	keys, _ := mc2.ListPreAuthKeys(context.Background(), "")
	if len(keys) != 1 {
		t.Errorf("persistence: want 1 key, got %d", len(keys))
	}
}

// TestEnrollWorkflow_KeyChainsAcrossSteps drives all three enroll steps the
// way the saga runner does — every step gets the ORIGINAL job spec, and
// prior step results accumulate in PriorResults keyed by step name. The
// regression this guards: dispatch used to re-parse the spec instead of
// mint_key's result, so the agent received an empty auth key ("agent
// rejected enroll: tailscale mock: empty auth key" — first Mu wizard run,
// 2026-06-12).
func TestEnrollWorkflow_KeyChainsAcrossSteps(t *testing.T) {
	f := newMeshFixture(t)

	// Fake agent on the embedded bus: capture the dispatched cmd, ack OK.
	gotKey := make(chan string, 1)
	sub, err := f.nc.Subscribe(proto.MeshEnrollSubject("node-1"), func(m *nats.Msg) {
		var cmd proto.MeshEnrollCmd
		_ = json.Unmarshal(m.Data, &cmd)
		gotKey <- cmd.AuthKey
		ack, _ := json.Marshal(proto.MeshEnrollAck{
			OK: true, TailnetID: "hs-42", TailnetIP: "100.64.0.9", Backend: "test",
		})
		_ = m.Respond(ack)
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	wf := EnrollNodeWorkflow(f.svc, nil, f.nc)
	spec, _ := json.Marshal(EnrollSpec{NodeID: "node-1"})
	prior := map[string]json.RawMessage{}
	for _, st := range wf.Steps {
		sc := &jobs.StepCtx{
			Ctx:          f.ctx,
			JobID:        "test-job",
			Spec:         spec, // original spec every step — runner semantics
			NATS:         f.nc,
			PriorResults: prior,
			Log:          func(string, string) {},
		}
		res, err := st.Do(sc)
		if err != nil {
			t.Fatalf("step %s: %v", st.Name, err)
		}
		if res != nil {
			prior[st.Name] = res
		}
	}

	select {
	case k := <-gotKey:
		if k == "" {
			t.Fatal("dispatch sent an empty auth key — mint_key's result was not chained forward")
		}
	default:
		t.Fatal("agent never received the enroll cmd")
	}

	devices, err := f.store.ListDevices(f.ctx)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devices) != 1 || devices[0].HSID != "hs-42" || devices[0].RasputinNodeID != "node-1" {
		t.Fatalf("record step: want one device hs-42/node-1, got %+v", devices)
	}
}
