package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(context.Background(), filepath.Join(dir, "apps.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// makeApp builds an app suitable for Store.Create. Important gotcha: Create
// persists only declarative fields (ID/Name/ComposeYAML/TargetNode/LastStatus
// /Created/Updated). LastDetail/LastDeployed/LastStopped/LastStatusAt are
// populated by RecordStatus. Fixtures must mirror this two-step shape.
func makeApp(id, name string) *App {
	now := time.Now().UTC()
	return &App{
		ID:          id,
		Name:        name,
		ComposeYAML: "services: {}",
		TargetNode:  "node-test",
		LastStatus:  proto.AppStatusUnknown,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// ============================================================================
// Store: Create / Get / GetByName
// ============================================================================

func TestStore_CreateAndGet(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	want := makeApp("a-1", "minecraft")
	if err := s.Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Get(ctx, "a-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil for known id")
	}
	if got.Name != "minecraft" || got.TargetNode != "node-test" {
		t.Errorf("scalar mismatch: %+v", got)
	}
	if got.LastStatus != proto.AppStatusUnknown {
		t.Errorf("LastStatus: got %q", got.LastStatus)
	}
	// Create does NOT populate status-related fields:
	if got.LastDetail != "" || got.LastStatusAt != nil || got.LastDeployed != nil || got.LastStopped != nil {
		t.Errorf("Create should leave status-derived fields zero, got %+v", got)
	}
}

func TestStore_GetByName(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.Create(ctx, makeApp("a-1", "minecraft")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.GetByName(ctx, "minecraft")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if got == nil || got.ID != "a-1" {
		t.Errorf("GetByName: got %+v", got)
	}

	none, err := s.GetByName(ctx, "no-such")
	if err != nil {
		t.Fatalf("GetByName unknown: %v", err)
	}
	if none != nil {
		t.Errorf("want nil for unknown, got %+v", none)
	}
}

func TestStore_Create_DuplicateNameIsError(t *testing.T) {
	// The schema has a UNIQUE on name.
	ctx := context.Background()
	s := newStore(t)
	if err := s.Create(ctx, makeApp("a", "minecraft")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if err := s.Create(ctx, makeApp("b", "minecraft")); err == nil {
		t.Error("duplicate name: want error, got nil")
	}
}

// ============================================================================
// Store: Update
// ============================================================================

func TestStore_Update(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	a := makeApp("a", "name1")
	if err := s.Create(ctx, a); err != nil {
		t.Fatalf("Create: %v", err)
	}
	a.Name = "name2"
	a.ComposeYAML = "services: web: { image: nginx }"
	a.TargetNode = "node-y"
	a.UpdatedAt = a.UpdatedAt.Add(1 * time.Second)
	if err := s.Update(ctx, a); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := s.Get(ctx, "a")
	if got.Name != "name2" || got.TargetNode != "node-y" {
		t.Errorf("Update lost fields: %+v", got)
	}
}

func TestStore_Update_UnknownIsErrNoRows(t *testing.T) {
	s := newStore(t)
	err := s.Update(context.Background(), makeApp("ghost", "g"))
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("want sql.ErrNoRows, got %v", err)
	}
}

// ============================================================================
// Store: Delete
// ============================================================================

func TestStore_Delete(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.Create(ctx, makeApp("a", "x")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Delete(ctx, "a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, _ := s.Get(ctx, "a")
	if got != nil {
		t.Errorf("after Delete: got %+v", got)
	}
}

func TestStore_Delete_UnknownIsErrNoRows(t *testing.T) {
	s := newStore(t)
	err := s.Delete(context.Background(), "ghost")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("want sql.ErrNoRows, got %v", err)
	}
}

// ============================================================================
// Store: List
// ============================================================================

func TestStore_List_OrderedByCreatedAt(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	base := time.Now().UTC()
	for i, id := range []string{"c", "a", "b"} {
		app := makeApp(id, "n-"+id)
		app.CreatedAt = base.Add(time.Duration(i) * time.Second)
		app.UpdatedAt = app.CreatedAt
		if err := s.Create(ctx, app); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	got, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3, got %d", len(got))
	}
	// Ordered ASC by created_at → insertion order: c, a, b.
	if got[0].ID != "c" || got[1].ID != "a" || got[2].ID != "b" {
		t.Errorf("List order: %s %s %s", got[0].ID, got[1].ID, got[2].ID)
	}
}

func TestStore_List_Empty(t *testing.T) {
	s := newStore(t)
	got, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty, got %d", len(got))
	}
}

// ============================================================================
// Store: RecordStatus — the side that Create does NOT write.
// ============================================================================

func TestStore_RecordStatus_FailedSetsDetailButNotDeployStop(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.Create(ctx, makeApp("a", "x")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	now := time.Now().UTC()
	if err := s.RecordStatus(ctx, "a", proto.AppStatusFailed, "container exit 1", now); err != nil {
		t.Fatalf("RecordStatus: %v", err)
	}
	got, _ := s.Get(ctx, "a")
	if got.LastStatus != proto.AppStatusFailed {
		t.Errorf("LastStatus: %q", got.LastStatus)
	}
	if got.LastDetail != "container exit 1" {
		t.Errorf("LastDetail: %q", got.LastDetail)
	}
	if got.LastStatusAt == nil || got.LastStatusAt.UnixMilli() != now.UnixMilli() {
		t.Errorf("LastStatusAt: %v", got.LastStatusAt)
	}
	if got.LastDeployed != nil {
		t.Errorf("Failed status should not set LastDeployed, got %v", got.LastDeployed)
	}
	if got.LastStopped != nil {
		t.Errorf("Failed status should not set LastStopped, got %v", got.LastStopped)
	}
}

func TestStore_RecordStatus_RunningSetsLastDeployed(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.Create(ctx, makeApp("a", "x")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	now := time.Now().UTC()
	if err := s.RecordStatus(ctx, "a", proto.AppStatusRunning, "", now); err != nil {
		t.Fatalf("RecordStatus: %v", err)
	}
	got, _ := s.Get(ctx, "a")
	if got.LastStatus != proto.AppStatusRunning {
		t.Errorf("LastStatus: %q", got.LastStatus)
	}
	if got.LastDeployed == nil || got.LastDeployed.UnixMilli() != now.UnixMilli() {
		t.Errorf("Running should set LastDeployed, got %v", got.LastDeployed)
	}
	if got.LastStopped != nil {
		t.Errorf("Running should not set LastStopped, got %v", got.LastStopped)
	}
}

func TestStore_RecordStatus_StoppedSetsLastStopped(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.Create(ctx, makeApp("a", "x")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	now := time.Now().UTC()
	if err := s.RecordStatus(ctx, "a", proto.AppStatusStopped, "", now); err != nil {
		t.Fatalf("RecordStatus: %v", err)
	}
	got, _ := s.Get(ctx, "a")
	if got.LastStopped == nil {
		t.Error("Stopped should set LastStopped")
	}
	if got.LastDeployed != nil {
		t.Errorf("Stopped should not set LastDeployed, got %v", got.LastDeployed)
	}
}

func TestStore_RecordStatus_UnknownAppIsErrNoRows(t *testing.T) {
	s := newStore(t)
	err := s.RecordStatus(context.Background(), "ghost", proto.AppStatusRunning, "", time.Now())
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("want sql.ErrNoRows, got %v", err)
	}
}

// ============================================================================
// joinCols helper
// ============================================================================

func TestJoinCols(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{"a"}, "a"},
		{[]string{"a", "b"}, "a, b"},
		{[]string{"a", "b", "c"}, "a, b, c"},
	}
	for _, tc := range cases {
		if got := joinCols(tc.in); got != tc.want {
			t.Errorf("joinCols(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ============================================================================
// Pure helpers from jobs.go (don't need NATS or inventory).
// ============================================================================

func TestParseSpec(t *testing.T) {
	got, err := parseSpec(json.RawMessage(`{"appId":"a-1"}`))
	if err != nil {
		t.Fatalf("parseSpec: %v", err)
	}
	if got.AppID != "a-1" {
		t.Errorf("AppID: %q", got.AppID)
	}

	if _, err := parseSpec(json.RawMessage(`{}`)); err == nil {
		t.Error("missing appId: want error")
	}
	if _, err := parseSpec(json.RawMessage(`not-json`)); err == nil {
		t.Error("bad JSON: want error")
	}
}

func TestComputeNodeStatus(t *testing.T) {
	now := time.Now()
	cases := []struct {
		gap  time.Duration
		want proto.NodeStatus
	}{
		{0, proto.StatusOnline},
		{29 * time.Second, proto.StatusOnline},
		{30 * time.Second, proto.StatusStale},
		{119 * time.Second, proto.StatusStale},
		{2 * time.Minute, proto.StatusOffline},
		{1 * time.Hour, proto.StatusOffline},
	}
	for _, tc := range cases {
		got := computeNodeStatus(now.Add(-tc.gap))
		if got != tc.want {
			t.Errorf("computeNodeStatus(gap=%v) = %q, want %q", tc.gap, got, tc.want)
		}
	}
}

// ============================================================================
// loadApp + deployLoad/stopLoad — exercisable without NATS because they only
// read from the store/inventory and write to the log. Everything past that
// (deployPush/stopPush) calls nc.RequestWithContext which needs a real bus.
// ============================================================================

// newInventory is a tiny helper that mirrors apps' fixture but for inventory.
func newInventory(t *testing.T) *inventory.Store {
	t.Helper()
	dir := t.TempDir()
	inv, err := inventory.OpenStore(context.Background(), filepath.Join(dir, "inv.db"))
	if err != nil {
		t.Fatalf("inventory OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	return inv
}

func newStepCtx(spec string) *jobs.StepCtx {
	return &jobs.StepCtx{
		Ctx:   context.Background(),
		JobID: "job-test",
		Spec:  json.RawMessage(spec),
		// Log is captured as a no-op so deployLoad/stopLoad's sc.Log call
		// doesn't panic. NATS is not used in these tests.
		Log: func(level, message string) {},
	}
}

func TestLoadApp_Happy(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	inv := newInventory(t)

	// Register a compute node and a corresponding app.
	if err := inv.Insert(ctx, &proto.Node{
		ID:        "n-x",
		Role:      proto.RoleCompute,
		Hostname:  "x.test",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	a := makeApp("a", "minecraft")
	a.TargetNode = "n-x"
	if err := store.Create(ctx, a); err != nil {
		t.Fatalf("Create app: %v", err)
	}

	sc := newStepCtx(`{"appId":"a"}`)
	got, err := loadApp(sc, store, inv)
	if err != nil {
		t.Fatalf("loadApp: %v", err)
	}
	if got == nil || got.ID != "a" {
		t.Errorf("loadApp got %+v", got)
	}
}

func TestLoadApp_ErrorCases(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	inv := newInventory(t)

	// Set up: app with target node that isn't in inventory yet.
	if err := store.Create(ctx, &App{
		ID:          "a-no-node",
		Name:        "no-node",
		ComposeYAML: "x",
		TargetNode:  "missing-node",
		LastStatus:  proto.AppStatusUnknown,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// And another with target node that exists but with wrong role.
	if err := inv.Insert(ctx, &proto.Node{
		ID: "fw", Role: proto.RoleFirewall, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	if err := store.Create(ctx, &App{
		ID:          "a-wrong-role",
		Name:        "wrong-role",
		ComposeYAML: "x",
		TargetNode:  "fw",
		LastStatus:  proto.AppStatusUnknown,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	cases := []struct {
		name      string
		spec      string
		wantMatch string
	}{
		{"bad spec", `{}`, "appId"},
		{"unknown app", `{"appId":"no-such"}`, "not found"},
		{"target node not registered", `{"appId":"a-no-node"}`, "not registered"},
		{"target node has wrong role", `{"appId":"a-wrong-role"}`, "expected compute or controlplane"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := newStepCtx(tc.spec)
			_, err := loadApp(sc, store, inv)
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantMatch)
			}
			if !strings.Contains(err.Error(), tc.wantMatch) {
				t.Errorf("error: got %q, want substring %q", err.Error(), tc.wantMatch)
			}
		})
	}
}

func TestDeployLoad_And_StopLoad_HappyPath(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	inv := newInventory(t)
	if err := inv.Insert(ctx, &proto.Node{
		ID: "n", Role: proto.RoleControlPlane, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	a := makeApp("a", "x")
	a.TargetNode = "n"
	if err := store.Create(ctx, a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	sc := newStepCtx(`{"appId":"a"}`)

	dRaw, err := deployLoad(store, inv)(sc)
	if err != nil {
		t.Fatalf("deployLoad: %v", err)
	}
	if !strings.Contains(string(dRaw), `"appId":"a"`) {
		t.Errorf("deployLoad result: %s", dRaw)
	}

	sRaw, err := stopLoad(store, inv)(sc)
	if err != nil {
		t.Fatalf("stopLoad: %v", err)
	}
	if !strings.Contains(string(sRaw), `"appId":"a"`) {
		t.Errorf("stopLoad result: %s", sRaw)
	}
}

func TestReconcileList_ReturnsCount(t *testing.T) {
	// reconcileList just lists and returns the count. No NATS, no inventory.
	ctx := context.Background()
	store := newStore(t)
	for _, id := range []string{"a", "b"} {
		if err := store.Create(ctx, makeApp(id, "name-"+id)); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	sc := newStepCtx(`{}`)
	raw, err := reconcileList(store)(sc)
	if err != nil {
		t.Fatalf("reconcileList: %v", err)
	}
	if !strings.Contains(string(raw), `"count":2`) {
		t.Errorf("reconcileList payload: %s", raw)
	}
}

func TestWorkflowShapes(t *testing.T) {
	// nil deps are fine — we only inspect the Workflow struct shape.
	for _, c := range []struct {
		name string
		w    func() interface { /* jobs.Workflow */
		}
	}{} {
		_ = c
	}
	// Direct calls — checking Kind + step names. Even with nil deps the
	// closures are constructed lazily and never invoked here.
	d := DeployWorkflow(nil, nil, nil)
	if d.Kind != "app.deploy" {
		t.Errorf("DeployWorkflow Kind: %q", d.Kind)
	}
	if len(d.Steps) != 2 || d.Steps[0].Name != "load" || d.Steps[1].Name != "push" {
		t.Errorf("DeployWorkflow steps: %+v", d.Steps)
	}

	s := StopWorkflow(nil, nil, nil)
	if s.Kind != "app.stop" {
		t.Errorf("StopWorkflow Kind: %q", s.Kind)
	}

	r := ReconcileWorkflow(nil, nil, nil)
	if r.Kind != "apps.reconcile" {
		t.Errorf("ReconcileWorkflow Kind: %q", r.Kind)
	}
}
