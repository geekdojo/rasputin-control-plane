package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// doorFixture is the projection under test: a real sqlite store, the
// capturing supervisor, cid bench, SelfNodeID cp1, and one app on node-a.
type doorFixture struct {
	svc      *Service
	st       *Store
	cap      *capturingSupervisor
	client   *fakeClient
	withheld bool
	logs     *bytes.Buffer
}

func newDoorFixture(t *testing.T, withheld func(*doorFixture) func() bool) *doorFixture {
	t.Helper()
	st, err := OpenStore(context.Background(), filepath.Join(t.TempDir(), "mesh.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	f := &doorFixture{st: st, cap: &capturingSupervisor{}, client: newFakeClient(), logs: &bytes.Buffer{}}
	cfg := Config{
		ClusterID:   "bench",
		AppDoorHost: proto.SignInFQDN("bench"),
		SelfNodeID:  "cp1",
		Log:         slog.New(slog.NewTextHandler(f.logs, nil)),
	}
	if withheld != nil {
		cfg.AppDoorWithheld = withheld(f)
	}
	f.svc = NewService(cfg, st, f.client, f.cap)
	f.svc.SetAppLister(func() []AppDNS { return []AppDNS{{Name: "jellyfin", TargetNode: "node-a"}} })
	if err := st.UpsertDevice(context.Background(), &Device{HSID: "h-a", RasputinNodeID: "node-a", TailnetIP: "100.64.0.2", Hostname: "a", Tags: []string{}, AdvertisedRoutes: []string{}}); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	return f
}

func (f *doorFixture) predicate() func() bool { return func() bool { return f.withheld } }

// enrol runs the real enrollRecord step for cp1 as device hsID.
func (f *doorFixture) enrol(t *testing.T, hsID, ip string) {
	t.Helper()
	spec, _ := json.Marshal(enrollSession{EnrollSpec: EnrollSpec{NodeID: "cp1"}, HSID: hsID, HSIP: ip})
	sc := &jobs.StepCtx{Ctx: context.Background(), JobID: "j-" + hsID, Spec: spec, Log: func(string, string) {}}
	if _, err := enrollRecord(f.svc, nil)(sc); err != nil {
		t.Fatalf("enrollRecord: %v", err)
	}
}

// TC-983-08 (mesh half) and TC-983-01 (projection key): the bind fact writes
// the door entry in the enrol step itself, with no reconcile tick, and app
// records are unchanged.
func TestEnrollRecord_ProjectsTheAppDoor(t *testing.T) {
	f := newDoorFixture(t, (*doorFixture).predicate)
	f.enrol(t, "h-cp", "100.64.0.5")
	if f.cap.calls != 1 {
		t.Fatalf("projection writes = %d, want 1 from the enrol step", f.cap.calls)
	}
	want := map[string]string{"signin.bench.internal": "100.64.0.5", "jellyfin.bench.internal": "100.64.0.2"}
	if len(f.cap.got) != len(want) {
		t.Fatalf("records = %v, want %v", f.cap.got, want)
	}
	for k, v := range want {
		if f.cap.got[k] != v {
			t.Errorf("records[%q] = %q, want %q", k, f.cap.got[k], v)
		}
	}
	if _, ok := f.cap.got[proto.SignInFQDN("bench")]; !ok {
		t.Errorf("projection key is not proto.SignInFQDN: %v", f.cap.got)
	}

	// Unbind: the device row goes, the next projection omits the door.
	if err := f.st.DeleteDevice(context.Background(), "h-cp"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ReconcileAppDNS(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.cap.got["signin.bench.internal"]; ok || f.cap.got["jellyfin.bench.internal"] != "100.64.0.2" {
		t.Errorf("after unbind records = %v, want only the app record", f.cap.got)
	}
}

// TC-983-08: no tailnet IP, or two bound devices, gives no door entry.
func TestReconcileAppDNS_NoDoorWithoutOneAddressedDevice(t *testing.T) {
	ctx := context.Background()
	t.Run("no tailnet IP", func(t *testing.T) {
		f := newDoorFixture(t, (*doorFixture).predicate)
		f.enrol(t, "h-cp", "")
		if _, ok := f.cap.got["signin.bench.internal"]; ok {
			t.Errorf("door projected with no tailnet IP: %v", f.cap.got)
		}
	})
	t.Run("two bound devices", func(t *testing.T) {
		f := newDoorFixture(t, (*doorFixture).predicate)
		// A legacy database holding two bindings for one node (the unique
		// index could not be built over them), as seedLegacyBinding does.
		if _, err := f.st.db.ExecContext(ctx, `DROP INDEX IF EXISTS ux_mesh_devices_bound_node`); err != nil {
			t.Fatal(err)
		}
		for _, d := range []*Device{
			{HSID: "h1", RasputinNodeID: "cp1", TailnetIP: "100.64.0.5", Tags: []string{}, AdvertisedRoutes: []string{}},
			{HSID: "h2", RasputinNodeID: "cp1", TailnetIP: "100.64.0.6", Tags: []string{}, AdvertisedRoutes: []string{}},
		} {
			if err := upsertDevice(ctx, f.st.db, d); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.svc.ReconcileAppDNS(ctx); err != nil {
			t.Fatal(err)
		}
		if _, ok := f.cap.got["signin.bench.internal"]; ok || f.cap.got["jellyfin.bench.internal"] != "100.64.0.2" {
			t.Errorf("records = %v, want only the app record", f.cap.got)
		}
	})
}

// TC-983-09 / TC-983-10 (mesh half): a withheld door, and a nil predicate,
// project no door entry; the app records stay.
func TestReconcileAppDNS_WithheldDoorFailsClosed(t *testing.T) {
	for name, mk := range map[string]func(*doorFixture) func() bool{
		"withheld":      func(f *doorFixture) func() bool { f.withheld = true; return f.predicate() },
		"nil predicate": nil,
	} {
		t.Run(name, func(t *testing.T) {
			f := newDoorFixture(t, mk)
			f.enrol(t, "h-cp", "100.64.0.5")
			if _, ok := f.cap.got["signin.bench.internal"]; ok {
				t.Errorf("door projected while withheld: %v", f.cap.got)
			}
			if f.cap.got["jellyfin.bench.internal"] != "100.64.0.2" {
				t.Errorf("app record lost: %v", f.cap.got)
			}
		})
	}
}

// TC-983-12: a device named signin or radius is renamed once, with one
// DeviceRenamed call and one WARN; laptop is untouched; a rename error raises
// nothing, logs err, and is retried on the next reconcileFetch.
func TestReconcileFetch_RenamesReservedDevices(t *testing.T) {
	ctx := context.Background()
	f := newDoorFixture(t, nil)
	f.client.nodes["12"] = HSNode{ID: "12", Hostname: "phone", GivenName: "signin"}
	f.client.nodes["13"] = HSNode{ID: "13", Hostname: "box", GivenName: "radius"}
	f.client.nodes["14"] = HSNode{ID: "14", Hostname: "laptop", GivenName: "laptop"}
	var renamed [][3]string
	f.svc.cfg.DeviceRenamed = func(_ context.Context, hsID, from, to string) {
		renamed = append(renamed, [3]string{hsID, from, to})
	}
	run := func() {
		sc := &jobs.StepCtx{Ctx: ctx, JobID: "r", Log: func(string, string) {}}
		if _, err := reconcileFetch(f.svc, nil)(sc); err != nil {
			t.Fatalf("reconcileFetch: %v", err)
		}
	}

	f.client.renameErr = errors.New("headscale said no")
	run()
	if len(renamed) != 0 {
		t.Errorf("DeviceRenamed fired on a failed rename: %v", renamed)
	}
	if !strings.Contains(f.logs.String(), "err=\"headscale said no\"") {
		t.Errorf("no WARN with err for the failed rename:\n%s", f.logs)
	}

	f.client.renameErr = nil
	f.client.renames = nil
	f.logs.Reset()
	run()
	wantCalls := [][2]string{{"12", "signin-12"}, {"13", "radius-13"}}
	if len(f.client.renames) != 2 || f.client.renames[0] != wantCalls[0] || f.client.renames[1] != wantCalls[1] {
		t.Fatalf("renames on retry = %v, want %v", f.client.renames, wantCalls)
	}
	if len(renamed) != 2 || renamed[0] != [3]string{"12", "signin", "signin-12"} || renamed[1] != [3]string{"13", "radius", "radius-13"} {
		t.Fatalf("DeviceRenamed = %v", renamed)
	}
	if n := strings.Count(f.logs.String(), "tailnet device renamed: reserved name"); n != 2 {
		t.Errorf("rename WARNs = %d, want 2:\n%s", n, f.logs)
	}
	for _, kv := range []string{"level=WARN", "hs_id=12", "from=signin", "to=signin-12"} {
		if !strings.Contains(f.logs.String(), kv) {
			t.Errorf("rename WARN missing %s:\n%s", kv, f.logs)
		}
	}

	// Renamed devices no longer carry the label: a third pass renames nothing.
	f.client.renames = nil
	run()
	if len(f.client.renames) != 0 || len(renamed) != 2 {
		t.Errorf("a renamed device was renamed again: %v", f.client.renames)
	}
}

// TC-983-12: Headscale's node JSON decodes givenName, and falls back to name
// when it is absent.
func TestToHSNode_GivenName(t *testing.T) {
	var n hsNode
	if err := json.Unmarshal([]byte(`{"id":"12","name":"phone","givenName":"signin","ipAddresses":["100.64.0.9"]}`), &n); err != nil {
		t.Fatal(err)
	}
	if got := toHSNode(n); got.GivenName != "signin" || got.Hostname != "phone" {
		t.Errorf("toHSNode = %+v", got)
	}
	if got := toHSNode(hsNode{ID: "1", Name: "phone"}); got.GivenName != "phone" {
		t.Errorf("fallback GivenName = %q, want the name", got.GivenName)
	}
}

// TC-983-12: the placeholder clients refuse a rename with their own errors.
func TestRenameNode_PlaceholderClients(t *testing.T) {
	if err := NewNotReadyClient("headscale").RenameNode(context.Background(), "1", "x"); !errors.Is(err, ErrMeshNotReady) {
		t.Errorf("notReady: %v", err)
	}
	if err := NewUnavailableClient("no docker").RenameNode(context.Background(), "1", "x"); !errors.Is(err, ErrMeshUnavailable) {
		t.Errorf("unavailable: %v", err)
	}
}

// TC-983-12: RealClient renames through POST /api/v1/node/{id}/rename/{name},
// the endpoint capability row T96 records, and reports a refusal.
func TestRealClient_RenameNode(t *testing.T) {
	var got []string
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.Path)
		if fail {
			http.Error(w, `{"code":3,"message":"bad name"}`, http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"node":{"id":"12","givenName":"signin-12"}}`))
	}))
	t.Cleanup(srv.Close)
	c, err := NewRealClient(RealClientConfig{BaseURL: srv.URL, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RenameNode(context.Background(), "12", "signin-12"); err != nil {
		t.Fatalf("RenameNode: %v", err)
	}
	if len(got) != 1 || got[0] != "POST /api/v1/node/12/rename/signin-12" {
		t.Errorf("requests = %v", got)
	}
	fail = true
	if err := c.RenameNode(context.Background(), "12", "signin-12"); err == nil {
		t.Error("a refused rename returned nil")
	}
	if err := c.RenameNode(context.Background(), "", "x"); err == nil {
		t.Error("an empty id was sent")
	}
}
