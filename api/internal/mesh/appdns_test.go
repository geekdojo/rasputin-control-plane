package mesh

import (
	"context"
	"path/filepath"
	"testing"
)

// capturingSupervisor records the last extra_records projection it was handed.
type capturingSupervisor struct {
	NoopSupervisor
	got   map[string]string
	calls int
}

func (c *capturingSupervisor) ReconcileAppRecords(m map[string]string) error {
	c.got = m
	c.calls++
	return nil
}

func newAppDNSService(t *testing.T, sup Supervisor) (*Service, *Store) {
	t.Helper()
	ctx := context.Background()
	st, err := OpenStore(ctx, filepath.Join(t.TempDir(), "mesh.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return NewService(Config{ClusterID: "home1"}, st, newFakeClient(), sup), st
}

func TestReconcileAppDNS_JoinsAndSkips(t *testing.T) {
	ctx := context.Background()
	cap := &capturingSupervisor{}
	svc, st := newAppDNSService(t, cap)

	// node-a enrolled with a tailnet IP; node-b enrolled but no IP yet; node-c
	// not enrolled at all.
	if err := st.UpsertDevice(ctx, &Device{HSID: "h-a", RasputinNodeID: "node-a", TailnetIP: "100.64.0.2", Hostname: "a", Tags: []string{}, AdvertisedRoutes: []string{}}); err != nil {
		t.Fatalf("UpsertDevice a: %v", err)
	}
	if err := st.UpsertDevice(ctx, &Device{HSID: "h-b", RasputinNodeID: "node-b", TailnetIP: "", Hostname: "b", Tags: []string{}, AdvertisedRoutes: []string{}}); err != nil {
		t.Fatalf("UpsertDevice b: %v", err)
	}

	svc.SetAppLister(func() []AppDNS {
		return []AppDNS{
			{Name: "jellyfin", TargetNode: "node-a"}, // → 100.64.0.2
			{Name: "radarr", TargetNode: "node-b"},   // node enrolled, no IP → skip
			{Name: "sonarr", TargetNode: "node-c"},   // unenrolled → skip
			{Name: "", TargetNode: "node-a"},         // empty name → skip
		}
	})

	if err := svc.ReconcileAppDNS(ctx); err != nil {
		t.Fatalf("ReconcileAppDNS: %v", err)
	}
	want := map[string]string{"jellyfin.home1.internal": "100.64.0.2"}
	if len(cap.got) != len(want) || cap.got["jellyfin.home1.internal"] != "100.64.0.2" {
		t.Fatalf("projection = %v, want %v", cap.got, want)
	}
}

func TestReconcileAppDNS_NilListerIsNoop(t *testing.T) {
	cap := &capturingSupervisor{}
	svc, _ := newAppDNSService(t, cap)
	if err := svc.ReconcileAppDNS(context.Background()); err != nil {
		t.Fatalf("ReconcileAppDNS: %v", err)
	}
	if cap.calls != 0 {
		t.Errorf("no app lister set → supervisor should not be called, got %d calls", cap.calls)
	}
}
