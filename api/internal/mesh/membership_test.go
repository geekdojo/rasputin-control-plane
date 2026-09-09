package mesh

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

func membershipFixture(t *testing.T) (*Service, *Store) {
	t.Helper()
	st, err := OpenStore(context.Background(), filepath.Join(t.TempDir(), "mesh.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return NewService(Config{ClusterID: "home1", ReconcileInterval: 5 * time.Minute}, st, nil, nil), st
}

func TestMembership_NoStoreOrNoReconcileIsUndetermined(t *testing.T) {
	if got := (&Service{}).Membership(context.Background()); got != nil {
		t.Errorf("no store: want nil, got %v", got)
	}
	var nilSvc *Service
	if got := nilSvc.Membership(context.Background()); got != nil {
		t.Errorf("nil service: want nil, got %v", got)
	}

	svc, st := membershipFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.UpsertDevice(ctx, &Device{HSID: "hs-1", RasputinNodeID: "c01", Kind: "rasputin", FirstSeen: now, LastSeen: now, Online: true}); err != nil {
		t.Fatal(err)
	}
	if got := svc.Membership(ctx); got != nil {
		t.Errorf("devices but no reconcile yet: want nil (undetermined), got %v", got)
	}
}

// The join, with the staleness bound: an online device is Online while the
// reconcile that observed it is younger than MembershipMaxAge, and its
// LastSeen is never older than that observation.
func TestMembership_OnlineIsBoundedByTheReconcileAge(t *testing.T) {
	svc, st := membershipFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	connectedAt := now.Add(-3 * time.Hour) // Headscale's unrefreshed last-seen for a long session
	droppedAt := now.Add(-40 * time.Minute)

	for _, d := range []*Device{
		{HSID: "hs-on", RasputinNodeID: "c02", Kind: "rasputin", TailnetIP: "100.64.0.2", FirstSeen: connectedAt, LastSeen: connectedAt, Online: true},
		{HSID: "hs-off", RasputinNodeID: "c03", Kind: "rasputin", TailnetIP: "100.64.0.3", FirstSeen: connectedAt, LastSeen: droppedAt, Online: false},
		{HSID: "hs-laptop", RasputinNodeID: "", Kind: "user", FirstSeen: now, LastSeen: now, Online: true},
	} {
		if err := st.UpsertDevice(ctx, d); err != nil {
			t.Fatalf("UpsertDevice %s: %v", d.HSID, err)
		}
	}
	observed := now.Add(-40 * time.Second)
	if err := st.UpdateAfterReconcile(ctx, "obs", observed); err != nil {
		t.Fatal(err)
	}

	if want := 15 * time.Minute; svc.MembershipMaxAge() != want {
		t.Fatalf("MembershipMaxAge = %v, want %v (3 × 5 min)", svc.MembershipMaxAge(), want)
	}

	got := svc.membershipAt(ctx, now)
	if got == nil {
		t.Fatal("after a reconcile, membership must be determined")
	}
	if len(got) != 2 {
		t.Errorf("map has %d entries, want 2 — user devices are not cluster nodes", len(got))
	}
	on := got["c02"]
	if on == nil || on.State != proto.MeshJoined || !on.Enrolled || !on.Online || on.TailnetIP != "100.64.0.2" {
		t.Fatalf("c02: want joined/enrolled/online, got %+v", on)
	}
	// Seen no earlier than the reconcile that saw it online — "mesh seen 40s
	// ago", not "3h ago" because Headscale never refreshed the timestamp.
	if on.LastSeen == nil || !on.LastSeen.Equal(observed) {
		t.Errorf("c02: LastSeen = %v, want the observation time %v", on.LastSeen, observed)
	}
	off := got["c03"]
	if off == nil || off.State != proto.MeshAbsent || !off.Enrolled || off.Online {
		t.Fatalf("c03: want absent/enrolled/not online, got %+v", off)
	}
	if off.LastSeen == nil || !off.LastSeen.Equal(droppedAt) {
		t.Errorf("c03: LastSeen = %v, want Headscale's own %v (not bumped: it was not online)", off.LastSeen, droppedAt)
	}

	// The same cache read 16 minutes later, with no reconcile in between:
	// the observation has aged out. State still reports what was observed;
	// Online — the input to OFF BUS — does not vouch for it any more.
	later := svc.membershipAt(ctx, observed.Add(svc.MembershipMaxAge()+time.Minute))
	if m := later["c02"]; m == nil || m.State != proto.MeshJoined || m.Online {
		t.Errorf("aged out: want joined but not online, got %+v", m)
	}
	// And exactly at the bound it still counts.
	edge := svc.membershipAt(ctx, observed.Add(svc.MembershipMaxAge()))
	if m := edge["c02"]; m == nil || !m.Online {
		t.Errorf("at the bound: want online, got %+v", m)
	}
}
