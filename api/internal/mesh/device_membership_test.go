package mesh

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	st, err := OpenStore(context.Background(), filepath.Join(t.TempDir(), "mesh.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestUpsertDevice_PreservesHeadscaleLastSeen is the regression for the bug
// that made mesh last-seen useless: UpsertDevice wrote time.Now() into
// last_seen regardless of what the caller passed, so a device that had been off
// the tailnet for five weeks read as seen moments ago. The whole value of the
// field is answering "how long has this been broken?".
func TestUpsertDevice_PreservesHeadscaleLastSeen(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	longAgo := time.Now().UTC().Add(-5 * 7 * 24 * time.Hour).Truncate(time.Millisecond)
	if err := st.UpsertDevice(ctx, &Device{
		HSID: "hs-1", User: "tagged", Hostname: "c07",
		RasputinNodeID: "c07", Kind: "rasputin",
		FirstSeen: longAgo, LastSeen: longAgo, Online: false,
	}); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}

	got, err := st.GetDeviceByRasputinNodeID(ctx, "c07")
	if err != nil || got == nil {
		t.Fatalf("GetDeviceByRasputinNodeID: %v (device=%v)", err, got)
	}
	if !got.LastSeen.Equal(longAgo) {
		t.Errorf("LastSeen = %s, want %s (the value Headscale reported, not the reconcile time)",
			got.LastSeen, longAgo)
	}
	if since := time.Since(got.LastSeen); since < 24*time.Hour {
		t.Errorf("LastSeen reads as %s old — a device absent for five weeks must not look freshly seen", since)
	}
}

// TestUpsertDevice_RoundTripsOnline pins the field the API needs to tell mesh
// membership from LAN liveness. Online cannot be derived from LastSeen —
// Headscale does not refresh LastSeen while a node stays connected — so it has
// to survive the round trip on its own.
func TestUpsertDevice_RoundTripsOnline(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// A joined node whose LastSeen is deliberately stale: this is the real
	// shape of a healthy Headscale row, and deriving liveness from the
	// timestamp would wrongly call it absent.
	stale := now.Add(-72 * time.Hour)
	for _, d := range []*Device{
		{HSID: "hs-on", RasputinNodeID: "c04", Kind: "rasputin", FirstSeen: stale, LastSeen: stale, Online: true},
		{HSID: "hs-off", RasputinNodeID: "c13", Kind: "rasputin", FirstSeen: stale, LastSeen: stale, Online: false},
	} {
		if err := st.UpsertDevice(ctx, d); err != nil {
			t.Fatalf("UpsertDevice %s: %v", d.HSID, err)
		}
	}

	on, _ := st.GetDeviceByRasputinNodeID(ctx, "c04")
	off, _ := st.GetDeviceByRasputinNodeID(ctx, "c13")
	if on == nil || off == nil {
		t.Fatal("devices not stored")
	}
	if !on.Online {
		t.Error("c04: Online lost in the round trip — a connected node would render as absent")
	}
	if off.Online {
		t.Error("c13: Online should be false")
	}
	if !on.LastSeen.Equal(off.LastSeen) {
		t.Fatal("test setup: both rows should share a LastSeen so only Online can distinguish them")
	}
}

// TestUpsertDevice_UpdatesOnlineOnConflict covers the transition that matters
// operationally: a node that drops off the tailnet must stop reporting joined
// on the next reconcile, not keep its old value.
func TestUpsertDevice_UpdatesOnlineOnConflict(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	d := &Device{HSID: "hs-1", RasputinNodeID: "c01", Kind: "rasputin", FirstSeen: now, LastSeen: now, Online: true}
	if err := st.UpsertDevice(ctx, d); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	d.Online = false
	d.LastSeen = now.Add(time.Minute)
	if err := st.UpsertDevice(ctx, d); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	got, _ := st.GetDeviceByRasputinNodeID(ctx, "c01")
	if got == nil || got.Online {
		t.Error("a node that left the tailnet still reports Online after reconcile")
	}
}

// TestListDevices_CarriesOnline guards the list path too — the API builds its
// whole membership map from ListDevices, so a scan that dropped the column
// would silently report the entire fleet as absent.
func TestListDevices_CarriesOnline(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.UpsertDevice(ctx, &Device{
		HSID: "hs-1", RasputinNodeID: "c02", Kind: "rasputin",
		FirstSeen: now, LastSeen: now, Online: true,
	}); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	devices, err := st.ListDevices(ctx)
	if err != nil || len(devices) != 1 {
		t.Fatalf("ListDevices: %v (n=%d)", err, len(devices))
	}
	if !devices[0].Online {
		t.Error("ListDevices dropped Online")
	}
}
