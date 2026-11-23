package mesh

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-984-02: the app-signin-unjoined warning rises and clears on the bind
// fact. Up with no device for cp1; gone after the real enrollRecord binds cp1
// with a tailnet IP; back when the device row is deleted; up with two devices
// bound to cp1 (F-984-01); never with the doors off or no self node id.
func TestAppDoorReachAlerts_FollowsTheBind(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	wantAlert := func(t *testing.T, got []proto.Alert) {
		t.Helper()
		if len(got) != 1 {
			t.Fatalf("alerts = %+v, want exactly one", got)
		}
		a := got[0]
		if a.ID != "app-signin-unjoined" || a.Severity != proto.AlertWarn || a.Source != proto.AlertSourceNode ||
			a.Title != "App sign-in is not reachable over your private network yet: the control plane has not joined it." ||
			a.RelatedKind != "node" || a.RelatedID != "cp1" || !a.Since.Equal(now) ||
			a.Detail != "The control plane joins its private network on its own. If this warning stays, the newest mesh.enroll_node task for cp1 says why." {
			t.Errorf("alert = %+v", a)
		}
	}

	f := newDoorFixture(t, (*doorFixture).predicate)
	wantAlert(t, f.svc.AppDoorReachAlerts(ctx, now))

	f.enrol(t, "h-cp", "100.64.0.5")
	if got := f.svc.AppDoorReachAlerts(ctx, now); len(got) != 0 {
		t.Errorf("after the bind alerts = %+v, want none", got)
	}

	if err := f.st.DeleteDevice(ctx, "h-cp"); err != nil {
		t.Fatal(err)
	}
	wantAlert(t, f.svc.AppDoorReachAlerts(ctx, now))

	t.Run("bound with no tailnet IP", func(t *testing.T) {
		f := newDoorFixture(t, (*doorFixture).predicate)
		f.enrol(t, "h-cp", "")
		wantAlert(t, f.svc.AppDoorReachAlerts(ctx, now))
	})

	t.Run("bound to two devices", func(t *testing.T) {
		f := newDoorFixture(t, (*doorFixture).predicate)
		// A legacy database holding two bindings for one node, as in
		// TestReconcileAppDNS_NoDoorWithoutOneAddressedDevice.
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
		wantAlert(t, f.svc.AppDoorReachAlerts(ctx, now))
	})

	t.Run("doors off", func(t *testing.T) {
		f := newDoorFixture(t, (*doorFixture).predicate)
		f.svc.cfg.AppDoorHost = ""
		if got := f.svc.AppDoorReachAlerts(ctx, now); len(got) != 0 {
			t.Errorf("alerts = %+v, want none with the doors off", got)
		}
	})

	t.Run("no self node id", func(t *testing.T) {
		f := newDoorFixture(t, (*doorFixture).predicate)
		f.svc.cfg.SelfNodeID = ""
		if got := f.svc.AppDoorReachAlerts(ctx, now); len(got) != 0 {
			t.Errorf("alerts = %+v, want none with no self node id", got)
		}
	})
}

// TC-984-03: an unreadable device table raises no alert and logs one WARN
// with node_id and err.
func TestAppDoorReachAlerts_UnreadableDevicesWarns(t *testing.T) {
	f := newDoorFixture(t, (*doorFixture).predicate)
	if err := f.st.Close(); err != nil {
		t.Fatal(err)
	}
	if got := f.svc.AppDoorReachAlerts(context.Background(), time.Now()); len(got) != 0 {
		t.Errorf("alerts = %+v, want none when the devices cannot be read", got)
	}
	out := f.logs.String()
	if n := strings.Count(out, "\n"); n != 1 {
		t.Fatalf("log records = %d, want 1:\n%s", n, out)
	}
	for _, kv := range []string{"level=WARN", `msg="app sign-in reach not checked: mesh devices unreadable"`, "node_id=cp1", "err="} {
		if !strings.Contains(out, kv) {
			t.Errorf("WARN record missing %s:\n%s", kv, out)
		}
	}
}

// TC-986-18: AppDoorOnline reads the bind fact and the bounded membership
// observation (F-986-02): false while unbound, bound with no tailnet IP,
// bound to two devices, bound but offline, with the doors off, or when the
// last reconcile is older than MembershipMaxAge though the cached device
// reads online; true for one bound device online within the bound; an error
// when the devices cannot be read.
func TestAppDoorOnline_FollowsTheBindAndTheBoundedObservation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	cp := func(hsID, ip string, online bool) *Device {
		return &Device{HSID: hsID, RasputinNodeID: "cp1", TailnetIP: ip, Online: online, Tags: []string{}, AdvertisedRoutes: []string{}}
	}
	reconciled := func(t *testing.T, f *doorFixture, at time.Time) {
		t.Helper()
		if err := f.st.UpdateAfterReconcile(ctx, "h", at); err != nil {
			t.Fatal(err)
		}
	}
	want := func(t *testing.T, f *doorFixture, at time.Time, wantOnline bool) {
		t.Helper()
		got, err := f.svc.appDoorOnlineAt(ctx, at)
		if err != nil || got != wantOnline {
			t.Errorf("AppDoorOnline = %v, %v; want %v, nil", got, err, wantOnline)
		}
	}
	for _, c := range []struct {
		name    string
		devices []*Device
		want    bool
	}{
		{"unbound", nil, false},
		{"bound with no tailnet IP", []*Device{cp("h-cp", "", true)}, false},
		{"bound but offline", []*Device{cp("h-cp", "100.64.0.5", false)}, false},
		{"bound and online", []*Device{cp("h-cp", "100.64.0.5", true)}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newDoorFixture(t, nil)
			for _, d := range c.devices {
				if err := f.st.UpsertDevice(ctx, d); err != nil {
					t.Fatal(err)
				}
			}
			reconciled(t, f, now.Add(-time.Minute))
			want(t, f, now, c.want)
		})
	}

	t.Run("bound to two devices", func(t *testing.T) {
		f := newDoorFixture(t, nil)
		if _, err := f.st.db.ExecContext(ctx, `DROP INDEX IF EXISTS ux_mesh_devices_bound_node`); err != nil {
			t.Fatal(err)
		}
		for _, d := range []*Device{cp("h1", "100.64.0.5", true), cp("h2", "100.64.0.6", true)} {
			if err := upsertDevice(ctx, f.st.db, d); err != nil {
				t.Fatal(err)
			}
		}
		reconciled(t, f, now.Add(-time.Minute))
		want(t, f, now, false)
	})

	t.Run("doors off", func(t *testing.T) {
		f := newDoorFixture(t, nil)
		if err := f.st.UpsertDevice(ctx, cp("h-cp", "100.64.0.5", true)); err != nil {
			t.Fatal(err)
		}
		reconciled(t, f, now.Add(-time.Minute))
		f.svc.cfg.AppDoorHost = ""
		want(t, f, now, false)
	})

	t.Run("a stale observation", func(t *testing.T) {
		f := newDoorFixture(t, nil)
		if err := f.st.UpsertDevice(ctx, cp("h-cp", "100.64.0.5", true)); err != nil {
			t.Fatal(err)
		}
		reconciled(t, f, now.Add(-f.svc.MembershipMaxAge()-time.Second))
		want(t, f, now, false)
		// The same cache, observed within the bound, reads online.
		reconciled(t, f, now.Add(-f.svc.MembershipMaxAge()))
		want(t, f, now, true)
	})

	t.Run("no reconcile yet", func(t *testing.T) {
		f := newDoorFixture(t, nil)
		if err := f.st.UpsertDevice(ctx, cp("h-cp", "100.64.0.5", true)); err != nil {
			t.Fatal(err)
		}
		want(t, f, now, false)
	})

	t.Run("the store fails", func(t *testing.T) {
		f := newDoorFixture(t, nil)
		_ = f.st.Close()
		if got, err := f.svc.AppDoorOnline(ctx); err == nil || got {
			t.Errorf("AppDoorOnline with a closed store = %v, %v; want false and an error", got, err)
		}
	})
}
