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
