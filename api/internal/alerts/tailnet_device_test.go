package alerts

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-983-12 (alert half): a rename raises one persisted, acknowledgeable warn
// naming the device and both names; the same rename raised again is the same
// row.
func TestRaiseTailnetDeviceRenamed(t *testing.T) {
	ctx := context.Background()
	svc, _ := nodeKeyService(t)
	for range 2 {
		if err := svc.RaiseTailnetDeviceRenamed(ctx, "12", "signin", "signin-12"); err != nil {
			t.Fatal(err)
		}
	}
	got, err := svc.ruleAlerts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d alerts, want 1: %+v", len(got), got)
	}
	a := got[0]
	if a.Severity != proto.AlertWarn || !strings.HasPrefix(a.ID, "tailnet-device-renamed:") {
		t.Errorf("alert = %+v", a)
	}
	for _, s := range []string{"12", "signin", "signin-12"} {
		if !strings.Contains(a.Detail, s) {
			t.Errorf("detail %q does not name %q", a.Detail, s)
		}
	}
	acked, err := svc.Ack(ctx, a.ID)
	if err != nil || acked == nil || !acked.Acked {
		t.Fatalf("Ack = %+v, %v", acked, err)
	}
	if err := (&Service{}).RaiseTailnetDeviceRenamed(ctx, "12", "signin", "signin-12"); err != nil {
		t.Errorf("no store: %v", err)
	}
}

// TC-983-09 / TC-983-11 (alert half): an app holding a reserved name carries
// a computed warn naming it and saying the app sign-in address is withheld,
// and the warn is gone once the app is.
func TestAppAlerts_ReservedName(t *testing.T) {
	f := newFixture(t)
	f.insertApp(t, "a1", "signin", proto.AppStatusRunning, "")
	f.insertApp(t, "a2", "radius", proto.AppStatusRunning, "")
	f.insertApp(t, "a3", "jellyfin", proto.AppStatusRunning, "")
	got, err := f.svc.appAlerts(f.ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]proto.Alert{}
	for _, a := range got {
		ids[a.ID] = a
	}
	if len(got) != 2 {
		t.Fatalf("alerts = %+v, want the two reserved apps", got)
	}
	a, ok := ids["app-reserved-name:a1"]
	if !ok || a.Severity != proto.AlertWarn || !strings.Contains(a.Detail, "signin") || !strings.Contains(a.Detail, "app sign-in address is withheld") {
		t.Errorf("signin alert = %+v", a)
	}
	if _, ok := ids["app-reserved-name:a2"]; !ok {
		t.Errorf("no alert for radius: %+v", got)
	}
	if err := f.apps.Delete(f.ctx, "a1"); err != nil {
		t.Fatal(err)
	}
	got, _ = f.svc.appAlerts(f.ctx, time.Now())
	for _, a := range got {
		if a.ID == "app-reserved-name:a1" {
			t.Error("alert outlived the app")
		}
	}
}
