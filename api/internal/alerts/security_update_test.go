package alerts

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/releases"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-772-14: the security-update source joins List. Its crit alert sorts
// before another source's warn, its error fails List wrapped, and with the
// setter never called List is what it was before the source existed.
func TestList_SecurityUpdateAlertsHook(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	f.insertFailedJob(t, "j1", "apps.deploy", "The deploy failed.", time.Hour)

	before, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := alertIDs(before); !slices.Equal(got, []string{"job-failed:j1"}) {
		t.Fatalf("unwired ids = %v, want only the job-failed warn", got)
	}

	// Since is newer than the warn's, so only severity can put it first.
	f.svc.SetSecurityUpdateAlerts(func(_ context.Context, now time.Time) ([]proto.Alert, error) {
		return []proto.Alert{{ID: releases.SecurityAlertID, Severity: proto.AlertCrit, Source: proto.AlertSourceSecurity, Since: now}}, nil
	})
	got, err := f.svc.List(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ids := alertIDs(got); !slices.Equal(ids, []string{releases.SecurityAlertID, "job-failed:j1"}) {
		t.Fatalf("ids = %v, want the security crit before the warn", ids)
	}

	cause := errors.New("inventory read failed")
	f.svc.SetSecurityUpdateAlerts(func(context.Context, time.Time) ([]proto.Alert, error) { return nil, cause })
	got, err = f.svc.List(f.ctx)
	if !errors.Is(err, cause) || got != nil {
		t.Fatalf("List = %v, %v; want nil and an error wrapping the source's", got, err)
	}
}

// failingNodes is an inventory read that always fails.
type failingNodes struct{ err error }

func (n failingNodes) List(context.Context) ([]*proto.Node, error) { return nil, n.err }

// floorSource returns one release declaring a security floor.
type floorSource struct{}

func (floorSource) LatestFor(context.Context, releases.Component, string) (*releases.ReleaseInfo, error) {
	return &releases.ReleaseInfo{Version: "2026.10.2", Manifest: releases.Manifest{Version: "2026.10.2", SecurityFloor: "2026.10.2"}}, nil
}

// TC-772-15 (the List half): with a floor known, a failed inventory read in
// the real watch fails List, and the error carries the watch's prefix and
// wraps the cause.
func TestList_SecurityWatchInventoryFailureFailsList(t *testing.T) {
	f := newFixture(t)
	f.markSetupComplete(t)
	cause := errors.New("database is locked")
	log, _ := logkittest.New()
	w, err := releases.NewSecurityWatch(releases.SecurityDeps{
		Source: floorSource{}, Nodes: failingNodes{cause}, Channel: releases.ChannelStable, Log: log, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Refresh(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.svc.SetSecurityUpdateAlerts(w.Alerts)

	got, err := f.svc.List(f.ctx)
	if got != nil || !errors.Is(err, cause) {
		t.Fatalf("List = %v, %v; want nil and an error wrapping the inventory failure", got, err)
	}
	if !strings.Contains(err.Error(), "releases: security alerts: list nodes") {
		t.Errorf("error %q does not name the security watch's inventory read", err)
	}
}
