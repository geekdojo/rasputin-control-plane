package sealrotate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-830-10: one crit alert, with the plan's exact copy and no vendor name,
// while the tree is not Clean and no rotation job runs; none while a rotation
// job runs; none once Clean.
func TestRotator_IncompleteAlert(t *testing.T) {
	s := newSeal(t)
	staged(s)
	g := newRig(t, s)
	running := map[string]bool{}
	log, _ := logkittest.New()
	gate, err := NewGate(g.files, func(_ context.Context, id string) (bool, error) { return running[id], nil }, log)
	if err != nil {
		t.Fatal(err)
	}
	g.build(t)
	g.rot.d.Gate = gate
	g.rot.d.JobRunning = func(_ context.Context, id string) (bool, error) { return running[id], nil }
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	g.rot.d.Now = func() time.Time { return now }

	list := g.rot.Alerts(t.Context(), now)
	if len(list) != 1 {
		t.Fatalf("alerts = %+v, want one", list)
	}
	a := list[0]
	want := proto.Alert{
		ID: "secret-store:seal-rotation-incomplete", Severity: proto.AlertCrit, Source: proto.AlertSourceSecurity,
		Title: "A seal-key rotation did not finish.",
		Detail: "The secret store's key change stopped before it finished, so backups are paused. " +
			"Start the seal-key rotation again to finish it. Do not restart the node or the secret store until it has finished: " +
			"a restart now can leave the store unable to open.",
		Since: now,
	}
	if a != want {
		t.Fatalf("alert =\n%+v\nwant\n%+v", a, want)
	}
	for _, vendor := range []string{"OpenBao", "bao"} {
		if strings.Contains(a.Title+a.Detail, vendor) {
			t.Errorf("the alert copy names %q", vendor)
		}
	}
	later := now.Add(time.Hour)
	g.rot.d.Now = func() time.Time { return later }
	if again := g.rot.Alerts(t.Context(), later); len(again) != 1 || !again[0].Since.Equal(now) {
		t.Errorf("a second reading moved Since: %+v", again)
	}

	if err := gate.TryAcquire("rot-job"); err != nil {
		t.Fatal(err)
	}
	running["rot-job"] = true
	if got := g.rot.Alerts(t.Context(), now); len(got) != 0 {
		t.Errorf("alerts while a rotation job runs = %+v", got)
	}
	running["rot-job"] = false
	if got := g.rot.Alerts(t.Context(), now); len(got) != 1 {
		t.Errorf("alerts once the holder stopped running = %+v", got)
	}
	gate.Release("rot-job")

	s.clean()
	if err := s.files.RemoveRotation(); err != nil {
		t.Fatal(err)
	}
	if got := g.rot.Alerts(t.Context(), now); len(got) != 0 {
		t.Errorf("alerts on a Clean tree = %+v", got)
	}
	// An unreadable tree raises it too: backups refuse on it the same way.
	s.write(FragmentName, []byte("garbage"))
	if got := g.rot.Alerts(t.Context(), now); len(got) != 1 {
		t.Errorf("alerts on an unreadable tree = %+v", got)
	}
}
