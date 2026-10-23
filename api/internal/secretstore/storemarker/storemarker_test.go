package storemarker

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

const (
	bootA = "0f3c5b2a-1d4e-4f6a-9b8c-7d6e5f4a3b2c"
	bootB = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
)

// realSettings is a real settings table in a temporary rasputin.db.
func realSettings(t *testing.T) *setup.Store {
	t.Helper()
	st, err := setup.OpenStore(context.Background(), filepath.Join(t.TempDir(), "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// failingSettings fails every Set and, with getErr, every Get.
type failingSettings struct {
	Settings
	getErr error
}

func (f failingSettings) Get(ctx context.Context, key string) (string, error) {
	if f.getErr != nil {
		return "", f.getErr
	}
	return f.Settings.Get(ctx, key)
}

func (failingSettings) Set(context.Context, string, string) error {
	return errors.New("database is locked")
}

func newMarker(t *testing.T, s Settings, boot string) (*Marker, *logkittest.Recorder) {
	t.Helper()
	log, rec := logkittest.New()
	m, err := New(Deps{Settings: s, BootID: func() (string, error) { return boot, nil }, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return m, rec
}

func get(t *testing.T, s Settings, key string) string {
	t.Helper()
	v, err := s.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func initRecord(boot string) osoutcome.Record {
	return osoutcome.Record{Outcome: "initialised", BootID: boot, Reason: "The store initialised."}
}

func TestNew_RefusesNil(t *testing.T) {
	s := realSettings(t)
	full := func() Deps {
		return Deps{Settings: s, BootID: func() (string, error) { return bootA, nil }, Log: slog.New(slog.DiscardHandler)}
	}
	for name, clear := range map[string]func(*Deps){
		"Settings": func(d *Deps) { d.Settings = nil },
		"BootID":   func(d *Deps) { d.BootID = nil },
		"Log":      func(d *Deps) { d.Log = nil },
	} {
		d := full()
		clear(&d)
		if m, err := New(d); err == nil || m != nil {
			t.Errorf("New without %s = (%v, %v), want an error", name, m, err)
		}
	}
}

// TC-765-25: with no marker an initialised record sets set_up_boot_id to its
// boot; the same boot again changes nothing; a record from another boot sets
// blank_boot_id and logs exactly one ERROR secretstore.blank_store with both
// boot ids; a failed record changes nothing.
func TestObserveInit(t *testing.T) {
	ctx := context.Background()
	s := realSettings(t)
	m, rec := newMarker(t, s, bootB)

	m.ObserveInit(ctx, osoutcome.Record{Outcome: "failed", BootID: bootA, Reason: "It failed."})
	if v := get(t, s, KeySetUpBootID); v != "" {
		t.Fatalf("a failed record set the marker to %q", v)
	}

	m.ObserveInit(ctx, initRecord(bootA))
	if v := get(t, s, KeySetUpBootID); v != bootA {
		t.Fatalf("set_up_boot_id = %q, want %s", v, bootA)
	}
	m.ObserveInit(ctx, initRecord(bootA))
	if v := get(t, s, KeyBlankBootID); v != "" {
		t.Fatalf("the same boot again set blank_boot_id to %q", v)
	}
	if blank, err := m.Blank(ctx); err != nil || blank {
		t.Fatalf("Blank = (%v, %v) after the same boot, want false", blank, err)
	}

	m.ObserveInit(ctx, initRecord(bootB))
	m.ObserveInit(ctx, initRecord(bootB)) // the after-restart re-read of the same record
	if v := get(t, s, KeyBlankBootID); v != bootB {
		t.Fatalf("blank_boot_id = %q, want %s", v, bootB)
	}
	if v := get(t, s, KeySetUpBootID); v != bootA {
		t.Fatalf("a blank start moved set_up_boot_id to %q", v)
	}
	errs := rec.Matching(slog.LevelError, "started blank")
	if len(errs) != 1 {
		t.Fatalf("%d blank-store ERRORs, want exactly 1:\n%s", len(errs), rec.Text())
	}
	for k, want := range map[string]string{"event": "secretstore.blank_store", "boot_id": bootB, "set_up_boot_id": bootA} {
		if got, _ := logkittest.Attr(errs[0], k); got != want {
			t.Errorf("ERROR %s = %q, want %q", k, got, want)
		}
	}
	if blank, err := m.Blank(ctx); err != nil || !blank {
		t.Fatalf("Blank = (%v, %v), want true", blank, err)
	}
}

// TC-765-26: Rebase sets set_up_boot_id to this boot and clears
// blank_boot_id. A write that fails logs an ERROR and leaves the verdict
// blank.
func TestRebase(t *testing.T) {
	ctx := context.Background()
	s := realSettings(t)
	if err := s.Set(ctx, KeySetUpBootID, bootA); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, KeyBlankBootID, bootA); err != nil {
		t.Fatal(err)
	}

	broken, rec := newMarker(t, failingSettings{Settings: s}, bootB)
	broken.Rebase(ctx)
	if len(rec.Matching(slog.LevelError, "not re-based")) != 1 {
		t.Fatalf("no ERROR for the failed re-base:\n%s", rec.Text())
	}
	if blank, err := broken.Blank(ctx); err != nil || !blank {
		t.Fatalf("after a failed re-base Blank = (%v, %v), want true", blank, err)
	}

	m, _ := newMarker(t, s, bootB)
	m.Rebase(ctx)
	if v := get(t, s, KeySetUpBootID); v != bootB {
		t.Errorf("set_up_boot_id = %q, want %s", v, bootB)
	}
	if v := get(t, s, KeyBlankBootID); v != "" {
		t.Errorf("blank_boot_id = %q, want cleared", v)
	}
}

// readyStore is a store answering 200 initialised and unsealed.
type readyStore struct{}

func (readyStore) Health(context.Context) (secretstore.Health, error) {
	return secretstore.Health{Initialized: true}, nil
}

// TC-765-27 (F-765-01): with no marker and store data present at start, Arm
// records this boot; an initialised record from a later boot then reads
// blank and raises the crit alert. With the data absent, and no record,
// nothing is written. An existing marker is never moved.
func TestArm_GuardsAnExistingCluster(t *testing.T) {
	ctx := context.Background()
	s := realSettings(t)
	m, _ := newMarker(t, s, bootA)

	m.Arm(ctx, false)
	if v := get(t, s, KeySetUpBootID); v != "" {
		t.Fatalf("Arm with no store data wrote %q", v)
	}

	m.Arm(ctx, true)
	if v := get(t, s, KeySetUpBootID); v != bootA {
		t.Fatalf("set_up_boot_id = %q, want %s", v, bootA)
	}
	later, _ := newMarker(t, s, bootB)
	later.Arm(ctx, true)
	if v := get(t, s, KeySetUpBootID); v != bootA {
		t.Fatalf("a second Arm moved the marker to %q", v)
	}

	later.ObserveInit(ctx, initRecord(bootB))
	mon, err := storestate.New(storestate.Deps{
		Store: readyStore{}, Now: time.Now, Log: slog.New(slog.DiscardHandler),
		JobRunning: func(context.Context, string) (bool, error) { return false, nil },
		Blank:      later.Blank,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st, err := mon.State(ctx); err != nil || st != storestate.Blank {
		t.Fatalf("state = (%s, %v), want blank", st, err)
	}
	if a := mon.Alerts(ctx, time.Now()); len(a) != 1 || a[0].ID != "secret-store:blank" {
		t.Fatalf("alerts = %+v, want secret-store:blank", a)
	}
}

// An unreadable marker arms nothing and says so; Blank passes the error on
// for the monitor to read as blank.
func TestUnreadableMarker(t *testing.T) {
	ctx := context.Background()
	m, rec := newMarker(t, failingSettings{Settings: realSettings(t), getErr: errors.New("disk I/O error")}, bootA)
	m.Arm(ctx, true)
	m.ObserveInit(ctx, initRecord(bootA))
	if n := len(rec.Matching(slog.LevelError, "marker unreadable")); n != 2 {
		t.Errorf("%d unreadable ERRORs, want 2:\n%s", n, rec.Text())
	}
	if _, err := m.Blank(ctx); err == nil {
		t.Error("Blank hid the read error")
	}
}
