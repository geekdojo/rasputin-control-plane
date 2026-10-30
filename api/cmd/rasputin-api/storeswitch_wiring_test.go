package main

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storeswitch"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca/tlscatest"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// openSettingsStore is a real settings table in a temporary rasputin.db.
func openSettingsStore(t *testing.T) *setup.Store {
	t.Helper()
	st, err := setup.OpenStore(context.Background(), filepath.Join(t.TempDir(), "rasputin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// testMarker is the switch marker over st, as main builds it.
func testMarker(t *testing.T, st *setup.Store) *storeswitch.Marker {
	t.Helper()
	m, err := storeswitch.New(storeswitch.Deps{Settings: st, Now: time.Now, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// testSwitch is a switch marker over a fresh settings table.
func testSwitch(t *testing.T) *storeswitch.Marker {
	t.Helper()
	return testMarker(t, openSettingsStore(t))
}

// failingGetSettings is a settings table whose every read fails.
type failingGetSettings struct{ err error }

func (f failingGetSettings) Get(context.Context, string) (string, error) { return "", f.err }
func (failingGetSettings) Set(context.Context, string, string) error     { return nil }

const switchTokened = "services:\n  web:\n    environment:\n      P: ${secret:db-password}\n"

// TC-604-14: switched, with no backend requested and a Disabled store. The
// readiness wiring builds the monitor, the deploy source is the Gate, a
// token compose is refused with the store's not-ready code and never reaches
// the HKDF source, the unreachable crit is raised, and one WARN
// secretstore.switched_unconfigured is logged.
func TestReadiness_SwitchedWithNoBackendRefusesNeverHKDF(t *testing.T) {
	log, rec := logkittest.New()
	r, err := storeReadinessWiring("", true, storeModeOff, secretstore.Disabled{}, openJobStore(t), time.Now, notBlank, log)
	if err != nil {
		t.Fatal(err)
	}
	if r.monitor == nil || r.alerts == nil {
		t.Fatal("switched with no backend built no monitor")
	}
	storeSrc, hkdf := &countingSource{}, &countingSource{}
	src, err := deploySourceWiring(r.monitor, storeSrc, hkdf, log)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := src.(*storestate.Gate); !ok {
		t.Fatalf("source is %T, want the Gate", src)
	}
	_, env, err := src.ResolveCompose(context.Background(), wiringAppID, switchTokened)
	if refusalCode(err) != storestate.Code || env != nil {
		t.Fatalf("a token resolve = %v, want the %s refusal", err, storestate.Code)
	}
	if hkdf.calls.Load() != 0 || storeSrc.calls.Load() != 0 {
		t.Fatalf("HKDF calls %d, store source calls %d; want none", hkdf.calls.Load(), storeSrc.calls.Load())
	}
	alerts := r.alerts(context.Background(), time.Now())
	if len(alerts) != 1 || alerts[0].ID != "secret-store:unreachable" || alerts[0].Severity != proto.AlertCrit {
		t.Fatalf("alerts = %+v, want the unreachable crit", alerts)
	}
	n := 0
	for _, rr := range rec.AtLevel(slog.LevelWarn) {
		if ev, _ := logkittest.Attr(rr, "event"); ev == "secretstore.switched_unconfigured" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d WARN secretstore.switched_unconfigured records, want 1", n)
	}
}

// TC-604-15: an upgrade from the previous release (no marker) with nothing
// requested keeps the HKDF source and no monitor; a requested backend gives
// the Gate with the marker absent or present; and storeSwitchFor wires
// NoStore with nothing requested and the marker otherwise (F-604-07).
func TestReadiness_NotSwitchedAndUpgrade(t *testing.T) {
	log, _ := logkittest.New()
	js := openJobStore(t)
	ctx := context.Background()

	st := openSettingsStore(t) // the previous release's database: no marker
	switched, err := storeSwitchedAtBoot(ctx, testMarker(t, st))
	if err != nil || switched {
		t.Fatalf("a fresh settings table reads switched=%v (%v)", switched, err)
	}
	r, err := storeReadinessWiring("", switched, storeModeOff, secretstore.Disabled{}, js, time.Now, notBlank, log)
	if err != nil {
		t.Fatal(err)
	}
	hkdf := &countingSource{}
	src, err := deploySourceWiring(r.monitor, &countingSource{}, hkdf, log)
	if err != nil {
		t.Fatal(err)
	}
	if r.monitor != nil || src != apps.SecretSource(hkdf) {
		t.Fatalf("not switched, nothing requested: monitor %v, source %T; want none and the HKDF source", r.monitor, src)
	}

	for _, marked := range []bool{false, true} {
		r, err := storeReadinessWiring(storeModeOpenBao, marked, storeModeOpenBao, secretstore.NewMock(time.Now), js, time.Now, notBlank, log)
		if err != nil {
			t.Fatal(err)
		}
		src, err := deploySourceWiring(r.monitor, &countingSource{}, &countingSource{}, log)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := src.(*storestate.Gate); !ok {
			t.Fatalf("requested, switched=%v: source is %T, want the Gate", marked, src)
		}
	}

	m := testSwitch(t)
	if sw, ok := storeSwitchFor("", m).(storeswitch.NoStore); !ok {
		t.Fatalf("storeSwitchFor(\"\") = %T, want NoStore", sw)
	}
	if sw := storeSwitchFor(storeModeOpenBao, m); sw != m {
		t.Fatalf("storeSwitchFor(openbao) = %T, want the marker", sw)
	}
}

// TC-604-16: a marker read that fails at boot is returned, wrapped, for main
// to treat as FATAL; it is never read as either answer, so no deploy source
// is chosen from it.
func TestStoreSwitchedAtBoot_UnreadableIsAnError(t *testing.T) {
	boom := errors.New("database is locked")
	m, err := storeswitch.New(storeswitch.Deps{Settings: failingGetSettings{err: boom}, Now: time.Now, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	switched, err := storeSwitchedAtBoot(context.Background(), m)
	if !errors.Is(err, boom) || switched {
		t.Fatalf("storeSwitchedAtBoot = %v, %v; want false and the read error", switched, err)
	}
}

// TC-604-20: a restored pre-switch archive. rasputin.db holds no marker and
// refs for derived names only; the app declares one required and one
// optional operator name with no store entries. With a backend requested the
// source is the Gate, Status shows both names unset, the deploy refuses with
// operator_secret_unset naming only the required name, and the owner's PUT
// sets the marker again; the next deploy delivers the value, "" for the
// optional name, and never reaches HKDF.
func TestRestore_PreSwitchArchive(t *testing.T) {
	log, _ := logkittest.New()
	ctx := jobs.ContextWithJobID(t.Context(), "job-restore-604")
	const compose = "services:\n  web:\n    environment:\n      FEED: ${secret:feed-key}\n      OPT: ${secret:opt-key}\n      PW: ${secret:db-password}\n"
	no := false

	as := openAppsStore(t)
	now := time.Now()
	if err := as.Create(ctx, &apps.App{ID: wiringAppID, Name: "feeds", ComposeYAML: compose, TargetNode: "node-1",
		OperatorSecrets: []tileschema.OperatorSecret{{Name: "feed-key", Label: "Feed API key"}, {Name: "opt-key", Label: "Optional key", Required: &no}},
		CreatedAt:       now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := as.RecordSecretRef(ctx, wiringAppID, "db-password"); err != nil {
		t.Fatal(err)
	}
	settings := openSettingsStore(t)
	marker := testMarker(t, settings)
	switched, err := storeSwitchedAtBoot(ctx, marker)
	if err != nil || switched {
		t.Fatalf("the restored database reads switched=%v (%v), want not switched", switched, err)
	}

	seed, hkdfSrc := loadAppSecrets(ctx, log, func(code int) { t.Fatalf("loadAppSecrets exited %d", code) }, t.TempDir())
	w, err := wireSecretStore(ctx, log, storeModeMock, defaultSecretStoreAddr,
		ensureStoreCA(t, t.TempDir(), tlscatest.Deps()), t.TempDir(), (&recordedRun{}).run, noRestartHook)
	if err != nil {
		t.Fatal(err)
	}
	r, err := storeReadinessWiring(storeModeOpenBao, switched, w.mode, w.store, openJobStore(t), time.Now, notBlank, log)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := storeSessionWiring(w.login, r.store, r.monitor, log)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := secretsWiring(sess, as, storeSwitchFor(storeModeOpenBao, marker), log)
	if err != nil {
		t.Fatal(err)
	}
	storeSource, err := appsecret.NewStoreSource(appsecret.StoreSourceDeps{Secrets: svc, Apps: appTargetNodes{store: as},
		Refs: appSecretRefs{store: as}, Seed: seed, Operator: appOperatorSecrets{store: as}, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	hkdf := &countingResolver{next: hkdfSrc}
	gatedStore, gatedHKDF, err := operatorGated(storeSource, hkdf, as, svc, log)
	if err != nil {
		t.Fatal(err)
	}
	src, err := deploySourceWiring(r.monitor, gatedStore, gatedHKDF, log)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := src.(*storestate.Gate); !ok {
		t.Fatalf("source is %T, want the Gate", src)
	}

	ops, err := apps.NewOperatorSecrets(apps.OperatorSecretsDeps{Apps: as, Secrets: svc, Refs: as, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	st, err := ops.Status(ctx, wiringAppID)
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 2 || st[0].Set || st[1].Set {
		t.Fatalf("Status = %+v, want both operator names unset", st)
	}

	_, env, err := src.ResolveCompose(ctx, wiringAppID, compose)
	if refusalCode(err) != apps.CodeOperatorSecretUnset || env != nil {
		t.Fatalf("the deploy = %v, want %s", err, apps.CodeOperatorSecretUnset)
	}
	if !strings.Contains(err.Error(), "feed-key") || strings.Contains(err.Error(), "opt-key") {
		t.Fatalf("the refusal must name only the required name: %q", err)
	}

	if err := ops.Set(ctx, "alice", wiringAppID, "feed-key", secret.New([]byte("S-604-owner"))); err != nil {
		t.Fatal(err)
	}
	if v, err := settings.Get(ctx, storeswitch.KeySwitchedAt); err != nil || v == "" {
		t.Fatalf("after the PUT the marker row is %q (%v), want present", v, err)
	}

	_, env, err = src.ResolveCompose(ctx, wiringAppID, compose)
	if err != nil {
		t.Fatalf("the deploy after the PUT = %v", err)
	}
	if string(env["RASPUTIN_SECRET_FEED_KEY"].Reveal()) != "S-604-owner" {
		t.Fatal("the owner's value was not delivered")
	}
	if v, ok := env["RASPUTIN_SECRET_OPT_KEY"]; !ok || v.Len() != 0 {
		t.Fatal("the optional name was not delivered as an empty value")
	}
	if hkdf.calls != 0 {
		t.Fatalf("the HKDF source was reached %d time(s)", hkdf.calls)
	}
}

// countingResolver counts calls to the source it wraps.
type countingResolver struct {
	next  apps.SecretSource
	calls int
}

func (c *countingResolver) ResolveCompose(ctx context.Context, appID, compose string) (secret.Value, map[string]secret.Value, error) {
	c.calls++
	return c.next.ResolveCompose(ctx, appID, compose)
}

// TC-604-09 (wiring half): appOperatorSecrets reads the row's declarations,
// and a missing row or an unreadable table is an error, which StoreSource
// refuses on rather than deriving (F-604-02).
func TestAppOperatorSecrets(t *testing.T) {
	as := openAppsStore(t)
	now := time.Now()
	decls := []tileschema.OperatorSecret{{Name: "feed-key", Label: "Feed API key"}}
	if err := as.Create(t.Context(), &apps.App{ID: wiringAppID, Name: "feeds", ComposeYAML: "services: {}\n", TargetNode: "node-1",
		OperatorSecrets: decls, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	got, err := appOperatorSecrets{store: as}.OperatorSecrets(t.Context(), wiringAppID)
	if err != nil || len(got) != 1 || got[0].Name != "feed-key" {
		t.Fatalf("OperatorSecrets = %+v, %v; want the row's declaration", got, err)
	}
	if _, err := (appOperatorSecrets{store: as}).OperatorSecrets(t.Context(), "01JZZZZZZZZZZZZZZZZZZZZZZ1"); err == nil {
		t.Fatal("a missing app gave no error")
	}
	closed := openAppsStore(t)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := (appOperatorSecrets{store: closed}).OperatorSecrets(t.Context(), wiringAppID); err == nil {
		t.Fatal("a closed database gave no error")
	}
}
