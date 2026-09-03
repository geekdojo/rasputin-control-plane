package quiesce

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/agent/internal/docker"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// The drivers against a fake runtime that models exactly what the real one
// exposes — a volume directory, a running flag, stop/start, and a snapshot
// that writes DISTINGUISHABLE bytes so a test can prove the snapshot path was
// taken rather than the live file. The filesystem side is real: the tar that
// lands is the tar hardware would write.

type fakeRuntime struct {
	mu         sync.Mutex
	dir        string
	running    map[string]bool
	stopErr    error
	startFail  int // failing start attempts before one succeeds
	startCalls int
	stopCalls  int
	snapErr    error
}

func newFake(t *testing.T) *fakeRuntime {
	t.Helper()
	return &fakeRuntime{dir: t.TempDir(), running: map[string]bool{}}
}

func (f *fakeRuntime) Name() string { return "fake" }

func (f *fakeRuntime) volDir(appID, vol string) string { return filepath.Join(f.dir, appID, vol) }

func (f *fakeRuntime) ResolveVolume(_ context.Context, appID, vol string) (string, error) {
	d := f.volDir(appID, vol)
	if st, err := os.Stat(d); err != nil || !st.IsDir() {
		return "", fmt.Errorf("%w: %s/%s", docker.ErrVolumeNotFound, appID, vol)
	}
	return d, nil
}

func (f *fakeRuntime) AppRunning(_ context.Context, appID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running[appID], nil
}

func (f *fakeRuntime) StopApp(_ context.Context, appID string, _ int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopErr != nil {
		return f.stopErr
	}
	f.stopCalls++
	f.running[appID] = false
	return nil
}

func (f *fakeRuntime) StartApp(_ context.Context, appID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startCalls++
	if f.startCalls <= f.startFail {
		return fmt.Errorf("injected start failure %d", f.startCalls)
	}
	f.running[appID] = true
	return nil
}

func (f *fakeRuntime) SnapshotSQLite(ctx context.Context, appID, vol, dbRel, dstRel string) (string, error) {
	if f.snapErr != nil {
		return "", f.snapErr
	}
	if ok, _ := f.AppRunning(ctx, appID); !ok {
		return "", docker.ErrNoRunningContainer
	}
	root := f.volDir(appID, vol)
	src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(dbRel)))
	if err != nil {
		return "", err
	}
	dst := filepath.Join(root, filepath.FromSlash(dstRel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	return "fake", os.WriteFile(dst, append([]byte("SNAPSHOT|"), src...), 0o600)
}

func (f *fakeRuntime) counts() (stops, starts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopCalls, f.startCalls
}

func (f *fakeRuntime) isRunning(appID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running[appID]
}

// fixtureVolume lays out the shape of homeassistant-config: a recorder
// database with its WAL sidecars, the `.storage/` credential half, plain
// config, a nested file and a symlink.
func fixtureVolume(t *testing.T, root string) {
	t.Helper()
	files := map[string]string{
		"configuration.yaml":            "default_config:\n",
		".storage/auth":                 `{"data":{"refresh_tokens":[{"token":"secret"}]}}`,
		".storage/core.device_registry": `{"data":{"devices":[]}}`,
		"home-assistant_v2.db":          sqliteMagic + "live pages of the recorder",
		"home-assistant_v2.db-wal":      "wal frames not yet checkpointed",
		"home-assistant_v2.db-shm":      "shared memory index",
		"www/custom.js":                 "console.log(1)\n",
	}
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("configuration.yaml", filepath.Join(root, "link.yaml")); err != nil {
		t.Fatal(err)
	}
}

// newStager builds a Stager with test-speed defaults: a disk that is never
// full, a watchdog that fires in ten seconds, and a retry schedule in
// milliseconds.
func newStager(t *testing.T, rt Runtime) *Stager {
	t.Helper()
	s := New(rt, t.TempDir(), t.TempDir())
	s.freeBytes = func(string) (uint64, error) { return 1 << 40, nil }
	s.watchdogDeadline = 10 * time.Second
	s.restartBackoff = []time.Duration{0, 10 * time.Millisecond, 10 * time.Millisecond}
	s.releaseWait = 5 * time.Second
	s.logf = t.Logf
	return s
}

func stageCmd(app, vol, class, strategy, name string) proto.BackupStageVolumeCmd {
	return proto.BackupStageVolumeCmd{AppID: app, AppName: "Home Assistant", Volume: vol, Class: class, Quiesce: strategy, StagingName: name}
}

// readTar returns the regular files (name → bytes), the symlinks (name →
// target) and every entry name in the archive.
func readTar(t *testing.T, path string) (files map[string][]byte, links map[string]string, names []string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open staged tar: %v", err)
	}
	defer func() { _ = f.Close() }()
	files, links = map[string][]byte{}, map[string]string{}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		names = append(names, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeReg:
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			files[hdr.Name] = b
		case tar.TypeSymlink:
			links[hdr.Name] = hdr.Linkname
		}
	}
	return files, links, names
}

func hasName(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// prepared sets up a fake runtime with one running app and its fixture
// volume, and a stager over it.
func prepared(t *testing.T) (*fakeRuntime, *Stager) {
	t.Helper()
	rt := newFake(t)
	rt.running["ha"] = true
	dir := rt.volDir("ha", "homeassistant-config")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fixtureVolume(t, dir)
	return rt, newStager(t, rt)
}

// TestStageEachStrategy is the table: the three built strategies against the
// fixture, and the refusals for the two declared-but-unbuilt ones and the two
// classes this verb never stages.
func TestStageEachStrategy(t *testing.T) {
	cases := []struct {
		name        string
		class       string
		strategy    string
		wantOK      bool
		wantRefusal proto.StorageRefusal
		wantCons    proto.BackupConsistency
		wantStopped bool
		wantDetail  string
	}{
		{"none copies live", tileschema.BackupState, tileschema.QuiesceNone, true, "", proto.BackupConsistencyLiveCopy, false, ""},
		{"stop yields clean shutdown", tileschema.BackupCritical, tileschema.QuiesceStop, true, "", proto.BackupConsistencyCleanShutdown, true, ""},
		{"sqlite snapshots and copies the rest", tileschema.BackupState, tileschema.QuiesceSQLite, true, "", proto.BackupConsistencySnapshotPlusLive, false, ""},
		{"postgres is declared but not built", tileschema.BackupState, tileschema.QuiescePostgres, false, proto.BackupRefusalQuiesceUnsupported, "", false, "not implemented in this build"},
		{"mysql is declared but not built", tileschema.BackupState, tileschema.QuiesceMySQL, false, proto.BackupRefusalQuiesceUnsupported, "", false, "not implemented in this build"},
		{"cache is never copied", tileschema.BackupCache, tileschema.QuiesceNone, false, proto.BackupRefusalClassNotStaged, "", false, "never copies"},
		{"bulk streams direct", tileschema.BackupBulk, tileschema.QuiesceNone, false, proto.BackupRefusalClassNotStaged, "", false, "streams direct"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, s := prepared(t)
			ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", tc.class, tc.strategy, "ha-config.tar"))
			if ack.OK != tc.wantOK {
				t.Fatalf("ok = %t, want %t: %+v", ack.OK, tc.wantOK, ack)
			}
			if ack.Refusal != tc.wantRefusal {
				t.Errorf("refusal = %q, want %q (%s)", ack.Refusal, tc.wantRefusal, ack.Detail)
			}
			if ack.Consistency != tc.wantCons {
				t.Errorf("consistency = %q, want %q", ack.Consistency, tc.wantCons)
			}
			if ack.Stopped != tc.wantStopped {
				t.Errorf("stopped = %t, want %t", ack.Stopped, tc.wantStopped)
			}
			if !ack.AppRestored {
				t.Errorf("appRestored = false on every path the app must be back: %s", ack.RestoreDetail)
			}
			if !rt.isRunning("ha") {
				t.Error("the app is not running afterwards")
			}
			if tc.wantDetail != "" {
				if !strings.Contains(ack.Detail, tc.wantDetail) {
					t.Errorf("detail %q does not say %q", ack.Detail, tc.wantDetail)
				}
				if !strings.Contains(ack.Detail, "homeassistant-config") {
					t.Errorf("a refusal must name the volume: %q", ack.Detail)
				}
				stops, starts := rt.counts()
				if stops != 0 || starts != 0 {
					t.Errorf("a refused strategy touched the app: %d stops, %d starts", stops, starts)
				}
				if _, err := os.Stat(filepath.Join(s.stagingRoot, "ha-config.tar")); err == nil {
					t.Error("a refused command left a staged file behind")
				}
				return
			}
			if ack.Window == "" {
				t.Error("the ack does not say what window the strategy leaves")
			}
			files, links, _ := readTar(t, ack.StagedPath)
			for _, want := range []string{"configuration.yaml", ".storage/auth", ".storage/core.device_registry", "www/custom.js", "home-assistant_v2.db"} {
				if _, ok := files[want]; !ok {
					t.Errorf("%s missing from the staged copy", want)
				}
			}
			if links["link.yaml"] != "configuration.yaml" {
				t.Errorf("symlink not preserved: %v", links)
			}
			if ack.FileCount == 0 || ack.PlaintextBytes == 0 || ack.SizeBytes == 0 || ack.Digest == "" {
				t.Errorf("ack under-reports the copy: %+v", ack)
			}
		})
	}
}

func TestStopRestartsOnSuccess(t *testing.T) {
	rt, s := prepared(t)
	ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceStop, "x.tar"))
	if !ack.OK || !ack.Stopped || !ack.WasRunning || !ack.ServiceInterrupting {
		t.Fatalf("ack = %+v", ack)
	}
	if !ack.AppRestored || ack.RestoredBy != "driver" {
		t.Errorf("restored=%t by %q: %s", ack.AppRestored, ack.RestoredBy, ack.RestoreDetail)
	}
	if ack.RestartedAt.Before(ack.StoppedAt) || ack.DowntimeMillis < 0 {
		t.Errorf("downtime not measured: stopped %s restarted %s (%dms)", ack.StoppedAt, ack.RestartedAt, ack.DowntimeMillis)
	}
	stops, starts := rt.counts()
	if stops != 1 || starts != 1 {
		t.Errorf("stops=%d starts=%d, want 1 and 1", stops, starts)
	}
	if ents, _ := os.ReadDir(s.markerDir); len(ents) != 0 {
		t.Errorf("marker left behind after a successful restart: %v", ents)
	}
}

// The copy fails partway. The app must still come back, and nothing may be
// left under the staging root.
func TestStopRestartsOnFailure(t *testing.T) {
	rt, s := prepared(t)
	s.afterFile = func(rel string) error { return errors.New("disk went away") }
	ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceStop, "x.tar"))
	if ack.OK {
		t.Fatal("a copy that failed reported ok")
	}
	if ack.Refusal != proto.StorageRefusalBackendError || !strings.Contains(ack.Detail, "disk went away") {
		t.Errorf("refusal %q detail %q", ack.Refusal, ack.Detail)
	}
	if !ack.AppRestored || !rt.isRunning("ha") {
		t.Errorf("the app was not restarted after a failed copy: %s", ack.RestoreDetail)
	}
	assertStagingEmpty(t, s.stagingRoot)
}

// The copy is KILLED — a panic, or a cancelled context — and the app must
// come back on both paths, with an ack that says what happened.
func TestStopRestartsOnAKilledCopy(t *testing.T) {
	t.Run("panic mid-copy", func(t *testing.T) {
		rt, s := prepared(t)
		n := 0
		s.afterFile = func(rel string) error {
			n++
			if n == 2 {
				panic("simulated crash in the copy")
			}
			return nil
		}
		ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceStop, "x.tar"))
		if ack.OK || !strings.Contains(ack.Detail, "panic") {
			t.Fatalf("ack = %+v", ack)
		}
		if !ack.AppRestored || !rt.isRunning("ha") {
			t.Errorf("the app was not restarted after a panic: %s", ack.RestoreDetail)
		}
		if !ack.Stopped {
			t.Error("the ack lost the fact that the app had been stopped")
		}
		assertStagingEmpty(t, s.stagingRoot)
	})
	t.Run("context cancelled mid-copy", func(t *testing.T) {
		rt, s := prepared(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s.afterFile = func(rel string) error { cancel(); return nil }
		ack := s.Stage(ctx, stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceStop, "x.tar"))
		if ack.OK || !strings.Contains(ack.Detail, "context canceled") {
			t.Fatalf("ack = %+v", ack)
		}
		if !ack.AppRestored || !rt.isRunning("ha") {
			t.Errorf("the app was not restarted after the request was cancelled: %s", ack.RestoreDetail)
		}
		assertStagingEmpty(t, s.stagingRoot)
	})
}

// A start that fails is retried; the app is back and the ack says on which
// attempt.
func TestStopRetriesAStartThatFails(t *testing.T) {
	rt, s := prepared(t)
	rt.startFail = 2
	ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceStop, "x.tar"))
	if !ack.OK || !ack.AppRestored || !rt.isRunning("ha") {
		t.Fatalf("ack = %+v", ack)
	}
	if !strings.Contains(ack.RestoreDetail, "attempt 3") {
		t.Errorf("restoreDetail = %q, want the attempt number", ack.RestoreDetail)
	}
}

// An app that will not start: the copy is fine, the ack is loud about the app,
// the marker survives, and the next agent start sweeps it.
func TestStopReportsAnAppThatWillNotComeBackAndTheSweepRetries(t *testing.T) {
	rt, s := prepared(t)
	rt.startFail = 1 << 20
	ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceStop, "x.tar"))
	if !ack.OK {
		t.Fatalf("the copy itself should have succeeded: %+v", ack)
	}
	if ack.AppRestored || rt.isRunning("ha") {
		t.Fatal("the ack claims the app is back when every start failed")
	}
	if !strings.Contains(ack.RestoreDetail, "next agent start") {
		t.Errorf("restoreDetail = %q", ack.RestoreDetail)
	}
	ents, _ := os.ReadDir(s.markerDir)
	if len(ents) != 1 {
		t.Fatalf("marker not kept for the boot sweep: %v", ents)
	}

	// "The agent restarts": a fresh Stager over the same marker dir, with a
	// runtime whose start now works.
	rt.mu.Lock()
	rt.startFail = 0
	rt.startCalls = 0
	rt.mu.Unlock()
	s2 := New(rt, s.stagingRoot, s.markerDir)
	s2.restartBackoff = s.restartBackoff
	s2.logf = t.Logf
	if n := s2.SweepArmedStops(); n != 1 {
		t.Errorf("sweep found %d markers, want 1", n)
	}
	if !rt.isRunning("ha") {
		t.Error("the boot sweep did not start the app")
	}
	if ents, _ := os.ReadDir(s.markerDir); len(ents) != 0 {
		t.Errorf("marker left after a successful sweep: %v", ents)
	}
}

// An app that was already stopped is copied without stopping and is NOT
// started afterwards.
func TestStopLeavesAStoppedAppStopped(t *testing.T) {
	rt, s := prepared(t)
	rt.running["ha"] = false
	ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceStop, "x.tar"))
	if !ack.OK || ack.WasRunning || ack.Stopped {
		t.Fatalf("ack = %+v", ack)
	}
	if ack.Consistency != proto.BackupConsistencyCleanShutdown {
		t.Errorf("a stopped app's volume is clean-shutdown consistent; got %q", ack.Consistency)
	}
	if stops, starts := rt.counts(); stops != 0 || starts != 0 {
		t.Errorf("stops=%d starts=%d: a backup must not start an app the operator stopped", stops, starts)
	}
	if rt.isRunning("ha") {
		t.Error("the app was started by a backup")
	}
	if !ack.AppRestored {
		t.Error("an app left as it was found is restored")
	}
}

// The driver hangs past the deadline. The watchdog restarts the app on its
// own; the copy that then completes is discarded and the ack says why.
func TestWatchdogFiresWhenTheDriverHangs(t *testing.T) {
	rt, s := prepared(t)
	s.watchdogDeadline = 150 * time.Millisecond
	s.afterFile = func(rel string) error {
		// Hang until the watchdog has brought the app back, then continue.
		deadline := time.Now().Add(5 * time.Second)
		for !rt.isRunning("ha") {
			if time.Now().After(deadline) {
				return errors.New("the watchdog never fired")
			}
			time.Sleep(10 * time.Millisecond)
		}
		return nil
	}
	ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceStop, "x.tar"))
	if ack.OK {
		t.Fatal("a copy the watchdog interrupted was reported consistent")
	}
	if !strings.Contains(ack.Detail, "watchdog") {
		t.Errorf("detail = %q", ack.Detail)
	}
	if ack.RestoredBy != "watchdog" || !ack.AppRestored || !rt.isRunning("ha") {
		t.Errorf("restoredBy=%q restored=%t running=%t", ack.RestoredBy, ack.AppRestored, rt.isRunning("ha"))
	}
	assertStagingEmpty(t, s.stagingRoot)
}

// The gap §4.3's definition left open: the database is a snapshot AND the
// credential half of the volume is captured, the WAL sidecars are not, and
// the scratch directory is gone from both the tar and the volume.
func TestSQLiteCapturesTheDatabaseAndTheRest(t *testing.T) {
	rt, s := prepared(t)
	ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceSQLite, "x.tar"))
	if !ack.OK {
		t.Fatalf("ack = %+v", ack)
	}
	files, _, names := readTar(t, ack.StagedPath)
	db, ok := files["home-assistant_v2.db"]
	if !ok {
		t.Fatal("the database is not in the copy")
	}
	if !strings.HasPrefix(string(db), "SNAPSHOT|") {
		t.Errorf("the database was copied live, not snapshotted: %q", db)
	}
	if _, ok := files[".storage/auth"]; !ok {
		t.Error(".storage/auth — the credential half of the volume — is missing; this is the restore-day failure")
	}
	for _, sidecar := range []string{"home-assistant_v2.db-wal", "home-assistant_v2.db-shm"} {
		if hasName(names, sidecar) {
			t.Errorf("%s captured beside a self-contained snapshot", sidecar)
		}
	}
	for _, n := range names {
		if strings.HasPrefix(n, scratchDirName) {
			t.Errorf("scratch directory leaked into the archive: %s", n)
		}
	}
	if _, err := os.Stat(filepath.Join(rt.volDir("ha", "homeassistant-config"), scratchDirName)); err == nil {
		t.Error("scratch directory left in the app's volume")
	}
	if len(ack.Databases) != 1 || ack.Databases[0] != "home-assistant_v2.db" || ack.SnapshotTool != "fake" {
		t.Errorf("databases=%v tool=%q", ack.Databases, ack.SnapshotTool)
	}
	if stops, starts := rt.counts(); stops != 0 || starts != 0 {
		t.Errorf("sqlite must leave the app up: stops=%d starts=%d", stops, starts)
	}
	if ack.ServiceInterrupting {
		t.Error("sqlite is not service-interrupting")
	}
}

// A sqlite volume whose app is stopped is a plain copy — sidecars included,
// since nothing writes them and SQLite recovers from them on open.
func TestSQLiteOnAStoppedAppCopiesPlainly(t *testing.T) {
	rt, s := prepared(t)
	rt.running["ha"] = false
	ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceSQLite, "x.tar"))
	if !ack.OK || ack.Consistency != proto.BackupConsistencyCleanShutdown || len(ack.Databases) != 0 {
		t.Fatalf("ack = %+v", ack)
	}
	_, _, names := readTar(t, ack.StagedPath)
	if !hasName(names, "home-assistant_v2.db-wal") {
		t.Error("a stopped app's WAL belongs in the copy")
	}
}

func TestSQLiteRefusesWhenTheSnapshotFails(t *testing.T) {
	rt, s := prepared(t)
	rt.snapErr = errors.New("no python3 in the image")
	ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceSQLite, "x.tar"))
	if ack.OK || ack.Refusal != proto.BackupRefusalQuiesceFailed {
		t.Fatalf("ack = %+v", ack)
	}
	if !strings.Contains(ack.Detail, "no python3") || !strings.Contains(ack.Detail, "home-assistant_v2.db") {
		t.Errorf("detail = %q", ack.Detail)
	}
	assertStagingEmpty(t, s.stagingRoot)
}

// The docker MOCK end to end: real directories, persisted status, the
// injected start failure, and the boot sweep.
func TestStopAndSQLiteOnTheDockerMock(t *testing.T) {
	mb, err := docker.NewMockBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := mb.Deploy(ctx, "ha", "Home Assistant", "services: {}\n"); err != nil {
		t.Fatal(err)
	}
	dir, err := mb.VolumeDir("ha", "homeassistant-config")
	if err != nil {
		t.Fatal(err)
	}
	fixtureVolume(t, dir)
	s := newStager(t, mb)

	ack := s.Stage(ctx, stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceSQLite, "sqlite.tar"))
	if !ack.OK || ack.SnapshotTool != "mock" || len(ack.Databases) != 1 {
		t.Fatalf("sqlite on the mock: %+v", ack)
	}
	files, _, _ := readTar(t, ack.StagedPath)
	if _, ok := files[".storage/auth"]; !ok {
		t.Error(".storage/auth missing")
	}

	ack = s.Stage(ctx, stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceStop, "stop.tar"))
	if !ack.OK || !ack.Stopped || !ack.AppRestored {
		t.Fatalf("stop on the mock: %+v", ack)
	}
	if running, _ := mb.AppRunning(ctx, "ha"); !running {
		t.Error("the mock app is not running after a stop-copy-start")
	}

	// The daemon refuses to start it: the ack is loud, the marker stays.
	t.Setenv("RASPUTIN_DOCKER_FAIL_MODE", "start")
	ack = s.Stage(ctx, stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceStop, "stuck.tar"))
	if !ack.OK || ack.AppRestored {
		t.Fatalf("with start failing: %+v", ack)
	}
	if running, _ := mb.AppRunning(ctx, "ha"); running {
		t.Fatal("the mock says running while every start failed")
	}
	// "Agent restarts" with the daemon healthy again.
	t.Setenv("RASPUTIN_DOCKER_FAIL_MODE", "")
	if n := s.SweepArmedStops(); n != 1 {
		t.Errorf("sweep found %d, want 1", n)
	}
	if running, _ := mb.AppRunning(ctx, "ha"); !running {
		t.Error("the sweep did not start the mock app")
	}
}

func TestFreeSpaceGuardRefusesBeforeTouchingAnything(t *testing.T) {
	rt, s := prepared(t)
	s.freeBytes = func(string) (uint64, error) { return 1, nil }
	ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceStop, "x.tar"))
	if ack.OK || ack.Refusal != proto.BackupRefusalInsufficientSpace {
		t.Fatalf("ack = %+v", ack)
	}
	for _, want := range []string{"free", "needs about", "reserve", "not stopped"} {
		if !strings.Contains(ack.Detail, want) {
			t.Errorf("detail %q does not say %q", ack.Detail, want)
		}
	}
	if stops, _ := rt.counts(); stops != 0 || ack.Stopped {
		t.Error("the app was stopped for a copy there was no room for")
	}
	assertStagingEmpty(t, s.stagingRoot)
}

// The reserve is counted: a disk with room for the volume but not for the
// volume plus the reserve refuses.
func TestFreeSpaceGuardCountsTheReserve(t *testing.T) {
	_, s := prepared(t)
	p, err := measure(s.rt.(*fakeRuntime).volDir("ha", "homeassistant-config"), false)
	if err != nil {
		t.Fatal(err)
	}
	s.freeBytes = func(string) (uint64, error) { return p.bytes + proto.BackupStagingReserveBytes - 1, nil }
	ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceNone, "x.tar"))
	if ack.OK || ack.Refusal != proto.BackupRefusalInsufficientSpace {
		t.Fatalf("one byte short of the reserve was accepted: %+v", ack)
	}
	s.freeBytes = func(string) (uint64, error) { return p.bytes + proto.BackupStagingReserveBytes, nil }
	if ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceNone, "y.tar")); !ack.OK {
		t.Fatalf("exactly the reserve was refused: %+v", ack)
	}
}

func TestDigestAndSizeMatchAReRead(t *testing.T) {
	_, s := prepared(t)
	ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", tileschema.BackupState, tileschema.QuiesceStop, "x.tar"))
	if !ack.OK {
		t.Fatalf("ack = %+v", ack)
	}
	sum, err := fileDigest(ack.StagedPath)
	if err != nil {
		t.Fatal(err)
	}
	if sum != ack.Digest {
		t.Errorf("digest on the ack %s != re-read %s", ack.Digest, sum)
	}
	st, err := os.Stat(ack.StagedPath)
	if err != nil {
		t.Fatal(err)
	}
	if uint64(st.Size()) != ack.SizeBytes {
		t.Errorf("size on the ack %d != on disk %d", ack.SizeBytes, st.Size())
	}
	if filepath.Dir(ack.StagedPath) != s.stagingRoot || filepath.Base(ack.StagedPath) != "x.tar" {
		t.Errorf("staged at %s, want directly under %s", ack.StagedPath, s.stagingRoot)
	}
	if ents, _ := os.ReadDir(s.stagingRoot); len(ents) != 1 {
		t.Errorf("partial file left beside the staged one: %v", ents)
	}
}

func TestStageRefusesByShape(t *testing.T) {
	rt, s := prepared(t)
	bad := []struct {
		name string
		cmd  proto.BackupStageVolumeCmd
	}{
		{"path as staging name", stageCmd("ha", "homeassistant-config", "state", "stop", "../x.tar")},
		{"dotfile staging name", stageCmd("ha", "homeassistant-config", "state", "stop", ".x.tar")},
		{"empty staging name", stageCmd("ha", "homeassistant-config", "state", "stop", "")},
		{"unknown class", stageCmd("ha", "homeassistant-config", "archive", "stop", "x.tar")},
		{"unknown strategy", stageCmd("ha", "homeassistant-config", "state", "freeze", "x.tar")},
		{"no app", stageCmd("", "homeassistant-config", "state", "stop", "x.tar")},
		{"no volume", stageCmd("ha", "", "state", "stop", "x.tar")},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			ack := s.Stage(context.Background(), tc.cmd)
			if ack.OK || ack.Refusal != proto.BackupRefusalStagingMissing {
				t.Errorf("ack = %+v", ack)
			}
			if stops, _ := rt.counts(); stops != 0 {
				t.Error("a malformed command stopped the app")
			}
		})
	}
	t.Run("unknown volume", func(t *testing.T) {
		ack := s.Stage(context.Background(), stageCmd("ha", "not-declared", "state", "stop", "x.tar"))
		if ack.OK || ack.Refusal != proto.BackupRefusalVolumeNotFound {
			t.Errorf("ack = %+v", ack)
		}
	})
	t.Run("existing staging name", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(s.stagingRoot, "taken.tar"), []byte("mid-upload"), 0o600); err != nil {
			t.Fatal(err)
		}
		ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", "state", "stop", "taken.tar"))
		if ack.OK || ack.Refusal != proto.BackupRefusalStagingExists {
			t.Errorf("ack = %+v", ack)
		}
		if b, _ := os.ReadFile(filepath.Join(s.stagingRoot, "taken.tar")); string(b) != "mid-upload" {
			t.Error("the existing staged file was overwritten")
		}
	})
	t.Run("no staging root", func(t *testing.T) {
		s2 := newStager(t, rt)
		s2.stagingRoot = ""
		ack := s2.Stage(context.Background(), stageCmd("ha", "homeassistant-config", "state", "stop", "x.tar"))
		if ack.OK || ack.Refusal != proto.BackupRefusalStagingMissing {
			t.Errorf("ack = %+v", ack)
		}
	})
}

func TestUnstage(t *testing.T) {
	_, s := prepared(t)
	ack := s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", "state", "none", "x.tar"))
	if !ack.OK {
		t.Fatal(ack.Detail)
	}
	u := s.Unstage(proto.BackupUnstageCmd{StagingName: "x.tar"})
	if !u.OK || !u.Existed || u.FreedBytes != ack.SizeBytes {
		t.Errorf("unstage = %+v", u)
	}
	if _, err := os.Stat(ack.StagedPath); err == nil {
		t.Error("the staged file is still there")
	}
	u = s.Unstage(proto.BackupUnstageCmd{StagingName: "x.tar"})
	if !u.OK || u.Existed {
		t.Errorf("a retried unstage must converge: %+v", u)
	}
	u = s.Unstage(proto.BackupUnstageCmd{StagingName: "../x.tar"})
	if u.OK || u.Refusal != proto.BackupRefusalStagingMissing {
		t.Errorf("a path was accepted: %+v", u)
	}
	if err := os.Mkdir(filepath.Join(s.stagingRoot, "adir"), 0o700); err != nil {
		t.Fatal(err)
	}
	u = s.Unstage(proto.BackupUnstageCmd{StagingName: "adir"})
	if u.OK {
		t.Errorf("a directory was removed: %+v", u)
	}
}

// §4.7: one volume at a time, so peak is the largest single volume.
func TestOneVolumeAtATime(t *testing.T) {
	rt, s := prepared(t)
	second := rt.volDir("ha", "other")
	if err := os.MkdirAll(second, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	hold := make(chan struct{})
	entered := make(chan struct{}, 1)
	s.afterFile = func(rel string) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-hold
		return nil
	}
	first := make(chan *proto.BackupStageVolumeAck, 1)
	go func() {
		first <- s.Stage(context.Background(), stageCmd("ha", "homeassistant-config", "state", "none", "a.tar"))
	}()
	<-entered
	s.afterFile = nil
	done := make(chan *proto.BackupStageVolumeAck, 1)
	go func() {
		done <- s.Stage(context.Background(), stageCmd("ha", "other", "state", "none", "b.tar"))
	}()
	select {
	case <-done:
		t.Fatal("a second volume was staged while the first was still copying")
	case <-time.After(150 * time.Millisecond):
	}
	close(hold)
	if a := <-first; !a.OK {
		t.Errorf("first: %+v", a)
	}
	if b := <-done; !b.OK {
		t.Errorf("second: %+v", b)
	}
}

// A marker this package did not write is left alone: a start is a
// service-affecting operation and the only authority for it is a marker this
// code can read.
func TestSweepIgnoresForeignMarkers(t *testing.T) {
	rt, s := prepared(t)
	rt.running["ha"] = false
	if err := os.MkdirAll(s.markerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.markerDir, "junk.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.markerDir, "notes.txt"), []byte(`{"appId":"ha"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := s.SweepArmedStops(); n != 0 {
		t.Errorf("sweep acted on %d foreign markers", n)
	}
	if rt.isRunning("ha") {
		t.Error("a foreign marker started an app")
	}
}

// A file that shrinks between being sized and being copied fails the run
// rather than producing a tar whose member does not match its header. Tested
// at the writer, because the window is between one stat and one read.
func TestWriteFileRefusesAFileThatShrank(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("twelve bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var sink strings.Builder
	tw := tar.NewWriter(&sink)
	err = writeFile(tw, info, "f", p)
	if !errors.Is(err, ErrFileChanged) {
		t.Fatalf("writeFile on a shrunk file: %v, want ErrFileChanged", err)
	}
}

// fileDigest hashes a staged file the way the writer did, so the ack can be
// checked against a re-read.
func fileDigest(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func assertStagingEmpty(t *testing.T, root string) {
	t.Helper()
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Errorf("staging root not empty after a failure: %v", ents)
	}
}
