package storage

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// fakeSecretStore is a SecretStore recording every call in order. Its store
// is "down" between a successful Stop and a successful Start.
type fakeSecretStore struct {
	mu       sync.Mutex
	calls    []string
	notReady string
	readyErr error
	keyID    string
	keyErr   error
	version  string
	verErr   error
	stopErr  error
	startErr error
	waitErr  error
	running  bool
	// onStop runs after a successful Stop, with the store down.
	onStop func()
}

func newFakeSecretStore() *fakeSecretStore {
	return &fakeSecretStore{keyID: fixtureKeyID, version: fixtureBaoVer, running: true}
}

func (f *fakeSecretStore) record(c string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
}

func (f *fakeSecretStore) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeSecretStore) Readiness(context.Context) (string, error) {
	f.record("readiness")
	return f.notReady, f.readyErr
}

func (f *fakeSecretStore) SealKeyID() (string, error) {
	f.record("keyid")
	return f.keyID, f.keyErr
}

func (f *fakeSecretStore) Version(context.Context) (string, error) {
	f.record("version")
	return f.version, f.verErr
}

func (f *fakeSecretStore) Stop(ctx context.Context) error {
	f.record("stop:" + jobs.JobIDFromContext(ctx))
	if f.stopErr != nil {
		return f.stopErr
	}
	f.mu.Lock()
	f.running = false
	f.mu.Unlock()
	if f.onStop != nil {
		f.onStop()
	}
	return nil
}

func (f *fakeSecretStore) Start(context.Context) error {
	f.record("start")
	if f.startErr != nil {
		return f.startErr
	}
	f.mu.Lock()
	f.running = true
	f.mu.Unlock()
	return nil
}

func (f *fakeSecretStore) WaitReady(context.Context) error {
	f.record("wait")
	return f.waitErr
}

func (f *fakeSecretStore) Quiesce(jobID string) func() {
	f.record("quiesce:" + jobID)
	var once sync.Once
	return func() { once.Do(func() { f.record("release") }) }
}

// Health is the store's sys/health: unreachable while stopped.
func (f *fakeSecretStore) Health(context.Context) (secretstore.Health, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.running {
		return secretstore.Health{}, &secretstore.Error{Op: "health", Kind: secretstore.ErrUnreachable}
	}
	return secretstore.Health{Initialized: true, Version: f.version}, nil
}

// stepOf returns the named step of jobID.
func stepOf(t *testing.T, h *runHarness, jobID, name string) *jobs.JobStep {
	t.Helper()
	steps, err := h.jobStore.ListSteps(context.Background(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range steps {
		if st.Name == name {
			return st
		}
	}
	return nil
}

func stepNames(t *testing.T, h *runHarness, jobID string) []string {
	t.Helper()
	steps, err := h.jobStore.ListSteps(context.Background(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, st := range steps {
		out = append(out, st.Name)
	}
	return out
}

// writtenManifest is the manifest of the generation jobID wrote.
func writtenManifest(t *testing.T, h *runHarness, jobID string) Manifest {
	t.Helper()
	run := h.run(t, jobID)
	b, err := os.ReadFile(filepath.Join(h.generationDir(run.GenerationID), proto.BackupManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TC-765-01: Assemble with a store capture writes a version-3 manifest
// listing every data file under store/data/, the seal files, the version
// member and the store CA, each sized and hashed from its source bytes and
// noted; the version member holds exactly the version string; the
// exclusions name the store's leaves and keep the audit line.
func TestAssembleCarriesTheStore(t *testing.T) {
	dir := t.TempDir()
	src := IdentitySources{TrustDir: filepath.Join(dir, "trust")}
	src.StoreDataDir = filepath.Join(dir, "openbao")
	src.SealDir = filepath.Join(dir, "openbao-seal")
	data := writeStoreDataFixture(t, src.StoreDataDir)
	sealKey := fixtureSealKey("K1")
	writeSealFixture(t, src.SealDir, fixtureKeyID, sealKey)
	writeStoreCAFixture(t, src.TrustDir)
	snap := filepath.Join(dir, "snap.db")
	writeTestFile(t, snap, "SNAP")

	var buf bytes.Buffer
	m, err := Assemble(&buf, AssembleOptions{
		Sources: src, SnapshotPath: snap, GenerationID: "g1", Scope: proto.BackupScopeFull,
		StoreCapture: stageStoreFixture(t, src, fixtureKeyID),
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if m.ManifestVersion != 3 {
		t.Fatalf("manifest version %d, want 3", m.ManifestVersion)
	}
	want := map[string][]byte{}
	for k, v := range data {
		want[k] = v
	}
	want[storeSealKeyArchivePath] = sealKey
	want[storeSealHCLArchivePath] = []byte(sealFragment(fixtureKeyID))
	want[storeVersionArchivePath] = []byte(fixtureBaoVer)
	for _, f := range []string{"store-ca.key", "store-ca.pem"} {
		b, _ := os.ReadFile(filepath.Join(src.TrustDir, f))
		want["trust/"+f] = b
	}
	got := map[string]ManifestEntry{}
	for _, e := range m.Entries {
		got[e.Path] = e
	}
	for p, b := range want {
		e, ok := got[p]
		if !ok {
			t.Errorf("manifest lacks %s", p)
			continue
		}
		if e.SizeBytes != int64(len(b)) || e.SHA256 != sha(b) || e.Note == "" {
			t.Errorf("%s: entry %+v, want size %d, sha %s and a note", p, e, len(b), sha(b))
		}
	}
	// The tar holds the same bytes the manifest describes.
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		if b, ok := want[hdr.Name]; ok && !bytes.Equal(body, b) {
			t.Errorf("tar member %s holds other bytes than its source", hdr.Name)
		}
		if hdr.Name == storeVersionArchivePath && string(body) != fixtureBaoVer {
			t.Errorf("%s = %q, want exactly %q", storeVersionArchivePath, body, fixtureBaoVer)
		}
	}
	ex := strings.Join(m.Excluded, "\n")
	for _, w := range []string{"tls/openbao-server/", "tls/openbao-client/", "openbao-audit/"} {
		if !strings.Contains(ex, w) {
			t.Errorf("exclusions do not name %s:\n%s", w, ex)
		}
	}
}

// TC-765-02: with no secret store wired there is no snapshot_store step,
// the manifest is version 2, and no store or store-CA entry exists — even
// with a store CA on disk, which every start creates.
func TestBackupRunWithoutAStoreIsVersionTwo(t *testing.T) {
	h := newRunHarness(t, nil, runHarnessOpts{})
	writeStoreCAFixture(t, h.trustDir)
	jobID := h.submit(t, RunSpec{Reason: ReasonManual})
	if j := h.waitTerminal(t, jobID); j.Status != jobs.StatusSucceeded {
		t.Fatalf("job %s: %s", j.Status, j.Error)
	}
	if names := stepNames(t, h, jobID); slices.Contains(names, storeCaptureStepName) {
		t.Fatalf("steps %v hold %s with no store wired", names, storeCaptureStepName)
	}
	m := writtenManifest(t, h, jobID)
	if m.ManifestVersion != 2 {
		t.Fatalf("manifest version %d, want 2", m.ManifestVersion)
	}
	for _, e := range m.Entries {
		if strings.HasPrefix(e.Path, "store/") || strings.HasPrefix(e.Path, "trust/store-ca") {
			t.Errorf("a store-less archive holds %s", e.Path)
		}
	}
}

// TC-765-21: a run with a store snapshots the database, then the store, then
// fans out; snapshot_store's result and its log lines carry the file count,
// the bytes, the version and the key id, and nothing key-shaped. The manifest
// is version 3.
func TestBackupRunCapturesTheStoreAfterTheDatabase(t *testing.T) {
	fs := newFakeSecretStore()
	h := newRunHarness(t, nil, runHarnessOpts{secretStore: fs})
	jobID := h.submit(t, RunSpec{Reason: ReasonManual})
	if j := h.waitTerminal(t, jobID); j.Status != jobs.StatusSucceeded {
		t.Fatalf("job %s: %s", j.Status, j.Error)
	}
	names := stepNames(t, h, jobID)
	i := slices.Index(names, "snapshot_db")
	if i < 0 || i+2 >= len(names) || names[i+1] != storeCaptureStepName || names[i+2] != "fan_out" {
		t.Fatalf("steps = %v, want snapshot_db, %s, fan_out in order", names, storeCaptureStepName)
	}
	var res map[string]any
	if err := json.Unmarshal(stepOf(t, h, jobID, storeCaptureStepName).Result, &res); err != nil {
		t.Fatal(err)
	}
	keys := slices.Sorted(func(yield func(string) bool) {
		for k := range res {
			if !yield(k) {
				return
			}
		}
	})
	if !reflect.DeepEqual(keys, []string{"files", "keyId", "sizeBytes", "stagingName", "version"}) {
		t.Errorf("result keys = %v", keys)
	}
	if res["files"] != float64(4) || res["version"] != fixtureBaoVer || res["keyId"] != fixtureKeyID || res["sizeBytes"].(float64) <= 0 {
		t.Errorf("result = %v", res)
	}
	ledger := h.ledgerText(t, jobID)
	for _, w := range []string{"copied 4 secret store file(s)", "version " + fixtureBaoVer, "seal key " + fixtureKeyID} {
		if !strings.Contains(ledger, w) {
			t.Errorf("the job feed lacks %q", w)
		}
	}
	if m := writtenManifest(t, h, jobID); m.ManifestVersion != 3 {
		t.Errorf("manifest version %d, want 3", m.ManifestVersion)
	}
	want := []string{"readiness", "keyid", "version", "quiesce:" + jobID, "stop:" + jobID, "start", "wait", "release"}
	if got := fs.got(); !reflect.DeepEqual(got, want) {
		t.Errorf("store calls = %v, want %v", got, want)
	}
}

// TC-765-03: a store-era run whose assemble finds no usable store copy —
// the result missing, or the staged tar gone — fails and writes no archive,
// never a version-2 one.
func TestBackupRunNeverWritesAPreStoreArchiveWithAStore(t *testing.T) {
	// The staged tar gone between the steps.
	late := &lateStore{}
	h2 := newRunHarness(t, nil, runHarnessOpts{secretStore: late})
	late.inner = &tarRemover{fakeSecretStore: newFakeSecretStore(), dir: h2.stagingDir}
	jobID := h2.submit(t, RunSpec{Reason: ReasonManual})
	j := h2.waitTerminal(t, jobID)
	if j.Status != jobs.StatusFailed || j.Error != string(errStoreCaptureMissing) {
		t.Fatalf("job %s %q, want failed with %q", j.Status, j.Error, errStoreCaptureMissing)
	}
	if st := stepOf(t, h2, jobID, "assemble"); st == nil || st.Status != jobs.StepFailed {
		t.Fatalf("assemble step = %+v, want failed", st)
	}
	if n := h2.agent.writeCount(); n != 0 {
		t.Errorf("%d write(s), want none", n)
	}
	if e := h2.stagingEntries(t); len(e) != 0 {
		t.Errorf("staging holds %v after the failure", e)
	}

	// The result missing: runAssemble with a store wired and no
	// snapshot_store result refuses before reading anything.
	sc := &jobs.StepCtx{Ctx: context.Background(), JobID: "j", PriorResults: map[string]json.RawMessage{}}
	tgt, _ := json.Marshal(runTarget{PartUUID: "p", NodeID: "n", GenerationID: "20261023T000000Z-j-full", Scope: proto.BackupScopeFull})
	pre, _ := json.Marshal(runPreflightResult{StagingRoot: t.TempDir()})
	snap, _ := json.Marshal(runSnapshotResult{StagingName: "20261023T000000Z-j-full.db"})
	fan, _ := json.Marshal(runFanOutResult{})
	sc.PriorResults["validate"], sc.PriorResults["preflight"], sc.PriorResults["snapshot_db"], sc.PriorResults["fan_out"] = tgt, pre, snap, fan
	if _, err := runAssemble(RunConfig{SecretStore: newFakeSecretStore()})(sc); !errors.Is(err, errStoreCaptureMissing) {
		t.Fatalf("assemble with no store result = %v, want %v", err, errStoreCaptureMissing)
	}
}

// tarRemover is a fake store whose WaitReady removes the staged copy the
// step just wrote, so assemble finds it gone.
type tarRemover struct {
	*fakeSecretStore
	dir string
}

func (r *tarRemover) WaitReady(ctx context.Context) error {
	err := r.fakeSecretStore.WaitReady(ctx)
	ents, _ := os.ReadDir(r.dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), "."+storeCaptureStagingKind) {
			_ = os.Remove(filepath.Join(r.dir, e.Name()))
		}
	}
	return err
}

// TC-765-16 and TC-765-28 (the backup half): a store that is not ready, a
// readiness that cannot be read, and a seal fragment that is not Clean or
// cannot be read each fail the run at snapshot_store with a sentence, before
// Stop or Quiesce, with nothing staged and no generation written. The
// job-failed alert is the alerts service's for every failed job
// (alerts.Service.jobAlerts); the run ending failed is its input.
func TestSnapshotStoreFailsClosedBeforeTheStop(t *testing.T) {
	cases := map[string]func(*fakeSecretStore){
		"sealed":        func(f *fakeSecretStore) { f.notReady = storestate.Clause(storestate.Sealed) },
		"uninitialised": func(f *fakeSecretStore) { f.notReady = storestate.Clause(storestate.Uninitialised) },
		"unreachable":   func(f *fakeSecretStore) { f.notReady = storestate.Clause(storestate.Unreachable) },
		"audit-blocked": func(f *fakeSecretStore) { f.notReady = storestate.Clause(storestate.AuditBlocked) },
		"blank":         func(f *fakeSecretStore) { f.notReady = storestate.Clause(storestate.Blank) },
		"readiness err": func(f *fakeSecretStore) { f.readyErr = errors.New("ctx ended") },
		"not clean":     func(f *fakeSecretStore) { f.keyErr = errors.New("sealrotate: the fragment is staged") },
		"seal unreadble": func(f *fakeSecretStore) {
			f.keyErr = errors.New("sealrotate: read the seal fragment: permission denied")
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			fs := newFakeSecretStore()
			setup(fs)
			h := newRunHarness(t, nil, runHarnessOpts{secretStore: fs})
			jobID := h.submit(t, RunSpec{Reason: ReasonManual})
			j := h.waitTerminal(t, jobID)
			if j.Status != jobs.StatusFailed {
				t.Fatalf("job %s, want failed", j.Status)
			}
			if st := stepOf(t, h, jobID, storeCaptureStepName); st == nil || st.Status != jobs.StepFailed {
				t.Fatalf("%s = %+v, want failed", storeCaptureStepName, st)
			}
			assertJobSentence(t, j.Error)
			if !strings.Contains(j.Error, "captured nothing and wrote nothing") {
				t.Errorf("error %q does not say the backup wrote nothing", j.Error)
			}
			if fs.notReady != "" && !strings.Contains(j.Error, "The secret store "+fs.notReady+",") {
				t.Errorf("error %q does not carry the state's clause %q", j.Error, fs.notReady)
			}
			for _, c := range fs.got() {
				if strings.HasPrefix(c, "stop") || strings.HasPrefix(c, "quiesce") || c == "start" {
					t.Errorf("%s called before the refusal: %v", c, fs.got())
				}
			}
			if e := h.stagingEntries(t); len(e) != 0 {
				t.Errorf("staging holds %v", e)
			}
			if n := h.agent.writeCount(); n != 0 {
				t.Errorf("%d generation write(s), want none", n)
			}
		})
	}
}

// assertJobSentence checks a job's error reads as a sentence and names no
// path.
func assertJobSentence(t *testing.T, s string) {
	t.Helper()
	if s == "" || s[0] < 'A' || s[0] > 'Z' || !strings.HasSuffix(s, ".") {
		t.Errorf("%q is not a sentence", s)
	}
	if strings.Contains(s, "/") {
		t.Errorf("%q names a path", s)
	}
}

// TC-765-17: a stop that fails, a symlink in the data directory and a file
// that cannot be read each remove the partial copy, start the store exactly
// once after the stop, release the quiesce, and fail the step with a
// sentence.
func TestSnapshotStoreRestartsTheStoreAfterEveryFailure(t *testing.T) {
	for name, tc := range map[string]struct {
		store func(*fakeSecretStore)
		data  func(t *testing.T, dir string)
		want  sentenceError
	}{
		"stop fails": {store: func(f *fakeSecretStore) { f.stopErr = errors.New("systemctl: exit 1") }, want: errStoreStopFailed},
		"symlink": {data: func(t *testing.T, dir string) {
			if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link")); err != nil {
				t.Fatal(err)
			}
		}, want: errStoreCopyFailed},
		"unreadable file": {data: func(t *testing.T, dir string) {
			p := filepath.Join(dir, "000001.log")
			if err := os.Chmod(p, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
		}, want: errStoreCopyFailed},
	} {
		t.Run(name, func(t *testing.T) {
			fs := newFakeSecretStore()
			if tc.store != nil {
				tc.store(fs)
			}
			h := newRunHarness(t, nil, runHarnessOpts{secretStore: fs})
			if tc.data != nil {
				tc.data(t, h.sources.StoreDataDir)
			}
			jobID := h.submit(t, RunSpec{Reason: ReasonManual})
			j := h.waitTerminal(t, jobID)
			if j.Status != jobs.StatusFailed || j.Error != string(tc.want) {
				t.Fatalf("job %s %q, want failed with %q", j.Status, j.Error, tc.want)
			}
			assertJobSentence(t, j.Error)
			calls := fs.got()
			stop := slices.IndexFunc(calls, func(c string) bool { return strings.HasPrefix(c, "stop") })
			starts := 0
			for i, c := range calls {
				if c == "start" {
					starts++
					if i < stop {
						t.Errorf("start before stop: %v", calls)
					}
				}
			}
			if stop < 0 || starts != 1 {
				t.Errorf("calls = %v, want one start after the stop", calls)
			}
			if calls[len(calls)-1] != "release" {
				t.Errorf("calls = %v, want the quiesce released last", calls)
			}
			for _, e := range h.stagingEntries(t) {
				if strings.HasSuffix(e, ".store") {
					t.Errorf("the partial copy %s was left", e)
				}
			}
		})
	}
}

// monitoredStore is the fake store under a real readiness monitor, as main's
// adapter wires it: readiness and the quiesce are the monitor's, and the
// wait is secretstore.WaitReady. sealedUntil, when set, keeps the store
// sealed after its start until closed.
type monitoredStore struct {
	*fakeSecretStore
	mon         *storestate.Monitor
	sealedUntil chan struct{}
	beforeWait  func()
	started     bool // guarded by fakeSecretStore.mu
}

// Start starts the fake and arms sealedUntil: the store comes up sealed.
func (m *monitoredStore) Start(ctx context.Context) error {
	m.mu.Lock()
	m.started = true
	m.mu.Unlock()
	return m.fakeSecretStore.Start(ctx)
}

func (m *monitoredStore) Health(ctx context.Context) (secretstore.Health, error) {
	h, err := m.fakeSecretStore.Health(ctx)
	m.mu.Lock()
	started := m.started
	m.mu.Unlock()
	if err == nil && started && m.sealedUntil != nil {
		select {
		case <-m.sealedUntil:
		default:
			return secretstore.Health{}, &secretstore.Error{Op: "health", Kind: secretstore.ErrSealed}
		}
	}
	return h, err
}

func (m *monitoredStore) Readiness(ctx context.Context) (string, error) {
	m.record("readiness")
	st, err := m.mon.State(ctx)
	if err != nil || st == storestate.Ready {
		return "", err
	}
	return storestate.Clause(st), nil
}

func (m *monitoredStore) Quiesce(jobID string) func() {
	m.record("quiesce:" + jobID)
	release := m.mon.Quiesce(jobID, storestate.QuiesceBackup)
	return func() { release(); m.record("release") }
}

func (m *monitoredStore) WaitReady(ctx context.Context) error {
	m.record("wait")
	if m.beforeWait != nil {
		m.beforeWait()
	}
	if m.waitErr != nil {
		return m.waitErr
	}
	return secretstore.WaitReady(ctx, m, 5*time.Second)
}

func newMonitoredStore(t *testing.T, h *runHarness, fs *fakeSecretStore) *monitoredStore {
	t.Helper()
	m := &monitoredStore{fakeSecretStore: fs}
	log, _ := logkittest.New()
	mon, err := storestate.New(storestate.Deps{
		Store: m, Now: time.Now, Log: log,
		JobRunning: func(ctx context.Context, id string) (bool, error) {
			j, err := h.jobStore.GetJob(ctx, id)
			return j != nil && j.Status == jobs.StatusRunning, err
		},
		Blank: func(context.Context) (bool, error) { return false, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	m.mon = mon
	return m
}

// lateStore lets a test build the harness first and the monitored store
// over its job ledger after: the harness takes this, the test sets inner.
type lateStore struct{ inner SecretStore }

func (l *lateStore) Readiness(ctx context.Context) (string, error) { return l.inner.Readiness(ctx) }
func (l *lateStore) SealKeyID() (string, error)                    { return l.inner.SealKeyID() }
func (l *lateStore) Version(ctx context.Context) (string, error)   { return l.inner.Version(ctx) }
func (l *lateStore) Stop(ctx context.Context) error                { return l.inner.Stop(ctx) }
func (l *lateStore) Start(ctx context.Context) error               { return l.inner.Start(ctx) }
func (l *lateStore) WaitReady(ctx context.Context) error           { return l.inner.WaitReady(ctx) }
func (l *lateStore) Quiesce(jobID string) func()                   { return l.inner.Quiesce(jobID) }

func alertIDs(as []proto.Alert) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.ID)
	}
	return out
}

// TC-765-18: a start that fails, and a wait that runs out, each fail the
// step and release the quiesce, so the next reading of the real monitor
// over the down store is unreachable, not quiesced.
func TestSnapshotStoreStartOrWaitFailureShowsTheRealState(t *testing.T) {
	for name, set := range map[string]func(*fakeSecretStore){
		"start fails": func(f *fakeSecretStore) { f.startErr = errors.New("systemctl: exit 1") },
		"wait bound":  func(f *fakeSecretStore) { f.waitErr = context.DeadlineExceeded },
	} {
		t.Run(name, func(t *testing.T) {
			fs := newFakeSecretStore()
			set(fs)
			late := &lateStore{}
			h := newRunHarness(t, nil, runHarnessOpts{secretStore: late})
			ms := newMonitoredStore(t, h, fs)
			late.inner = ms
			if fs.waitErr != nil {
				// The wait's bound passes with the store still down.
				fs.onStop = nil
				ms.beforeWait = func() {
					fs.mu.Lock()
					fs.running = false
					fs.mu.Unlock()
				}
			}
			jobID := h.submit(t, RunSpec{Reason: ReasonManual})
			j := h.waitTerminal(t, jobID)
			if j.Status != jobs.StatusFailed || j.Error != string(errStoreStartFailed) {
				t.Fatalf("job %s %q, want failed with %q", j.Status, j.Error, errStoreStartFailed)
			}
			if c := fs.got(); c[len(c)-1] != "release" {
				t.Fatalf("calls = %v, want the quiesce released", c)
			}
			if st, err := ms.mon.State(context.Background()); err != nil || st != storestate.Unreachable {
				t.Fatalf("state after the step = (%s, %v), want unreachable", st, err)
			}
			for _, e := range h.stagingEntries(t) {
				if strings.HasSuffix(e, ".store") {
					t.Errorf("the copy %s was left", e)
				}
			}
		})
	}
}

// TC-765-19 and TC-765-20: with a real monitor and Gate over a store that
// is down between Stop and Start, a watcher sampling mid-stop sees
// secret-store:quiesced, warn, "The secret store is paused for a backup.",
// never unreachable, and a secret-bearing deploy is refused with
// secret_store_not_ready. After Start the store stays sealed for a while and
// the alert is still quiesced until the first 200; after the step no store
// alert is raised.
func TestSnapshotStoreWatcherSeesBackupInProgress(t *testing.T) {
	fs := newFakeSecretStore()
	late := &lateStore{}
	h := newRunHarness(t, nil, runHarnessOpts{secretStore: late})
	ms := newMonitoredStore(t, h, fs)
	ms.sealedUntil = make(chan struct{})
	late.inner = ms
	gate, err := storestate.NewGate(&denySource{}, ms.mon, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	var samples [][]proto.Alert
	var deployErr error
	ctx := context.Background()
	fs.onStop = func() {
		samples = append(samples, ms.mon.Alerts(ctx, time.Now()))
		_, _, deployErr = gate.ResolveCompose(ctx, "app-1", "services:\n  web:\n    environment:\n      P: ${secret:db}\n")
	}
	var sealedSample []proto.Alert
	ms.beforeWait = func() {
		// Started, still sealed: the hold must still read quiesced.
		sealedSample = ms.mon.Alerts(ctx, time.Now())
		close(ms.sealedUntil)
	}
	jobID := h.submit(t, RunSpec{Reason: ReasonManual})
	if j := h.waitTerminal(t, jobID); j.Status != jobs.StatusSucceeded {
		t.Fatalf("job %s: %s", j.Status, j.Error)
	}
	if len(samples) != 1 || len(samples[0]) != 1 {
		t.Fatalf("mid-stop alerts = %v", samples)
	}
	a := samples[0][0]
	if a.ID != "secret-store:quiesced" || a.Severity != proto.AlertWarn || a.Title != "The secret store is paused for a backup." {
		t.Errorf("mid-stop alert = %+v", a)
	}
	var nre *storestate.NotReadyError
	if !errors.As(deployErr, &nre) || nre.Code() != storestate.Code {
		t.Errorf("mid-stop deploy = %v, want %s", deployErr, storestate.Code)
	}
	if got := alertIDs(sealedSample); !reflect.DeepEqual(got, []string{"secret-store:quiesced"}) {
		t.Errorf("between Start and the first 200 alerts = %v, want quiesced", got)
	}
	if got := ms.mon.Alerts(ctx, time.Now()); len(got) != 0 {
		t.Errorf("after the step alerts = %v, want none", alertIDs(got))
	}
	calls := fs.got()
	if i := slices.Index(calls, "wait"); i < 0 || calls[len(calls)-1] != "release" || i > len(calls)-2 {
		t.Errorf("calls = %v, want the release after the wait", calls)
	}
}

// denySource is a deploy source a gated compose never reaches.
type denySource struct{}

func (denySource) ResolveCompose(context.Context, string, string) (secret.Value, map[string]secret.Value, error) {
	return secret.Value{}, nil, errors.New("the inner source was reached")
}

// stagingProbe is an AppLister that records whether a staged store copy is
// present each time it is called, and fails its call number failOn (1-based;
// 0 never). preflight lists first, fan_out second.
type stagingProbe struct {
	mu     sync.Mutex
	dir    string
	calls  int
	failOn int
	seen   []bool
}

func (p *stagingProbe) List(context.Context) ([]*apps.App, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	p.seen = append(p.seen, hasStoreCopy(p.dir))
	if p.calls == p.failOn {
		return nil, errors.New("apps store closed")
	}
	return nil, nil
}

func hasStoreCopy(dir string) bool {
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), "."+storeCaptureStagingKind) {
			return true
		}
	}
	return false
}

// TC-765-24: the staged store copy never outlives the run. A run failing at
// fan_out, assemble, write or prune has it removed by the terminal hook; a
// successful run removes it once assemble has consumed it, before the write.
// (The seal step has no failure this harness can inject; the terminal sweep
// it would rely on is the same one the other paths exercise.)
func TestStagedStoreCopyNeverOutlivesTheRun(t *testing.T) {
	refuse := proto.BackupWriteAck{OK: false, Refusal: proto.BackupRefusalDigestMismatch, Detail: "no"}
	for _, tc := range []struct {
		name     string
		failAt   string
		failOn   int
		keyFlip  bool
		write    bool
		prune    bool
		succeeds bool
	}{
		{name: "fan_out", failAt: "fan_out", failOn: 2},
		{name: "assemble", failAt: "assemble", keyFlip: true},
		{name: "write", failAt: "write", write: true},
		{name: "prune", failAt: "prune", prune: true},
		{name: "success", succeeds: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeSecretStore()
			agent := &fakeBackupAgent{}
			var atWrite []bool
			agent.write = func(cmd proto.BackupWriteCmd) proto.BackupWriteAck {
				atWrite = append(atWrite, hasStoreCopy(agent.stagingRoot))
				if tc.write {
					refuse.PartUUID = cmd.PartUUID
					return refuse
				}
				return defaultWriteAck(cmd, "")
			}
			if tc.prune {
				agent.prune = func(cmd proto.BackupPruneCmd) proto.BackupPruneAck {
					return proto.BackupPruneAck{OK: false, PartUUID: cmd.PartUUID, Refusal: proto.BackupRefusalDigestMismatch, Detail: "no"}
				}
			}
			probe := &stagingProbe{failOn: tc.failOn}
			h := newRunHarness(t, agent, runHarnessOpts{secretStore: fs, appLister: probe})
			probe.dir = h.stagingDir
			if tc.keyFlip {
				fs.onStop = func() { writeSealFixture(t, h.sources.SealDir, fixtureKeyID2, fixtureSealKey("K2")) }
			}
			jobID := h.submit(t, RunSpec{Reason: ReasonManual})
			j := h.waitTerminal(t, jobID)
			if tc.succeeds {
				if j.Status != jobs.StatusSucceeded {
					t.Fatalf("job %s: %s", j.Status, j.Error)
				}
				if len(atWrite) != 1 || atWrite[0] {
					t.Errorf("store copy present at the write: %v, want removed once assembled", atWrite)
				}
			} else {
				if j.Status != jobs.StatusFailed {
					t.Fatalf("job %s, want failed", j.Status)
				}
				if st := stepOf(t, h, jobID, tc.failAt); st == nil || st.Status != jobs.StepFailed {
					t.Fatalf("%s = %+v, want failed", tc.failAt, st)
				}
			}
			if tc.failAt == "fan_out" && (len(probe.seen) != 2 || !probe.seen[1]) {
				t.Fatalf("the store copy was not staged when fan_out ran (%v), so the case proves nothing", probe.seen)
			}
			if tc.keyFlip && j.Error != string(errStoreCaptureKeyIDChanged) {
				t.Errorf("assemble error %q, want %q", j.Error, errStoreCaptureKeyIDChanged)
			}
			if hasStoreCopy(h.stagingDir) {
				t.Errorf("the staged store copy outlived the run: %v", h.stagingEntries(t))
			}
		})
	}
}
