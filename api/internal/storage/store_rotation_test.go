package storage

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// The production credential directory the fixture's fragments name.
const fixtureCredDir = "/run/credentials/openbao.service"

// sealFiles is sealrotate's model service over the harness's seal dir, with
// the production credential paths the fixture fragments name.
func sealFiles(t *testing.T, sealDir string) *sealrotate.Files {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(sealDir, sealrotate.RotationDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := sealrotate.NewFiles(sealrotate.Paths{
		SealDir: sealDir, CredDir: fixtureCredDir,
		RotationCred: func(id sealrotate.KeyID) string { return filepath.Join(fixtureCredDir, "seal-rotation_"+string(id)) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// filesKeyStore is the fake store whose seal key id is read from the real
// seal files, Clean only, as main's adapter reads it.
type filesKeyStore struct {
	*fakeSecretStore
	files *sealrotate.Files
}

func (f *filesKeyStore) SealKeyID() (string, error) {
	f.record("keyid")
	tree, err := f.files.State()
	if err != nil {
		return "", err
	}
	if tree.Fragment.Shape != sealrotate.Clean {
		return "", errors.New("the seal fragment is not Clean")
	}
	return tree.Fragment.Current.String(), nil
}

// rotationFakes are the store-side collaborators a Rotator needs, answering
// as a healthy store does.
type rotationFakes struct{}

func (rotationFakes) Health(context.Context) (secretstore.Health, error) {
	return secretstore.Health{Initialized: true}, nil
}
func (rotationFakes) CertLogin(context.Context, string) (secret.Value, error) {
	return secret.New([]byte("rotation-token")), nil
}
func (rotationFakes) RotateRoot(context.Context, secret.Value) error { return nil }
func (rotationFakes) Active() (string, bool)                         { return "", false }

// prepareFromRun restores generation genID from the run harness's target
// into a fresh data dir and returns it.
func prepareFromRun(t *testing.T, h *runHarness, genID string) string {
	t.Helper()
	fresh := filepath.Join(t.TempDir(), "var-lib-rasputin")
	if err := os.MkdirAll(fresh, 0o700); err != nil {
		t.Fatal(err)
	}
	prepareInto(t, h, genID, fresh)
	return fresh
}

// prepareInto prepares generation genID from the run harness's target into
// the data dir fresh and returns the report.
func prepareInto(t *testing.T, h *runHarness, genID, fresh string) *RestoreReport {
	t.Helper()
	marker := proto.StorageBackupSet{
		MarkerVersion: proto.StorageMarkerVersion, ClusterID: "home1", PartUUID: runPartUUID,
		KeyID: "key-1", PublicKey: h.key.publicB64, Label: "the archive disk", CreatedAt: time.Now().UTC(),
	}
	mb, _ := json.Marshal(marker)
	if err := os.WriteFile(filepath.Join(h.mountDir, proto.StorageMarkerFile), mb, 0o600); err != nil {
		t.Fatal(err)
	}
	sub, err := h.nc.Subscribe(proto.StorageMountSubject(runNodeID), func(m *nats.Msg) {
		b, _ := json.Marshal(proto.StorageMountAck{OK: true, PartUUID: runPartUUID, MountPath: h.mountDir})
		_ = m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	cfg := RestoreConfig{NC: h.nc, SelfNodeID: runNodeID, DataDir: fresh, ClusterID: "home1", ControlPlaneVersion: runCPVersion}
	report, err := PrepareRestore(context.Background(), cfg, RestoreRequest{
		PartUUID: runPartUUID, GenerationID: genID, KeyID: "key-1", PrivateKey: h.key.priv.Bytes(),
	})
	if err != nil {
		t.Fatalf("PrepareRestore %s: %v", genID, err)
	}
	return report
}

// stagedSeal reads the seal key and fragment a prepared restore staged.
func stagedSeal(t *testing.T, fresh string) ([]byte, sealrotate.KeyID) {
	t.Helper()
	key, err := os.ReadFile(filepath.Join(fresh, restorePendingDirName, "store", storeSealKeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	frag, err := os.ReadFile(filepath.Join(fresh, restorePendingDirName, "store", storeSealFragmentName))
	if err != nil {
		t.Fatal(err)
	}
	id, err := sealrotate.CurrentKeyID(frag)
	if err != nil {
		t.Fatal(err)
	}
	return key, id
}

// TC-765-12: a backup under K1, a rotation through #830's Rotator, then a
// backup under K2: each archive, prepared, stages its own seal-key bytes and
// a seal.hcl naming its own key id.
func TestRotationRoundTripStagesEachArchivesOwnKey(t *testing.T) {
	ctx := context.Background()
	late := &lateStore{}
	h := newRunHarness(t, nil, runHarnessOpts{secretStore: late})
	files := sealFiles(t, h.sources.SealDir)
	gate, err := sealrotate.NewGate(files, func(ctx context.Context, id string) (bool, error) {
		j, err := h.jobStore.GetJob(ctx, id)
		return j != nil && j.Status == jobs.StatusRunning, err
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	late.inner = &filesKeyStore{fakeSecretStore: newFakeSecretStore(), files: files}
	k1, _ := os.ReadFile(filepath.Join(h.sources.SealDir, storeSealKeyFileName))

	backup := func() string {
		t.Helper()
		jobID := h.submit(t, RunSpec{Reason: ReasonManual})
		if j := h.waitTerminal(t, jobID); j.Status != jobs.StatusSucceeded {
			t.Fatalf("backup %s: %s", j.Status, j.Error)
		}
		return h.run(t, jobID).GenerationID
	}
	g1 := backup()

	f := rotationFakes{}
	rot, err := sealrotate.NewRotator(sealrotate.Config{Enabled: true, UnsealWait: 2 * time.Second}, sealrotate.Deps{
		Store: f, Rotate: f, Restart: func(context.Context) error { return nil }, Files: files, Gate: gate,
		Quiesce:  func(string, storestate.QuiesceReason) func() { return func() {} },
		Restores: f, Rand: rand.Reader,
		KeyID: func() (sealrotate.KeyID, error) { return sealrotate.ParseKeyID(fixtureKeyID2) },
		Log:   slog.New(slog.DiscardHandler),
		JobRunning: func(ctx context.Context, id string) (bool, error) {
			j, err := h.jobStore.GetJob(ctx, id)
			return j != nil && j.Status == jobs.StatusRunning, err
		},
		Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.runner.Register(rot.Workflow())
	rj, err := h.runner.Submit(ctx, sealrotate.Kind, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	if j := h.waitTerminal(t, rj.ID); j.Status != jobs.StatusSucceeded {
		t.Fatalf("rotation %s: %s", j.Status, j.Error)
	}
	k2, _ := os.ReadFile(filepath.Join(h.sources.SealDir, storeSealKeyFileName))
	if string(k1) == string(k2) {
		t.Fatal("the rotation left the seal key as it was")
	}
	g2 := backup()

	for _, tc := range []struct {
		gen string
		key []byte
		id  string
	}{{g1, k1, fixtureKeyID}, {g2, k2, fixtureKeyID2}} {
		key, id := stagedSeal(t, prepareFromRun(t, h, tc.gen))
		if string(key) != string(tc.key) || id.String() != tc.id {
			t.Errorf("generation %s staged key id %s and %d key bytes, want its own key under %s", tc.gen, id, len(key), tc.id)
		}
	}
}

// holdingRotation is a rotation that holds the real Gate: its job reads as
// running until it settles.
type holdingRotation struct {
	mu       sync.Mutex
	settled  bool
	asked    chan struct{}
	askOnce  sync.Once
	backupID func() string
}

func (r *holdingRotation) running(_ context.Context, id string) (bool, error) {
	if id != "rot-job" {
		return id == r.backupID(), nil
	}
	r.askOnce.Do(func() { close(r.asked) })
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.settled, nil
}

// gateProbe reports whether a backup holds the gate: TryAcquire refuses a
// rotation while one does, and takes nothing when it refuses.
func gateProbe(g *sealrotate.Gate) bool {
	if err := g.TryAcquire("probe"); err != nil {
		return strings.Contains(err.Error(), "A backup is capturing the secret store")
	}
	g.Release("probe")
	return false
}

// lateLock lets the harness take a CaptureLock built after it.
type lateLock struct{ inner CaptureLock }

func (l *lateLock) Acquire(ctx context.Context, jobID string) error {
	return l.inner.Acquire(ctx, jobID)
}
func (l *lateLock) Release(jobID string) { l.inner.Release(jobID) }

// fanOutGateProbe is an AppLister sampling the gate at its second call,
// fan_out's listing, which runs after snapshot_store and before assemble.
type fanOutGateProbe struct {
	mu    sync.Mutex
	calls int
	gate  *sealrotate.Gate
	held  bool
}

func (p *fanOutGateProbe) List(context.Context) ([]*apps.App, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.calls == 2 {
		p.held = gateProbe(p.gate)
	}
	return nil, nil
}

// TC-765-13: a rotation holding the gate makes snapshot_db wait. After the
// release, the archive's seal-key and seal.hcl are the post-rotation ones,
// and the backup job holds the gate throughout snapshot_store and at
// fan_out, until assemble releases it. Assemble refuses a key id that
// changed after the store copy.
func TestCaptureLockSpansTheStoreCopy(t *testing.T) {
	var mu sync.Mutex
	var jobID string
	rot := &holdingRotation{asked: make(chan struct{}), backupID: func() string { mu.Lock(); defer mu.Unlock(); return jobID }}
	late, lock, lister := &lateStore{}, &lateLock{}, &fanOutGateProbe{}
	h := newRunHarness(t, nil, runHarnessOpts{secretStore: late, captureLock: lock, appLister: lister})
	files := sealFiles(t, h.sources.SealDir)
	gate, err := sealrotate.NewGate(files, rot.running, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	lock.inner, lister.gate = gate, gate
	fs := newFakeSecretStore()
	var heldDuringCopy bool
	fs.onStop = func() { heldDuringCopy = gateProbe(gate) }
	late.inner = &filesKeyStore{fakeSecretStore: fs, files: files}

	if err := gate.TryAcquire("rot-job"); err != nil {
		t.Fatal(err)
	}
	id := h.submit(t, RunSpec{Reason: ReasonManual})
	mu.Lock()
	jobID = id
	mu.Unlock()
	select {
	case <-rot.asked:
	case <-time.After(20 * time.Second):
		t.Fatal("snapshot_db never waited on the rotation's gate")
	}
	if st := stepOf(t, h, id, storeCaptureStepName); st != nil {
		t.Fatalf("%s ran while the rotation held the gate: %+v", storeCaptureStepName, st)
	}
	// The rotation's settle: the new key and the Clean fragment naming it,
	// then the release.
	k2 := fixtureSealKey("K2")
	writeSealFixture(t, h.sources.SealDir, fixtureKeyID2, k2)
	rot.mu.Lock()
	rot.settled = true
	rot.mu.Unlock()
	gate.Release("rot-job")

	if j := h.waitTerminal(t, id); j.Status != jobs.StatusSucceeded {
		t.Fatalf("backup %s: %s", j.Status, j.Error)
	}
	if !heldDuringCopy {
		t.Error("the backup did not hold the gate during snapshot_store")
	}
	if !lister.held {
		t.Error("the backup did not hold the gate at fan_out, before assemble")
	}
	if gateProbe(gate) {
		t.Error("the gate is still held after the run")
	}
	key, kid := stagedSeal(t, prepareFromRun(t, h, h.run(t, id).GenerationID))
	if string(key) != string(k2) || kid.String() != fixtureKeyID2 {
		t.Errorf("the archive holds key id %s, want the post-rotation %s and its key", kid, fixtureKeyID2)
	}

	// The changed key id: a fragment rewritten after the store copy is
	// refused at assemble.
	fs.onStop = func() { writeSealFixture(t, h.sources.SealDir, fixtureKeyID, fixtureSealKey("K3")) }
	lister.mu.Lock()
	lister.calls = 0
	lister.mu.Unlock()
	id = h.submit(t, RunSpec{Reason: ReasonManual})
	mu.Lock()
	jobID = id
	mu.Unlock()
	j := h.waitTerminal(t, id)
	if j.Status != jobs.StatusFailed || j.Error != string(errStoreCaptureKeyIDChanged) {
		t.Fatalf("a changed key id: job %s %q", j.Status, j.Error)
	}
	if st := stepOf(t, h, id, "assemble"); st == nil || st.Status != jobs.StepFailed {
		t.Fatalf("assemble = %+v, want failed", st)
	}
}
