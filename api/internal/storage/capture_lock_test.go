package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
)

// rotationLock is a CaptureLock held by a seal-key rotation: Acquire blocks
// until the rotation releases, and the rotation writes its Clean fragment
// naming the new key before it does. It records what Acquire saw and every
// Release.
type rotationLock struct {
	fragment string
	held     chan struct{} // closed by the rotation's release
	waiting  chan struct{} // closed once Acquire is waiting

	mu           sync.Mutex
	keyAtCapture string
	acquiredAt   time.Time
	releases     []string
	releasedAt   time.Time
}

func newRotationLock(t *testing.T) *rotationLock {
	return &rotationLock{
		fragment: filepath.Join(t.TempDir(), "seal.hcl"),
		held:     make(chan struct{}),
		waiting:  make(chan struct{}),
	}
}

func (l *rotationLock) Acquire(ctx context.Context, _ string) error {
	select {
	case <-l.waiting:
	default:
		close(l.waiting)
	}
	select {
	case <-l.held:
	case <-ctx.Done():
		return ctx.Err()
	}
	b, err := os.ReadFile(l.fragment)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err == nil {
		l.keyAtCapture = string(b)
	}
	l.acquiredAt = time.Now()
	return nil
}

func (l *rotationLock) Release(jobID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.releases) == 0 {
		l.releasedAt = time.Now()
	}
	l.releases = append(l.releases, jobID)
}

// finishRotation is the rotation's settle: the Clean fragment names the new
// key, then the lock is released.
func (l *rotationLock) finishRotation(t *testing.T, keyID string) {
	t.Helper()
	frag := "seal \"static\" {\n  current_key_id = \"" + keyID + "\"\n}\n"
	if err := os.WriteFile(l.fragment, []byte(frag), 0o600); err != nil {
		t.Fatal(err)
	}
	close(l.held)
}

// TC-830-09: a backup's snapshot waits on a rotation's capture lock and
// captures only after the release, when the fragment already names the new
// key; the lock is released at the end of assemble, and by OnTerminal in a run
// that fails before it.
func TestBackupRunWaitsForTheCaptureLock(t *testing.T) {
	const keyB = "rasputin-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	lock := newRotationLock(t)
	h := newRunHarness(t, nil, runHarnessOpts{captureLock: lock})
	jobID := h.submit(t, RunSpec{Reason: ReasonScheduled})

	select {
	case <-lock.waiting:
	case <-time.After(20 * time.Second):
		t.Fatal("snapshot_db never reached the capture lock")
	}
	for _, e := range h.stagingEntries(t) {
		if strings.Contains(e, "db") {
			t.Fatalf("the database was staged (%s) while the rotation held the lock", e)
		}
	}
	lock.finishRotation(t, keyB)

	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusSucceeded {
		t.Fatalf("job %s: %s", j.Status, j.Error)
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if !strings.Contains(lock.keyAtCapture, keyB) {
		t.Errorf("the fragment at capture = %q, want it to name %s", lock.keyAtCapture, keyB)
	}
	steps, err := h.jobStore.ListSteps(context.Background(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	var snapStart, assembleEnd, sealStart time.Time
	for _, st := range steps {
		switch {
		case st.Name == "snapshot_db" && st.StartedAt != nil:
			snapStart = *st.StartedAt
		case st.Name == "assemble" && st.FinishedAt != nil:
			assembleEnd = *st.FinishedAt
		case st.Name == "seal" && st.StartedAt != nil:
			sealStart = *st.StartedAt
		}
	}
	// The ledger keeps milliseconds, so the fake's times are compared at that
	// precision.
	acquired, released := lock.acquiredAt.Truncate(time.Millisecond), lock.releasedAt.Truncate(time.Millisecond)
	if acquired.Before(snapStart) {
		t.Error("the lock was taken before snapshot_db started")
	}
	if len(lock.releases) == 0 || lock.releases[0] != jobID {
		t.Fatalf("releases = %v, want this job's", lock.releases)
	}
	if released.After(assembleEnd) || released.After(sealStart) {
		t.Errorf("the first release (%v) came after assemble ended (%v)", lock.releasedAt, assembleEnd)
	}
}

// TC-830-09: a run that fails at fan_out, after taking the lock, has it
// released by its terminal hook.
func TestBackupRunReleasesTheCaptureLockOnFailure(t *testing.T) {
	lock := newRotationLock(t)
	lock.finishRotation(t, "rasputin-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	h := newRunHarness(t, nil, runHarnessOpts{captureLock: lock, appLister: &failsAfter{n: 1}})
	jobID := h.submit(t, RunSpec{Reason: ReasonScheduled})
	j := h.waitTerminal(t, jobID)
	if j.Status != jobs.StatusFailed {
		t.Fatalf("job %s, want failed", j.Status)
	}
	steps, err := h.jobStore.ListSteps(context.Background(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	var failedAt string
	for _, st := range steps {
		if st.Status == jobs.StepFailed {
			failedAt = st.Name
		}
	}
	if failedAt != "fan_out" {
		t.Fatalf("failed at %q, want fan_out", failedAt)
	}
	lock.mu.Lock()
	defer lock.mu.Unlock()
	if len(lock.releases) != 1 || lock.releases[0] != jobID {
		t.Errorf("releases = %v, want one, by OnTerminal", lock.releases)
	}
}

// A lock that refuses fails the run at snapshot_db with its sentence, and a
// wait cut short by the step's ctx fails with the backup's own sentence.
func TestBackupRunCaptureLockRefusal(t *testing.T) {
	refused := sentenceError("A seal-key rotation has not finished, so this backup did not capture anything.")
	h := newRunHarness(t, nil, runHarnessOpts{captureLock: refusingLock{err: refused}})
	j := h.waitTerminal(t, h.submit(t, RunSpec{Reason: ReasonScheduled}))
	if j.Status != jobs.StatusFailed || j.Error != string(refused) {
		t.Fatalf("job %s: %q", j.Status, j.Error)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := acquireCapture(&jobs.StepCtx{Ctx: ctx, JobID: "j"}, RunConfig{CaptureLock: refusingLock{err: ctx.Err()}})
	if err != errCaptureLockWait {
		t.Errorf("a cancelled wait = %v, want errCaptureLockWait", err)
	}
	if err := acquireCapture(&jobs.StepCtx{Ctx: context.Background()}, RunConfig{}); err != nil {
		t.Errorf("no lock wired = %v", err)
	}
}

type refusingLock struct{ err error }

func (r refusingLock) Acquire(context.Context, string) error { return r.err }
func (refusingLock) Release(string)                          {}

// failsAfter lists no apps n times, then fails: preflight's sizing reads the
// list first, so the failure lands on the fan-out's read.
type failsAfter struct {
	mu sync.Mutex
	n  int
}

func (f *failsAfter) List(context.Context) ([]*apps.App, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n == 0 {
		return nil, errors.New("apps store closed")
	}
	f.n--
	return nil, nil
}
