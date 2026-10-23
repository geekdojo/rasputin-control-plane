package storage

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
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

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/sealrotate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// fakeUpdateLock is an UpdateLock recording acquire and release; err is
// Acquire's refusal, and block makes it wait until ctx ends.
type fakeUpdateLock struct {
	mu       sync.Mutex
	err      error
	block    bool
	acquired []string
	released []string
}

func (l *fakeUpdateLock) AcquireForUpdate(ctx context.Context, jobID string) error {
	if l.block {
		<-ctx.Done()
		return ctx.Err()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	l.acquired = append(l.acquired, jobID)
	return nil
}

func (l *fakeUpdateLock) Release(jobID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.released = append(l.released, jobID)
}

func (l *fakeUpdateLock) held() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.acquired) > len(l.released)
}

// copierRig is a PreUpdateCopier over a fake store and lock, with a data
// directory holding two files and a previous copy already published.
type copierRig struct {
	c        *PreUpdateCopier
	store    *fakeSecretStore
	lock     *fakeUpdateLock
	rec      *logkittest.Recorder
	dataDir  string
	copyPath string
	previous []byte
	lines    []string
}

const (
	copierDataA = "pebble-bytes-0f3e-A"
	copierDataB = "pebble-bytes-0f3e-B"
)

func newCopierRig(t *testing.T) *copierRig {
	t.Helper()
	root := t.TempDir()
	data := filepath.Join(root, "openbao")
	mustMkdirAll(t, filepath.Join(data, "sub"))
	for p, b := range map[string]string{"000001.log": copierDataA, "sub/MANIFEST": copierDataB} {
		if err := os.WriteFile(filepath.Join(data, p), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	copyPath := filepath.Join(root, "openbao-preupdate.tar")
	previous := []byte("the previous copy")
	if err := os.WriteFile(copyPath, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	log, rec := logkittest.New()
	r := &copierRig{store: newFakeSecretStore(), lock: &fakeUpdateLock{}, rec: rec, dataDir: data, copyPath: copyPath, previous: previous}
	c, err := NewPreUpdateCopier(PreUpdateCopierDeps{Store: r.store, Lock: r.lock, DataDir: data, CopyPath: copyPath, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	r.c = c
	return r
}

func (r *copierRig) run(ctx context.Context) (json.RawMessage, error) {
	sc := &jobs.StepCtx{Ctx: ctx, JobID: "upd-1", Log: func(level, msg string) {
		r.lines = append(r.lines, level+": "+msg)
	}}
	return r.c.CopyBeforeUpdate(sc)
}

// TC-800-08: the copier fails closed at each stage. Per stage: the sentence
// opens with the update refusal and never says backup; a store the copy
// stopped is started again exactly once, and the store is never stopped for
// a refusal before the stop; the quiesce and the lock are released; no
// .partial remains; the previous copy is byte-identical.
func TestPreUpdateCopier_FailsClosedAtEachStage(t *testing.T) {
	refusal := errors.New(sealrotate.UpdateCopyRefused + " A seal-key rotation has not finished: start the seal-key rotation again to finish it, then run the update again.")
	for name, tc := range map[string]struct {
		set      func(r *copierRig)
		ctx      func() (context.Context, context.CancelFunc)
		want     error
		stops    bool
		lockHeld bool // whether the lock was ever taken
	}{
		"lock refused": {set: func(r *copierRig) { r.lock.err = refusal }, want: refusal},
		"lock wait cut off": {set: func(r *copierRig) { r.lock.block = true }, want: errUpdateLockWait,
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 10*time.Millisecond)
			}},
		"readiness unknown":  {set: func(r *copierRig) { r.store.readyErr = errors.New("ctx done") }, want: errUpdateReadinessUnknown, lockHeld: true},
		"not ready":          {set: func(r *copierRig) { r.store.notReady = "is sealed" }, want: updateStoreNotReady("is sealed"), lockHeld: true},
		"version unreadable": {set: func(r *copierRig) { r.store.verErr = errors.New("unreachable") }, want: errUpdateVersionUnknown, lockHeld: true},
		"version unusable":   {set: func(r *copierRig) { r.store.version = " " }, want: errUpdateVersionUnknown, lockHeld: true},
		"stop fails":         {set: func(r *copierRig) { r.store.stopErr = errors.New("systemctl: exit 1") }, want: errUpdateStopFailed, stops: true, lockHeld: true},
		"copy fails":         {set: func(r *copierRig) { symlinkInto(t, r.dataDir) }, want: errUpdateCopyFailed, stops: true, lockHeld: true},
		"start fails":        {set: func(r *copierRig) { r.store.startErr = errors.New("systemctl: exit 1") }, want: errUpdateStartFailed, stops: true, lockHeld: true},
		"WaitReady fails":    {set: func(r *copierRig) { r.store.waitErr = context.DeadlineExceeded }, want: errUpdateStartFailed, stops: true, lockHeld: true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newCopierRig(t)
			tc.set(r)
			ctx, cancel := context.Background(), context.CancelFunc(func() {})
			if tc.ctx != nil {
				ctx, cancel = tc.ctx()
			}
			defer cancel()
			got, err := r.run(ctx)
			if got != nil || err == nil || err.Error() != tc.want.Error() {
				t.Fatalf("= (%s, %v), want %q", got, err, tc.want)
			}
			// Only the lock wait may mention a backup, as what it waited for;
			// no sentence reads as a backup's own refusal.
			if !strings.HasPrefix(err.Error(), sealrotate.UpdateCopyRefused) || strings.Contains(err.Error(), "this backup") {
				t.Errorf("sentence %q does not name the OS update", err)
			}
			assertJobSentence(t, err.Error())
			calls := r.store.got()
			stop := slices.IndexFunc(calls, func(c string) bool { return strings.HasPrefix(c, "stop") })
			starts := 0
			for _, c := range calls {
				if c == "start" {
					starts++
				}
			}
			switch {
			case tc.stops && (stop < 0 || starts != 1):
				t.Errorf("calls %v: want one stop and exactly one start", calls)
			case !tc.stops && stop >= 0:
				t.Errorf("calls %v: a refusal before the stop stopped the store", calls)
			}
			if q := slices.IndexFunc(calls, func(c string) bool { return strings.HasPrefix(c, "quiesce") }); q >= 0 && calls[len(calls)-1] != "release" {
				t.Errorf("calls %v: the quiesce was not released", calls)
			}
			if r.lock.held() {
				t.Error("the lock was not released")
			}
			if tc.lockHeld != (len(r.lock.acquired) == 1) {
				t.Errorf("lock acquired %v, want taken=%v", r.lock.acquired, tc.lockHeld)
			}
			if _, err := os.Stat(r.copyPath + ".partial"); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the .partial remains: %v", err)
			}
			if b, err := os.ReadFile(r.copyPath); err != nil || sha256.Sum256(b) != sha256.Sum256(r.previous) {
				t.Errorf("the previous copy changed: %q, %v", b, err)
			}
			recs := r.rec.Matching(slog.LevelError, "secret store not copied before an OS update")
			if len(recs) != 1 {
				t.Fatalf("%d refusal ERROR record(s), want 1", len(recs))
			}
			if id, _ := logkittest.Attr(recs[0], "job_id"); id != "upd-1" {
				t.Errorf("job_id = %q", id)
			}
		})
	}
}

// symlinkInto plants a symlink in dir, which the copy refuses.
func symlinkInto(t *testing.T, dir string) {
	t.Helper()
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
}

// TC-800-09: a successful copy replaces the previous one with the cold copy
// in the staged store layout, 0600, removing a stale .partial first; it logs
// one INFO record with the counts and no data bytes.
func TestPreUpdateCopier_PublishesTheCopy(t *testing.T) {
	r := newCopierRig(t)
	if err := os.WriteFile(r.copyPath+".partial", []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := r.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var res preUpdateCopyResult
	if err := json.Unmarshal(got, &res); err != nil {
		t.Fatal(err)
	}
	want := preUpdateCopyResult{Copied: true, Version: fixtureBaoVer, Files: 2, SizeBytes: uint64(len(copierDataA) + len(copierDataB))}
	if res != want {
		t.Errorf("result %+v, want %+v", res, want)
	}
	info, err := os.Stat(r.copyPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("copy mode %v, %v; want 0600", info, err)
	}
	members := tarMembers(t, r.copyPath)
	wantMembers := map[string]string{
		"store/data/000001.log":   copierDataA,
		"store/data/sub/MANIFEST": copierDataB,
		storeVersionArchivePath:   fixtureBaoVer,
	}
	if !reflect.DeepEqual(members, wantMembers) {
		t.Errorf("members %v, want %v", members, wantMembers)
	}
	if _, err := os.Stat(r.copyPath + ".partial"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a .partial remains: %v", err)
	}
	if calls := r.store.got(); !reflect.DeepEqual(calls, []string{"readiness", "version", "quiesce:upd-1", "stop:upd-1", "start", "wait", "release"}) {
		t.Errorf("calls %v", calls)
	}
	if r.lock.held() || len(r.lock.acquired) != 1 {
		t.Errorf("lock acquired %v released %v", r.lock.acquired, r.lock.released)
	}
	recs := r.rec.Matching(slog.LevelInfo, "secret store copied before an OS update")
	if len(recs) != 1 {
		t.Fatalf("%d INFO record(s), want 1", len(recs))
	}
	for k, w := range map[string]string{"event": "secretstore.preupdate_copy", "outcome": "copied", "version": fixtureBaoVer, "files": "2", "job_id": "upd-1"} {
		if v, _ := logkittest.Attr(recs[0], k); v != w {
			t.Errorf("%s = %q, want %q", k, v, w)
		}
	}
	if _, ok := logkittest.Attr(recs[0], "bytes"); !ok {
		t.Error("no bytes field")
	}
	text := r.rec.Text() + strings.Join(r.lines, "\n")
	if strings.Contains(text, copierDataA) || strings.Contains(text, copierDataB) {
		t.Error("store data bytes reached a log record or job line")
	}
}

// A copy that cannot be published leaves no staged file and refuses.
func TestPreUpdateCopier_PublishFails(t *testing.T) {
	r := newCopierRig(t)
	// A directory at the published path makes the rename fail.
	if err := os.Remove(r.copyPath); err != nil {
		t.Fatal(err)
	}
	mustMkdirAll(t, filepath.Join(r.copyPath, "x"))
	if _, err := r.run(context.Background()); err == nil || err.Error() != errUpdatePublishFailed.Error() {
		t.Fatalf("err = %v, want errUpdatePublishFailed", err)
	}
	if _, err := os.Stat(r.copyPath + ".partial"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a .partial remains: %v", err)
	}
	if r.lock.held() {
		t.Error("the lock was not released")
	}
}

// A stale .partial that cannot be removed refuses before the store is
// stopped.
func TestPreUpdateCopier_PrepareFails(t *testing.T) {
	r := newCopierRig(t)
	mustMkdirAll(t, filepath.Join(r.copyPath+".partial", "x"))
	if _, err := r.run(context.Background()); err == nil || err.Error() != errUpdatePrepareFailed.Error() {
		t.Fatalf("err = %v, want errUpdatePrepareFailed", err)
	}
	if slices.ContainsFunc(r.store.got(), func(c string) bool { return strings.HasPrefix(c, "stop") }) {
		t.Error("the store was stopped")
	}
}

// TC-800-10: the constructor refuses each nil or empty collaborator.
func TestNewPreUpdateCopier_Refuses(t *testing.T) {
	log, _ := logkittest.New()
	full := PreUpdateCopierDeps{Store: newFakeSecretStore(), Lock: &fakeUpdateLock{}, DataDir: "/d", CopyPath: "/c.tar", Log: log}
	for name, clear := range map[string]func(*PreUpdateCopierDeps){
		"Store":    func(d *PreUpdateCopierDeps) { d.Store = nil },
		"Lock":     func(d *PreUpdateCopierDeps) { d.Lock = nil },
		"Log":      func(d *PreUpdateCopierDeps) { d.Log = nil },
		"DataDir":  func(d *PreUpdateCopierDeps) { d.DataDir = " " },
		"CopyPath": func(d *PreUpdateCopierDeps) { d.CopyPath = "" },
	} {
		d := full
		clear(&d)
		if c, err := NewPreUpdateCopier(d); err == nil || c != nil {
			t.Errorf("%s: %v, %v; want an error and no copier", name, c, err)
		}
	}
}

// tarMembers reads every member of the tar at p.
func tarMembers(t *testing.T, p string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		v, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = string(v)
	}
}
