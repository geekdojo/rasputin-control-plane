package storeaudit

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// fakeStore answers Health with a fixed result.
type fakeStore struct {
	h   secretstore.Health
	err error
}

func (f fakeStore) Health(context.Context) (secretstore.Health, error) { return f.h, f.err }

var activeStore = fakeStore{h: secretstore.Health{Initialized: true}}

// faultFiles is the real filesystem with a hook before each call. A hook
// that returns an error fails the call with it; nil lets the real call run.
type faultFiles struct {
	OSFiles
	stat    func(path string) error
	link    func(oldname, newname string) error
	remove  func(path string) error
	readDir func(dir string) error
}

func (f *faultFiles) Stat(path string) (fs.FileInfo, error) {
	if f.stat != nil {
		if err := f.stat(path); err != nil {
			return nil, err
		}
	}
	return f.OSFiles.Stat(path)
}

func (f *faultFiles) Link(oldname, newname string) error {
	if f.link != nil {
		if err := f.link(oldname, newname); err != nil {
			return err
		}
	}
	return f.OSFiles.Link(oldname, newname)
}

func (f *faultFiles) Remove(path string) error {
	if f.remove != nil {
		if err := f.remove(path); err != nil {
			return err
		}
	}
	return f.OSFiles.Remove(path)
}

func (f *faultFiles) ReadDir(dir string) ([]fs.DirEntry, error) {
	if f.readDir != nil {
		if err := f.readDir(dir); err != nil {
			return nil, err
		}
	}
	return f.OSFiles.ReadDir(dir)
}

// reopener counts calls and runs effect, which is what the store does on
// SIGHUP in the simplest tests: create a new file at the live path.
type reopener struct {
	calls  atomic.Int32
	effect func() error
}

func (r *reopener) Reopen(context.Context) error {
	r.calls.Add(1)
	if r.effect == nil {
		return nil
	}
	return r.effect()
}

// storeReopen is the store's reopen: a new, empty file at the live path.
func storeReopen(dir string) func() error {
	return func() error {
		f, err := os.OpenFile(filepath.Join(dir, LiveName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		return f.Close()
	}
}

const (
	testRotateAt  = 100
	testKeepBytes = 300
)

func testConfig(dir string) Config {
	return Config{Dir: dir, RotateAt: testRotateAt, KeepBytes: testKeepBytes, ReopenWait: 300 * time.Millisecond}
}

type fixture struct {
	dir   string
	live  string
	rot   *Rotator
	files *faultFiles
	open  *reopener
	rec   *logkittest.Recorder
}

func newFixture(t *testing.T, store Store) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{dir: dir, live: filepath.Join(dir, LiveName), files: &faultFiles{}, open: &reopener{effect: storeReopen(dir)}}
	log, rec := logkittest.New()
	f.rec = rec
	rot, err := NewRotator(testConfig(dir), Deps{Store: store, Reopen: f.open, Files: f.files, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	f.rot = rot
	return f
}

// write creates or appends n bytes to name in the fixture's dir.
func (f *fixture) write(t *testing.T, name string, n int) {
	t.Helper()
	fh, err := os.OpenFile(filepath.Join(f.dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	if _, err := fh.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) inode(t *testing.T, name string) uint64 {
	t.Helper()
	fi, err := os.Stat(filepath.Join(f.dir, name))
	if err != nil {
		t.Fatal(err)
	}
	ino, ok := inodeOf(fi)
	if !ok {
		t.Fatal("no inode")
	}
	return ino
}

// names lists the fixture's dir, sorted.
func (f *fixture) names(t *testing.T) []string {
	t.Helper()
	es, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// stepLine is one line a step wrote through StepCtx.Log.
type stepLine struct{ level, msg string }

// stepCtx is a StepCtx for calling a step directly, and the lines it logs.
func stepCtx(t *testing.T) (*jobs.StepCtx, *[]stepLine) {
	t.Helper()
	var lines []stepLine
	return &jobs.StepCtx{
		Ctx:   t.Context(),
		JobID: "job-test",
		Log:   func(level, msg string) { lines = append(lines, stepLine{level, msg}) },
	}, &lines
}

// runJob runs one rotation job on a real jobs.Runner over a temporary
// ledger, and returns the finished job and its events.
func runJob(t *testing.T, rot *Rotator) (*jobs.Job, []*jobs.JobEvent) {
	t.Helper()
	ctx := t.Context()
	store, err := jobs.OpenStore(ctx, filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	runner := jobs.NewRunner(store, nil)
	runner.Register(rot.Workflow())
	j, err := runner.Submit(ctx, RotateKind, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	runner.Wait()
	job, err := store.GetJob(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	evs, err := store.ListEvents(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	return job, evs
}

// stepFailedErrors are the Error fields of a job's step-failed events.
func stepFailedErrors(t *testing.T, evs []*jobs.JobEvent) []string {
	t.Helper()
	var out []string
	for _, e := range evs {
		if e.Type != string(proto.JobStepFailed) {
			continue
		}
		var d struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(e.Data, &d); err != nil {
			t.Fatal(err)
		}
		out = append(out, d.Error)
	}
	return out
}

// attr is a record's field, failing the test when absent.
func attr(t *testing.T, rec slog.Record, key string) string {
	t.Helper()
	v, ok := logkittest.Attr(rec, key)
	if !ok {
		t.Fatalf("record %q has no %s field", rec.Message, key)
	}
	return v
}

var errInjected = errors.New("injected failure: permission denied")
