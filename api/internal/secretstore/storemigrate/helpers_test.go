package storemigrate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/sysunit"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

const (
	thisBoot  = "0f3c5b2a-1d4e-4f6a-9b8c-7d6e5f4a3b2c"
	otherBoot = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	prevBoot  = "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e"
	runBefore = "00000000000000000000000000000001"
	jobID     = "01JMIGRATE0000000000000000"
	appA      = "01J8Z3K5QW6X7Y8Z9A0B1C2D3A"
	appB      = "01J8Z3K5QW6X7Y8Z9A0B1C2D3B"
)

// calls is one ordered log every fake writes to.
type calls struct {
	mu  sync.Mutex
	got []string
}

func (c *calls) add(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, s)
}

func (c *calls) list() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.got)
}

func (c *calls) has(s string) bool { return slices.Contains(c.list(), s) }

// indexOf is the position of s, or -1.
func (c *calls) indexOf(s string) int { return slices.Index(c.list(), s) }

// fakeInventory serves apps, or err.
type fakeInventory struct {
	apps  []apps.AppSecretInventory
	err   error
	calls *calls
}

func (f *fakeInventory) SecretInventory(context.Context) ([]apps.AppSecretInventory, error) {
	f.calls.add("inventory")
	return f.apps, f.err
}

// fakeRepo is one tree of entries: the live one. The swap replaces it with
// an empty tree and the put-back restores the old one, as the store's root
// step does with its data directory.
type fakeRepo struct {
	mu      sync.Mutex
	tree    map[string][]byte
	old     map[string][]byte
	getErr  map[string]error
	writeEr error
	// corrupt makes every read-back differ from what was written.
	corrupt bool
	writes  int
	// handed are every Value a Get returned, to check each is destroyed.
	handed []secret.Value
	calls  *calls
}

func (r *fakeRepo) Get(_ context.Context, ref secrets.Ref) (secrets.Secret, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.getErr[ref.String()]; err != nil {
		return secrets.Secret{}, err
	}
	b, ok := r.tree[ref.String()]
	if !ok {
		return secrets.Secret{}, &secretstore.Error{Op: "read", Kind: secretstore.ErrNotFound}
	}
	if r.corrupt && r.old != nil {
		b = append(slices.Clone(b), 'x')
	}
	v := secret.New(b)
	r.handed = append(r.handed, v)
	return secrets.Secret{Value: v, Version: 1}, nil
}

func (r *fakeRepo) Write(_ context.Context, ref secrets.Ref, value secret.Value, cas int) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes++
	r.calls.add("write " + ref.String())
	if r.writeEr != nil {
		return 0, r.writeEr
	}
	if _, exists := r.tree[ref.String()]; exists && cas == 0 {
		return 0, &secretstore.Error{Op: "write", Kind: secretstore.ErrCASMismatch}
	}
	r.tree[ref.String()] = slices.Clone(value.Reveal())
	return 1, nil
}

// swap sets the live tree aside for a fresh, empty one.
func (r *fakeRepo) swap() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.old, r.tree = r.tree, map[string][]byte{}
}

// putBack restores the tree swap set aside.
func (r *fakeRepo) putBack() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.old != nil {
		r.tree, r.old = r.old, nil
	}
}

// commitTree drops the set-aside tree.
func (r *fakeRepo) commitTree() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.old = nil
}

func (r *fakeRepo) value(ref string) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.tree[ref]
	return b, ok
}

// allDestroyed reports whether every Value handed out holds nothing now.
func (r *fakeRepo) allDestroyed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.handed {
		if v.Len() != 0 {
			return false
		}
	}
	return true
}

// fakeControl is the store unit. onStart runs the store's root step.
type fakeControl struct {
	calls      *calls
	notReady   string
	readyErr   error
	sealErr    error
	stopErr    []error
	startErr   []error
	waitErr    error
	onStart    func()
	quiesced   int
	released   int
	stopCount  int
	startCount int
}

func (c *fakeControl) Readiness(context.Context) (string, error) { return c.notReady, c.readyErr }
func (c *fakeControl) SealKeyID() (string, error)                { return "rasputin-key", c.sealErr }

func (c *fakeControl) Quiesce(string) func() {
	c.calls.add("quiesce")
	c.quiesced++
	return func() { c.calls.add("unquiesce"); c.released++ }
}

func (c *fakeControl) Stop(context.Context) error {
	c.calls.add("stop")
	i := c.stopCount
	c.stopCount++
	if i < len(c.stopErr) {
		return c.stopErr[i]
	}
	return nil
}

func (c *fakeControl) Start(context.Context) error {
	c.calls.add("start")
	i := c.startCount
	c.startCount++
	if i < len(c.startErr) && c.startErr[i] != nil {
		return c.startErr[i]
	}
	if c.onStart != nil {
		c.onStart()
	}
	return nil
}

func (c *fakeControl) WaitReady(context.Context) error {
	c.calls.add("wait_ready")
	return c.waitErr
}

// fakeLock records who holds it.
type fakeLock struct {
	calls  *calls
	err    error
	holder string
}

func (l *fakeLock) Acquire(_ context.Context, id string) error {
	l.calls.add("acquire")
	if l.err != nil {
		return l.err
	}
	l.holder = id
	return nil
}

func (l *fakeLock) Release(id string) {
	if l.holder == id {
		l.calls.add("release")
		l.holder = ""
	}
}

// fakeMarker records the rebase and the restore.
type fakeMarker struct {
	calls      *calls
	rebaseErr  error
	restoreErr error
}

func (m *fakeMarker) RebaseChecked(context.Context) (string, error) {
	m.calls.add("rebase")
	return prevBoot, m.rebaseErr
}

func (m *fakeMarker) RestoreSetUp(_ context.Context, prev string) error {
	m.calls.add("restore_set_up " + prev)
	return m.restoreErr
}

// fakeSettings is a settings map.
type fakeSettings struct {
	mu     sync.Mutex
	kv     map[string]string
	getErr error
	setErr error
}

func (s *fakeSettings) Get(_ context.Context, k string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kv[k], s.getErr
}

func (s *fakeSettings) Set(_ context.Context, k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setErr != nil {
		return s.setErr
	}
	s.kv[k] = v
	return nil
}

// fakeRecords serves the two records.
type fakeRecords struct {
	mu        sync.Mutex
	prov      osoutcome.Record
	provErr   error
	migrate   osoutcome.Record
	migrateEr error
}

func (r *fakeRecords) Provision() (osoutcome.Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.prov, r.provErr
}

func (r *fakeRecords) Migrate() (osoutcome.Record, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.migrate, r.migrateEr
}

func (r *fakeRecords) setMigrate(outcome, runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.migrate = osoutcome.Record{Outcome: outcome, BootID: thisBoot, RunID: runID, Reason: "The root step said " + outcome + "."}
}

// hookFiles is the real state directory with failures and hooks injected.
type hookFiles struct {
	*StateDir
	calls      *calls
	writeErr   map[string]error
	removeErr  map[string]error
	presentErr map[string]error
	afterWrite func(name string)
}

func (h *hookFiles) Present(name string) (bool, error) {
	if err := h.presentErr[name]; err != nil {
		return false, err
	}
	return h.StateDir.Present(name)
}

func (h *hookFiles) Write(name string, data []byte) error {
	h.calls.add("write_file " + name)
	if err := h.writeErr[name]; err != nil {
		return err
	}
	if err := h.StateDir.Write(name, data); err != nil {
		return err
	}
	if h.afterWrite != nil {
		h.afterWrite(name)
	}
	return nil
}

func (h *hookFiles) Remove(name string) error {
	h.calls.add("remove_file " + name)
	if err := h.removeErr[name]; err != nil {
		return err
	}
	return h.StateDir.Remove(name)
}

// fx is one migration's fixture: two apps with three entries in the old
// tree, a store whose root step behaves as rasputin-store-migrate.sh does.
type fx struct {
	t        *testing.T
	calls    *calls
	dir      string
	files    *hookFiles
	inv      *fakeInventory
	repo     *fakeRepo
	ctl      *fakeControl
	lock     *fakeLock
	marker   *fakeMarker
	settings *fakeSettings
	records  *fakeRecords
	unit     sysunit.Unit
	unitErr  error
	hold     *Hold
	rec      *logkittest.Recorder
	m        *Migrator
	// terminal counts AfterTerminal calls.
	terminal int
	// runs counts store starts, for each start's invocation id.
	runs int
}

// oldTree is the fixture's store before the migration.
func oldTree() map[string][]byte {
	return map[string][]byte{
		"apps/" + appA + "/db-pass":          []byte("p@ss"),
		"apps/" + appA + "/_runtime/session": []byte("runtime-value"),
		"apps/" + appB + "/smtp-pass":        []byte("smtp"),
	}
}

func newFx(t *testing.T) *fx {
	t.Helper()
	c := &calls{}
	dir := t.TempDir()
	sd, err := NewStateDir(dir, func(f *os.File) error {
		c.add("fsync " + filepath.Base(f.Name()))
		return f.Sync()
	})
	if err != nil {
		t.Fatal(err)
	}
	log, rec := logkittest.New()
	f := &fx{
		t: t, calls: c, dir: dir, rec: rec,
		files: &hookFiles{StateDir: sd, calls: c},
		inv: &fakeInventory{calls: c, apps: []apps.AppSecretInventory{
			{AppID: appA, Names: []string{"db-pass", "gone"}, RuntimeNames: []string{"session"}},
			{AppID: appB, Names: []string{"smtp-pass"}},
		}},
		repo:     &fakeRepo{tree: oldTree(), calls: c},
		ctl:      &fakeControl{calls: c},
		lock:     &fakeLock{calls: c},
		marker:   &fakeMarker{calls: c},
		settings: &fakeSettings{kv: map[string]string{}},
		records: &fakeRecords{prov: osoutcome.Record{Outcome: "applied", BootID: thisBoot, RunID: runBefore,
			Reason: "Provisioned.", Author: osoutcome.AuthorAbsent}},
		unit: sysunit.Unit{ActiveState: "active", SubState: "running", InvocationID: runBefore},
	}
	f.ctl.onStart = f.rootStep
	f.hold, err = NewHold(f.files, log)
	if err != nil {
		t.Fatal(err)
	}
	f.m, err = New(Deps{
		Inventory: f.inv, Repo: f.repo, Control: f.ctl, Lock: f.lock, Marker: f.marker, Settings: f.settings,
		Records: f.records, StoreUnit: func(context.Context) (sysunit.Unit, error) { return f.unit, f.unitErr },
		Files: f.files, BootID: func() (string, error) { return thisBoot, nil }, Hold: f.hold,
		AfterTerminal: func(context.Context) { f.terminal++ }, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// rootStep is rasputin-store-migrate.sh's decisions, on the fixture: a new
// invocation id per start, then commit → finished, aside.tar → restored,
// this boot's request → moved, else nothing.
func (f *fx) rootStep() {
	f.runs++
	run := strings.Repeat("0", 31) + string(rune('a'+f.runs))
	f.unit.InvocationID = run
	has := func(n string) bool { ok, _ := f.files.StateDir.Present(n); return ok }
	switch {
	case has(NameCommit):
		for _, n := range []string{NameAside, NameAttempt, NameRequest, NameCommit} {
			_ = f.files.StateDir.Remove(n)
		}
		f.repo.commitTree()
		f.records.setMigrate("finished", run)
	case has(NameAside):
		f.repo.putBack()
		for _, n := range []string{NameRequest, NameAside, NameAttempt} {
			_ = f.files.StateDir.Remove(n)
		}
		f.records.setMigrate(outcomeRestored, run)
	case has(NameRequest):
		b, _ := f.files.StateDir.Read(NameRequest)
		if !strings.Contains(string(b), "boot_id="+thisBoot+"\n") {
			_ = f.files.StateDir.Remove(NameRequest)
			f.records.setMigrate("failed", run)
			return
		}
		if err := f.files.StateDir.Write(NameAside, []byte("old tree")); err != nil {
			f.t.Fatal(err)
		}
		f.repo.swap()
		if err := os.Rename(filepath.Join(f.dir, NameRequest), filepath.Join(f.dir, NameAttempt)); err != nil {
			f.t.Fatal(err)
		}
		f.records.setMigrate(outcomeMoved, run)
	}
}

// present reports whether the state directory holds name.
func (f *fx) present(name string) bool {
	f.t.Helper()
	ok, err := f.files.StateDir.Present(name)
	if err != nil {
		f.t.Fatal(err)
	}
	return ok
}

// run drives the workflow as the runner does: each step in order with its
// own context, the terminal hook once. It returns the failing step's error.
func (f *fx) run(ctx context.Context) error {
	wf := f.m.Workflow()
	for _, st := range wf.Steps {
		_, err := st.Do(&jobs.StepCtx{Ctx: ctx, JobID: jobID, Log: func(string, string) {}})
		if err != nil {
			wf.OnTerminal(context.Background(), jobID, false, err.Error())
			return err
		}
	}
	wf.OnTerminal(context.Background(), jobID, true, "")
	return nil
}

// assertSentence fails unless err is a sentence a person reads.
func assertSentence(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("no error")
	}
	s := err.Error()
	if s == "" || s[0] < 'A' || s[0] > 'Z' || !strings.HasSuffix(s, ".") {
		t.Fatalf("job error %q is not a sentence", s)
	}
}

// assertLetGo checks the job holds nothing: the Hold is off, the gate free,
// every quiesce released and every value read destroyed.
func (f *fx) assertLetGo() {
	f.t.Helper()
	if on, _ := f.hold.Held(); on {
		f.t.Error("the Hold is still on")
	}
	if f.lock.holder != "" {
		f.t.Errorf("the gate is still held by %q", f.lock.holder)
	}
	if f.ctl.quiesced != f.ctl.released {
		f.t.Errorf("quiesced %d, released %d", f.ctl.quiesced, f.ctl.released)
	}
	if !f.repo.allDestroyed() {
		f.t.Error("a value read was not destroyed")
	}
	if f.terminal != 1 {
		f.t.Errorf("AfterTerminal ran %d time(s), want 1", f.terminal)
	}
}

var errBoom = errors.New("boom")
