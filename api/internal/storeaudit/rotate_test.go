package storeaudit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// TC-799-01: below the threshold, Due is false with no reason and logs nothing.
func TestDue_BelowThreshold(t *testing.T) {
	f := newFixture(t, activeStore)
	f.write(t, LiveName, testRotateAt-1)
	due, reason := f.rot.Due(t.Context())
	if due || reason != "" {
		t.Errorf("Due = %v, %q; want false, empty", due, reason)
	}
	if n := len(f.rec.Records()); n != 0 {
		t.Errorf("%d log records, want none:\n%s", n, f.rec.Text())
	}
}

// TC-799-02: exactly at the threshold, Due is true.
func TestDue_AtThreshold(t *testing.T) {
	f := newFixture(t, activeStore)
	f.write(t, LiveName, testRotateAt)
	if due, reason := f.rot.Due(t.Context()); !due || reason == "" {
		t.Errorf("Due = %v, %q; want true with a reason", due, reason)
	}
}

// TC-799-03: a cluster before #804 has no audit directory, and a fresh one an
// empty directory. Neither is due, gives a reason or logs anything.
func TestDue_NoAuditFileYet(t *testing.T) {
	for _, tc := range []struct {
		name string
		dir  func(t *testing.T) string
	}{
		{"no directory", func(t *testing.T) string { return filepath.Join(t.TempDir(), DirName) }},
		{"empty directory", func(t *testing.T) string { return t.TempDir() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log, rec := logkittest.New()
			rot, err := NewRotator(testConfig(tc.dir(t)), Deps{Store: activeStore, Reopen: &reopener{}, Files: OSFiles{}, Log: log})
			if err != nil {
				t.Fatal(err)
			}
			if due, reason := rot.Due(t.Context()); due || reason != "" {
				t.Errorf("Due = %v, %q; want false, empty", due, reason)
			}
			if n := len(rec.Records()); n != 0 {
				t.Errorf("%d log records, want none:\n%s", n, rec.Text())
			}
		})
	}
}

// TC-799-04: a stat error other than ENOENT is false with a reason and one
// WARN carrying the path and the error (ERR-CLOSED).
func TestDue_UnreadableFact(t *testing.T) {
	f := newFixture(t, activeStore)
	f.files.stat = func(string) error { return errInjected }
	due, reason := f.rot.Due(t.Context())
	if due || reason == "" {
		t.Errorf("Due = %v, %q; want false with a reason", due, reason)
	}
	warns := f.rec.AtLevel(slog.LevelWarn)
	if len(warns) != 1 || len(f.rec.Records()) != 1 {
		t.Fatalf("records:\n%s\nwant exactly one WARN", f.rec.Text())
	}
	if got := attr(t, warns[0], "file"); got != f.live {
		t.Errorf("WARN file = %q, want %q", got, f.live)
	}
	if got := attr(t, warns[0], "err"); !strings.Contains(got, errInjected.Error()) {
		t.Errorf("WARN err = %q, want the injected error", got)
	}

	// The directory listing fails the same way when the live file is absent.
	g := newFixture(t, activeStore)
	g.files.readDir = func(string) error { return errInjected }
	if due, reason := g.rot.Due(t.Context()); due || reason == "" {
		t.Errorf("Due on an unlistable dir = %v, %q; want false with a reason", due, reason)
	}
	if n := len(g.rec.AtLevel(slog.LevelWarn)); n != 1 {
		t.Errorf("%d WARNs on an unlistable dir, want 1", n)
	}
}

// TC-799-05: a failed rotation of inode I at size S is retried only once the
// file grows to S+RotateAt or the live inode changes.
func TestDue_FailedInodeRetriedOnFact(t *testing.T) {
	f := newFixture(t, activeStore)
	f.open.effect = func() error { return errInjected }
	f.write(t, LiveName, testRotateAt)
	sc, _ := stepCtx(t)
	if _, err := f.rot.rotateStep(sc); !errors.Is(err, errRolledBack) {
		t.Fatalf("rotate = %v, want the rolled-back error", err)
	}
	if due, _ := f.rot.Due(t.Context()); due {
		t.Error("Due on the unchanged failed inode = true, want false")
	}
	f.write(t, LiveName, testRotateAt-1)
	if due, _ := f.rot.Due(t.Context()); due {
		t.Error("Due at S+RotateAt-1 = true, want false")
	}
	f.write(t, LiveName, 1)
	if due, _ := f.rot.Due(t.Context()); !due {
		t.Error("Due at S+RotateAt = false, want true")
	}

	// A different inode at the live path is a fact too.
	g := newFixture(t, activeStore)
	g.open.effect = func() error { return errInjected }
	g.write(t, LiveName, testRotateAt)
	sc, _ = stepCtx(t)
	if _, err := g.rot.rotateStep(sc); !errors.Is(err, errRolledBack) {
		t.Fatalf("rotate = %v, want the rolled-back error", err)
	}
	if err := os.Rename(g.live, filepath.Join(g.dir, "elsewhere")); err != nil {
		t.Fatal(err)
	}
	g.write(t, LiveName, testRotateAt)
	if due, _ := g.rot.Due(t.Context()); !due {
		t.Error("Due on a new inode = false, want true")
	}
}

// TC-799-06: prune is due only when it could remove a copy, and not again on
// a copy set whose prune failed until the set changes.
func TestDue_PruneOnlyWhenItCanRemove(t *testing.T) {
	f := newFixture(t, activeStore)
	for i := 1; i <= 4; i++ {
		f.write(t, LiveName+"."+strconv.Itoa(i), 100) // 400 > 300
	}
	if due, _ := f.rot.Due(t.Context()); !due {
		t.Error("Due with removable copies over the cap = false, want true")
	}

	g := newFixture(t, activeStore)
	g.write(t, LiveName+".7", testKeepBytes+1)
	if due, reason := g.rot.Due(t.Context()); due || reason != "" {
		t.Errorf("Due with one oversize newest copy = %v, %q; want false, empty", due, reason)
	}

	h := newFixture(t, activeStore)
	for i := 1; i <= 4; i++ {
		h.write(t, LiveName+"."+strconv.Itoa(i), 100)
	}
	h.files.remove = func(string) error { return errInjected }
	sc, _ := stepCtx(t)
	if _, err := h.rot.pruneStep(sc); !errors.Is(err, errPruneFailed) {
		t.Fatalf("prune = %v, want the prune error", err)
	}
	if due, _ := h.rot.Due(t.Context()); due {
		t.Error("Due on the copy set whose prune failed = true, want false")
	}
	h.write(t, LiveName+".5", 100)
	if due, _ := h.rot.Due(t.Context()); !due {
		t.Error("Due once the copy set changed = false, want true")
	}
}

// storeWriter stands in for the store: it holds an O_APPEND descriptor on
// the live file, writes numbered lines continuously, and on Reopen closes it
// and opens the live path again with O_CREATE.
type storeWriter struct {
	path string
	mu   sync.Mutex
	f    *os.File
	n    int
	err  error
}

func (w *storeWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	w.f = f
	return nil
}

func (w *storeWriter) writeOne() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return
	}
	if _, err := fmt.Fprintf(w.f, "%08d\n", w.n); err != nil {
		w.err = err
		return
	}
	w.n++
}

func (w *storeWriter) Reopen(context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.f.Close(); err != nil {
		return err
	}
	return w.open()
}

// lineNumbers reads every numbered line in path.
func lineNumbers(t *testing.T, path string) []int {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	var out []int
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		n, err := strconv.Atoi(sc.Text())
		if err != nil {
			t.Fatalf("line %q in %s", sc.Text(), path)
		}
		out = append(out, n)
	}
	return out
}

// TC-799-07: the happy path under continuous writes. Every line written is in
// the copy or the new live file exactly once; the copy holds the original
// inode; Reopen ran once.
func TestRotate_HappyPathNoLineLost(t *testing.T) {
	dir := t.TempDir()
	w := &storeWriter{path: filepath.Join(dir, LiveName)}
	if err := w.open(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ { // 20 lines of 9 bytes: past RotateAt
		w.writeOne()
	}
	calls := 0
	log, _ := logkittest.New()
	rot, err := NewRotator(testConfig(dir), Deps{
		Store: activeStore,
		Reopen: ReopenFunc(func(ctx context.Context) error {
			calls++
			return w.Reopen(ctx)
		}),
		Files: OSFiles{}, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(w.path)
	if err != nil {
		t.Fatal(err)
	}
	origIno, _ := inodeOf(fi)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				w.writeOne()
			}
		}
	}()
	sc, _ := stepCtx(t)
	_, stepErr := rot.rotateStep(sc)
	for i := 0; i < 1000; i++ { // let the writer reach the new file
		w.writeOne()
	}
	close(stop)
	<-done
	if stepErr != nil {
		t.Fatalf("rotate: %v", stepErr)
	}
	w.mu.Lock()
	total, werr := w.n, w.err
	_ = w.f.Close()
	w.mu.Unlock()
	if werr != nil {
		t.Fatalf("writer: %v", werr)
	}

	cp := filepath.Join(dir, LiveName+".1")
	cfi, err := os.Stat(cp)
	if err != nil {
		t.Fatal(err)
	}
	if ino, _ := inodeOf(cfi); ino != origIno {
		t.Errorf("copy inode = %d, want the original %d", ino, origIno)
	}
	if calls != 1 {
		t.Errorf("Reopen called %d times, want 1", calls)
	}
	before, after := lineNumbers(t, cp), lineNumbers(t, w.path)
	if len(after) == 0 {
		t.Error("the new live file holds no lines; the reopen was not followed by writes")
	}
	all := append(before, after...)
	if len(all) != total {
		t.Fatalf("%d lines across copy and live, want %d", len(all), total)
	}
	for i, n := range all {
		if n != i {
			t.Fatalf("line %d is %d: a line was lost, repeated or reordered", i, n)
		}
	}
}

// TC-799-08: the copy's number is one more than the highest existing,
// compared numerically, ignoring non-matching names; with none it is 1.
func TestRotate_CopyNamingFromSequence(t *testing.T) {
	f := newFixture(t, activeStore)
	f.write(t, LiveName+".2", 1)
	f.write(t, LiveName+".9", 1)
	f.write(t, LiveName+".old", 1)
	f.write(t, LiveName, testRotateAt)
	sc, _ := stepCtx(t)
	if _, err := f.rot.rotateStep(sc); err != nil {
		t.Fatal(err)
	}
	want := []string{LiveName, LiveName + ".10", LiveName + ".2", LiveName + ".9", LiveName + ".old"}
	if got := f.names(t); !slices.Equal(got, want) {
		t.Errorf("dir = %v, want %v", got, want)
	}

	g := newFixture(t, activeStore)
	g.write(t, LiveName, testRotateAt)
	sc, _ = stepCtx(t)
	if _, err := g.rot.rotateStep(sc); err != nil {
		t.Fatal(err)
	}
	if got := g.names(t); !slices.Equal(got, []string{LiveName, LiveName + ".1"}) {
		t.Errorf("dir = %v, want audit.log and audit.log.1", got)
	}
}

// TC-799-09: a store that is not active stops the workflow early with no
// rename and no signal, and one WARN naming why.
func TestRotate_StoreNotActive(t *testing.T) {
	for _, tc := range []struct {
		name, kind string
		store      fakeStore
	}{
		{"sealed", "sealed", fakeStore{err: &secretstore.Error{Op: "health", Kind: secretstore.ErrSealed}}},
		{"uninitialised", "uninitialised", fakeStore{err: &secretstore.Error{Op: "health", Kind: secretstore.ErrUninitialised}}},
		{"unreachable", "unreachable", fakeStore{err: &secretstore.Error{Op: "health", Kind: secretstore.ErrUnreachable}}},
		{"sealed answer", "sealed", fakeStore{h: secretstore.Health{Initialized: true, Sealed: true}}},
		{"uninitialised answer", "uninitialised", fakeStore{h: secretstore.Health{}}},
		{"disabled", "disabled", fakeStore{err: &secretstore.Error{Op: "health", Kind: secretstore.ErrDisabled}}},
		{"other error", "error", fakeStore{err: errInjected}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.store)
			f.write(t, LiveName, testRotateAt)
			ino := f.inode(t, LiveName)
			sc, _ := stepCtx(t)
			if _, err := f.rot.rotateStep(sc); !errors.Is(err, jobs.ErrStopWorkflow) {
				t.Fatalf("rotate = %v, want ErrStopWorkflow", err)
			}
			if got := f.inode(t, LiveName); got != ino {
				t.Error("the live file was replaced")
			}
			if got := f.names(t); !slices.Equal(got, []string{LiveName}) {
				t.Errorf("dir = %v, want only audit.log", got)
			}
			if n := f.open.calls.Load(); n != 0 {
				t.Errorf("Reopen called %d times, want 0", n)
			}
			warns := f.rec.AtLevel(slog.LevelWarn)
			if len(warns) != 1 {
				t.Fatalf("records:\n%s\nwant one WARN", f.rec.Text())
			}
			if got := attr(t, warns[0], "kind"); got != tc.kind {
				t.Errorf("WARN kind = %q, want %q", got, tc.kind)
			}
		})
	}
}

// assertRolledBack is TC-799-10's outcome: the live path holds the original
// inode, no copy is left, the error is the rolled-back sentence, one ERROR is
// logged, and the failed inode is remembered.
func assertRolledBack(t *testing.T, f *fixture, ino uint64, err error) {
	t.Helper()
	if !errors.Is(err, errRolledBack) {
		t.Fatalf("rotate = %v, want the rolled-back error", err)
	}
	if got := f.inode(t, LiveName); got != ino {
		t.Errorf("live inode = %d, want the original %d", got, ino)
	}
	if got := f.names(t); !slices.Equal(got, []string{LiveName}) {
		t.Errorf("dir = %v, want only audit.log", got)
	}
	if n := len(f.rec.AtLevel(slog.LevelError)); n != 1 {
		t.Errorf("%d ERROR records, want 1:\n%s", n, f.rec.Text())
	}
	f.rot.mu.Lock()
	mem := f.rot.failedRotate
	f.rot.mu.Unlock()
	if mem == nil || mem.inode != ino || mem.size != testRotateAt {
		t.Errorf("remembered failure = %+v, want inode %d size %d", mem, ino, testRotateAt)
	}
}

// TC-799-10: a Reopen error rolls the rename back.
func TestRotate_ReopenErrorRollsBack(t *testing.T) {
	f := newFixture(t, activeStore)
	f.open.effect = func() error { return errInjected }
	f.write(t, LiveName, testRotateAt)
	ino := f.inode(t, LiveName)
	sc, _ := stepCtx(t)
	_, err := f.rot.rotateStep(sc)
	assertRolledBack(t, f, ino, err)
}

// TC-799-11: a wait that runs out rolls the rename back the same way.
func TestRotate_WaitRunsOutRollsBack(t *testing.T) {
	f := newFixture(t, activeStore)
	f.open.effect = nil // delivered, but the store never reopens
	f.write(t, LiveName, testRotateAt)
	ino := f.inode(t, LiveName)
	sc, _ := stepCtx(t)
	_, err := f.rot.rotateStep(sc)
	assertRolledBack(t, f, ino, err)
	if n := f.open.calls.Load(); n != 1 {
		t.Errorf("Reopen called %d times, want 1", n)
	}
}

// TC-799-12: the store reopens after the wait and before the rollback link.
// The link finds the live path taken; the rotation stands, with one WARN and
// no ERROR.
func TestRotate_LateReopenIsSuccess(t *testing.T) {
	f := newFixture(t, activeStore)
	f.open.effect = nil
	late := storeReopen(f.dir)
	f.files.link = func(oldname, newname string) error {
		if newname == f.live { // the rollback link
			return late()
		}
		return nil
	}
	f.write(t, LiveName, testRotateAt)
	ino := f.inode(t, LiveName)
	sc, _ := stepCtx(t)
	if _, err := f.rot.rotateStep(sc); err != nil {
		t.Fatalf("rotate = %v, want success", err)
	}
	if got := f.inode(t, LiveName+".1"); got != ino {
		t.Error("the copy does not hold the original inode")
	}
	if got := f.names(t); !slices.Equal(got, []string{LiveName, LiveName + ".1"}) {
		t.Errorf("dir = %v, want audit.log and audit.log.1", got)
	}
	if n := len(f.rec.AtLevel(slog.LevelWarn)); n != 1 {
		t.Errorf("%d WARNs, want 1", n)
	}
	if n := len(f.rec.AtLevel(slog.LevelError)); n != 0 {
		t.Errorf("%d ERRORs, want 0", n)
	}
}

// TC-799-13: the reopen fails and so does the rollback link. The job fails,
// and the ERROR names the copy the store is still writing to.
func TestRotate_RollbackFailure(t *testing.T) {
	f := newFixture(t, activeStore)
	f.open.effect = func() error { return errInjected }
	f.files.link = func(oldname, newname string) error {
		if newname == f.live {
			return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EPERM}
		}
		return nil
	}
	f.write(t, LiveName, testRotateAt)
	sc, _ := stepCtx(t)
	if _, err := f.rot.rotateStep(sc); !errors.Is(err, errRollbackFailed) {
		t.Fatalf("rotate = %v, want the rollback-failed error", err)
	}
	errs := f.rec.AtLevel(slog.LevelError)
	if len(errs) != 1 {
		t.Fatalf("%d ERRORs, want 1", len(errs))
	}
	if got, want := attr(t, errs[0], "copy"), filepath.Join(f.dir, LiveName+".1"); got != want {
		t.Errorf("ERROR copy = %q, want %q", got, want)
	}
}

// TC-799-14: removing the old name fails after the link. The link is undone,
// the live file is untouched, nothing is signalled, and the job fails.
func TestRotate_RemoveLiveFails(t *testing.T) {
	f := newFixture(t, activeStore)
	f.files.remove = func(path string) error {
		if path == f.live {
			return errInjected
		}
		return nil
	}
	f.write(t, LiveName, testRotateAt)
	ino := f.inode(t, LiveName)
	sc, _ := stepCtx(t)
	if _, err := f.rot.rotateStep(sc); !errors.Is(err, errNotMoved) {
		t.Fatalf("rotate = %v, want the not-moved error", err)
	}
	if got := f.names(t); !slices.Equal(got, []string{LiveName}) {
		t.Errorf("dir = %v, want only audit.log", got)
	}
	if got := f.inode(t, LiveName); got != ino {
		t.Error("the live file changed")
	}
	if n := f.open.calls.Load(); n != 0 {
		t.Errorf("Reopen called %d times, want 0", n)
	}
	if n := len(f.rec.AtLevel(slog.LevelError)); n != 1 {
		t.Errorf("%d ERRORs, want 1", n)
	}

	// The link itself failing is the same sentence, with nothing to undo.
	g := newFixture(t, activeStore)
	g.files.link = func(string, string) error { return errInjected }
	g.write(t, LiveName, testRotateAt)
	sc, _ = stepCtx(t)
	if _, err := g.rot.rotateStep(sc); !errors.Is(err, errNotMoved) {
		t.Fatalf("rotate with a failing link = %v, want the not-moved error", err)
	}
	if got := g.names(t); !slices.Equal(got, []string{LiveName}) {
		t.Errorf("dir = %v, want only audit.log", got)
	}
}

// TC-799-15: prune removes copies oldest first until the rest are within the
// cap, never the newest, never a non-matching name, and logs one INFO.
func TestPrune_OldestFirst(t *testing.T) {
	f := newFixture(t, activeStore)
	for i := 1; i <= 6; i++ {
		f.write(t, LiveName+"."+strconv.Itoa(i), 100)
	}
	f.write(t, LiveName+".old", 1000)
	f.write(t, "notes.txt", 1000)
	sc, _ := stepCtx(t)
	if _, err := f.rot.pruneStep(sc); err != nil {
		t.Fatal(err)
	}
	want := []string{LiveName + ".4", LiveName + ".5", LiveName + ".6", LiveName + ".old", "notes.txt"}
	if got := f.names(t); !slices.Equal(got, want) {
		t.Errorf("dir = %v, want %v", got, want)
	}
	infos := f.rec.Matching(slog.LevelInfo, "rotated audit copies removed")
	if len(infos) != 1 {
		t.Fatalf("records:\n%s\nwant one INFO", f.rec.Text())
	}
	if got := attr(t, infos[0], "removed"); got != "3" {
		t.Errorf("INFO removed = %s, want 3", got)
	}
	if got := attr(t, infos[0], "bytes"); got != "300" {
		t.Errorf("INFO bytes = %s, want 300", got)
	}
}

// TC-799-15 (the newest copy is always kept), on the pure planner.
func TestPlanPrune(t *testing.T) {
	c := func(sizes ...int64) []auditCopy {
		var out []auditCopy
		for i, s := range sizes {
			out = append(out, auditCopy{name: fmt.Sprint(i + 1), seq: uint64(i + 1), size: s})
		}
		return out
	}
	for _, tc := range []struct {
		name  string
		in    []auditCopy
		keep  int64
		wantN int
	}{
		{"none", nil, 300, 0},
		{"within the cap", c(100, 100, 100), 300, 0},
		{"one over", c(100, 100, 100, 1), 300, 1},
		{"newest alone over the cap", c(500), 300, 0},
		{"newest over the cap with others", c(1, 1, 500), 300, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := planPrune(tc.in, tc.keep); len(got) != tc.wantN {
				t.Errorf("planPrune removes %d, want %d", len(got), tc.wantN)
			}
		})
	}
}

// TC-799-16: a copy that cannot be removed fails the job with one ERROR, and
// Due stays false on the unchanged copy set.
func TestPrune_RemoveFailure(t *testing.T) {
	f := newFixture(t, activeStore)
	for i := 1; i <= 4; i++ {
		f.write(t, LiveName+"."+strconv.Itoa(i), 100)
	}
	f.files.remove = func(path string) error {
		if filepath.Base(path) == LiveName+".1" {
			return errInjected
		}
		return nil
	}
	sc, _ := stepCtx(t)
	if _, err := f.rot.pruneStep(sc); !errors.Is(err, errPruneFailed) {
		t.Fatalf("prune = %v, want the prune error", err)
	}
	if n := len(f.rec.AtLevel(slog.LevelError)); n != 1 {
		t.Errorf("%d ERRORs, want 1", n)
	}
	if due, _ := f.rot.Due(t.Context()); due {
		t.Error("Due on the unchanged copy set = true, want false")
	}
}

// A partial prune remembers the set as it was left, so Due does not fire on
// it again.
func TestPrune_PartialFailureRemembersWhatIsLeft(t *testing.T) {
	f := newFixture(t, activeStore)
	for i := 1; i <= 6; i++ {
		f.write(t, LiveName+"."+strconv.Itoa(i), 100)
	}
	f.files.remove = func(path string) error {
		if filepath.Base(path) == LiveName+".2" {
			return errInjected
		}
		return nil
	}
	sc, _ := stepCtx(t)
	if _, err := f.rot.pruneStep(sc); !errors.Is(err, errPruneFailed) {
		t.Fatalf("prune = %v, want the prune error", err)
	}
	if got := f.names(t); slices.Contains(got, LiveName+".1") {
		t.Error("audit.log.1 should have been removed before the failure")
	}
	if due, _ := f.rot.Due(t.Context()); due {
		t.Error("Due on the set the failed prune left = true, want false")
	}
}

// A directory that cannot be listed fails the prune with its own sentence.
func TestPrune_ListFailure(t *testing.T) {
	f := newFixture(t, activeStore)
	f.files.readDir = func(string) error { return errInjected }
	sc, _ := stepCtx(t)
	if _, err := f.rot.pruneStep(sc); !errors.Is(err, errListFailed) {
		t.Fatalf("prune = %v, want the list error", err)
	}
	g := newFixture(t, activeStore)
	if err := os.Remove(g.dir); err != nil {
		t.Fatal(err)
	}
	sc, _ = stepCtx(t)
	if _, err := g.rot.pruneStep(sc); err != nil {
		t.Errorf("prune of a missing dir = %v, want nil", err)
	}
}

// TC-799-17: every refusal of NewRotator and NewFreeSpace returns an error
// and no value.
func TestConstructorRefusals(t *testing.T) {
	log, _ := logkittest.New()
	ok := Deps{Store: activeStore, Reopen: &reopener{}, Files: OSFiles{}, Log: log}
	cfg := testConfig("/x")
	for _, tc := range []struct {
		name string
		cfg  Config
		deps Deps
	}{
		{"nil Store", cfg, Deps{Reopen: ok.Reopen, Files: ok.Files, Log: ok.Log}},
		{"nil Reopen", cfg, Deps{Store: ok.Store, Files: ok.Files, Log: ok.Log}},
		{"nil Files", cfg, Deps{Store: ok.Store, Reopen: ok.Reopen, Log: ok.Log}},
		{"nil Log", cfg, Deps{Store: ok.Store, Reopen: ok.Reopen, Files: ok.Files}},
		{"empty Dir", Config{RotateAt: 1, KeepBytes: 1, ReopenWait: time.Second}, ok},
		{"KeepBytes below RotateAt", Config{Dir: "/x", RotateAt: 2, KeepBytes: 1, ReopenWait: time.Second}, ok},
		{"RotateAt zero", Config{Dir: "/x", KeepBytes: 1, ReopenWait: time.Second}, ok},
		{"ReopenWait zero", Config{Dir: "/x", RotateAt: 1, KeepBytes: 1}, ok},
		{"ReopenWait not below the step timeout", Config{Dir: "/x", RotateAt: 1, KeepBytes: 1, ReopenWait: rotateTimeout}, ok},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRotator(tc.cfg, tc.deps)
			if err == nil || r != nil {
				t.Errorf("NewRotator = %v, %v; want nil and an error", r, err)
			}
		})
	}
	read := func(string) (uint64, error) { return 0, nil }
	for _, tc := range []struct {
		name string
		dir  string
		read func(string) (uint64, error)
		log  *slog.Logger
	}{
		{"empty dir", "", read, log},
		{"nil read", "/x", nil, log},
		{"nil logger", "/x", read, nil},
	} {
		t.Run("NewFreeSpace "+tc.name, func(t *testing.T) {
			f, err := NewFreeSpace(tc.dir, tc.read, tc.log)
			if err == nil || f != nil {
				t.Errorf("NewFreeSpace = %v, %v; want nil and an error", f, err)
			}
		})
	}
	if r, err := NewRotator(Defaults("/var/lib/rasputin"), ok); err != nil || r == nil {
		t.Errorf("NewRotator(Defaults) = %v, %v; want a rotator", r, err)
	}
}

const canary = "CANARY-7f3c9a-not-for-logs"

// sentence is the shape ERR-MESSAGE asks of a message a person reads.
var sentence = regexp.MustCompile(`^[A-Z][^/]*[.]$`)

// TC-799-18, TC-799-19: each failure path, run as a real job. The job's
// persisted error and its step-failed event are the plan's fixed sentence,
// with no path and no OS error; the path and the OS error are in the slog
// ERROR record with the job's id. No canary written to the audit file
// reaches either capture.
func TestJobErrors_AreSafeSentences(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, f *fixture)
		want  jobError
	}{
		{"TC-799-10 reopen error", func(t *testing.T, f *fixture) { f.open.effect = func() error { return errInjected } }, errRolledBack},
		{"TC-799-11 wait runs out", func(t *testing.T, f *fixture) { f.open.effect = nil }, errRolledBack},
		{"TC-799-13 rollback fails", func(t *testing.T, f *fixture) {
			f.open.effect = func() error { return errInjected }
			f.files.link = func(o, n string) error {
				if n == f.live {
					return &os.LinkError{Op: "link", Old: o, New: n, Err: syscall.EPERM}
				}
				return nil
			}
		}, errRollbackFailed},
		{"TC-799-14 remove live fails", func(t *testing.T, f *fixture) {
			f.files.remove = func(p string) error {
				if p == f.live {
					return &os.PathError{Op: "remove", Path: p, Err: syscall.EACCES}
				}
				return nil
			}
		}, errNotMoved},
		{"TC-799-16 prune remove fails", func(t *testing.T, f *fixture) {
			for i := 1; i <= 4; i++ {
				f.write(t, LiveName+"."+strconv.Itoa(i), 100)
			}
			f.files.remove = func(p string) error { return &os.PathError{Op: "remove", Path: p, Err: syscall.EACCES} }
		}, errPruneFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, activeStore)
			f.write(t, LiveName, testRotateAt)
			if err := os.WriteFile(f.live, []byte(strings.Repeat(canary+"\n", 10)), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.want == errPruneFailed {
				// Below the threshold, so the job reaches prune with no rotation.
				if err := os.Truncate(f.live, 1); err != nil {
					t.Fatal(err)
				}
			}
			tc.setup(t, f)
			job, evs := runJob(t, f.rot)
			if job.Status != jobs.StatusFailed {
				t.Fatalf("job status = %s, want failed", job.Status)
			}
			if job.Error != string(tc.want) {
				t.Errorf("job error = %q, want %q", job.Error, tc.want)
			}
			if !sentence.MatchString(job.Error) {
				t.Errorf("job error %q is not a sentence free of paths", job.Error)
			}
			for _, osText := range []string{"permission denied", "operation not permitted", "injected", "context deadline"} {
				if strings.Contains(job.Error, osText) {
					t.Errorf("job error carries OS text %q", osText)
				}
			}
			if got := stepFailedErrors(t, evs); !slices.Equal(got, []string{string(tc.want)}) {
				t.Errorf("step-failed errors = %q, want [%q]", got, tc.want)
			}
			errs := f.rec.AtLevel(slog.LevelError)
			if len(errs) != 1 {
				t.Fatalf("%d ERROR records, want 1:\n%s", len(errs), f.rec.Text())
			}
			if got := attr(t, errs[0], "job_id"); got != job.ID {
				t.Errorf("ERROR job_id = %q, want %q", got, job.ID)
			}
			if got := attr(t, errs[0], "file"); !strings.HasPrefix(got, f.dir) {
				t.Errorf("ERROR file = %q, want a path under %s", got, f.dir)
			}
			if _, ok := logkittest.Attr(errs[0], "err"); !ok {
				t.Error("ERROR carries no err field")
			}
			raw, _ := json.Marshal(evs)
			if strings.Contains(f.rec.Text(), canary) || strings.Contains(string(raw), canary) {
				t.Error("the audit file's content reached a log or a job event")
			}
		})
	}
}

// TC-799-18 (success path) and TC-799-20: a rotation that succeeds logs an
// INFO "audit file rotated" in the job's step log and in slog, with the
// fields an operator acts on; no audit content reaches either.
func TestRotate_LogsThroughBothPipelines(t *testing.T) {
	f := newFixture(t, activeStore)
	if err := os.WriteFile(f.live, []byte(strings.Repeat(canary+"\n", 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 4; i++ {
		f.write(t, LiveName+"."+strconv.Itoa(i), 100)
	}
	job, evs := runJob(t, f.rot)
	if job.Status != jobs.StatusSucceeded {
		t.Fatalf("job = %s %q, want succeeded", job.Status, job.Error)
	}
	var stepLines []proto.LogEventData
	for _, e := range evs {
		if e.Type != string(proto.JobLog) {
			continue
		}
		var d proto.LogEventData
		if err := json.Unmarshal(e.Data, &d); err != nil {
			t.Fatal(err)
		}
		stepLines = append(stepLines, d)
	}
	if !slices.Contains(stepLines, proto.LogEventData{Level: "info", Message: "audit file rotated"}) {
		t.Errorf("step log = %+v, want an info 'audit file rotated'", stepLines)
	}
	if !slices.Contains(stepLines, proto.LogEventData{Level: "info", Message: "rotated audit copies removed"}) {
		t.Errorf("step log = %+v, want an info 'rotated audit copies removed'", stepLines)
	}
	infos := f.rec.Matching(slog.LevelInfo, "audit file rotated")
	if len(infos) != 1 {
		t.Fatalf("records:\n%s\nwant one INFO 'audit file rotated'", f.rec.Text())
	}
	for key, want := range map[string]string{
		"component": "storeaudit", "job_id": job.ID, "copy": LiveName + ".5",
		"bytes": strconv.Itoa(10 * (len(canary) + 1)), "seq": "5",
	} {
		if got := attr(t, infos[0], key); got != want {
			t.Errorf("INFO %s = %q, want %q", key, got, want)
		}
	}
	raw, _ := json.Marshal(evs)
	if strings.Contains(f.rec.Text(), canary) || strings.Contains(string(raw), canary) {
		t.Error("the audit file's content reached a log or a job event")
	}
}

// TC-799-21: SystemdReopener's argv, and a run error returned wrapped.
func TestSystemdReopener(t *testing.T) {
	var argv []string
	r := SystemdReopener(func(_ context.Context, name string, args ...string) ([]byte, error) {
		argv = append([]string{name}, args...)
		return nil, nil
	}, "openbao.service")
	if err := r.Reopen(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := []string{"systemctl", "kill", "--kill-whom=main", "--signal=SIGHUP", "openbao.service"}
	if !slices.Equal(argv, want) {
		t.Errorf("argv = %q, want %q", argv, want)
	}
	failing := SystemdReopener(func(context.Context, string, ...string) ([]byte, error) {
		return []byte("Failed"), errInjected
	}, "openbao.service")
	if err := failing.Reopen(t.Context()); !errors.Is(err, errInjected) {
		t.Errorf("Reopen = %v, want the run error wrapped", err)
	}
}

// TC-799-35: the workflow's kind, steps and bounds.
func TestWorkflowShape(t *testing.T) {
	f := newFixture(t, activeStore)
	wf := f.rot.Workflow()
	if wf.Kind != "secretstore.audit_rotate" {
		t.Errorf("kind = %q", wf.Kind)
	}
	if err := jobs.ValidateWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range wf.Steps {
		names = append(names, s.Name)
		if s.Retries != 0 {
			t.Errorf("step %s Retries = %d, want 0", s.Name, s.Retries)
		}
		if s.Timeout <= 0 {
			t.Errorf("step %s has no Timeout", s.Name)
		}
	}
	if !slices.Equal(names, []string{"rotate", "prune"}) {
		t.Fatalf("steps = %v, want rotate, prune", names)
	}
	if wf.Steps[0].Timeout != time.Minute || wf.Steps[0].Timeout <= ReopenWait || ReopenWait != 30*time.Second {
		t.Errorf("rotate Timeout = %s, ReopenWait = %s; want 1m above 30s", wf.Steps[0].Timeout, ReopenWait)
	}
	if wf.Steps[1].Timeout != 30*time.Second {
		t.Errorf("prune Timeout = %s, want 30s", wf.Steps[1].Timeout)
	}
	if RotateAt != 64<<20 || KeepBytes != 448<<20 {
		t.Errorf("RotateAt, KeepBytes = %d, %d; want 64 MiB, 448 MiB", RotateAt, KeepBytes)
	}
}

// The rotate step does nothing when there is no live file or it is below the
// threshold, and prune still runs.
func TestRotate_NothingToRotate(t *testing.T) {
	f := newFixture(t, activeStore)
	sc, _ := stepCtx(t)
	if _, err := f.rot.rotateStep(sc); err != nil {
		t.Errorf("rotate with no file = %v", err)
	}
	f.write(t, LiveName, testRotateAt-1)
	if _, err := f.rot.rotateStep(sc); err != nil {
		t.Errorf("rotate below the threshold = %v", err)
	}
	if n := f.open.calls.Load(); n != 0 {
		t.Errorf("Reopen called %d times, want 0", n)
	}
	if got := f.names(t); !slices.Equal(got, []string{LiveName}) {
		t.Errorf("dir = %v", got)
	}
	g := newFixture(t, activeStore)
	g.files.stat = func(string) error { return errInjected }
	if _, err := g.rot.rotateStep(sc); !errors.Is(err, errNotMoved) {
		t.Errorf("rotate on an unreadable file = %v, want the not-moved error", err)
	}
	h := newFixture(t, activeStore)
	h.write(t, LiveName, testRotateAt)
	h.files.readDir = func(string) error { return errInjected }
	if _, err := h.rot.rotateStep(sc); !errors.Is(err, errNotMoved) {
		t.Errorf("rotate on an unlistable dir = %v, want the not-moved error", err)
	}
}
