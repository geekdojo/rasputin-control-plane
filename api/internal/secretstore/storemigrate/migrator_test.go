package storemigrate

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/osoutcome"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// TC-1132-19 (success) and the done-when copy: every entry is written back
// create-only, read back and found byte-identical; commit is written and
// fsynced, file and directory, while the Hold is still on; then the Hold,
// the quiesce and the gate are released, every value is destroyed, the
// attempt bound is cleared, and migrate_committed logs the count with the
// job id. The next store start deletes the old tree.
func TestMigrate_Commits(t *testing.T) {
	f := newFx(t)
	holdOnAtCommit := false
	f.files.afterWrite = func(name string) {
		if name == NameCommit {
			holdOnAtCommit, _ = f.hold.Held()
		}
	}
	if err := f.run(context.Background()); err != nil {
		t.Fatalf("job failed: %v", err)
	}
	for ref, want := range oldTree() {
		if got, ok := f.repo.value(ref); !ok || string(got) != string(want) {
			t.Errorf("%s in the fresh store = %q, %v; want the old value", ref, got, ok)
		}
	}
	if f.repo.writes != 3 {
		t.Errorf("%d writes, want 3: the not-found candidate is skipped", f.repo.writes)
	}
	if !f.present(NameCommit) || !holdOnAtCommit {
		t.Fatalf("commit present %v, Hold on while it was written %v; want both", f.present(NameCommit), holdOnAtCommit)
	}
	c := f.calls
	if i, j := c.indexOf("write_file "+NameCommit), c.indexOf("fsync "+NameCommit); i < 0 || j < i {
		t.Errorf("commit not fsynced after its write: %v", c.list())
	}
	if c.indexOf("release") < c.indexOf("fsync "+NameCommit) {
		t.Errorf("the gate was released before the commit was durable: %v", c.list())
	}
	f.assertLetGo()
	if v := f.settings.kv[KeyAttemptBootID]; v != "" {
		t.Errorf("attempt bound %q left after the commit", v)
	}
	recs := f.rec.Matching(slog.LevelInfo, "secret store migration committed")
	if len(recs) != 1 {
		t.Fatalf("no migrate_committed record:\n%s", f.rec.Text())
	}
	if got, _ := logkittest.Attr(recs[0], "count"); got != "3" {
		t.Errorf("count = %q, want 3", got)
	}
	if got, _ := logkittest.Attr(recs[0], "job_id"); got != jobID {
		t.Errorf("job_id = %q", got)
	}
	started := f.rec.Matching(slog.LevelInfo, "read the entries to copy")
	if len(started) != 1 {
		t.Fatal("no migrate_started record")
	}
	if got, _ := logkittest.Attr(started[0], "not_found"); got != "1" {
		t.Errorf("not_found = %q, want 1 (TC-1132-15: skipped and counted)", got)
	}
	// The store's next start finishes it: the old tree is deleted.
	f.rootStep()
	if f.present(NameAside) || f.present(NameCommit) || f.present(NameAttempt) {
		t.Error("the start after the commit left migration state")
	}
}

// TC-1132-19 (zero candidates): a store with nothing to copy is still
// swapped and committed, so it gains the author role.
func TestMigrate_ZeroCandidatesStillSwaps(t *testing.T) {
	f := newFx(t)
	f.inv.apps = nil
	if err := f.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !f.calls.has("stop") || !f.calls.has("start") || !f.present(NameCommit) {
		t.Fatalf("calls %v, commit %v; want a swap and a commit", f.calls.list(), f.present(NameCommit))
	}
}

// TC-1132-15: a candidate's Get that fails other than not-found, a name that
// is not a Ref, and a failed inventory read each fail the job with a
// sentence before anything changes: no request is written, Stop is never
// called, the Hold and the gate are released and every value read so far is
// destroyed.
func TestMigrate_ReadRefusals(t *testing.T) {
	refA := "apps/" + appB + "/smtp-pass"
	for name, set := range map[string]func(*fx){
		"protocol": func(f *fx) { f.repo.getErr = map[string]error{refA: secretstore.ErrProtocol} },
		"denied": func(f *fx) {
			f.repo.getErr = map[string]error{refA: &secretstore.Error{Op: "read", Kind: secretstore.ErrDenied}}
		},
		"unreachable": func(f *fx) {
			f.repo.getErr = map[string]error{refA: &secretstore.Error{Op: "read", Kind: secretstore.ErrUnreachable}}
		},
		"context":   func(f *fx) { f.repo.getErr = map[string]error{refA: context.Canceled} },
		"bad name":  func(f *fx) { f.inv.apps[1].Names = []string{"Not_A_Label"} },
		"inventory": func(f *fx) { f.inv.err = errBoom },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFx(t)
			set(f)
			err := f.run(context.Background())
			assertSentence(t, err)
			if f.calls.has("write_file "+NameRequest) || f.calls.has("stop") || f.present(NameRequest) {
				t.Fatalf("a read failure went on: %v", f.calls.list())
			}
			f.assertLetGo()
			if len(f.rec.Matching(slog.LevelError, "stopped before its commit")) != 1 {
				t.Errorf("no migrate_aborted record:\n%s", f.rec.Text())
			}
		})
	}
}

// TC-1132-16: each validate refusal fails the job before the Hold is taken
// or anything is read, and writes nothing: no attempt bound, no state file.
func TestMigrate_ValidateRefusals(t *testing.T) {
	cases := map[string]func(*fx){
		"author present": func(f *fx) { f.records.prov.Author = osoutcome.AuthorPresent },
		"author unknown": func(f *fx) { f.records.prov.Author = osoutcome.AuthorUnknown },
		"failed outcome": func(f *fx) { f.records.prov.Outcome = "failed" },
		"other boot":     func(f *fx) { f.records.prov.BootID = otherBoot },
		"no record":      func(f *fx) { f.records.provErr = errBoom },
		"seal not clean": func(f *fx) { f.ctl.sealErr = errBoom },
		"not ready":      func(f *fx) { f.ctl.notReady = "is sealed" },
		"gate refused":   func(f *fx) { f.lock.err = errBoom },
	}
	for _, n := range []string{NameRequest, NameAttempt, NameAside, NameAsidePartial, NameCommit} {
		cases[n+" present"] = func(f *fx) {
			if err := f.files.StateDir.Write(n, []byte("x")); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFx(t)
			set(f)
			before := f.calls.list()
			err := f.run(context.Background())
			assertSentence(t, err)
			for _, c := range f.calls.list()[len(before):] {
				if c != "acquire" {
					t.Errorf("validate refusal went on to %q", c)
				}
			}
			if _, ok := f.settings.kv[KeyAttemptBootID]; ok {
				t.Error("the attempt bound was written")
			}
			if len(f.repo.handed) != 0 {
				t.Error("an entry was read")
			}
			f.assertLetGo()
		})
	}
	// The gate refusal is the only one that reached the gate.
	f := newFx(t)
	f.ctl.notReady = "is sealed"
	_ = f.run(context.Background())
	if f.calls.has("acquire") {
		t.Error("a store that is not ready reached the gate")
	}
	if !strings.Contains(f.rec.Text(), "step=validate") {
		t.Errorf("migrate_aborted does not name the step:\n%s", f.rec.Text())
	}
}

// TC-1132-17: the swap's calls run in order: quiesce, rebase, request
// written and fsynced (file, then directory), stop, start. The write-back
// starts only when the record says moved for the store's current run.
func TestMigrate_SwapOrder(t *testing.T) {
	f := newFx(t)
	if err := f.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := f.calls.list()
	want := []string{"quiesce", "rebase", "write_file " + NameRequest, "fsync " + NameRequest, "fsync .", "stop", "start"}
	at := -1
	for _, w := range want {
		i := indexAfter(c, w, at)
		if i < 0 {
			t.Fatalf("%q not found in order after %d: %v", w, at, c)
		}
		at = i
	}
	if first := indexAfter(c, "write apps/"+appA+"/db-pass", -1); first < at {
		t.Fatalf("write-back began before the swap: %v", c)
	}
}

// TC-1132-17 (record check): a record that is restored, failed or
// superseded, from an older run, or unreadable, means no write-back and the
// failure path.
func TestMigrate_SwapRecordCheck(t *testing.T) {
	for name, set := range map[string]func(*fx){
		"restored":   func(f *fx) { f.records.setMigrate(outcomeRestored, f.unit.InvocationID) },
		"failed":     func(f *fx) { f.records.setMigrate("failed", f.unit.InvocationID) },
		"superseded": func(f *fx) { f.records.setMigrate("superseded", f.unit.InvocationID) },
		"stale run":  func(f *fx) { f.records.setMigrate(outcomeMoved, runBefore) },
		"unreadable": func(f *fx) { f.records.migrateEr = errBoom },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFx(t)
			f.ctl.onStart = func() {
				f.runs++
				f.unit.InvocationID = fmt.Sprintf("%032x", 0xabc0+f.runs)
				set(f)
			}
			err := f.run(context.Background())
			assertSentence(t, err)
			if f.repo.writes != 0 {
				t.Fatalf("%d entries written back", f.repo.writes)
			}
			if f.present(NameCommit) || f.present(NameRequest) {
				t.Error("commit or request left after the failure")
			}
			f.assertLetGo()
		})
	}
}

// TC-1132-18: a failure before the swap disarms the request (F-1132-02,
// F-1132-04): after a Rebase failure, a failed request write, a failed Stop
// or a context cancelled after the request, no request is left, no Stop or
// Start runs after the failure, the marker is put back when it was moved,
// and the Hold and the gate are released. A Rebase failure never writes a
// request.
func TestMigrate_FailureBeforeSwapDisarms(t *testing.T) {
	t.Run("rebase fails", func(t *testing.T) {
		f := newFx(t)
		f.marker.rebaseErr = errBoom
		assertSentence(t, f.run(context.Background()))
		if f.calls.has("write_file " + NameRequest) {
			t.Fatal("a request was written after a failed rebase")
		}
		if f.calls.has("stop") || f.calls.has("start") || f.calls.has("restore_set_up "+prevBoot) {
			t.Fatalf("calls %v", f.calls.list())
		}
		f.assertLetGo()
	})
	t.Run("request write fails", func(t *testing.T) {
		f := newFx(t)
		f.files.writeErr = map[string]error{NameRequest: errBoom}
		assertSentence(t, f.run(context.Background()))
		f.assertDisarmed(false)
	})
	t.Run("stop fails", func(t *testing.T) {
		f := newFx(t)
		f.ctl.stopErr = []error{errBoom}
		assertSentence(t, f.run(context.Background()))
		f.assertDisarmed(true)
	})
	t.Run("cancelled after the request", func(t *testing.T) {
		f := newFx(t)
		ctx, cancel := context.WithCancel(context.Background())
		f.files.afterWrite = func(name string) {
			if name == NameRequest {
				cancel()
			}
		}
		assertSentence(t, f.run(ctx))
		f.assertDisarmed(false)
	})
	t.Run("request removal fails: the Hold stays on until the fact", func(t *testing.T) {
		f := newFx(t)
		f.ctl.stopErr = []error{errBoom}
		f.files.removeErr = map[string]error{NameRequest: errBoom}
		assertSentence(t, f.run(context.Background()))
		if on, stuck := f.hold.Held(); !on || !stuck {
			t.Fatalf("Hold on %v stuck %v; want stuck on", on, stuck)
		}
		f.hold.Observe(context.Background(), osoutcome.Record{Outcome: "failed"})
		if on, _ := f.hold.Held(); !on {
			t.Fatal("the Hold was released while the request is still there")
		}
		if err := f.files.StateDir.Remove(NameRequest); err != nil {
			t.Fatal(err)
		}
		f.hold.Observe(context.Background(), osoutcome.Record{Outcome: "failed"})
		if on, _ := f.hold.Held(); on {
			t.Fatal("the Hold was not released once no request or aside.tar was left")
		}
	})
}

// TC-1132-18 (the store left stopped): a start that failed before the root
// step set anything aside leaves the request disarmed, and the abort starts
// the store, which is not active, and waits for it.
func TestMigrate_StartFailsBeforeMoveAside(t *testing.T) {
	f := newFx(t)
	f.ctl.startErr = []error{errBoom}
	f.unit.ActiveState = "failed"
	assertSentence(t, f.run(context.Background()))
	if f.present(NameRequest) || f.ctl.startCount != 2 || !f.calls.has("wait_ready") {
		t.Fatalf("request %v, starts %d, calls %v", f.present(NameRequest), f.ctl.startCount, f.calls.list())
	}
	f.assertLetGo()
}

// StateDir: an empty path is refused, a missing file is absent and removing
// it is success, and a directory that cannot be read is an error, never
// absent.
func TestStateDir(t *testing.T) {
	if _, err := NewStateDir("", nil); err == nil {
		t.Error("an empty directory was accepted")
	}
	dir := t.TempDir()
	d, err := NewStateDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := d.Present(NameRequest); ok || err != nil {
		t.Fatalf("Present on a missing file = (%v, %v)", ok, err)
	}
	if err := d.Remove(NameRequest); err != nil {
		t.Fatalf("Remove of a missing file: %v", err)
	}
	if err := d.Write(NameRequest, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, NameRequest)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("request mode %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	notDir, _ := NewStateDir(filepath.Join(dir, NameRequest), nil)
	if _, err := notDir.Present("x"); err == nil {
		t.Error("an unreadable directory read as absent")
	}
	if err := notDir.Write("x", nil); err == nil {
		t.Error("a write into a file succeeded")
	}
	if err := notDir.Remove("x"); err == nil {
		t.Error("a remove under a file succeeded")
	}
	failSync, _ := NewStateDir(dir, func(*os.File) error { return errBoom })
	if err := failSync.Write(NameCommit, []byte("x")); err == nil {
		t.Error("a write whose sync failed succeeded")
	}
	if err := failSync.Remove(NameCommit); err == nil {
		t.Error("a remove whose directory sync failed succeeded")
	}
}

// assertDisarmed checks TC-1132-18's outcome; stopped says the failure was
// the Stop itself.
func (f *fx) assertDisarmed(stopped bool) {
	f.t.Helper()
	if f.present(NameRequest) {
		f.t.Fatal("the request is still armed")
	}
	if !f.calls.has("restore_set_up " + prevBoot) {
		f.t.Errorf("the marker was not put back: %v", f.calls.list())
	}
	if f.calls.has("start") || (!stopped && f.calls.has("stop")) {
		f.t.Errorf("a stop or start ran after the failure: %v", f.calls.list())
	}
	f.assertLetGo()
}

// TC-1132-19 (failure after the swap): a read-back that differs, a CAS
// mismatch and a write error each leave no commit; the store is stopped and
// started, its root step puts the old tree back, the job checks that
// aside.tar is gone and the record says restored, then fails with a
// sentence and lets go of everything. The old values are live again.
func TestMigrate_FailureAfterSwapPutsBack(t *testing.T) {
	for name, set := range map[string]func(*fx){
		"read-back differs": func(f *fx) { f.repo.corrupt = true },
		"cas mismatch": func(f *fx) {
			f.ctl.onStart = func() {
				f.rootStep()
				if f.records.migrate.Outcome == outcomeMoved {
					f.repo.tree["apps/"+appA+"/db-pass"] = []byte("already")
				}
			}
		},
		"write error": func(f *fx) {
			f.files.afterWrite = func(name string) {
				if name == NameRequest {
					f.repo.writeEr = &secretstore.Error{Op: "write", Kind: secretstore.ErrUnreachable}
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFx(t)
			set(f)
			assertSentence(t, f.run(context.Background()))
			if f.present(NameCommit) || f.present(NameAside) {
				t.Fatal("commit or aside.tar left")
			}
			if f.records.migrate.Outcome != outcomeRestored {
				t.Fatalf("record %q, want restored", f.records.migrate.Outcome)
			}
			if f.ctl.stopCount != 2 {
				t.Errorf("%d stops, want the swap's and the put-back's", f.ctl.stopCount)
			}
			for ref, want := range oldTree() {
				if got, _ := f.repo.value(ref); string(got) != string(want) {
					t.Errorf("%s = %q after the put-back", ref, got)
				}
			}
			f.assertLetGo()
		})
	}
	t.Run("put-back cannot be confirmed: the Hold stays on until the fact", func(t *testing.T) {
		f := newFx(t)
		f.repo.corrupt = true
		f.ctl.stopErr = []error{nil, errBoom}
		assertSentence(t, f.run(context.Background()))
		if on, stuck := f.hold.Held(); !on || !stuck {
			t.Fatalf("Hold on %v stuck %v; want stuck on", on, stuck)
		}
		if f.lock.holder != "" || f.ctl.quiesced != f.ctl.released || !f.repo.allDestroyed() {
			t.Error("the gate, the quiesce or a value was kept")
		}
		if got := f.rec.Matching(slog.LevelError, "stopped before its commit"); len(got) != 1 {
			t.Fatal("no migrate_aborted record")
		} else if v, _ := logkittest.Attr(got[0], "hold_stays"); v != "true" {
			t.Errorf("hold_stays = %q", v)
		}
		// A later store start (a backup, a leaf restart) puts the tree back.
		f.rootStep()
		f.hold.Observe(context.Background(), f.records.migrate)
		if on, _ := f.hold.Held(); on {
			t.Fatal("the restored fact did not release the Hold")
		}
	})
}

// TC-1132-23 (on the migrated store): the reference check, run once the
// migration ends, checks every recorded reference and finds none missing.
func TestMigrate_ReferenceCheckOnMigratedStore(t *testing.T) {
	f := newFx(t)
	if err := f.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	wf, err := appsecret.ReferenceCheckWorkflow(appsecret.ReferenceCheckDeps{
		Refs:    refList{{AppID: appA, Name: "db-pass"}, {AppID: appB, Name: "smtp-pass"}},
		Secrets: repoChecker{f.repo}, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := wf.Steps[0].Do(&jobs.StepCtx{Ctx: context.Background(), JobID: "check", Log: func(string, string) {}})
	if err != nil {
		t.Fatal(err)
	}
	var res struct{ Checked, Missing int }
	if err := json.Unmarshal(out, &res); err != nil || res.Checked != 2 || res.Missing != 0 {
		t.Fatalf("result %s (%v), want 2 checked and 0 missing", out, err)
	}
}

type refList []appsecret.SecretRef

func (r refList) ListSecretRefs(context.Context) ([]appsecret.SecretRef, error) { return r, nil }

// repoChecker answers Exists from the fake store's live tree.
type repoChecker struct{ r *fakeRepo }

func (c repoChecker) Exists(_ context.Context, _ secrets.Actor, ref secrets.Ref) (bool, error) {
	_, ok := c.r.value(ref.String())
	return ok, nil
}

func indexAfter(list []string, s string, after int) int {
	for i := after + 1; i < len(list); i++ {
		if list[i] == s {
			return i
		}
	}
	return -1
}

// New refuses a nil collaborator.
func TestNew_RefusesNil(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("empty Deps accepted")
	}
}
