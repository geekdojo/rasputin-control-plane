package sealrotate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore/storestate"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/geekdojo/rasputin-control-plane/secret"
)

// counting is a stand-in for every collaborator outside openbao that counts
// each call, so a test can show validate refused before touching any.
type counting struct{ n int }

func (c *counting) Health(context.Context) (secretstore.Health, error) {
	c.n++
	return secretstore.Health{}, errors.New("off")
}
func (c *counting) CertLogin(context.Context, string) (secret.Value, error) {
	c.n++
	return secret.Value{}, errors.New("off")
}
func (c *counting) RotateRoot(context.Context, secret.Value) error { c.n++; return errors.New("off") }
func (c *counting) State() (Tree, error)                           { c.n++; return Tree{}, errors.New("off") }
func (c *counting) WriteRotationKey(KeyID, secret.Value) error     { c.n++; return errors.New("off") }
func (c *counting) WriteSealKey(secret.Value) error                { c.n++; return errors.New("off") }
func (c *counting) ReadRotationKey(KeyID) (secret.Value, error) {
	c.n++
	return secret.Value{}, errors.New("off")
}
func (c *counting) WriteFragment(Fragment) error { c.n++; return errors.New("off") }
func (c *counting) RemoveRotation() error        { c.n++; return errors.New("off") }
func (c *counting) TryAcquire(string) error      { c.n++; return errors.New("off") }
func (c *counting) Release(string)               { c.n++ }
func (c *counting) RotationHolder() string       { c.n++; return "" }
func (c *counting) Active() (string, bool)       { c.n++; return "", false }
func (c *counting) Read([]byte) (int, error)     { c.n++; return 0, errors.New("off") }

// TC-830-04: every refusal changes nothing, fails the job at its step with a
// sentence naming the cause, logs one WARN with the record's fields, frees
// the gate and the quiesce, and yields the job-failed warn alert. KeyID and
// Rand failures fail at stage before any write (F-830-07).
func TestRotator_Refusals(t *testing.T) {
	denied := &secretstore.Error{Op: "login", Status: 403, Kind: secretstore.ErrDenied}
	unreachable := &secretstore.Error{Op: "login", Kind: secretstore.ErrUnreachable}
	for _, tc := range []struct {
		name string
		step string
		want jobError
		set  func(g *rig, s *seal)
	}{
		{"health sealed", "validate", errStoreNotReady, func(g *rig, _ *seal) { g.store.up = false }},
		{"health unreachable", "validate", errStoreNotReady, func(g *rig, _ *seal) {
			g.store.err = &secretstore.Error{Op: "health", Kind: secretstore.ErrUnreachable}
		}},
		{"health uninitialised", "validate", errStoreNotReady, func(g *rig, _ *seal) {
			g.store.err = &secretstore.Error{Op: "health", Status: 501, Kind: secretstore.ErrUninitialised}
		}},
		{"a backup holds the gate", "validate", errBackupHolds, nil},
		{"a restore is active", "validate", errRestoreActive, func(g *rig, _ *seal) { g.restores.active = true }},
		{"an unrecognised fragment", "validate", errSealUnrecognised, func(_ *rig, s *seal) {
			s.write(FragmentName, []byte("seal \"transit\" {\n}\n"))
		}},
		{"a key that is not 32 bytes", "validate", errSealUnrecognised, func(_ *rig, s *seal) { s.write(SealKeyName, keyA[:16]) }},
		{"login denied", "validate", errLoginDenied, func(g *rig, _ *seal) { g.rotate.loginErr = denied }},
		{"login unreachable", "validate", errLoginUnreachable, func(g *rig, _ *seal) { g.rotate.loginErr = unreachable }},
		{"the key-id source fails", "stage", errNoKeyID, func(g *rig, _ *seal) { g.keyIDErr = errors.New("uuid unreadable") }},
		{"Rand returns a short read", "stage", errNoKey, func(g *rig, _ *seal) { g.rand.short = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSeal(t)
			s.clean()
			g := newRig(t, s)
			if tc.set != nil {
				tc.set(g, s)
			}
			g.build(t)
			if tc.name == "a backup holds the gate" {
				if err := g.gate.Acquire(t.Context(), "job-backup"); err != nil {
					t.Fatal(err)
				}
			}
			before := s.hash()
			r := g.run(t)
			if s.hash() != before {
				t.Fatal("a refusal changed the seal tree")
			}
			if r.job.Status != jobs.StatusFailed || r.failedStep() != tc.step {
				t.Fatalf("job %s at %q, want failed at %q", r.job.Status, r.failedStep(), tc.step)
			}
			if r.job.Error != string(tc.want) || !isSentence(r.job.Error) {
				t.Fatalf("job error = %q, want %q", r.job.Error, tc.want)
			}
			for _, c := range g.rec.list() {
				if strings.HasPrefix(c, "write") || strings.HasPrefix(c, "fragment") || c == "restart" || c == "remove rotation" {
					t.Fatalf("a refusal made the call %q", c)
				}
			}
			warns := g.log.AtLevel(slog.LevelWarn)
			if len(warns) != 1 {
				t.Fatalf("%d WARN records, want 1:\n%s", len(warns), g.log.Text())
			}
			if attr(t, warns[0], "component") != "secretstore" ||
				attr(t, warns[0], "event") != "secretstore.seal_rotate."+tc.step ||
				attr(t, warns[0], "job_id") != r.job.ID {
				t.Errorf("WARN record fields: %s", g.log.Text())
			}
			if len(g.log.AtLevel(slog.LevelError)) != 0 {
				t.Errorf("a refusal logged an ERROR")
			}
			if tc.name == "a backup holds the gate" {
				g.gate.Release("job-backup")
			}
			if err := g.gate.TryAcquire("job-after"); err != nil {
				t.Errorf("the gate is still held after the refusal: %v", err)
			}
			if g.quiesce.holds != g.quiesce.releases {
				t.Errorf("quiesce holds %d, releases %d", g.quiesce.holds, g.quiesce.releases)
			}
			a, ok := jobFailedAlert(t, r.js, r.job.ID)
			if !ok || a.Severity != proto.AlertWarn || a.Detail != string(tc.want) {
				t.Errorf("job-failed alert = %+v (found %v)", a, ok)
			}
		})
	}
}

// TC-830-04, F-830-04: outside openbao the run is a job that fails at
// validate, and no stand-in collaborator is called.
func TestRotator_RefusesOutsideOpenBao(t *testing.T) {
	c := &counting{}
	log, recd := logkittest.New()
	rot, err := NewRotator(Config{Enabled: false, UnsealWait: time.Second}, Deps{
		Store: c, Rotate: c, Files: c, Gate: c, Restores: c, Rand: c,
		Restart:    func(context.Context) error { c.n++; return nil },
		Quiesce:    func(string, storestate.QuiesceReason) func() { c.n++; return func() {} },
		KeyID:      func() (KeyID, error) { c.n++; return "", nil },
		Log:        log,
		JobRunning: func(context.Context, string) (bool, error) { c.n++; return false, nil },
		Now:        func() time.Time { c.n++; return time.Time{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	g := &rig{rot: rot}
	r := g.run(t)
	if r.job.Status != jobs.StatusFailed || r.failedStep() != "validate" || r.job.Error != string(errNotOpenBao) {
		t.Fatalf("job %s at %q: %q", r.job.Status, r.failedStep(), r.job.Error)
	}
	if c.n != 0 {
		t.Errorf("%d stand-in calls, want 0", c.n)
	}
	if len(recd.AtLevel(slog.LevelWarn)) != 1 {
		t.Errorf("WARN records:\n%s", recd.Text())
	}
	if _, ok := jobFailedAlert(t, r.js, r.job.ID); !ok {
		t.Error("no job-failed alert")
	}
}

// TC-830-05: a fresh run makes its calls in the plan's order, re-wraps after
// the first 200 and before any Verify write, succeeds as "rotated" with one
// INFO naming both ids, and releases everything in OnTerminal.
func TestRotator_FreshRunOrder(t *testing.T) {
	s := newSeal(t)
	s.clean()
	g := newRig(t, s).build(t)
	r := g.run(t)
	if r.job.Status != jobs.StatusSucceeded {
		t.Fatalf("job %s: %s", r.job.Status, r.job.Error)
	}
	B := string(idB)
	want := []string{
		"health", "login", "key id",
		"write rotation/" + B, "fragment staged",
		"restart", "health",
		"rotate_root",
		"fragment verify", "restart", "health",
		"read rotation/" + B, "write seal-key", "fragment clean", "restart", "health",
		"remove rotation",
	}
	if got := g.rec.list(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("calls =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !bytes.Equal(s.read(SealKeyName), keyB) {
		t.Error("seal-key is not the new key")
	}
	if tree := s.state(); tree.Fragment != (Fragment{Shape: Clean, Current: idB}) || tree.Resume != Fresh {
		t.Errorf("tree after = %+v, want Clean B with rotation/ empty", tree)
	}
	if res := r.stepResult("settle"); !strings.Contains(res, `"outcome":"rotated"`) {
		t.Errorf("settle result = %s", res)
	}
	infos := g.log.Matching(slog.LevelInfo, "seal key rotated")
	if len(infos) != 1 || attr(t, infos[0], "key_id") != B || attr(t, infos[0], "previous_key_id") != string(idA) {
		t.Fatalf("rotated INFO records:\n%s", g.log.Text())
	}
	for _, tok := range g.rotate.tokens {
		if tok.Len() != 0 {
			t.Error("the login token was not destroyed in OnTerminal")
		}
	}
	if g.gate.RotationHolder() != "" || g.quiesce.holds != 1 || g.quiesce.releases != 1 ||
		g.quiesce.reasons[0] != storestate.QuiesceSealRotation {
		t.Errorf("gate holder %q, quiesce %+v", g.gate.RotationHolder(), g.quiesce)
	}
}

// TC-830-06: the failure-action table. Rollback happens only on a fresh run
// before any re-wrap; a re-wrap error never restarts the store.
func TestRotator_Failures(t *testing.T) {
	injected := errors.New("injected: disk full at /var/lib/rasputin/openbao-seal")
	for _, tc := range []struct {
		name  string
		set   func(g *rig)
		check func(t *testing.T, g *rig, s *seal, r result, before string)
	}{
		{"(a) the rotation/B write fails", func(g *rig) {
			g.files.fail = failOn("write rotation/"+string(idB), injected)
		}, func(t *testing.T, g *rig, s *seal, r result, before string) {
			failedWith(t, r, "stage", errStageWrite)
			unchanged(t, s, before)
		}},
		{"(b) the staged fragment write fails", func(g *rig) {
			g.files.fail = failOn("fragment staged", injected)
		}, func(t *testing.T, g *rig, s *seal, r result, before string) {
			failedWith(t, r, "stage", errStageWrite)
			unchanged(t, s, before)
		}},
		{"(c) no 200 after staged", func(g *rig) {
			g.store.next = []bool{false, true}
		}, func(t *testing.T, g *rig, s *seal, r result, before string) {
			failedWith(t, r, "unseal_staged", errStagedRolledBack)
			if g.rec.count("rotate_root") != 0 {
				t.Error("a rollback re-wrapped")
			}
			if g.rec.count("restart") != 2 {
				t.Errorf("restarts = %d, want the staged one and the rollback's", g.rec.count("restart"))
			}
			unchanged(t, s, before)
		}},
		{"(d) re-wrap denied", func(g *rig) {
			g.rotate.rewrapErr = &secretstore.Error{Op: "rotate_root", Status: 403, Kind: secretstore.ErrDenied, StoreMessages: []string{"permission denied"}}
		}, rewrapHeld},
		{"(d) re-wrap unreachable", func(g *rig) {
			g.rotate.rewrapErr = &secretstore.Error{Op: "rotate_root", Kind: secretstore.ErrUnreachable, Err: errors.New("connection reset")}
		}, rewrapHeld},
		{"(d) re-wrap timeout", func(g *rig) {
			g.rotate.rewrapErr = &secretstore.Error{Op: "rotate_root", Kind: secretstore.ErrUnreachable, Err: context.DeadlineExceeded}
		}, rewrapHeld},
		{"(e) verify gets no 200 once", func(g *rig) {
			g.store.next = []bool{true, false}
		}, func(t *testing.T, g *rig, s *seal, r result, _ string) {
			if r.job.Status != jobs.StatusSucceeded {
				t.Fatalf("job %s: %s", r.job.Status, r.job.Error)
			}
			if g.rec.count("rotate_root") != 2 || g.rec.count("fragment staged") != 2 || g.rec.count("fragment verify") != 2 {
				t.Errorf("calls %v: want staged put back, a second re-wrap and a second verify", g.rec.list())
			}
			if tree := s.state(); tree.Fragment.Current != idB || tree.Fragment.Shape != Clean {
				t.Errorf("tree = %+v", tree)
			}
		}},
		{"(f) verify gets no 200 twice", func(g *rig) {
			g.store.next = []bool{true, false, true, false}
		}, func(t *testing.T, g *rig, s *seal, r result, _ string) {
			failedWith(t, r, "verify", errVerify)
			notClean(t, s)
		}},
		{"(g) the seal-key write fails in settle", func(g *rig) {
			g.files.fail = failOn("write seal-key", injected)
		}, func(t *testing.T, g *rig, s *seal, r result, _ string) {
			failedWith(t, r, "settle", errSettle)
			notClean(t, s)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSeal(t)
			s.clean()
			g := newRig(t, s)
			tc.set(g)
			g.build(t)
			before := s.hash()
			r := g.run(t)
			tc.check(t, g, s, r, before)
			// Every job message is a sentence with no store or file text,
			// which reaches only the log.
			if r.job.Error != "" {
				if !isSentence(r.job.Error) || strings.Contains(r.job.Error, "/") || strings.Contains(r.job.Error, "permission denied") {
					t.Errorf("job error = %q", r.job.Error)
				}
				if len(g.log.AtLevel(slog.LevelError)) != 1 {
					t.Errorf("ERROR records:\n%s", g.log.Text())
				}
			}
		})
	}
}

func failOn(call string, err error) func(string) error {
	return func(c string) error {
		if c == call {
			return err
		}
		return nil
	}
}

func failedWith(t *testing.T, r result, step string, want jobError) {
	t.Helper()
	if r.job.Status != jobs.StatusFailed || r.failedStep() != step || r.job.Error != string(want) {
		t.Fatalf("job %s at %q: %q; want failed at %q with %q", r.job.Status, r.failedStep(), r.job.Error, step, want)
	}
}

// unchanged asserts the tree is byte-identical and rotation/ empty.
func unchanged(t *testing.T, s *seal, before string) {
	t.Helper()
	if s.hash() != before {
		t.Error("the seal tree changed")
	}
	if names := s.rotationNames(); len(names) != 0 {
		t.Errorf("rotation/ = %v", names)
	}
}

func notClean(t *testing.T, s *seal) {
	t.Helper()
	if tree, err := s.files.State(); err == nil && tree.Fragment.Shape == Clean {
		t.Errorf("tree is Clean after the failure: %+v", tree)
	}
}

// rewrapHeld is TC-830-06 (d): Staged is kept byte for byte, no restart after
// the error, and the job fails at ERROR with the store's text in the log only.
func rewrapHeld(t *testing.T, g *rig, s *seal, r result, _ string) {
	t.Helper()
	failedWith(t, r, "rewrap", errRewrap)
	want, err := Fragment{Shape: Staged, Current: idB, Previous: idA}.render(s.paths)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.read(FragmentName), want) {
		t.Error("the staged fragment changed after the re-wrap error")
	}
	calls := g.rec.list()
	at := g.rec.index("rotate_root", 0)
	for _, c := range calls[at+1:] {
		if c == "restart" {
			t.Fatalf("a restart after the re-wrap error: %v", calls)
		}
	}
	errs := g.log.AtLevel(slog.LevelError)
	if len(errs) != 1 || attr(t, errs[0], "kind") == "" {
		t.Errorf("the ERROR record lacks the store error's fields:\n%s", g.log.Text())
	}
}

// TC-830-07: a run that finds an unfinished tree finishes it, mints nothing,
// and ends "resumed" with a sentence saying no new key was made.
func TestRotator_Resume(t *testing.T) {
	for _, tc := range []struct {
		name    string
		build   func(s *seal)
		storeUp bool
		check   func(t *testing.T, g *rig)
	}{
		{"staged, store at 200: re-wrap before any restart", staged, true, func(t *testing.T, g *rig) {
			rw, rs := g.rec.index("rotate_root", 0), g.rec.index("restart", 0)
			if rw < 0 || (rs >= 0 && rs < rw) {
				t.Errorf("calls %v: want rotate_root before any restart", g.rec.list())
			}
		}},
		{"staged, store not at 200: restart, then re-wrap", staged, false, func(t *testing.T, g *rig) {
			rs, rw := g.rec.index("restart", 0), g.rec.index("rotate_root", 0)
			if rs < 0 || rw < rs || g.rec.index("login", rs) < 0 {
				t.Errorf("calls %v: want restart, login, then rotate_root", g.rec.list())
			}
		}},
		{"verify: verify, then settle", func(s *seal) {
			s.clean().rot(idB, keyB)
			s.fragment(Fragment{Shape: Verify, Current: idB})
		}, true, func(t *testing.T, g *rig) {
			if g.rec.count("rotate_root") != 0 || g.rec.index("fragment verify", 0) > g.rec.index("write seal-key", 0) {
				t.Errorf("calls %v", g.rec.list())
			}
		}},
		{"clean with leftovers: removed", func(s *seal) { s.clean().rot(idB, keyB) }, true, func(t *testing.T, g *rig) {
			if want := []string{"health", "remove rotation"}; strings.Join(g.rec.list(), "|") != strings.Join(want, "|") {
				t.Errorf("calls %v, want %v", g.rec.list(), want)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSeal(t)
			tc.build(s)
			g := newRig(t, s)
			g.store.up = tc.storeUp
			g.build(t)
			r := g.run(t)
			if r.job.Status != jobs.StatusSucceeded {
				t.Fatalf("job %s: %s", r.job.Status, r.job.Error)
			}
			tc.check(t, g)
			if g.keyIDs != 0 || len(g.rand.filled) != 0 {
				t.Errorf("a resume minted: %d key ids, %d Rand reads", g.keyIDs, len(g.rand.filled))
			}
			if tree := s.state(); tree.Fragment.Shape != Clean || tree.Resume != Fresh {
				t.Errorf("tree after = %+v", tree)
			}
			if res := r.stepResult("settle"); !strings.Contains(res, `"outcome":"resumed"`) {
				t.Errorf("settle result = %s", res)
			}
			if len(g.log.Matching(slog.LevelInfo, "No new key was made; start the rotation again for a new key.")) != 1 {
				t.Errorf("no resumed sentence:\n%s", g.log.Text())
			}
		})
	}
}

func staged(s *seal) {
	s.clean().rot(idB, keyB)
	s.fragment(Fragment{Shape: Staged, Current: idB, Previous: idA})
}

// A resume whose restart or login fails stops with the tree as it was.
func TestRotator_ResumeFailures(t *testing.T) {
	t.Run("staged store never opens", func(t *testing.T) {
		s := newSeal(t)
		staged(s)
		g := newRig(t, s)
		g.store.up = false
		g.store.next = []bool{false}
		g.build(t)
		failedWith(t, g.run(t), "unseal_staged", errStagedResume)
		if tree := s.state(); tree.Fragment.Shape != Staged {
			t.Errorf("tree = %+v", tree)
		}
	})
	t.Run("staged login refused after the restart", func(t *testing.T) {
		s := newSeal(t)
		staged(s)
		g := newRig(t, s)
		g.store.up = false
		g.rotate.loginErr = &secretstore.Error{Op: "login", Status: 403, Kind: secretstore.ErrDenied}
		g.build(t)
		failedWith(t, g.run(t), "rewrap", errRewrapLogin)
	})
	t.Run("verify resume gets no 200", func(t *testing.T) {
		s := newSeal(t)
		s.clean().rot(idB, keyB)
		s.fragment(Fragment{Shape: Verify, Current: idB})
		g := newRig(t, s)
		g.store.next = []bool{false}
		g.build(t)
		failedWith(t, g.run(t), "verify", errVerify)
	})
	t.Run("clean-up cannot remove", func(t *testing.T) {
		s := newSeal(t)
		s.clean().rot(idB, keyB)
		g := newRig(t, s)
		g.files.fail = failOn("remove rotation", errors.New("busy"))
		g.build(t)
		failedWith(t, g.run(t), "settle", errSettle)
	})
	t.Run("rollback write fails", func(t *testing.T) {
		s := newSeal(t)
		s.clean()
		g := newRig(t, s)
		g.store.next = []bool{false}
		g.files.fail = func(c string) error {
			if c == "fragment clean" {
				return errors.New("read-only")
			}
			return nil
		}
		g.build(t)
		failedWith(t, g.run(t), "unseal_staged", errStagedRollbackFailed)
	})
}

// TC-830-15: no key byte, token or store text reaches a log, an error, a job
// event or a step result, on the happy path and every failure row; the Rand
// buffer and the read-back buffer are zero after their secret.New; every key
// handed to a write is destroyed once the write returns.
func TestRotator_NoSecretOnAnySurface(t *testing.T) {
	encodings := func(b []byte) []string {
		return []string{string(b), hexOf(b), b64(b), b64raw(b)}
	}
	rows := []func(g *rig){
		func(*rig) {},
		func(g *rig) { g.files.fail = failOn("write rotation/"+string(idB), errors.New("x")) },
		func(g *rig) { g.files.fail = failOn("fragment staged", errors.New("x")) },
		func(g *rig) { g.store.next = []bool{false, true} },
		func(g *rig) { g.rotate.rewrapErr = &secretstore.Error{Op: "rotate_root", Kind: secretstore.ErrDenied} },
		func(g *rig) { g.store.next = []bool{true, false} },
		func(g *rig) { g.store.next = []bool{true, false, true, false} },
		func(g *rig) { g.files.fail = failOn("write seal-key", errors.New("x")) },
	}
	for i, set := range rows {
		s := newSeal(t)
		s.clean()
		var readBufs [][]byte
		s.files.newBuf = func(n int) []byte { b := make([]byte, n); readBufs = append(readBufs, b); return b }
		g := newRig(t, s)
		set(g)
		g.build(t)
		r := g.run(t)
		var surfaces strings.Builder
		surfaces.WriteString(g.log.Text())
		surfaces.WriteString(r.job.Error)
		for _, e := range r.events {
			surfaces.Write(e.Data)
		}
		for _, st := range r.steps {
			surfaces.Write(st.Result)
			surfaces.WriteString(st.Error)
		}
		text := surfaces.String()
		for _, secretText := range append(append(encodings(keyA), encodings(keyB)...), g.rotate.token) {
			if strings.Contains(text, secretText) {
				t.Fatalf("row %d: a key or the token reached a surface", i)
			}
		}
		for _, buf := range append(g.rand.filled, readBufs...) {
			if !bytes.Equal(buf, make([]byte, len(buf))) {
				t.Fatalf("row %d: a key buffer was not zeroed after secret.New", i)
			}
		}
		for _, v := range g.files.values {
			if v.Len() != 0 {
				t.Fatalf("row %d: a seal key Value outlived its write", i)
			}
		}
	}
}

func TestNewRotator_RefusesNil(t *testing.T) {
	ok := func() Deps {
		c := &counting{}
		log, _ := logkittest.New()
		return Deps{
			Store: c, Rotate: c, Files: c, Gate: c, Restores: c, Rand: c,
			Restart:    func(context.Context) error { return nil },
			Quiesce:    func(string, storestate.QuiesceReason) func() { return func() {} },
			KeyID:      func() (KeyID, error) { return "", nil },
			Log:        log,
			JobRunning: func(context.Context, string) (bool, error) { return false, nil },
			Now:        time.Now,
		}
	}
	if _, err := NewRotator(Config{UnsealWait: time.Second}, ok()); err != nil {
		t.Fatalf("complete deps refused: %v", err)
	}
	for _, tc := range []struct {
		field string
		clear func(*Deps)
	}{
		{"Store", func(d *Deps) { d.Store = nil }},
		{"Rotate", func(d *Deps) { d.Rotate = nil }},
		{"Restart", func(d *Deps) { d.Restart = nil }},
		{"Files", func(d *Deps) { d.Files = nil }},
		{"Gate", func(d *Deps) { d.Gate = nil }},
		{"Quiesce", func(d *Deps) { d.Quiesce = nil }},
		{"Restores", func(d *Deps) { d.Restores = nil }},
		{"Rand", func(d *Deps) { d.Rand = nil }},
		{"KeyID", func(d *Deps) { d.KeyID = nil }},
		{"Log", func(d *Deps) { d.Log = nil }},
		{"JobRunning", func(d *Deps) { d.JobRunning = nil }},
		{"Now", func(d *Deps) { d.Now = nil }},
	} {
		d := ok()
		tc.clear(&d)
		_, err := NewRotator(Config{UnsealWait: time.Second}, d)
		if err == nil || !strings.Contains(err.Error(), "Deps."+tc.field) {
			t.Errorf("nil %s: err = %v", tc.field, err)
		}
	}
	if _, err := NewRotator(Config{}, ok()); err == nil {
		t.Error("a zero UnsealWait accepted")
	}
}

var _ io.Reader = (*fakeRand)(nil)

func hexOf(b []byte) string  { return hex.EncodeToString(b) }
func b64(b []byte) string    { return base64.StdEncoding.EncodeToString(b) }
func b64raw(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }
