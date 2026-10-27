package appsecret

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secrets"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
)

// fakeRefs is the reference table: RecordSecretRef keeps each reference once
// (the table's primary key), and ListSecretRefs lists them in record order.
type fakeRefs struct {
	mu      sync.Mutex
	refs    []SecretRef
	err     error // RecordSecretRef's answer
	listErr error
}

func (f *fakeRefs) RecordSecretRef(_ context.Context, appID, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	r := SecretRef{AppID: appID, Name: name}
	for _, have := range f.refs {
		if have == r {
			return nil
		}
	}
	f.refs = append(f.refs, r)
	return nil
}

func (f *fakeRefs) ListSecretRefs(context.Context) ([]SecretRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]SecretRef(nil), f.refs...), f.listErr
}

func (f *fakeRefs) list() []SecretRef {
	r, _ := f.ListSecretRefs(context.Background())
	return r
}

// fakeExists answers Exists from a fakeSecrets' entries, or with err, and
// counts its calls and the actors it saw.
type fakeExists struct {
	svc    *fakeSecrets
	err    error
	calls  int
	actors []secrets.Actor
}

func (f *fakeExists) Exists(_ context.Context, a secrets.Actor, r secrets.Ref) (bool, error) {
	f.calls++
	f.actors = append(f.actors, a)
	if f.err != nil {
		return false, f.err
	}
	f.svc.mu.Lock()
	defer f.svc.mu.Unlock()
	_, ok := f.svc.entries[r.String()]
	return ok, nil
}

const otherApp = "01K5R6P8Q9ZJ7V2XW4YB3D5EFH"

// checkRig is the check's step over fake references and a fake store.
type checkRig struct {
	refs   *fakeRefs
	exists *fakeExists
	rec    *logkittest.Recorder
	wf     jobs.Workflow
	lines  []string
}

func newCheckRig(t *testing.T, refs *fakeRefs, svc *fakeSecrets) *checkRig {
	t.Helper()
	log, rec := logkittest.New()
	ex := &fakeExists{svc: svc}
	wf, err := ReferenceCheckWorkflow(ReferenceCheckDeps{Refs: refs, Secrets: ex, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	return &checkRig{refs: refs, exists: ex, rec: rec, wf: wf}
}

func (c *checkRig) run() (json.RawMessage, error) {
	sc := &jobs.StepCtx{Ctx: context.Background(), JobID: "job-check", Log: func(level, msg string) {
		c.lines = append(c.lines, level+": "+msg)
	}}
	return c.wf.Steps[0].Do(sc)
}

func refsOf(pairs ...string) *fakeRefs {
	f := &fakeRefs{}
	for i := 0; i < len(pairs); i += 2 {
		f.refs = append(f.refs, SecretRef{AppID: pairs[i], Name: pairs[i+1]})
	}
	return f
}

// TC-800-17: the check's verdicts, one row each. Rows written against the
// pre-revision plan (a Ready dependency, compose scanning) are replaced as
// the approved plan has them: the check reads recorded references, and has
// no readiness input (F-800-03).
func TestReferenceCheck_Verdicts(t *testing.T) {
	a, b := "apps/"+appID+"/db-pass", "apps/"+otherApp+"/token"
	t.Run("no references", func(t *testing.T) {
		c := newCheckRig(t, &fakeRefs{}, newFakeSecrets(nil))
		got, err := c.run()
		if err != nil || string(got) != `{"checked":0,"missing":0}` {
			t.Fatalf("= (%s, %v)", got, err)
		}
	})
	t.Run("all present", func(t *testing.T) {
		c := newCheckRig(t, refsOf(appID, "db-pass", otherApp, "token"), newFakeSecrets(map[string]string{a: "x", b: "y"}))
		got, err := c.run()
		if err != nil || string(got) != `{"checked":2,"missing":0}` {
			t.Fatalf("= (%s, %v)", got, err)
		}
		if n := len(c.rec.Matching(slog.LevelInfo, "secret store reference check passed")); n != 1 {
			t.Errorf("%d INFO record(s), want 1", n)
		}
		for _, act := range c.exists.actors {
			if act != secrets.CheckActor() {
				t.Errorf("Exists asked as %+v, want the check actor", act)
			}
		}
	})
	t.Run("one missing", func(t *testing.T) {
		c := newCheckRig(t, refsOf(appID, "db-pass", otherApp, "token"), newFakeSecrets(map[string]string{b: "y"}))
		_, err := c.run()
		if err == nil || !strings.Contains(err.Error(), a) || strings.Contains(err.Error(), b) {
			t.Fatalf("err = %v, want a sentence naming %s alone", err, a)
		}
		assertCheckSentence(t, err.Error())
		recs := c.rec.Matching(slog.LevelError, "secret store entry missing for a recorded reference")
		if len(recs) != 1 {
			t.Fatalf("%d dangling ERROR record(s), want 1", len(recs))
		}
		for k, want := range map[string]string{"event": "appsecret.dangling_ref", "app_id": appID, "ref": a, "job_id": "job-check"} {
			if got, _ := logkittest.Attr(recs[0], k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
		if !containsLine(c.lines, "missing from the secret store: "+a) {
			t.Errorf("job lines %v lack the missing reference", c.lines)
		}
	})
	t.Run("missing in two apps", func(t *testing.T) {
		c := newCheckRig(t, refsOf(appID, "db-pass", otherApp, "token"), newFakeSecrets(nil))
		_, err := c.run()
		if err == nil || !strings.Contains(err.Error(), a) || !strings.Contains(err.Error(), b) || !strings.Contains(err.Error(), "2 secrets") {
			t.Fatalf("err = %v, want both named", err)
		}
		if n := len(c.rec.Matching(slog.LevelError, "secret store entry missing")); n != 2 {
			t.Errorf("%d dangling ERROR record(s), want 2", n)
		}
	})
	t.Run("a recorded row that does not parse", func(t *testing.T) {
		c := newCheckRig(t, refsOf(appID, "Not_A_Label"), newFakeSecrets(nil))
		_, err := c.run()
		if !errors.Is(err, errReferencesUnchecked) || c.exists.calls != 0 {
			t.Fatalf("err = %v with %d Exists call(s), want could-not-check and none", err, c.exists.calls)
		}
	})
	t.Run("a store error is never counted present", func(t *testing.T) {
		c := newCheckRig(t, refsOf(appID, "db-pass"), newFakeSecrets(map[string]string{a: "x"}))
		c.exists.err = &secretstore.Error{Op: "versions", Kind: secretstore.ErrUnreachable, StoreMessages: []string{storeText}}
		got, err := c.run()
		if !errors.Is(err, errReferencesUnchecked) || got != nil {
			t.Fatalf("= (%s, %v), want could-not-check", got, err)
		}
		assertCheckSentence(t, err.Error())
		if n := len(c.rec.Matching(slog.LevelError, "secret store reference check could not finish")); n != 1 {
			t.Errorf("%d could-not-finish ERROR record(s), want 1", n)
		}
		if strings.Contains(err.Error(), storeText) {
			t.Error("the store's own words reached the sentence")
		}
	})
	t.Run("the references cannot be listed", func(t *testing.T) {
		refs := refsOf(appID, "db-pass")
		refs.listErr = errors.New("database is locked")
		c := newCheckRig(t, refs, newFakeSecrets(nil))
		if _, err := c.run(); !errors.Is(err, errReferencesUnchecked) || c.exists.calls != 0 {
			t.Fatalf("err = %v with %d Exists call(s)", err, c.exists.calls)
		}
	})
	t.Run("a reference recorded twice is asked about once", func(t *testing.T) {
		refs := &fakeRefs{}
		for range 3 {
			_ = refs.RecordSecretRef(context.Background(), appID, "db-pass")
		}
		c := newCheckRig(t, refs, newFakeSecrets(map[string]string{a: "x"}))
		if _, err := c.run(); err != nil || c.exists.calls != 1 {
			t.Fatalf("err = %v with %d Exists call(s), want one", err, c.exists.calls)
		}
	})
}

// TC-800-18 (F-800-01): an app whose entry the cluster never created, (a)
// installed and never deployed, (b) an app that predates the store on an
// upgraded cluster, is never reported; an app whose entry was created
// through StoreSource and is now gone is. The references come from
// StoreSource's own records, as in production.
func TestReferenceCheck_NoFalseDanglingReport(t *testing.T) {
	const neverDeployed, preStore = "01K5R6P8Q9ZJ7V2XW4YB3D5EFJ", "01K5R6P8Q9ZJ7V2XW4YB3D5EFK"
	h := newHarness(t, testSeed(t), nil)
	h.nodes.nodes[neverDeployed] = node
	h.nodes.nodes[preStore] = node
	if _, _, err := h.src.ResolveCompose(jobCtx(), appID, tokened); err != nil {
		t.Fatal(err)
	}
	c := newCheckRig(t, h.refs, h.svc)
	if _, err := c.run(); err != nil {
		t.Fatalf("with every created entry present: %v", err)
	}
	if n := len(c.rec.Matching(slog.LevelError, "")); n != 0 {
		t.Errorf("%d ERROR record(s) for apps never created in the store", n)
	}
	// The created entry is lost, as a put-back of an older copy loses it.
	lost := "apps/" + appID + "/db-password"
	h.svc.mu.Lock()
	delete(h.svc.entries, lost)
	h.svc.mu.Unlock()
	_, err := c.run()
	if err == nil || !strings.Contains(err.Error(), lost) || strings.Contains(err.Error(), neverDeployed) || strings.Contains(err.Error(), preStore) {
		t.Fatalf("err = %v, want only %s named", err, lost)
	}
}

// TC-800-19: the constructor refuses a nil Refs, Secrets or Log (the
// revised plan has no Ready input, F-800-03).
func TestReferenceCheckWorkflow_RefusesNil(t *testing.T) {
	log, _ := logkittest.New()
	full := ReferenceCheckDeps{Refs: &fakeRefs{}, Secrets: &fakeExists{}, Log: log}
	for name, clear := range map[string]func(*ReferenceCheckDeps){
		"Refs":    func(d *ReferenceCheckDeps) { d.Refs = nil },
		"Secrets": func(d *ReferenceCheckDeps) { d.Secrets = nil },
		"Log":     func(d *ReferenceCheckDeps) { d.Log = nil },
	} {
		d := full
		clear(&d)
		if wf, err := ReferenceCheckWorkflow(d); err == nil || wf.Kind != "" {
			t.Errorf("nil %s: %+v, %v; want an error and no workflow", name, wf.Kind, err)
		}
	}
	wf, err := ReferenceCheckWorkflow(full)
	if err != nil || wf.Kind != ReferenceCheckKind || len(wf.Steps) != 1 || wf.Steps[0].Name != "check_references" {
		t.Fatalf("workflow = %+v, %v", wf, err)
	}
}

// StoreSource records each entry once it is confirmed: after a read hit and
// after a create whose read-back matched; never for a refused resolve; and a
// record that fails refuses the resolve with the zero value
// (geekdojo/geekdojo-brain#800, F-800-01).
func TestStoreSource_RecordsConfirmedEntries(t *testing.T) {
	seed := testSeed(t)
	ref := "apps/" + appID + "/db-password"
	want := []SecretRef{{AppID: appID, Name: "db-password"}}
	t.Run("read hit", func(t *testing.T) {
		h := newHarness(t, seed, map[string]string{ref: sentinelStored})
		if _, _, err := h.src.ResolveCompose(jobCtx(), appID, tokened); err != nil {
			t.Fatal(err)
		}
		if got := h.refs.list(); !reflect.DeepEqual(got, want) {
			t.Fatalf("recorded %v, want %v", got, want)
		}
	})
	t.Run("created", func(t *testing.T) {
		h := newHarness(t, seed, nil)
		if _, _, err := h.src.ResolveCompose(jobCtx(), appID, tokened); err != nil {
			t.Fatal(err)
		}
		if got := h.refs.list(); !reflect.DeepEqual(got, want) {
			t.Fatalf("recorded %v, want %v", got, want)
		}
		if ops := h.svc.ops(); len(ops) != 3 || !strings.HasPrefix(ops[1], "create") {
			t.Fatalf("calls %v, want read, create, read-back before the record", ops)
		}
	})
	t.Run("refused", func(t *testing.T) {
		h := newHarness(t, seed, nil)
		h.svc.hook = func(_ int, c fakeCall) ([]byte, error, bool) {
			return nil, storeErr(c.op, c.ref, 0, secretstore.ErrUnreachable, nil), true
		}
		if _, _, err := h.src.ResolveCompose(jobCtx(), appID, tokened); err == nil {
			t.Fatal("a store failure resolved")
		}
		if got := h.refs.list(); len(got) != 0 {
			t.Fatalf("a refused resolve recorded %v", got)
		}
	})
	t.Run("the record fails", func(t *testing.T) {
		h := newHarness(t, seed, map[string]string{ref: sentinelStored})
		h.refs.err = errors.New("database is locked")
		got, _, err := h.src.ResolveCompose(jobCtx(), appID, tokened)
		if err == nil || len(got.Reveal()) != 0 {
			t.Fatalf("= (%d bytes, %v), want the zero value and an error", len(got.Reveal()), err)
		}
		if n := len(h.rec.Matching(slog.LevelWarn, "secret refused")); n != 1 {
			t.Errorf("%d refusal WARN(s), want 1", n)
		}
		assertNoLeak(t, h.rec, []error{err}, sentinelStored)
	})
}

func assertCheckSentence(t *testing.T, s string) {
	t.Helper()
	if !strings.HasPrefix(s, "The secret store") || !strings.HasSuffix(s, ".") {
		t.Errorf("%q is not a sentence about the secret store", s)
	}
}

func containsLine(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}
