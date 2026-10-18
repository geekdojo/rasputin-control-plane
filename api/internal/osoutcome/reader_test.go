package osoutcome

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// tickClock advances one second on every reading, so each job is newer than
// the one before it.
type tickClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTickClock() *tickClock {
	return &tickClock{now: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
}

func (c *tickClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(time.Second)
	return c.now
}

// units records StartUnit calls; onStart runs inside each one.
type units struct {
	mu      sync.Mutex
	calls   []string
	err     error
	onStart func(unit string)
}

func (u *units) start(_ context.Context, unit string) error {
	u.mu.Lock()
	u.calls = append(u.calls, unit)
	u.mu.Unlock()
	if u.onStart != nil {
		u.onStart(unit)
	}
	return u.err
}

func (u *units) got() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.calls)
}

type harness struct {
	dir    string
	srcs   []Source
	ledger *jobs.Store
	rec    *logkittest.Recorder
	units  *units
	clock  *tickClock
	bootID func() (string, error)
}

func openLedger(t *testing.T, path string) *jobs.Store {
	t.Helper()
	js, err := jobs.OpenStore(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.Close() })
	return js
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	return &harness{
		dir:    dir,
		srcs:   testSources(dir),
		ledger: openLedger(t, filepath.Join(dir, "jobs.db")),
		units:  &units{},
		clock:  newTickClock(),
		bootID: func() (string, error) { return testBoot2, nil },
	}
}

// reader builds a fresh Reader over the harness's ledger, as an api start does.
func (h *harness) reader(t *testing.T) *Reader {
	t.Helper()
	log, rec := logkittest.New()
	h.rec = rec
	r, err := New(Deps{Ledger: h.ledger, Log: log, Now: h.clock.Now, BootID: h.bootID, StartUnit: h.units.start}, h.srcs)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (h *harness) write(t *testing.T, src int, body string) {
	t.Helper()
	if err := os.WriteFile(h.srcs[src].Path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) jobs(t *testing.T, kind string) []*jobs.Job {
	t.Helper()
	js, err := h.ledger.ListAllJobsByKind(t.Context(), kind)
	if err != nil {
		t.Fatal(err)
	}
	return js
}

func spec(t *testing.T, j *jobs.Job) Spec {
	t.Helper()
	var s Spec
	if err := json.Unmarshal(j.Spec, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func alertsOf(t *testing.T, r *Reader) []proto.Alert {
	t.Helper()
	a, err := r.Alerts(t.Context(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func attr(rec slog.Record, k string) string {
	v, _ := logkittest.Attr(rec, k)
	return v
}

// TC-833-10: an absent record records nothing, alerts nothing, and logs one
// DEBUG line with source and path.
func TestReader_AbsentRecord(t *testing.T) {
	h := newHarness(t)
	r := h.reader(t)
	r.ReadAtStart(t.Context())
	for _, s := range h.srcs {
		if n := len(h.jobs(t, s.Kind)); n != 0 {
			t.Errorf("%s: %d jobs, want 0", s.Kind, n)
		}
	}
	if a := alertsOf(t, r); len(a) != 0 {
		t.Errorf("alerts = %+v, want none", a)
	}
	absent := h.rec.Matching(slog.LevelDebug, "os outcome record absent")
	if len(absent) != 3 || len(h.rec.Records()) != 3 {
		t.Fatalf("records:\n%s", h.rec.Text())
	}
	if attr(absent[0], "source") != "os.seal_key" || attr(absent[0], "path") != h.srcs[0].Path {
		t.Errorf("absent line: %s", h.rec.Text())
	}
}

// TC-833-11: a record that cannot be read is one failed `unreadable` job
// keyed to the api's boot, a crit alert, and an ERROR line; a second read in
// the same boot adds no job.
func TestReader_UnreadableFile(t *testing.T) {
	h := newHarness(t)
	if err := os.Mkdir(h.srcs[0].Path, 0o700); err != nil {
		t.Fatal(err)
	}
	r := h.reader(t)
	r.ReadAtStart(t.Context())
	js := h.jobs(t, "os.seal_key")
	if len(js) != 1 || js[0].Status != jobs.StatusFailed || js[0].ID != jobID("os.seal_key", testBoot2+"-unreadable", OutcomeUnreadable) {
		t.Fatalf("jobs = %+v", js)
	}
	if s := spec(t, js[0]); s.Outcome != OutcomeUnreadable || s.BootID != testBoot2 || s.Path != h.srcs[0].Path {
		t.Errorf("spec = %+v", s)
	}
	if a := alertsOf(t, r); len(a) != 1 || a[0].ID != "os-outcome:os.seal_key" || a[0].Severity != proto.AlertCrit {
		t.Errorf("alerts = %+v", a)
	}
	errs := h.rec.Matching(slog.LevelError, "os outcome record unreadable")
	if len(errs) != 1 || attr(errs[0], "err") == "" || attr(errs[0], "source") != "os.seal_key" || attr(errs[0], "path") != h.srcs[0].Path {
		t.Fatalf("log:\n%s", h.rec.Text())
	}
	r.ReadAtStart(t.Context())
	if n := len(h.jobs(t, "os.seal_key")); n != 1 {
		t.Errorf("second read: %d jobs, want 1", n)
	}
}

// TC-833-12: a record that says untouched but is malformed is never success.
func TestReader_MalformedIsNeverSuccess(t *testing.T) {
	h := newHarness(t)
	h.write(t, 0, sealRec("untouched", testBoot, testKeyID, "Fine.")+"extra=1\n")
	r := h.reader(t)
	r.ReadAtStart(t.Context())
	js := h.jobs(t, "os.seal_key")
	if len(js) != 1 || js[0].Status != jobs.StatusFailed || spec(t, js[0]).Outcome != OutcomeUnreadable {
		t.Fatalf("jobs = %+v", js)
	}
	if a := alertsOf(t, r); len(a) != 1 {
		t.Errorf("alerts = %+v, want the crit", a)
	}
}

// TC-833-13: an unreadable record with no api boot id records nothing, logs
// one ERROR line, and the other sources are still read.
func TestReader_UnreadableWithoutBootID(t *testing.T) {
	h := newHarness(t)
	h.bootID = func() (string, error) { return "", errors.New("no /proc") }
	if err := os.Mkdir(h.srcs[0].Path, 0o700); err != nil {
		t.Fatal(err)
	}
	h.write(t, 1, initRec("initialised", testBoot, "Done."))
	h.write(t, 2, provRec("applied", testBoot, testRun, "Done."))
	r := h.reader(t)
	r.ReadAtStart(t.Context())
	if n := len(h.jobs(t, "os.seal_key")); n != 0 {
		t.Errorf("seal key: %d jobs, want 0", n)
	}
	if len(h.jobs(t, "os.store_init")) != 1 || len(h.jobs(t, "os.store_provision")) != 1 {
		t.Error("the other sources were not read")
	}
	errs := h.rec.AtLevel(slog.LevelError)
	if len(errs) != 1 || attr(errs[0], "boot_id_err") == "" || attr(errs[0], "err") == "" {
		t.Fatalf("log:\n%s", h.rec.Text())
	}
}

// TC-833-14: two Readers over the same database record one job, with the
// same ID.
func TestReader_OneJobPerKeyAcrossRestarts(t *testing.T) {
	h := newHarness(t)
	h.write(t, 0, sealRec("created", testBoot, testKeyID, "Made."))
	h.reader(t).ReadAtStart(t.Context())
	first := h.jobs(t, "os.seal_key")
	// A fresh ledger handle on the same file, as a restarted api opens.
	h.ledger = openLedger(t, filepath.Join(h.dir, "jobs.db"))
	h.reader(t).ReadAtStart(t.Context())
	second := h.jobs(t, "os.seal_key")
	if len(first) != 1 || len(second) != 1 || first[0].ID != second[0].ID ||
		first[0].ID != jobID("os.seal_key", testBoot, "created") {
		t.Fatalf("first %+v, second %+v", first, second)
	}
	if len(h.rec.Matching(slog.LevelDebug, "already recorded")) != 1 {
		t.Errorf("log:\n%s", h.rec.Text())
	}
}

// TC-833-15: a store-init record that changes from failed to initialised in
// the same boot is a second job, and the alert clears.
func TestReader_SameBootOutcomeChange(t *testing.T) {
	h := newHarness(t)
	r := h.reader(t)
	h.write(t, 1, initRec("failed", testBoot, "The store did not init."))
	r.ReadAtStart(t.Context())
	if a := alertsOf(t, r); len(a) != 1 || a[0].ID != "os-outcome:os.store_init" {
		t.Fatalf("alerts = %+v", a)
	}
	h.write(t, 1, initRec("initialised", testBoot, "The store initialised."))
	r.ReadAtStart(t.Context())
	if n := len(h.jobs(t, "os.store_init")); n != 2 {
		t.Errorf("%d jobs, want 2", n)
	}
	if a := alertsOf(t, r); len(a) != 0 {
		t.Errorf("alerts = %+v, want cleared", a)
	}
}

// TC-833-16: the provisioner's key is run_id.
func TestReader_OneJobPerRunID(t *testing.T) {
	h := newHarness(t)
	r := h.reader(t)
	h.write(t, 2, provRec("applied", testBoot, testRun, "Done."))
	r.ReadAtStart(t.Context())
	h.write(t, 2, provRec("applied", testBoot, testRun2, "Done."))
	r.ReadAtStart(t.Context())
	if n := len(h.jobs(t, "os.store_provision")); n != 2 {
		t.Errorf("%d jobs, want 2", n)
	}
	r.ReadAtStart(t.Context())
	if n := len(h.jobs(t, "os.store_provision")); n != 2 {
		t.Errorf("re-read: %d jobs, want 2", n)
	}
}

// TC-833-17: a new source is a declaration and nothing else.
func TestReader_SecondSourceIsADeclaration(t *testing.T) {
	h := newHarness(t)
	h.srcs = []Source{{
		Kind: "os.test_thing", Path: filepath.Join(h.dir, "thing"),
		Fields: []string{FieldRunID, FieldReason}, KeyField: FieldRunID,
		Outcomes: map[string]Verdict{"fine": OK, "broken": Alert},
		Title:    "The test thing broke",
	}}
	r := h.reader(t)
	if err := os.WriteFile(h.srcs[0].Path, []byte("outcome=fine\nrun_id="+testRun+"\nreason=OK.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.ReadAtStart(t.Context())
	if js := h.jobs(t, "os.test_thing"); len(js) != 1 || js[0].Status != jobs.StatusSucceeded {
		t.Fatalf("jobs = %+v", js)
	}
	if err := os.WriteFile(h.srcs[0].Path, []byte("outcome=broken\nrun_id="+testRun2+"\nreason=It broke.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.ReadAtStart(t.Context())
	js := h.jobs(t, "os.test_thing")
	if len(js) != 2 || js[0].Status != jobs.StatusFailed || js[0].Error != "It broke." {
		t.Fatalf("jobs = %+v", js)
	}
	if a := alertsOf(t, r); len(a) != 1 || a[0].Title != "The test thing broke" || a[0].Severity != proto.AlertCrit {
		t.Errorf("alerts = %+v", a)
	}
	if !slices.Equal(r.Kinds(), []string{"os.test_thing"}) {
		t.Errorf("kinds = %v", r.Kinds())
	}
}

type fakeLedger struct {
	mu        sync.Mutex
	records   int
	recordErr error
	listErr   error
}

func (f *fakeLedger) RecordFinishedJob(context.Context, *jobs.Job) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records++
	return false, f.recordErr
}

func (f *fakeLedger) ListJobsByKind(context.Context, string, int) ([]*jobs.Job, error) {
	return nil, f.listErr
}

// TC-833-18: New refuses each nil collaborator and each bad declaration.
func TestNew_Refuses(t *testing.T) {
	log, _ := logkittest.New()
	good := func() Deps {
		return Deps{Ledger: &fakeLedger{}, Log: log, Now: time.Now,
			BootID: func() (string, error) { return testBoot, nil }, StartUnit: (&units{}).start}
	}
	if _, err := New(good(), testSources(t.TempDir())); err != nil {
		t.Fatalf("good input refused: %v", err)
	}
	for name, mut := range map[string]func(*Deps){
		"nil ledger":     func(d *Deps) { d.Ledger = nil },
		"nil log":        func(d *Deps) { d.Log = nil },
		"nil now":        func(d *Deps) { d.Now = nil },
		"nil boot id":    func(d *Deps) { d.BootID = nil },
		"nil start unit": func(d *Deps) { d.StartUnit = nil },
	} {
		d := good()
		mut(&d)
		if r, err := New(d, testSources(t.TempDir())); err == nil || r != nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, mut := range map[string]func([]Source) []Source{
		"duplicate kind":       func(s []Source) []Source { s[1].Kind = s[0].Kind; return s },
		"unknown field":        func(s []Source) []Source { s[0].Fields = append(s[0].Fields, "changed"); return s },
		"outcome as a field":   func(s []Source) []Source { s[0].Fields = append(s[0].Fields, "outcome"); return s },
		"field twice":          func(s []Source) []Source { s[0].Fields = append(s[0].Fields, FieldReason); return s },
		"key field undeclared": func(s []Source) []Source { s[0].KeyField = FieldRunID; return s },
		"key field not a key":  func(s []Source) []Source { s[0].KeyField = FieldReason; return s },
		"empty vocabulary":     func(s []Source) []Source { s[0].Outcomes = nil; return s },
		"outcome with no verdict": func(s []Source) []Source {
			s[0].Outcomes = map[string]Verdict{"created": 0}
			return s
		},
		"no kind": func(s []Source) []Source { s[0].Kind = ""; return s },
		"no path": func(s []Source) []Source { s[0].Path = ""; return s },
	} {
		if r, err := New(good(), mut(testSources(t.TempDir()))); err == nil || r != nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TC-833-19: the alert's fields, its clearing fact, and a failed ledger read.
func TestReader_AlertDerivationAndClearing(t *testing.T) {
	h := newHarness(t)
	r := h.reader(t)
	h.write(t, 0, sealRec("failed", testBoot, "-", "The seal fragment is missing."))
	r.ReadAtStart(t.Context())
	js := h.jobs(t, "os.seal_key")
	if len(js) != 1 {
		t.Fatalf("jobs = %+v", js)
	}
	a := alertsOf(t, r)
	want := proto.Alert{
		ID: "os-outcome:os.seal_key", Severity: proto.AlertCrit, Source: proto.AlertSourceJob,
		Title: "seal key", Detail: "The seal fragment is missing.", Since: *js[0].FinishedAt,
		RelatedKind: "job", RelatedID: js[0].ID,
	}
	if len(a) != 1 || a[0] != want {
		t.Fatalf("alerts = %+v, want %+v", a, want)
	}
	// A later boot's untouched record clears it.
	h.write(t, 0, sealRec("untouched", testBoot2, testKeyID, "The key is in place."))
	r.ReadAtStart(t.Context())
	if a := alertsOf(t, r); len(a) != 0 {
		t.Errorf("alerts = %+v, want cleared", a)
	}

	log, _ := logkittest.New()
	broken, err := New(Deps{Ledger: &fakeLedger{listErr: errors.New("disk I/O")}, Log: log, Now: time.Now,
		BootID: h.bootID, StartUnit: h.units.start}, h.srcs)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := broken.Alerts(t.Context(), time.Now()); err == nil || got != nil {
		t.Errorf("a failed ledger read gave %+v, %v; want an error", got, err)
	}
}

// TC-833-20: a ledger that refuses every write: one ERROR line per source
// with every outcome field, and every source attempted.
func TestReader_LedgerWriteFailure(t *testing.T) {
	h := newHarness(t)
	h.write(t, 0, sealRec("failed", testBoot, testKeyID, "Seal broke."))
	h.write(t, 1, initRec("initialised", testBoot, "Init done."))
	h.write(t, 2, provRec("applied", testBoot, testRun, "Provisioned."))
	log, rec := logkittest.New()
	fl := &fakeLedger{recordErr: errors.New("database is locked")}
	r, err := New(Deps{Ledger: fl, Log: log, Now: h.clock.Now, BootID: h.bootID, StartUnit: h.units.start}, h.srcs)
	if err != nil {
		t.Fatal(err)
	}
	r.ReadAtStart(t.Context())
	if fl.records != 3 {
		t.Errorf("ledger saw %d writes, want 3", fl.records)
	}
	errs := rec.Matching(slog.LevelError, "not recorded")
	if len(errs) != 3 {
		t.Fatalf("log:\n%s", rec.Text())
	}
	wants := []map[string]string{
		{"source": "os.seal_key", "outcome": "failed", "boot_id": testBoot, "key_id": testKeyID, "reason": "Seal broke."},
		{"source": "os.store_init", "outcome": "initialised", "boot_id": testBoot, "reason": "Init done."},
		{"source": "os.store_provision", "outcome": "applied", "boot_id": testBoot, "run_id": testRun, "reason": "Provisioned."},
	}
	for i, want := range wants {
		want["path"] = h.srcs[i].Path
		for k, v := range want {
			if got := attr(errs[i], k); got != v {
				t.Errorf("line %d %s = %q, want %q", i, k, got, v)
			}
		}
		if attr(errs[i], "ledger_err") == "" {
			t.Errorf("line %d has no ledger_err", i)
		}
	}
	if _, ok := logkittest.Attr(errs[1], "run_id"); ok {
		t.Error("store init's line carries run_id, which it does not declare")
	}
	if _, ok := logkittest.Attr(errs[1], "key_id"); ok {
		t.Error("store init's line carries key_id, which it does not declare")
	}
}

// TC-833-21: after a store restart, the provisioner's unit is started before
// its record is read, store init is read with no start, and the seal key is
// not read. A unit that will not start is one WARN, and its record is read.
func TestReader_AfterStoreRestart(t *testing.T) {
	h := newHarness(t)
	h.write(t, 0, sealRec("untouched", testBoot, testKeyID, "Fine."))
	h.write(t, 1, initRec("initialised", testBoot, "Done."))
	// The provisioner's record exists only once its unit was started.
	h.units.onStart = func(string) { h.write(t, 2, provRec("applied", testBoot, testRun, "Done.")) }
	r := h.reader(t)
	r.AfterStoreRestart(t.Context())
	if got := h.units.got(); !slices.Equal(got, []string{"rasputin-store-provision.service"}) {
		t.Errorf("units started = %v", got)
	}
	if len(h.jobs(t, "os.store_provision")) != 1 || len(h.jobs(t, "os.store_init")) != 1 {
		t.Error("store init or provision not recorded")
	}
	if n := len(h.jobs(t, "os.seal_key")); n != 0 {
		t.Errorf("the seal key was read after a store restart: %d jobs", n)
	}

	h2 := newHarness(t)
	h2.units.err = errors.New("unit not found")
	h2.write(t, 2, provRec("unchanged", testBoot, testRun, "Nothing to do."))
	r2 := h2.reader(t)
	r2.AfterStoreRestart(t.Context())
	warns := h2.rec.AtLevel(slog.LevelWarn)
	if len(warns) != 1 || attr(warns[0], "unit") != "rasputin-store-provision.service" || !strings.Contains(attr(warns[0], "err"), "unit not found") {
		t.Fatalf("log:\n%s", h2.rec.Text())
	}
	if n := len(h2.jobs(t, "os.store_provision")); n != 1 {
		t.Errorf("provisioner record not read after a failed start: %d jobs", n)
	}
}

// TC-833-22: levels: INFO for an OK outcome newly recorded, ERROR with the
// reason for an alerting one, DEBUG for a repeat; each line carries the
// source, path, outcome, key fields and job id.
func TestReader_LogLevels(t *testing.T) {
	h := newHarness(t)
	h.write(t, 0, sealRec("failed", testBoot, "-", "Seal broke."))
	h.write(t, 2, provRec("applied", testBoot, testRun, "Provisioned."))
	r := h.reader(t)
	r.ReadAtStart(t.Context())
	info := h.rec.Matching(slog.LevelInfo, "os outcome recorded")
	errs := h.rec.Matching(slog.LevelError, "os outcome recorded")
	if len(info) != 1 || len(errs) != 1 {
		t.Fatalf("log:\n%s", h.rec.Text())
	}
	sealJob := h.jobs(t, "os.seal_key")[0]
	provJob := h.jobs(t, "os.store_provision")[0]
	for k, v := range map[string]string{"source": "os.seal_key", "path": h.srcs[0].Path, "outcome": "failed",
		"boot_id": testBoot, "key_id": "-", "reason": "Seal broke.", "job_id": sealJob.ID} {
		if got := attr(errs[0], k); got != v {
			t.Errorf("ERROR %s = %q, want %q", k, got, v)
		}
	}
	for k, v := range map[string]string{"source": "os.store_provision", "path": h.srcs[2].Path, "outcome": "applied",
		"boot_id": testBoot, "run_id": testRun, "job_id": provJob.ID} {
		if got := attr(info[0], k); got != v {
			t.Errorf("INFO %s = %q, want %q", k, got, v)
		}
	}
	if sealJob.CreatedBy != "rasputin-os" || provJob.Status != jobs.StatusSucceeded || provJob.Error != "" {
		t.Errorf("jobs: %+v, %+v", sealJob, provJob)
	}
	r.ReadAtStart(t.Context())
	repeats := h.rec.Matching(slog.LevelDebug, "already recorded")
	if len(repeats) != 2 || attr(repeats[0], "job_id") != sealJob.ID || attr(repeats[1], "job_id") != provJob.ID {
		t.Errorf("repeat lines:\n%s", h.rec.Text())
	}
	if len(h.rec.AtLevel(slog.LevelInfo)) != 1 || len(h.rec.AtLevel(slog.LevelError)) != 1 {
		t.Errorf("a repeat logged above DEBUG:\n%s", h.rec.Text())
	}
}
