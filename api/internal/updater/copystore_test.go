package updater

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/alerts"
	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/setup"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// updateSentence opens every copy refusal (sealrotate.UpdateCopyRefused,
// restated here because updater does not import the store's packages).
const updateSentence = "The secret store could not be copied before this OS update, so the update was refused and nothing was installed."

// fakeCopier is a StoreCopier recording the job ids it was called with, and
// answering with result or err.
type fakeCopier struct {
	mu     sync.Mutex
	jobIDs []string
	result json.RawMessage
	err    error
}

func (f *fakeCopier) CopyBeforeUpdate(sc *jobs.StepCtx) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobIDs = append(f.jobIDs, sc.JobID)
	return f.result, f.err
}

func (f *fakeCopier) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.jobIDs...)
}

// sagaRig runs the real node.update saga on the runner and the bus, against
// a fake agent that answers precheck and download and counts install
// requests, refusing them so the saga ends there.
type sagaRig struct {
	nc       *nats.Conn
	store    *Store
	inv      *inventory.Store
	jobStore *jobs.Store
	runner   *jobs.Runner
	installs atomic.Int32
	rec      *logkittest.Recorder
	dir      string
}

const (
	sagaSHA  = "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00"
	sagaSelf = "cp-self"
)

func newSagaRig(t *testing.T, nodes map[string]proto.NodeRole, cfg Config) *sagaRig {
	t.Helper()
	ctx := context.Background()
	r := &sagaRig{nc: startNATS(t), store: newStoreFixture(t).store, inv: newInventory(t), jobStore: newJobsStore(t), dir: t.TempDir()}
	log, rec := logkittest.New()
	r.rec = rec
	if cfg.StoreCopy != nil && cfg.Log == nil {
		cfg.Log = log
	}
	for id, role := range nodes {
		if err := r.inv.Insert(ctx, &proto.Node{ID: id, Role: role, Hostname: id + ".test", FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		r.fakeAgent(t, id)
	}
	if err := r.store.CreateBundle(ctx, &Bundle{SHA256: sagaSHA, Version: "v2", Compatible: "rasputin-test", Architecture: "arm64",
		SizeBytes: 1024, UploadedAt: time.Now().UTC(), UploadedBy: "tester"}); err != nil {
		t.Fatal(err)
	}
	r.runner = jobs.NewRunner(r.jobStore, r.nc)
	r.runner.SetBackoff(func(int) time.Duration { return time.Millisecond })
	r.runner.Register(UpdateWorkflow(r.store, r.inv, r.nc, cfg))
	t.Cleanup(r.runner.Wait)
	return r
}

func (r *sagaRig) fakeAgent(t *testing.T, id string) {
	t.Helper()
	respond := func(subj string, fn func(*nats.Msg) any) {
		sub, err := r.nc.Subscribe(subj, func(m *nats.Msg) {
			b, _ := json.Marshal(fn(m))
			_ = m.Respond(b)
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
	}
	respond(proto.UpdatePrecheckSubject(id), func(*nats.Msg) any {
		return proto.UpdatePrecheckAck{OK: true, ActiveSlot: proto.SlotA, InactiveSlot: proto.SlotB, CurrentVersion: "v1"}
	})
	respond(proto.UpdateDownloadSubject(id), func(*nats.Msg) any {
		return proto.UpdateDownloadAck{OK: true, SHA256: sagaSHA, LocalPath: "/cache/" + sagaSHA}
	})
	respond(proto.UpdateInstallSubject(id), func(*nats.Msg) any {
		r.installs.Add(1)
		return proto.UpdateInstallAck{OK: false, Detail: "the test stops the saga at install"}
	})
}

// run submits a node.update for nodeID and waits for it to end. Every
// saga here ends failed: the fake agent refuses install.
func (r *sagaRig) run(t *testing.T, nodeID string) *jobs.Job {
	t.Helper()
	j, err := r.runner.Submit(context.Background(), "node.update", UpdateSpec{NodeID: nodeID, BundleSHA256: sagaSHA}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	// Wait returns once the job's goroutine is done, after the terminal hook
	// has written the row: the job's status alone is set before the hook.
	r.runner.Wait()
	got, err := r.jobStore.GetJob(context.Background(), j.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// copyResult is copy_store's recorded result, or nil when it has none.
func (r *sagaRig) copyResult(t *testing.T, jobID string) map[string]any {
	t.Helper()
	steps, err := r.jobStore.ListSteps(context.Background(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	raw := stepResult(steps, "copy_store")
	if raw == nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (r *sagaRig) rowStatus(t *testing.T, jobID string) NodeUpdateStatus {
	t.Helper()
	row, err := r.store.GetNodeUpdate(context.Background(), jobID)
	if err != nil || row == nil {
		t.Fatalf("node_update row = %v, %v", row, err)
	}
	return row.Status
}

// installRefusedAtTheAgent is the fake agent's install refusal: a job that
// ends with it reached install.
const installRefusedAtTheAgent = "the test stops the saga at install"

// TC-800-01: the saga's steps, in order, with copy_store before install,
// never retried and not irreversible.
func TestUpdateWorkflow_CopyStoreBeforeInstall(t *testing.T) {
	wf := UpdateWorkflow(nil, nil, nil, Config{})
	var names []string
	for _, s := range wf.Steps {
		names = append(names, s.Name)
		if s.Name == "copy_store" && (s.Retries != 0 || s.Irreversible || s.Timeout != 20*time.Minute) {
			t.Errorf("copy_store = %+v, want Retries 0, not Irreversible, 20m", s)
		}
	}
	want := []string{"validate", "precheck", "download", "copy_store", "install", "reboot", "wait_online_and_verify_slot", "health_check_and_commit"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("steps %v, want %v", names, want)
	}
	if err := jobs.ValidateWorkflow(wf); err != nil {
		t.Fatal(err)
	}
}

// TC-800-02: with no store wired, copy_store succeeds as no-store with one
// job line, and the saga reaches install.
func TestCopyStore_NoStoreSkips(t *testing.T) {
	r := newSagaRig(t, map[string]proto.NodeRole{sagaSelf: proto.RoleControlPlane}, Config{SelfNodeID: sagaSelf})
	j := r.run(t, sagaSelf)
	if got := r.copyResult(t, j.ID); !reflect.DeepEqual(got, map[string]any{"copied": false, "reason": "no-store"}) {
		t.Errorf("copy_store result %v", got)
	}
	if r.installs.Load() != 1 || !strings.Contains(j.Error, installRefusedAtTheAgent) {
		t.Errorf("installs %d, job error %q: the saga did not reach install", r.installs.Load(), j.Error)
	}
	if n := countLines(t, r.jobStore, j.ID, "nothing to copy"); n != 1 {
		t.Errorf("%d copy_store job line(s), want 1", n)
	}
}

// TC-800-03: a compute, storage or firewall target skips as
// not-store-host, and the copier is never called.
func TestCopyStore_NotTheStoreHostSkips(t *testing.T) {
	for _, role := range []proto.NodeRole{proto.RoleCompute, proto.RoleStorage, proto.RoleFirewall} {
		t.Run(string(role), func(t *testing.T) {
			cp := &fakeCopier{}
			r := newSagaRig(t, map[string]proto.NodeRole{sagaSelf: proto.RoleControlPlane, "n1": role}, Config{SelfNodeID: sagaSelf, StoreCopy: cp})
			j := r.run(t, "n1")
			if got := r.copyResult(t, j.ID); !reflect.DeepEqual(got, map[string]any{"copied": false, "reason": "not-store-host"}) {
				t.Errorf("copy_store result %v", got)
			}
			if len(cp.calls()) != 0 || r.installs.Load() != 1 {
				t.Errorf("copier calls %v, installs %d; want none and one", cp.calls(), r.installs.Load())
			}
		})
	}
}

// TC-800-04 (ERR-CLOSED, F-800-04): a control plane that is not this api's
// own node (a), or any control plane when the api's own node is not known
// (b), is refused before install: no install, the row failed, the copier
// never called, one WARN record with node_id.
func TestCopyStore_RefusesAnUnknownStoreHost(t *testing.T) {
	for name, self := range map[string]string{"a: another control plane": sagaSelf, "b: self unknown": ""} {
		t.Run(name, func(t *testing.T) {
			cp := &fakeCopier{}
			r := newSagaRig(t, map[string]proto.NodeRole{sagaSelf: proto.RoleControlPlane, "cp2": proto.RoleControlPlane},
				Config{SelfNodeID: self, StoreCopy: cp})
			j := r.run(t, "cp2")
			if j.Error != errStoreHostUnknown.Error() || r.installs.Load() != 0 || len(cp.calls()) != 0 {
				t.Fatalf("job %q, installs %d, copier %v", j.Error, r.installs.Load(), cp.calls())
			}
			if st := r.rowStatus(t, j.ID); st != NodeUpdateFailed {
				t.Errorf("row %s, want failed", st)
			}
			recs := r.rec.Matching(slog.LevelWarn, "os update refused")
			if len(recs) != 1 {
				t.Fatalf("%d WARN record(s), want 1", len(recs))
			}
			if id, _ := logkittest.Attr(recs[0], "node_id"); id != "cp2" {
				t.Errorf("node_id = %q", id)
			}
		})
	}
	// Self is copied whatever inventory says its role is (F-800-04).
	cp := &fakeCopier{result: json.RawMessage(`{"copied":true}`)}
	r := newSagaRig(t, map[string]proto.NodeRole{sagaSelf: proto.RoleCompute}, Config{SelfNodeID: sagaSelf, StoreCopy: cp})
	r.run(t, sagaSelf)
	if len(cp.calls()) != 1 {
		t.Errorf("self with a compute role: copier calls %v, want one", cp.calls())
	}
}

// TC-800-05 and TC-800-06: each refusal the copier can return fails the job
// with that sentence before install, the row is failed, and the failed job
// raises the job-failed warn alert carrying the sentence.
func TestCopyStore_AFailedCopyRefusesTheUpdate(t *testing.T) {
	for _, tail := range []string{
		"A seal-key rotation has not finished: start the seal-key rotation again to finish it, then run the update again.",
		"The update waited for a backup or a seal-key rotation to finish and ran out of time.",
		"The store's readiness could not be read; run the update again once the store is ready.",
		"The secret store is sealed; run the update again once it is ready.",
		"The store's version could not be read; run the update again once the store is ready.",
		"The store could not be stopped for its copy; it was started again, and the job feed names the cause.",
		"The store's data could not be copied; the store was started again, and the job feed names the cause.",
		"The store did not come back after its copy; its own unit keeps restarting it, and the secret store alert says when it is back.",
	} {
		sentence := updateSentence + " " + tail
		t.Run(tail[:24], func(t *testing.T) {
			cp := &fakeCopier{err: errors.New(sentence)}
			r := newSagaRig(t, map[string]proto.NodeRole{sagaSelf: proto.RoleControlPlane}, Config{SelfNodeID: sagaSelf, StoreCopy: cp})
			j := r.run(t, sagaSelf)
			if j.Error != sentence || !strings.HasPrefix(j.Error, updateSentence) {
				t.Fatalf("job error %q, want %q", j.Error, sentence)
			}
			if r.installs.Load() != 0 {
				t.Errorf("%d install RPC(s) after a failed copy", r.installs.Load())
			}
			if st := r.rowStatus(t, j.ID); st != NodeUpdateFailed {
				t.Errorf("row %s, want failed", st)
			}
			list, err := newAlerts(t, r).List(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, a := range list {
				if a.ID == "job-failed:"+j.ID {
					found = true
					if a.Severity != proto.AlertWarn || a.Title != "node.update failed" || a.Detail != sentence {
						t.Errorf("alert %+v", a)
					}
				}
			}
			if !found {
				t.Errorf("no job-failed:%s alert in %+v", j.ID, list)
			}
		})
	}
}

// TC-800-07: a successful copy is called once with the job's id, its result
// is the step's, and install runs next.
func TestCopyStore_SuccessThenInstall(t *testing.T) {
	cp := &fakeCopier{result: json.RawMessage(`{"copied":true,"version":"2.7.1","files":3,"sizeBytes":4096}`)}
	r := newSagaRig(t, map[string]proto.NodeRole{sagaSelf: proto.RoleControlPlane}, Config{SelfNodeID: sagaSelf, StoreCopy: cp})
	j := r.run(t, sagaSelf)
	if got := cp.calls(); !reflect.DeepEqual(got, []string{j.ID}) {
		t.Errorf("copier calls %v, want [%s]", got, j.ID)
	}
	want := map[string]any{"copied": true, "version": "2.7.1", "files": float64(3), "sizeBytes": float64(4096)}
	if got := r.copyResult(t, j.ID); !reflect.DeepEqual(got, want) {
		t.Errorf("copy_store result %v", got)
	}
	if r.installs.Load() != 1 {
		t.Errorf("installs %d, want 1", r.installs.Load())
	}
}

// A copier wired without a logger refuses rather than copy unlogged.
func TestCopyStore_NoLoggerRefuses(t *testing.T) {
	cp := &fakeCopier{}
	sc := newUpdaterCtx("j", specJSON(sagaSelf, sagaSHA), nil)
	if _, err := updateCopyStore(nil, Config{SelfNodeID: sagaSelf, StoreCopy: cp})(sc); err == nil || len(cp.calls()) != 0 {
		t.Fatalf("err = %v, copier calls %v", err, cp.calls())
	}
	if _, err := updateCopyStore(nil, Config{})(newUpdaterCtx("j", `{}`, nil)); err == nil {
		t.Error("a bad spec was accepted")
	}
}

// TC-800-21: a self-update the previous release deferred, whose step rows
// have no copy_store and number install and reboot as the seven-step saga
// did, is finished by Recover and ResumeSelfUpdates under the new step list:
// committed on the new slot.
func TestResumeSelfUpdates_AcrossTheChangedStepList(t *testing.T) {
	const jid = "selfjob-old-saga"
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	jobStore := newJobStore(t)
	if err := jobStore.CreateJob(ctx, &jobs.Job{ID: jid, Kind: "node.update", Spec: json.RawMessage(specJSON(sagaSelf, sagaSHA)),
		Status: jobs.StatusRunning, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for seq, name := range []string{"validate", "precheck", "download", "install", "reboot"} {
		if err := jobStore.CreateStep(ctx, &jobs.JobStep{JobID: jid, Seq: seq, Name: name, Status: jobs.StepSucceeded, Attempt: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.CreateNodeUpdate(ctx, &NodeUpdate{JobID: jid, NodeID: sagaSelf, BundleSHA256: sagaSHA,
		FromSlot: proto.SlotA, ToSlot: proto.SlotB, ToVersion: "v1", Status: NodeUpdateInProgress, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	log, _ := logkittest.New()
	runner := jobs.NewRunner(jobStore, nc)
	runner.Register(UpdateWorkflow(store, nil, nc, Config{SelfNodeID: sagaSelf, StoreCopy: &fakeCopier{}, Log: log}))
	runner.SetRecoverDecider(SelfUpdateRecoverDecider(ctx, jobStore, sagaSelf))
	if err := runner.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if j, _ := jobStore.GetJob(ctx, jid); j == nil || j.Status != jobs.StatusRunning {
		t.Fatalf("after Recover the job is %+v, want still running (deferred)", j)
	}
	fakeAgentForSelfUpdate(t, nc, sagaSelf, proto.SlotB)
	ResumeSelfUpdates(ctx, store, nil, jobStore, runner, nc, sagaSelf, nil)
	waitJobStatus(t, jobStore, jid, jobs.StatusSucceeded)
	if row, _ := store.GetNodeUpdate(ctx, jid); row == nil || row.Status != NodeUpdateCommitted {
		t.Errorf("row %+v, want committed", row)
	}
}

// newAlerts is the alert service over the rig's job ledger and inventory.
func newAlerts(t *testing.T, r *sagaRig) *alerts.Service {
	t.Helper()
	ctx := context.Background()
	as, err := apps.OpenStore(ctx, filepath.Join(r.dir, "apps.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = as.Close() })
	ss, err := setup.OpenStore(ctx, filepath.Join(r.dir, "setup.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	no := func(context.Context) (bool, error) { return false, nil }
	return alerts.New(r.inv, r.jobStore, as, setup.NewService(ss, setup.Probes{HasUsers: no, ConsoleRootSet: no}, "", "", ""), nil, nil, true)
}

// countLines counts the job's log lines containing sub.
func countLines(t *testing.T, js *jobs.Store, jobID, sub string) int {
	t.Helper()
	evs, err := js.ListEvents(context.Background(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range evs {
		if e.Type == string(proto.JobLog) && strings.Contains(string(e.Data), sub) {
			n++
		}
	}
	return n
}
