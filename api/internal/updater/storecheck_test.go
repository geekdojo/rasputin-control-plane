package updater

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/deadlinetest"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/api/internal/secretstore"
	"github.com/geekdojo/rasputin-control-plane/logkit/logkittest"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Tests for geekdojo/geekdojo-brain#767: a control plane's update of itself
// commits only once its own secret store answers ready, and the mark-bad
// branch records only what actually happened (F-767-01).

// testWindow stands in for the self-update window in these tests: long
// enough that the store's sealed answers are read several times, short
// enough that a store which never comes ready costs a fraction of a second.
const testWindow = 300 * time.Millisecond

// storeAnswer is one sys/health answer the fake store gives.
type storeAnswer struct {
	h   secretstore.Health
	err error
}

var (
	answerReady  = storeAnswer{h: secretstore.Health{Initialized: true}}
	answerSealed = storeAnswer{err: secretstore.ErrSealed}
)

// fakeStore answers Health from script, one entry per call, repeating the
// last. With forbidden set, any call fails the test.
type fakeStore struct {
	t         *testing.T
	script    []storeAnswer
	forbidden bool
	calls     atomic.Int32
}

func (f *fakeStore) Health(context.Context) (secretstore.Health, error) {
	n := int(f.calls.Add(1)) - 1
	if f.forbidden {
		f.t.Errorf("the secret store was consulted (call %d); it must not be", n+1)
	}
	if n >= len(f.script) {
		n = len(f.script) - 1
	}
	return f.script[n].h, f.script[n].err
}

func newStoreCheck(t *testing.T, store StoreHealth, log *slog.Logger) *SelfStoreCheck {
	t.Helper()
	sc, err := NewSelfStoreCheck(store, log)
	if err != nil {
		t.Fatalf("NewSelfStoreCheck: %v", err)
	}
	sc.window = testWindow
	return sc
}

// markBadMode is how the fake agent answers update.mark-bad.
type markBadMode int

const (
	markBadAccepts     markBadMode = iota // {"ok":true}
	markBadRejects                        // {"ok":false,"detail":...}, as when rauc status mark-bad fails
	markBadNoResponder                    // nobody subscribed
)

const raucMarkBadFailure = "rauc mark-bad: exit status 1"

// selfAgent is a fake agent for the node a test updates. It answers precheck
// on the target slot, diag.health, mark-good and mark-bad, counts what it
// receives, and models the slot's good/bad mark.
type selfAgent struct {
	markGood, markBad, diagHealth atomic.Int32
	slotGood                      atomic.Bool
	mu                            sync.Mutex
	markBadAt                     time.Time
}

func (a *selfAgent) markBadArrival() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.markBadAt
}

func startSelfAgent(t *testing.T, nc *nats.Conn, nodeID string, healthy bool, mode markBadMode, slotStartsGood bool) *selfAgent {
	t.Helper()
	a := &selfAgent{}
	a.slotGood.Store(slotStartsGood)
	sub := func(subj string, h nats.MsgHandler) {
		s, err := nc.Subscribe(subj, h)
		if err != nil {
			t.Fatalf("subscribe %s: %v", subj, err)
		}
		t.Cleanup(func() { _ = s.Unsubscribe() })
	}
	sub(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		_ = m.Respond(mustJSON(proto.UpdatePrecheckAck{OK: true, ActiveSlot: proto.SlotB, InactiveSlot: proto.SlotA,
			CurrentVersion: "v1", BootID: "boot-after"}))
	})
	sub(proto.NodeCmdSubject(nodeID, "diag.health"), func(m *nats.Msg) {
		a.diagHealth.Add(1)
		ack := proto.DiagHealthAck{OK: healthy}
		if !healthy {
			ack.Detail = "failed critical checks: nft-ruleset"
		}
		_ = m.Respond(mustJSON(ack))
	})
	sub(proto.UpdateMarkGoodSubject(nodeID), func(m *nats.Msg) {
		a.markGood.Add(1)
		a.slotGood.Store(true)
		_ = m.Respond(mustJSON(proto.UpdateMarkGoodAck{OK: true}))
	})
	if mode != markBadNoResponder {
		sub(proto.UpdateMarkBadSubject(nodeID), func(m *nats.Msg) {
			a.mu.Lock()
			a.markBadAt = time.Now()
			a.mu.Unlock()
			a.markBad.Add(1)
			if mode == markBadRejects {
				_ = m.Respond(mustJSON(proto.UpdateMarkBadAck{OK: false, Detail: raucMarkBadFailure}))
				return
			}
			a.slotGood.Store(false)
			_ = m.Respond(mustJSON(proto.UpdateMarkBadAck{OK: true}))
		})
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	return a
}

// changeLog records every UpdateChangeEvt published for one node.
type changeLog struct {
	nc     *nats.Conn
	nodeID string
	mu     sync.Mutex
	evts   []proto.UpdateChangeEvt
	seen   chan struct{}
}

func watchChanges(t *testing.T, nc *nats.Conn, nodeID string) *changeLog {
	t.Helper()
	l := &changeLog{nc: nc, nodeID: nodeID, seen: make(chan struct{}, 1)}
	s, err := nc.Subscribe("rasputin.updates."+nodeID+".>", func(m *nats.Msg) {
		if strings.HasSuffix(m.Subject, ".sentinel") {
			l.seen <- struct{}{}
			return
		}
		var ev proto.UpdateChangeEvt
		_ = json.Unmarshal(m.Data, &ev)
		l.mu.Lock()
		l.evts = append(l.evts, ev)
		l.mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Unsubscribe() })
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	return l
}

// settled returns every event published before it was called. It publishes
// a sentinel on the same connection and waits for it: NATS keeps one
// publisher's order, so once the sentinel is in, every earlier event is too,
// and an absent event is genuinely absent.
func (l *changeLog) settled(t *testing.T) []proto.UpdateChangeEvt {
	t.Helper()
	if err := l.nc.Publish("rasputin.updates."+l.nodeID+".sentinel", nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-l.seen:
	case <-time.After(5 * time.Second):
		t.Fatal("the sentinel never arrived")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]proto.UpdateChangeEvt(nil), l.evts...)
}

func countChange(evts []proto.UpdateChangeEvt, c proto.UpdateChangeType) int {
	n := 0
	for _, e := range evts {
		if e.Change == c {
			n++
		}
	}
	return n
}

func seedInProgressRow(t *testing.T, store *Store, jobID, nodeID string) {
	t.Helper()
	if err := store.CreateNodeUpdate(context.Background(), &NodeUpdate{
		JobID: jobID, NodeID: nodeID, BundleSHA256: "sha",
		FromSlot: proto.SlotA, ToSlot: proto.SlotB, ToVersion: "v1",
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

func rowStatus(t *testing.T, store *Store, jobID string) *NodeUpdate {
	t.Helper()
	row, err := store.GetNodeUpdate(context.Background(), jobID)
	if err != nil || row == nil {
		t.Fatalf("GetNodeUpdate(%s) = %v, %v", jobID, row, err)
	}
	return row
}

// windowCtx is the self-update window as healthCheckAndCommit sees it.
func windowCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testWindow)
	t.Cleanup(cancel)
	return ctx
}

// TC-767-01: a ready store → mark-good once, no mark-bad, row committed, a
// committed event.
func TestSelfStoreCheck_ReadyStoreCommits(t *testing.T) {
	const node, jid = "cp", "j-ready"
	nc := startNATS(t)
	store := newStoreFixture(t).store
	seedInProgressRow(t, store, jid, node)
	agent := startSelfAgent(t, nc, node, true, markBadAccepts, false)
	changes := watchChanges(t, nc, node)
	log, _ := logkittest.New()
	sc := newStoreCheck(t, &fakeStore{t: t, script: []storeAnswer{answerReady}}, log)

	if _, err := healthCheckAndCommit(context.Background(), nc, store, nil, sc, node, "sha", jid, nil); err != nil {
		t.Fatalf("healthCheckAndCommit: %v", err)
	}
	if g, b := agent.markGood.Load(), agent.markBad.Load(); g != 1 || b != 0 {
		t.Errorf("mark-good %d, mark-bad %d; want 1 and 0", g, b)
	}
	if row := rowStatus(t, store, jid); row.Status != NodeUpdateCommitted {
		t.Errorf("row status %q, want committed", row.Status)
	}
	if evts := changes.settled(t); countChange(evts, proto.UpdateCommitted) != 1 || countChange(evts, proto.UpdateRolledBack) != 0 {
		t.Errorf("events %+v, want one committed and no rolled_back", evts)
	}
}

// TC-767-02: every answer other than ready, held until the window ends, takes
// the mark-bad branch: no mark-good, one mark-bad, row rolled_back, a
// rolled_back event, and the fixed sentence in the error. One subtest each
// (SC-CP 7).
func TestSelfStoreCheck_EveryNotReadyOutcomeMarksBad(t *testing.T) {
	cases := []struct {
		name string
		ans  storeAnswer
	}{
		{"sealed", storeAnswer{err: secretstore.ErrSealed}},
		{"uninitialised", storeAnswer{err: secretstore.ErrUninitialised}},
		{"unreachable or standby", storeAnswer{err: secretstore.ErrUnreachable}},
		{"disabled", storeAnswer{err: secretstore.ErrDisabled}},
		{"protocol", storeAnswer{err: secretstore.ErrProtocol}},
		{"health says uninitialised", storeAnswer{h: secretstore.Health{Initialized: false}}},
		{"health says sealed", storeAnswer{h: secretstore.Health{Initialized: true, Sealed: true}}},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			node := "cp" + string(rune('a'+i))
			const jid = "j-notready"
			nc := startNATS(t)
			store := newStoreFixture(t).store
			seedInProgressRow(t, store, jid, node)
			agent := startSelfAgent(t, nc, node, true, markBadAccepts, false)
			changes := watchChanges(t, nc, node)
			log, _ := logkittest.New()
			sc := newStoreCheck(t, &fakeStore{t: t, script: []storeAnswer{c.ans}}, log)

			_, err := healthCheckAndCommit(windowCtx(t), nc, store, nil, sc, node, "sha", jid, nil)
			if err == nil || !strings.Contains(err.Error(), selfStoreNotReady) {
				t.Fatalf("error %v, want it to carry %q", err, selfStoreNotReady)
			}
			if g, b := agent.markGood.Load(), agent.markBad.Load(); g != 0 || b != 1 {
				t.Errorf("mark-good %d, mark-bad %d; want 0 and 1", g, b)
			}
			if row := rowStatus(t, store, jid); row.Status != NodeUpdateRolledBack {
				t.Errorf("row status %q, want rolled_back", row.Status)
			}
			if evts := changes.settled(t); countChange(evts, proto.UpdateRolledBack) != 1 {
				t.Errorf("events %+v, want one rolled_back", evts)
			}
		})
	}
}

// TC-767-03: the wait ends on the store's answer, not on one reading: sealed,
// sealed, then ready commits, after at least three reads.
func TestSelfStoreCheck_WaitsThroughSealedToReady(t *testing.T) {
	const node, jid = "cp", "j-slow"
	nc := startNATS(t)
	store := newStoreFixture(t).store
	seedInProgressRow(t, store, jid, node)
	agent := startSelfAgent(t, nc, node, true, markBadAccepts, false)
	log, _ := logkittest.New()
	fs := &fakeStore{t: t, script: []storeAnswer{answerSealed, answerSealed, answerReady}}
	sc := newStoreCheck(t, fs, log)
	sc.window = selfUpdateWindow // ends on the 200, not on this bound

	if _, err := healthCheckAndCommit(context.Background(), nc, store, nil, sc, node, "sha", jid, nil); err != nil {
		t.Fatalf("healthCheckAndCommit: %v", err)
	}
	if n := fs.calls.Load(); n < 3 {
		t.Errorf("store read %d times, want at least 3", n)
	}
	if g, b := agent.markGood.Load(), agent.markBad.Load(); g != 1 || b != 0 {
		t.Errorf("mark-good %d, mark-bad %d; want 1 and 0", g, b)
	}
	if row := rowStatus(t, store, jid); row.Status != NodeUpdateCommitted {
		t.Errorf("row status %q, want committed", row.Status)
	}
}

// seedPreviousReleaseSelfJob persists a running self-update exactly as the
// previous release leaves it across its reboot: every step through reboot
// succeeded, and precheck's result carries the pre-reboot boot id.
func seedPreviousReleaseSelfJob(t *testing.T, jobStore *jobs.Store, store *Store, jobID, nodeID string) {
	t.Helper()
	ctx := context.Background()
	if err := jobStore.CreateJob(ctx, &jobs.Job{ID: jobID, Kind: "node.update", Spec: json.RawMessage(specJSON(nodeID, "sha")),
		Status: jobs.StatusRunning, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for seq, name := range []string{"validate", "precheck", "download", "copy_store", "install", "reboot"} {
		if err := jobStore.CreateStep(ctx, &jobs.JobStep{JobID: jobID, Seq: seq, Name: name, Status: jobs.StepRunning, Attempt: 1}); err != nil {
			t.Fatal(err)
		}
		var result json.RawMessage
		if name == "precheck" {
			result = mustJSON(proto.UpdatePrecheckAck{OK: true, ActiveSlot: proto.SlotA, InactiveSlot: proto.SlotB,
				CurrentVersion: "v0", BootID: "boot-before"})
		}
		if err := jobStore.MarkStepSucceeded(ctx, jobID, seq, 1, result, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	seedInProgressRow(t, store, jobID, nodeID)
}

// runResumedSelfUpdate drives ResumeSelfUpdates over a sealed store and
// returns the finished job.
func runResumedSelfUpdate(t *testing.T, slotStartsGood bool) (*selfAgent, *jobs.Job, *Store, *changeLog) {
	t.Helper()
	const self, jid = "cp", "j-resume"
	nc := startNATS(t)
	store := newStoreFixture(t).store
	jobStore := newJobStore(t)
	runner := jobs.NewRunner(jobStore, nc)
	seedPreviousReleaseSelfJob(t, jobStore, store, jid, self)
	agent := startSelfAgent(t, nc, self, true, markBadAccepts, slotStartsGood)
	changes := watchChanges(t, nc, self)
	log, _ := logkittest.New()
	sc := newStoreCheck(t, &fakeStore{t: t, script: []storeAnswer{answerSealed}}, log)

	ResumeSelfUpdates(context.Background(), store, nil, jobStore, runner, nc, self, sc)

	waitJobStatus(t, jobStore, jid, jobs.StatusFailed)
	j, err := jobStore.GetJob(context.Background(), jid)
	if err != nil || j == nil {
		t.Fatalf("GetJob: %v, %v", j, err)
	}
	return agent, j, store, changes
}

// TC-767-04: Pi semantics. The api never sends mark-good, so the commit is
// withheld; mark-bad goes once and the job fails with the fixed sentence.
func TestResumeSelfUpdates_SealedStoreWithholdsTheCommit(t *testing.T) {
	agent, j, _, _ := runResumedSelfUpdate(t, false)
	if g, b := agent.markGood.Load(), agent.markBad.Load(); g != 0 || b != 1 {
		t.Errorf("mark-good %d, mark-bad %d; want 0 and 1", g, b)
	}
	if !strings.Contains(j.Error, selfStoreNotReady) {
		t.Errorf("job error %q, want it to carry %q", j.Error, selfStoreNotReady)
	}
}

// TC-767-05: N100 semantics. rasputin-mark-good.service has already marked
// the slot good at boot; mark-bad still reaches the agent and moves it to bad.
func TestResumeSelfUpdates_SealedStoreMarksBadAfterTheAutomaticMarkGood(t *testing.T) {
	agent, j, store, changes := runResumedSelfUpdate(t, true)
	if agent.slotGood.Load() {
		t.Error("the modelled slot is still good; mark-bad did not move it to bad")
	}
	if g, b := agent.markGood.Load(), agent.markBad.Load(); g != 0 || b != 1 {
		t.Errorf("mark-good %d, mark-bad %d; want 0 and 1", g, b)
	}
	if row := rowStatus(t, store, j.ID); row.Status != NodeUpdateRolledBack {
		t.Errorf("row status %q, want rolled_back", row.Status)
	}
	if j.Status != jobs.StatusFailed {
		t.Errorf("job status %q, want failed", j.Status)
	}
	if evts := changes.settled(t); countChange(evts, proto.UpdateRolledBack) != 1 {
		t.Errorf("events %+v, want one rolled_back", evts)
	}
}

// TC-767-06: the check is measured against the window. The store wait ends no
// earlier than the window's deadline, mark-bad still reaches the agent after
// that deadline has passed (the detached context), and the whole thing takes
// at most the window plus markBadBound.
func TestSelfStoreCheck_MarkBadIsDeliveredAfterTheWindow(t *testing.T) {
	const node, jid = "cp", "j-window"
	nc := startNATS(t)
	store := newStoreFixture(t).store
	seedInProgressRow(t, store, jid, node)
	agent := startSelfAgent(t, nc, node, true, markBadAccepts, false)
	log, _ := logkittest.New()
	sc := newStoreCheck(t, &fakeStore{t: t, script: []storeAnswer{answerSealed}}, log)
	sc.window = selfUpdateWindow // the ctx deadline is the window here

	start := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), start.Add(testWindow))
	defer cancel()
	deadline, _ := ctx.Deadline()
	if _, err := healthCheckAndCommit(ctx, nc, store, nil, sc, node, "sha", jid, nil); err == nil {
		t.Fatal("want an error: the store never came ready")
	}
	arrived := agent.markBadArrival()
	if arrived.IsZero() {
		t.Fatal("mark-bad never reached the agent")
	}
	if arrived.Before(deadline) {
		t.Errorf("mark-bad arrived %v before the window's deadline; the store wait ended early", deadline.Sub(arrived))
	}
	if ctx.Err() == nil {
		t.Error("the window's context had not expired when mark-bad was delivered")
	}
	if took, limit := arrived.Sub(start), testWindow+markBadBound; took > limit {
		t.Errorf("call to mark-bad took %v, want at most %v", took, limit)
	}
}

// TC-767-07: no responder for mark-bad. The error says not delivered, wraps
// the transport cause and never says "mark-bad sent"; the row is failed, not
// rolled_back; and the job fails.
func TestSelfStoreCheck_MarkBadNotDeliveredIsNotARollback(t *testing.T) {
	const node, jid = "cp", "j-nomarkbad"
	nc := startNATS(t)
	store := newStoreFixture(t).store
	jobStore := newJobStore(t)
	runner := jobs.NewRunner(jobStore, nc)
	seedSelfUpdateJob(t, jobStore, store, jid, node, "sha")
	startSelfAgent(t, nc, node, true, markBadNoResponder, false)
	changes := watchChanges(t, nc, node)
	log, _ := logkittest.New()
	sc := newStoreCheck(t, &fakeStore{t: t, script: []storeAnswer{answerSealed}}, log)

	_, err := healthCheckAndCommit(windowCtx(t), nc, store, nil, sc, node, "sha", jid, nil)
	if !errors.Is(err, nats.ErrNoResponders) {
		t.Errorf("error %v does not wrap the transport cause", err)
	}
	if err == nil || !strings.Contains(err.Error(), "mark-bad not delivered") || !strings.Contains(err.Error(), "NOT rolled back") {
		t.Errorf("error %v, want it to say mark-bad was not delivered and the update was NOT rolled back", err)
	}
	if err != nil && strings.Contains(err.Error(), "mark-bad sent") {
		t.Errorf("error %q claims mark-bad was sent", err)
	}
	if row := rowStatus(t, store, jid); row.Status != NodeUpdateFailed {
		t.Errorf("row status %q, want failed", row.Status)
	}
	if evts := changes.settled(t); countChange(evts, proto.UpdateRolledBack) != 0 {
		t.Errorf("events %+v, want no rolled_back", evts)
	}

	// The job: the same branch, reached through the self-update's finish.
	reconcileSelfUpdate(context.Background(), store, nil, runner, nc, sc, UpdateSpec{NodeID: node, BundleSHA256: "sha"}, jid, "")
	j, _ := jobStore.GetJob(context.Background(), jid)
	if j == nil || j.Status != jobs.StatusFailed || !strings.Contains(j.Error, "NOT rolled back") {
		t.Errorf("job %+v, want failed with an error saying the update was NOT rolled back", j)
	}
}

// TC-767-08 (F-767-01): mark-bad answered OK:false. The error names the
// rejection and its detail, the row is failed, no rolled_back event is
// published, and the job fails.
func TestSelfStoreCheck_MarkBadRejectedIsNotARollback(t *testing.T) {
	const node, jid = "cp", "j-rejected"
	nc := startNATS(t)
	store := newStoreFixture(t).store
	jobStore := newJobStore(t)
	runner := jobs.NewRunner(jobStore, nc)
	seedSelfUpdateJob(t, jobStore, store, jid, node, "sha")
	agent := startSelfAgent(t, nc, node, true, markBadRejects, true)
	changes := watchChanges(t, nc, node)
	log, _ := logkittest.New()
	sc := newStoreCheck(t, &fakeStore{t: t, script: []storeAnswer{answerSealed}}, log)

	reconcileSelfUpdate(context.Background(), store, nil, runner, nc, sc, UpdateSpec{NodeID: node, BundleSHA256: "sha"}, jid, "")

	j, _ := jobStore.GetJob(context.Background(), jid)
	if j == nil || j.Status != jobs.StatusFailed {
		t.Fatalf("job %+v, want failed", j)
	}
	for _, want := range []string{"mark-bad rejected: " + raucMarkBadFailure, "NOT rolled back"} {
		if !strings.Contains(j.Error, want) {
			t.Errorf("job error %q, want it to carry %q", j.Error, want)
		}
	}
	if agent.markBad.Load() != 1 {
		t.Errorf("mark-bad received %d times, want 1", agent.markBad.Load())
	}
	row := rowStatus(t, store, jid)
	if row.Status != NodeUpdateFailed {
		t.Errorf("row status %q, want failed", row.Status)
	}
	if !strings.Contains(row.Error, raucMarkBadFailure) || row.ToVersion != "v1" {
		t.Errorf("row %+v, want the rejection in its error and its target version kept", row)
	}
	if evts := changes.settled(t); countChange(evts, proto.UpdateRolledBack) != 0 {
		t.Errorf("events %+v, want no rolled_back", evts)
	}
}

// The row write's error is joined into the returned error, not dropped
// (F-767-01).
func TestMarkBadAndRecord_RowWriteErrorIsReturned(t *testing.T) {
	const node = "cp"
	nc := startNATS(t)
	fx := newStoreFixture(t)
	startSelfAgent(t, nc, node, true, markBadAccepts, false)
	if err := fx.store.db.Close(); err != nil {
		t.Fatal(err)
	}
	err := markBadAndRecord(context.Background(), nc, fx.store, nil, node, "sha", "j", "unhealthy", nil)
	if err == nil || !strings.Contains(err.Error(), "record node_update:") || !strings.Contains(err.Error(), "mark-bad sent") {
		t.Errorf("error %v, want the mark-bad outcome and the row write's failure", err)
	}
}

// An unreadable mark-bad reply is not a rollback either.
func TestSendMarkBad_UnreadableReply(t *testing.T) {
	nc := startNATS(t)
	s, err := nc.Subscribe(proto.UpdateMarkBadSubject("cp"), func(m *nats.Msg) { _ = m.Respond([]byte("not json")) })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Unsubscribe() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sendMarkBad(ctx, nc, "cp", "sha", "r"); err == nil || !strings.Contains(err.Error(), "mark-bad reply unreadable") {
		t.Errorf("sendMarkBad = %v, want an unreadable-reply error", err)
	}
}

// TC-767-09: step 8 consults the store only for the self node, and a nil
// check commits the self node on diag.health alone.
func TestUpdateHealthCheckAndCommit_StoreCheckIsForTheSelfNodeOnly(t *testing.T) {
	log, _ := logkittest.New()
	run := func(t *testing.T, node string, cfg Config) {
		t.Helper()
		nc := startNATS(t)
		store := newStoreFixture(t).store
		seedInProgressRow(t, store, "j", node)
		agent := startSelfAgent(t, nc, node, true, markBadAccepts, false)
		sc := newUpdaterCtx("j", specJSON(node, "sha"), nc)
		if _, err := updateHealthCheckAndCommit(store, nil, cfg)(sc); err != nil {
			t.Fatalf("step: %v", err)
		}
		if g, b := agent.markGood.Load(), agent.markBad.Load(); g != 1 || b != 0 {
			t.Errorf("mark-good %d, mark-bad %d; want 1 and 0", g, b)
		}
		if row := rowStatus(t, store, "j"); row.Status != NodeUpdateCommitted {
			t.Errorf("row status %q, want committed", row.Status)
		}
	}
	t.Run("another node never consults the store", func(t *testing.T) {
		fs := &fakeStore{t: t, script: []storeAnswer{answerSealed}, forbidden: true}
		run(t, "compute1", Config{SelfNodeID: "cp", StoreCheck: newStoreCheck(t, fs, log)})
		if fs.calls.Load() != 0 {
			t.Errorf("store consulted %d times", fs.calls.Load())
		}
	})
	t.Run("the self node consults the store", func(t *testing.T) {
		fs := &fakeStore{t: t, script: []storeAnswer{answerReady}}
		run(t, "cp", Config{SelfNodeID: "cp", StoreCheck: newStoreCheck(t, fs, log)})
		if fs.calls.Load() == 0 {
			t.Error("the store was never consulted for the self node")
		}
	})
	t.Run("no check commits on diag.health alone", func(t *testing.T) {
		run(t, "cp", Config{SelfNodeID: "cp"})
	})
}

// TC-767-10: a remote node whose step deadline fires while diag.health is in
// flight still gets its mark-bad (the detached context), and the row is
// rolled_back.
func TestUpdateHealthCheckAndCommit_MarkBadAfterTheStepDeadline(t *testing.T) {
	const node = "compute1"
	nc := startNATS(t)
	store := newStoreFixture(t).store
	seedInProgressRow(t, store, "j", node)

	d := deadlinetest.New()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) }) // runs before the server shuts down
	hs, err := nc.Subscribe(proto.NodeCmdSubject(node, "diag.health"), func(m *nats.Msg) {
		d.Fire() // the deadline fires while diag.health is in flight
		<-release
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hs.Unsubscribe() }()
	var firedBeforeMarkBad atomic.Bool
	var markBads atomic.Int32
	ms, err := nc.Subscribe(proto.UpdateMarkBadSubject(node), func(m *nats.Msg) {
		firedBeforeMarkBad.Store(d.Err() != nil)
		markBads.Add(1)
		_ = m.Respond(mustJSON(proto.UpdateMarkBadAck{OK: true}))
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ms.Unsubscribe() }()
	_ = nc.Flush()

	sc := newUpdaterCtx("j", specJSON(node, "sha"), nc)
	sc.Ctx = d
	if _, err := updateHealthCheckAndCommit(store, nil, Config{SelfNodeID: "cp"})(sc); err == nil || !strings.Contains(err.Error(), "mark-bad sent") {
		t.Fatalf("step error %v, want the armed rollback", err)
	}
	if markBads.Load() != 1 || !firedBeforeMarkBad.Load() {
		t.Errorf("mark-bad received %d times, deadline fired first %v; want 1 and true", markBads.Load(), firedBeforeMarkBad.Load())
	}
	if row := rowStatus(t, store, "j"); row.Status != NodeUpdateRolledBack {
		t.Errorf("row status %q, want rolled_back", row.Status)
	}
}

// TC-767-11: an unhealthy diag.health never reaches the store check; the
// existing mark-bad path runs with diag.health's own detail.
func TestSelfStoreCheck_UnhealthyNodeNeverAsksTheStore(t *testing.T) {
	const node, jid = "cp", "j-unhealthy"
	nc := startNATS(t)
	store := newStoreFixture(t).store
	seedInProgressRow(t, store, jid, node)
	agent := startSelfAgent(t, nc, node, false, markBadAccepts, false)
	log, _ := logkittest.New()
	fs := &fakeStore{t: t, script: []storeAnswer{answerReady}, forbidden: true}
	sc := newStoreCheck(t, fs, log)

	_, err := healthCheckAndCommit(windowCtx(t), nc, store, nil, sc, node, "sha", jid, nil)
	if err == nil || !strings.Contains(err.Error(), "failed critical checks: nft-ruleset") {
		t.Errorf("error %v, want diag.health's detail", err)
	}
	if fs.calls.Load() != 0 {
		t.Errorf("store consulted %d times, want 0", fs.calls.Load())
	}
	if agent.markBad.Load() != 1 {
		t.Errorf("mark-bad received %d times, want 1", agent.markBad.Load())
	}
}

// TC-767-12 (updater half): the constructor refuses a nil collaborator, and a
// check over a Disabled store, which a refused store configuration wires,
// answers not ready.
func TestNewSelfStoreCheck(t *testing.T) {
	log, _ := logkittest.New()
	if _, err := NewSelfStoreCheck(nil, log); err == nil {
		t.Error("nil store: want an error")
	}
	if _, err := NewSelfStoreCheck(secretstore.Disabled{}, nil); err == nil {
		t.Error("nil logger: want an error")
	}
	sc := newStoreCheck(t, secretstore.Disabled{}, log)
	if ok, detail := sc.ready(windowCtx(t), "cp", "j"); ok || detail != selfStoreNotReady {
		t.Errorf("Disabled store: ready = (%v, %q), want (false, %q)", ok, detail, selfStoreNotReady)
	}
}

// TC-767-14: one WARN record with its fields when the store is not ready, one
// INFO record when it is, and none of WaitReady's text on the job error, the
// row or the event (ERR-BOUNDARY).
func TestSelfStoreCheck_RecordsAndBoundaryText(t *testing.T) {
	t.Run("not ready", func(t *testing.T) {
		const node, jid = "cp", "j-warn"
		nc := startNATS(t)
		store := newStoreFixture(t).store
		seedInProgressRow(t, store, jid, node)
		startSelfAgent(t, nc, node, true, markBadAccepts, false)
		changes := watchChanges(t, nc, node)
		log, rec := logkittest.New()
		sc := newStoreCheck(t, &fakeStore{t: t, script: []storeAnswer{answerSealed}}, log)

		_, err := healthCheckAndCommit(windowCtx(t), nc, store, nil, sc, node, "sha", jid, nil)
		if err == nil {
			t.Fatal("want an error")
		}
		recs := rec.Matching(slog.LevelWarn, "secret store not ready; marking the self-update bad")
		if len(recs) != 1 {
			t.Fatalf("%d WARN records, want 1: %s", len(recs), rec.Text())
		}
		want := map[string]string{"component": "updater", "event": "updater.self_update_store_not_ready", "node_id": node, "job_id": jid}
		for k, v := range want {
			if got, _ := logkittest.Attr(recs[0], k); got != v {
				t.Errorf("field %s = %q, want %q", k, got, v)
			}
		}
		storeErr, ok := logkittest.Attr(recs[0], "err")
		if !ok || !strings.Contains(storeErr, "did not answer 200") {
			t.Fatalf("err field %q, want WaitReady's error", storeErr)
		}
		row := rowStatus(t, store, jid)
		evts := changes.settled(t)
		if len(evts) != 1 {
			t.Fatalf("events %+v, want one", evts)
		}
		for where, text := range map[string]string{"job error": err.Error(), "row detail": row.Error, "event reason": evts[0].Reason} {
			if !strings.Contains(text, selfStoreNotReady) {
				t.Errorf("%s %q lacks the fixed sentence", where, text)
			}
			for _, leak := range []string{"did not answer 200", "last: sealed", secretstore.ErrSealed.Error()} {
				if strings.Contains(text, leak) {
					t.Errorf("%s %q carries the store's error text %q", where, text, leak)
				}
			}
		}
	})
	t.Run("ready", func(t *testing.T) {
		const node, jid = "cp", "j-info"
		nc := startNATS(t)
		store := newStoreFixture(t).store
		seedInProgressRow(t, store, jid, node)
		startSelfAgent(t, nc, node, true, markBadAccepts, false)
		log, rec := logkittest.New()
		sc := newStoreCheck(t, &fakeStore{t: t, script: []storeAnswer{answerReady}}, log)

		if _, err := healthCheckAndCommit(context.Background(), nc, store, nil, sc, node, "sha", jid, nil); err != nil {
			t.Fatal(err)
		}
		recs := rec.Matching(slog.LevelInfo, "secret store ready for the self-update commit")
		if len(recs) != 1 {
			t.Fatalf("%d INFO records, want 1: %s", len(recs), rec.Text())
		}
		want := map[string]string{"event": "updater.self_update_store_ready", "node_id": node, "job_id": jid}
		for k, v := range want {
			if got, _ := logkittest.Attr(recs[0], k); got != v {
				t.Errorf("field %s = %q, want %q", k, got, v)
			}
		}
	})
}
