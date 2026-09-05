package storage

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Target health (#398): the poll's verdict for every way a claimed target can
// stop being one, and the row's memory of when it first noticed.

const healthPartUUID = "part-uuid-health"

// seedClaimed records a claimed target on testNode at testDevice with the
// post-claim fingerprint, the way persist_target leaves it.
func seedClaimed(t *testing.T, st *Store) *BackupTarget {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.CreatePending(ctx, "job-health", testNode, testDevice, "e3bench-backup", now); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkClaimed(ctx, "job-health", ClaimResult{
		PartUUID: healthPartUUID, DevicePath: testDevice, MountPath: "/mnt/rasputin-backup",
		FSType: "ext4", SizeBytes: 2 << 40, Fingerprint: "fp-after-format", At: now,
	}); err != nil {
		t.Fatal(err)
	}
	tgt, err := st.GetByPartUUID(ctx, healthPartUUID)
	if err != nil || tgt == nil {
		t.Fatalf("GetByPartUUID: %v %v", tgt, err)
	}
	return tgt
}

func healthyInspect(cmd proto.StorageInspectCmd) proto.StorageInspectAck {
	ack := defaultInspectAck(cmd)
	ack.FreeBytes = 1 << 40
	if cmd.Probe {
		ack.WriteProbe = &proto.StorageWriteProbe{OK: true, Detail: "wrote, fsynced, read back and deleted a 4096-byte file", DurationMs: 12}
	}
	return ack
}

type healthFixture struct {
	nc    *nats.Conn
	store *Store
	inv   *inventory.Store
	agent *fakeAgent
	tgt   *BackupTarget
}

func newHealthFixture(t *testing.T) *healthFixture {
	t.Helper()
	nc := startNATS(t)
	st := newStore(t)
	inv := newInventory(t, testNode)
	agent := (&fakeAgent{nodeID: testNode, inspect: healthyInspect}).start(t, nc)
	return &healthFixture{nc: nc, store: st, inv: inv, agent: agent, tgt: seedClaimed(t, st)}
}

func (f *healthFixture) check(t *testing.T) proto.BackupTargetHealth {
	t.Helper()
	h, err := CheckTarget(context.Background(), f.nc, f.inv, f.store, f.tgt)
	if err != nil {
		t.Fatalf("CheckTarget: %v", err)
	}
	return h
}

func (f *healthFixture) setInspect(fn func(proto.StorageInspectCmd) proto.StorageInspectAck) {
	f.agent.mu.Lock()
	f.agent.inspect = fn
	f.agent.mu.Unlock()
}

func TestTargetHealth_UnknownUntilTheFirstPoll(t *testing.T) {
	st := newStore(t)
	tgt := seedClaimed(t, st)
	if tgt.Health == nil || tgt.Health.State != proto.BackupTargetHealthUnknown {
		t.Fatalf("health before any poll = %+v, want unknown", tgt.Health)
	}
	reports, err := st.ClaimedTargetHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].Health.State.Unhealthy() {
		t.Errorf("reports = %+v; unknown must not read as unhealthy", reports)
	}
	// A row that is not in service carries no health at all.
	if err := st.CreatePending(context.Background(), "job-failed", testNode, testDevice, "x", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkFailed(context.Background(), "job-failed", "boom", time.Now()); err != nil {
		t.Fatal(err)
	}
	failed, _ := st.GetByJob(context.Background(), "job-failed")
	if failed.Health != nil {
		t.Errorf("a failed claim carries health %+v", failed.Health)
	}
}

func TestTargetHealth_HealthyTargetIsOK(t *testing.T) {
	f := newHealthFixture(t)
	h := f.check(t)
	if h.State != proto.BackupTargetHealthOK {
		t.Fatalf("state = %s (%s), want ok", h.State, h.Detail)
	}
	if h.ProbeDurationMs != 12 || !strings.Contains(h.Detail, "read back") {
		t.Errorf("health = %+v; the probe's finding should be on the row", h)
	}
	cmds := f.agent.inspectCmds
	if len(cmds) != 1 || !cmds[0].Probe {
		t.Errorf("inspect cmds = %+v; the poll must ask for the write probe", cmds)
	}
	if f.agent.enumerateCalls != 0 {
		t.Error("a healthy target was enumerated — that RPC is for the missing case only")
	}
}

func TestTargetHealth_AbsentIsMissingAndNamesADifferentDiskAtTheOldPath(t *testing.T) {
	f := newHealthFixture(t)
	f.setInspect(func(cmd proto.StorageInspectCmd) proto.StorageInspectAck {
		return proto.StorageInspectAck{OK: true, Present: false, PartUUID: cmd.PartUUID,
			Refusal: proto.StorageRefusalNotFound, Detail: "no attached disk carries that partition UUID"}
	})
	other := blankCandidate()
	other.Fingerprint = testOtherFing
	other.Model = "SanDisk Cruzer"
	f.agent.enumerate = func(int) proto.StorageEnumerateAck { return ackWith(other) }

	h := f.check(t)
	if h.State != proto.BackupTargetHealthMissing {
		t.Fatalf("state = %s, want missing", h.State)
	}
	for _, want := range []string{healthPartUUID, "DIFFERENT disk", testDevice, "SanDisk Cruzer", "nothing will be written"} {
		if !strings.Contains(h.Detail, want) {
			t.Errorf("detail %q does not say %q", h.Detail, want)
		}
	}

	// Nothing at the old path at all: said in those words.
	f.agent.enumerate = func(int) proto.StorageEnumerateAck { return ackWith() }
	h = f.check(t)
	if h.State != proto.BackupTargetHealthMissing || !strings.Contains(h.Detail, "nothing is attached at "+testDevice) {
		t.Errorf("health = %+v", h)
	}
}

func TestTargetHealth_AttachedButUnmountable(t *testing.T) {
	f := newHealthFixture(t)
	f.setInspect(func(cmd proto.StorageInspectCmd) proto.StorageInspectAck {
		return proto.StorageInspectAck{OK: false, Present: true, PartUUID: cmd.PartUUID, DevicePath: "/dev/sdb1",
			Refusal: proto.StorageRefusalBackendError, Detail: "/dev/sdb1 is attached but could not be mounted: mount: wrong fs type"}
	})
	h := f.check(t)
	if h.State != proto.BackupTargetHealthUnmounted || !strings.Contains(h.Detail, "wrong fs type") {
		t.Errorf("health = %+v, want unmounted with the mount error", h)
	}
}

func TestTargetHealth_MountedButFailingWritesIsUnwritable(t *testing.T) {
	f := newHealthFixture(t)
	f.setInspect(func(cmd proto.StorageInspectCmd) proto.StorageInspectAck {
		ack := healthyInspect(cmd)
		ack.WriteProbe = &proto.StorageWriteProbe{OK: false, Detail: "fsync probe file: input/output error", DurationMs: 4100}
		return ack
	})
	h := f.check(t)
	if h.State != proto.BackupTargetHealthUnwritable {
		t.Fatalf("state = %s, want unwritable — the e3bench disk enumerated fine and refused writes", h.State)
	}
	if !strings.Contains(h.Detail, "input/output error") || h.ProbeDurationMs != 4100 {
		t.Errorf("health = %+v; the probe's own finding is the detail", h)
	}
}

func TestTargetHealth_NoAnswerIsUnreachableAndNamesTheSilence(t *testing.T) {
	nc := startNATS(t)
	st := newStore(t)
	inv := newInventory(t, testNode)
	tgt := seedClaimed(t, st)
	// No fake agent at all: nothing subscribes to testNode's inspect subject.
	h, err := CheckTarget(context.Background(), nc, inv, st, tgt)
	if err != nil {
		t.Fatal(err)
	}
	if h.State != proto.BackupTargetHealthUnreachable {
		t.Fatalf("state = %s, want unreachable — a silence is a failure, not a skip", h.State)
	}
	if h.State == proto.BackupTargetHealthUnknown {
		t.Fatal("unknown after a poll")
	}
	for _, want := range []string{"no answer", testNode, "storage.inspect"} {
		if !strings.Contains(h.Detail, want) {
			t.Errorf("detail %q does not say %q", h.Detail, want)
		}
	}
	// inventory's reading of the silence: the node is online (just seeded)
	// and nothing answered, so it is a fault and said so.
	if !strings.Contains(h.Detail, "did not") && !strings.Contains(h.Detail, "online") {
		t.Errorf("detail %q does not carry inventory's reading of the silence", h.Detail)
	}
}

func TestTargetHealth_OldAgentIsOKWithTheProbeGapStated(t *testing.T) {
	f := newHealthFixture(t)
	f.setInspect(func(cmd proto.StorageInspectCmd) proto.StorageInspectAck {
		ack := defaultInspectAck(cmd) // no WriteProbe, whatever was asked
		return ack
	})
	node, _ := f.inv.Get(context.Background(), testNode)
	node.AgentVersion = "2026.08.5-dev.140"
	if err := f.inv.Update(context.Background(), node); err != nil {
		t.Fatal(err)
	}
	h := f.check(t)
	if h.State != proto.BackupTargetHealthOK {
		t.Fatalf("state = %s; presence and mount are real findings", h.State)
	}
	for _, want := range []string{"NOT performed", "predates", "update the node"} {
		if !strings.Contains(h.Detail, want) {
			t.Errorf("detail %q does not say %q", h.Detail, want)
		}
	}
}

func TestTargetHealth_MarkerNamingAnotherSetIsMissing(t *testing.T) {
	f := newHealthFixture(t)
	f.setInspect(func(cmd proto.StorageInspectCmd) proto.StorageInspectAck {
		ack := healthyInspect(cmd)
		ack.BackupSet.PartUUID = "part-uuid-someone-elses"
		return ack
	})
	h := f.check(t)
	if h.State != proto.BackupTargetHealthMissing || !strings.Contains(h.Detail, "part-uuid-someone-elses") {
		t.Errorf("health = %+v, want missing naming the other set", h)
	}
}

func TestTargetHealth_SincePersistsAcrossPollsAndResetsOnChange(t *testing.T) {
	f := newHealthFixture(t)
	absent := func(cmd proto.StorageInspectCmd) proto.StorageInspectAck {
		return proto.StorageInspectAck{OK: true, Present: false, PartUUID: cmd.PartUUID}
	}
	f.setInspect(absent)
	first := f.check(t)
	time.Sleep(15 * time.Millisecond)
	second := f.check(t)
	if second.State != proto.BackupTargetHealthMissing {
		t.Fatalf("state = %s", second.State)
	}
	if !second.Since.Equal(first.Since) {
		t.Errorf("since moved from %s to %s on a poll that found the same state — the row must count from the first poll that noticed", first.Since, second.Since)
	}
	if !second.CheckedAt.After(first.CheckedAt) {
		t.Errorf("checkedAt did not advance: %s → %s", first.CheckedAt, second.CheckedAt)
	}

	// The disk comes back: ok on the next poll, no operator action, since reset.
	f.setInspect(healthyInspect)
	back := f.check(t)
	if back.State != proto.BackupTargetHealthOK {
		t.Fatalf("state after return = %s", back.State)
	}
	if !back.Since.After(first.Since) {
		t.Errorf("since did not reset on the state change: %s vs %s", back.Since, first.Since)
	}
	row, _ := f.store.GetByPartUUID(context.Background(), healthPartUUID)
	if row.Health == nil || row.Health.State != proto.BackupTargetHealthOK || !row.Health.Since.Equal(back.Since) {
		t.Errorf("row health = %+v, want what CheckTarget returned", row.Health)
	}
}

func TestTargetHealth_RecordRefusesUnknown(t *testing.T) {
	st := newStore(t)
	seedClaimed(t, st)
	if _, err := st.RecordHealth(context.Background(), healthPartUUID, proto.BackupTargetHealth{State: proto.BackupTargetHealthUnknown}); err == nil {
		t.Error("recording unknown was accepted; after a poll the state is never unknown")
	}
	if _, err := st.RecordHealth(context.Background(), "no-such", proto.BackupTargetHealth{State: proto.BackupTargetHealthOK}); err == nil {
		t.Error("recording health on an unclaimed partition was accepted")
	}
}

// The scheduled workflow: succeeds on an unhealthy target (the row and the
// alert are the signal; a failing job every five minutes is noise) and records
// every claimed target.
func TestTargetHealthWorkflow_RecordsWithoutFailingTheJob(t *testing.T) {
	f := newHealthFixture(t)
	f.setInspect(func(cmd proto.StorageInspectCmd) proto.StorageInspectAck {
		return proto.StorageInspectAck{OK: true, Present: false, PartUUID: cmd.PartUUID}
	})
	// The jobs ledger shares the target ledger's SQLite file in production;
	// here a separate file is enough — the workflow only reads jobs through
	// the runner.
	js, err := jobs.OpenStore(context.Background(), filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.Close() })
	r := jobs.NewRunner(js, f.nc)
	r.SetBackoff(func(int) time.Duration { return 0 })
	r.Register(TargetHealthWorkflow(f.store, f.inv))

	due, _ := TargetHealthDue(f.store)(context.Background())
	if !due {
		t.Fatal("a claimed target exists and the tick is not due")
	}
	j, err := r.Submit(context.Background(), TargetHealthJobKind, []byte(`{}`), "test")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, _ := js.GetJob(context.Background(), j.ID)
		if got != nil && (got.Status == jobs.StatusSucceeded || got.Status == jobs.StatusFailed) {
			if got.Status != jobs.StatusSucceeded {
				t.Fatalf("job %s: %s — an unhealthy target must not fail the poll", got.Status, got.Error)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("job never finished")
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.Wait()
	row, _ := f.store.GetByPartUUID(context.Background(), healthPartUUID)
	if row.Health == nil || row.Health.State != proto.BackupTargetHealthMissing {
		t.Errorf("row health = %+v after the workflow, want missing", row.Health)
	}
}

func TestTargetHealthDue_SilentWithoutATarget(t *testing.T) {
	st := newStore(t)
	due, reason := TargetHealthDue(st)(context.Background())
	if due || reason != "" {
		t.Errorf("due = %v %q with nothing claimed; want a silent skip", due, reason)
	}
}

func TestHealthFresh(t *testing.T) {
	now := time.Now().UTC()
	fresh := &proto.BackupTargetHealth{State: proto.BackupTargetHealthMissing, CheckedAt: now.Add(-4 * time.Minute)}
	stale := &proto.BackupTargetHealth{State: proto.BackupTargetHealthMissing, CheckedAt: now.Add(-2 * time.Hour)}
	unknown := &proto.BackupTargetHealth{State: proto.BackupTargetHealthUnknown}
	if !HealthFresh(fresh, now) || HealthFresh(stale, now) || HealthFresh(unknown, now) || HealthFresh(nil, now) {
		t.Error("freshness window is wrong")
	}
}

func TestDescribeHealth(t *testing.T) {
	now := time.Now().UTC()
	h := proto.BackupTargetHealth{State: proto.BackupTargetHealthMissing, Since: now.Add(-3 * time.Hour), CheckedAt: now.Add(-2 * time.Minute), Detail: "nothing attached carries it"}
	s := DescribeHealth(h)
	for _, want := range []string{"MISSING since", "3h", "last probe", "nothing attached carries it"} {
		if !strings.Contains(s, want) {
			t.Errorf("%q does not say %q", s, want)
		}
	}
	if DescribeHealth(proto.BackupTargetHealth{}) != "health not checked yet" {
		t.Error("an empty record should read as not checked")
	}
}
