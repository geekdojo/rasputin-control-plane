package updater

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
	natsserver "github.com/nats-io/nats-server/v2/test"
	"github.com/nats-io/nats.go"
)

// startNATS spins up an in-process NATS server on a random port and returns a
// connected client. Server shuts down on test cleanup.
func startNATS(t *testing.T) *nats.Conn {
	t.Helper()
	srv := natsserver.RunRandClientPortServer()
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func newInventory(t *testing.T) *inventory.Store {
	t.Helper()
	dir := t.TempDir()
	inv, err := inventory.OpenStore(context.Background(), filepath.Join(dir, "inv.db"))
	if err != nil {
		t.Fatalf("inventory OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = inv.Close() })
	return inv
}

// seedNodeAndBundle puts a compute node in the inventory and a bundle in the
// updater store, returning the populated stores. The bundle's SHA matches
// the saga spec.
func seedNodeAndBundle(t *testing.T, store *Store, inv *inventory.Store, nodeID, bundleSHA, version string) {
	t.Helper()
	ctx := context.Background()
	if err := inv.Insert(ctx, &proto.Node{
		ID:        nodeID,
		Role:      proto.RoleCompute,
		Hostname:  nodeID + ".test",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	if err := store.CreateBundle(ctx, &Bundle{
		SHA256:       bundleSHA,
		Version:      version,
		Compatible:   "rasputin-test",
		Architecture: "arm64",
		SizeBytes:    1024,
		UploadedAt:   time.Now().UTC(),
		UploadedBy:   "tester",
	}); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
}

func newUpdaterCtx(jobID, spec string, nc *nats.Conn) *jobs.StepCtx {
	return &jobs.StepCtx{
		Ctx:   context.Background(),
		JobID: jobID,
		NATS:  nc,
		Spec:  json.RawMessage(spec),
		Log:   func(level, message string) {},
	}
}

func specJSON(nodeID, sha string) string {
	return `{"nodeId":"` + nodeID + `","bundleSha256":"` + sha + `"}`
}

// ============================================================================
// updateValidate
// ============================================================================

func TestUpdateValidate_HappyPath(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)
	seedNodeAndBundle(t, store, inv, "n", "sha-1", "v1")

	sc := newUpdaterCtx("j", specJSON("n", "sha-1"), nc)
	out, err := updateValidate(store, inv)(sc)
	if err != nil {
		t.Fatalf("updateValidate: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected result")
	}
	// Persisted in-progress row.
	row, _ := store.GetNodeUpdate(ctx, "j")
	if row == nil || row.Status != NodeUpdateInProgress {
		t.Errorf("update row: %+v", row)
	}
}

func TestUpdateValidate_BadSpec(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)
	sc := newUpdaterCtx("j", `{}`, nc)
	if _, err := updateValidate(store, inv)(sc); err == nil {
		t.Error("missing nodeId: want error")
	}
}

func TestUpdateValidate_UnknownNode(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)
	sc := newUpdaterCtx("j", specJSON("missing", "sha"), nc)
	if _, err := updateValidate(store, inv)(sc); err == nil {
		t.Error("unknown node: want error")
	}
}

func TestUpdateValidate_UnknownBundle(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)
	if err := inv.Insert(context.Background(), &proto.Node{
		ID: "n", Role: proto.RoleCompute, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv: %v", err)
	}
	sc := newUpdaterCtx("j", specJSON("n", "no-such"), nc)
	if _, err := updateValidate(store, inv)(sc); err == nil {
		t.Error("unknown bundle: want error")
	}
}

// ============================================================================
// updatePrecheck
// ============================================================================

func TestUpdatePrecheck_HappyPath(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n"
	sub, _ := nc.Subscribe(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{
			OK:             true,
			ActiveSlot:     proto.SlotA,
			InactiveSlot:   proto.SlotB,
			CurrentVersion: "v0",
			Backend:        "mock",
		})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()
	sc := newUpdaterCtx("j", specJSON(nodeID, "sha"), nc)
	out, err := updatePrecheck()(sc)
	if err != nil {
		t.Fatalf("updatePrecheck: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected ack")
	}
}

func TestUpdatePrecheck_BadSpec(t *testing.T) {
	nc := startNATS(t)
	sc := newUpdaterCtx("j", `{}`, nc)
	if _, err := updatePrecheck()(sc); err == nil {
		t.Error("missing nodeId: want error")
	}
}

func TestUpdatePrecheck_AgentRejects(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n"
	sub, _ := nc.Subscribe(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{OK: false, Detail: "no slots free"})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()
	sc := newUpdaterCtx("j", specJSON(nodeID, "sha"), nc)
	if _, err := updatePrecheck()(sc); err == nil {
		t.Error("OK=false: want error")
	}
}

func TestUpdatePrecheck_RPCTimeout(t *testing.T) {
	nc := startNATS(t)
	tctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	sc := newUpdaterCtx("j", specJSON("n", "sha"), nc)
	sc.Ctx = tctx
	if _, err := updatePrecheck()(sc); err == nil {
		t.Error("timeout: want error")
	}
}

func TestUpdatePrecheck_BadAck(t *testing.T) {
	nc := startNATS(t)
	sub, _ := nc.Subscribe(proto.UpdatePrecheckSubject("n"), func(m *nats.Msg) {
		_ = m.Respond([]byte("not-json"))
	})
	defer func() { _ = sub.Unsubscribe() }()
	sc := newUpdaterCtx("j", specJSON("n", "sha"), nc)
	if _, err := updatePrecheck()(sc); err == nil {
		t.Error("bad ack: want error")
	}
}

// ============================================================================
// updateDownload
// ============================================================================

func TestUpdateDownload_HappyPath(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)
	seedNodeAndBundle(t, store, inv, "n", "sha-1", "v1")

	sub, _ := nc.Subscribe(proto.UpdateDownloadSubject("n"), func(m *nats.Msg) {
		var cmd proto.UpdateDownloadCmd
		_ = json.Unmarshal(m.Data, &cmd)
		ack, _ := json.Marshal(proto.UpdateDownloadAck{
			OK:        true,
			LocalPath: "/var/cache/bundles/sha-1",
			SHA256:    cmd.ExpectedSHA256,
		})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()

	sc := newUpdaterCtx("j", specJSON("n", "sha-1"), nc)
	if _, err := updateDownload(store, Config{PublicBaseURL: "http://api"})(sc); err != nil {
		t.Fatalf("updateDownload: %v", err)
	}
}

func TestUpdateDownload_BadSpec(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	sc := newUpdaterCtx("j", `{}`, nc)
	if _, err := updateDownload(store, Config{})(sc); err == nil {
		t.Error("bad spec: want error")
	}
}

func TestUpdateDownload_MissingBundle(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	sc := newUpdaterCtx("j", specJSON("n", "missing"), nc)
	if _, err := updateDownload(store, Config{})(sc); err == nil {
		t.Error("missing bundle: want error")
	}
}

func TestUpdateDownload_AgentRejects(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)
	seedNodeAndBundle(t, store, inv, "n", "sha-1", "v1")
	sub, _ := nc.Subscribe(proto.UpdateDownloadSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdateDownloadAck{OK: false, Detail: "no space"})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()
	sc := newUpdaterCtx("j", specJSON("n", "sha-1"), nc)
	if _, err := updateDownload(store, Config{})(sc); err == nil {
		t.Error("OK=false: want error")
	}
}

func TestUpdateDownload_SHAMismatch(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)
	seedNodeAndBundle(t, store, inv, "n", "sha-1", "v1")
	sub, _ := nc.Subscribe(proto.UpdateDownloadSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdateDownloadAck{OK: true, SHA256: "totally-different"})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()
	sc := newUpdaterCtx("j", specJSON("n", "sha-1"), nc)
	if _, err := updateDownload(store, Config{})(sc); err == nil {
		t.Error("sha mismatch: want error")
	}
}

func TestUpdateDownload_RPCTimeout(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)
	seedNodeAndBundle(t, store, inv, "n", "sha-1", "v1")
	tctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	sc := newUpdaterCtx("j", specJSON("n", "sha-1"), nc)
	sc.Ctx = tctx
	if _, err := updateDownload(store, Config{})(sc); err == nil {
		t.Error("timeout: want error")
	}
}

// ============================================================================
// updateInstall
// ============================================================================

func TestUpdateInstall_HappyPath(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)
	seedNodeAndBundle(t, store, inv, "n", "sha-1", "v1")
	// updateInstall calls SetNodeUpdateSlots which needs a row.
	_ = store.CreateNodeUpdate(ctx, &NodeUpdate{
		JobID: "j", NodeID: "n", BundleSHA256: "sha-1",
		FromSlot: proto.SlotUnknown, ToSlot: proto.SlotUnknown,
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	})

	// Precheck and install RPCs.
	preSub, _ := nc.Subscribe(proto.UpdatePrecheckSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{
			OK: true, ActiveSlot: proto.SlotA, InactiveSlot: proto.SlotB,
			CurrentVersion: "v0", Backend: "mock",
		})
		_ = m.Respond(ack)
	})
	defer func() { _ = preSub.Unsubscribe() }()
	inSub, _ := nc.Subscribe(proto.UpdateInstallSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdateInstallAck{
			OK: true, TargetSlot: proto.SlotB, NewVersion: "v1",
		})
		_ = m.Respond(ack)
	})
	defer func() { _ = inSub.Unsubscribe() }()

	sc := newUpdaterCtx("j", specJSON("n", "sha-1"), nc)
	if _, err := updateInstall(store)(sc); err != nil {
		t.Fatalf("updateInstall: %v", err)
	}
}

func TestUpdateInstall_BadSpec(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	sc := newUpdaterCtx("j", `{}`, nc)
	if _, err := updateInstall(store)(sc); err == nil {
		t.Error("bad spec: want error")
	}
}

func TestUpdateInstall_PrecheckRPCFails(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	tctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	sc := newUpdaterCtx("j", specJSON("n", "sha-1"), nc)
	sc.Ctx = tctx
	if _, err := updateInstall(store)(sc); err == nil {
		t.Error("precheck RPC timeout: want error")
	}
}

func TestUpdateInstall_NoInactiveSlot(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	preSub, _ := nc.Subscribe(proto.UpdatePrecheckSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{
			OK: true, ActiveSlot: proto.SlotA, InactiveSlot: proto.SlotUnknown,
		})
		_ = m.Respond(ack)
	})
	defer func() { _ = preSub.Unsubscribe() }()
	sc := newUpdaterCtx("j", specJSON("n", "sha-1"), nc)
	if _, err := updateInstall(store)(sc); err == nil {
		t.Error("no inactive slot: want error")
	}
}

func TestUpdateInstall_AgentRejects(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	preSub, _ := nc.Subscribe(proto.UpdatePrecheckSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{
			OK: true, ActiveSlot: proto.SlotA, InactiveSlot: proto.SlotB,
		})
		_ = m.Respond(ack)
	})
	defer func() { _ = preSub.Unsubscribe() }()
	inSub, _ := nc.Subscribe(proto.UpdateInstallSubject("n"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdateInstallAck{OK: false, Detail: "install failed"})
		_ = m.Respond(ack)
	})
	defer func() { _ = inSub.Unsubscribe() }()
	sc := newUpdaterCtx("j", specJSON("n", "sha-1"), nc)
	if _, err := updateInstall(store)(sc); err == nil {
		t.Error("OK=false: want error")
	}
}

// ============================================================================
// updateReboot
// ============================================================================

func TestUpdateReboot_HappyPath(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n"

	// Agent acks RPC and immediately publishes the rebooting event.
	sub, _ := nc.Subscribe(proto.UpdateRebootSubject(nodeID), func(m *nats.Msg) {
		_ = m.Respond([]byte(`{"ok":true}`))
		_ = nc.Publish(proto.NodeEvtSubject(nodeID, "rebooting"), []byte(`{"ts":"now"}`))
	})
	defer func() { _ = sub.Unsubscribe() }()

	sc := newUpdaterCtx("j", specJSON(nodeID, "sha"), nc)
	out, err := updateReboot()(sc)
	if err != nil {
		t.Fatalf("updateReboot: %v", err)
	}
	if len(out) == 0 {
		t.Error("expected rebooting event payload")
	}
}

func TestUpdateReboot_BadSpec(t *testing.T) {
	nc := startNATS(t)
	sc := newUpdaterCtx("j", `{}`, nc)
	if _, err := updateReboot()(sc); err == nil {
		t.Error("bad spec: want error")
	}
}

func TestUpdateReboot_RPCFails(t *testing.T) {
	nc := startNATS(t)
	tctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	sc := newUpdaterCtx("j", specJSON("n", "sha"), nc)
	sc.Ctx = tctx
	if _, err := updateReboot()(sc); err == nil {
		t.Error("timeout: want error")
	}
}

// ============================================================================
// updateWaitOnlineAndVerifySlot
// ============================================================================

func TestUpdateWaitOnlineAndVerifySlot_HappyPath(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	const nodeID = "n"
	// Seed the in-progress row with toSlot=B; verify will compare to precheck's
	// ActiveSlot=B and pass.
	_ = store.CreateNodeUpdate(ctx, &NodeUpdate{
		JobID: "j", NodeID: nodeID, BundleSHA256: "sha",
		FromSlot: proto.SlotA, ToSlot: proto.SlotB,
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	})

	preSub, _ := nc.Subscribe(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{
			OK: true, ActiveSlot: proto.SlotB, InactiveSlot: proto.SlotA,
			CurrentVersion: "v1",
		})
		_ = m.Respond(ack)
	})
	defer func() { _ = preSub.Unsubscribe() }()

	// Spawn a publisher that fires the registered event repeatedly so the
	// step's subscribe (which sets up *inside* the step) catches it.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = nc.Publish(proto.NodeRegisteredSubject(nodeID), []byte(`{"nodeId":"`+nodeID+`"}`))
			time.Sleep(20 * time.Millisecond)
		}
	}()

	tctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sc := newUpdaterCtx("j", specJSON(nodeID, "sha"), nc)
	sc.Ctx = tctx
	if _, err := updateWaitOnlineAndVerifySlot(store)(sc); err != nil {
		t.Fatalf("updateWaitOnlineAndVerifySlot: %v", err)
	}
}

func TestUpdateWaitOnlineAndVerifySlot_BootloaderRollback(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	const nodeID = "n"
	_ = store.CreateNodeUpdate(ctx, &NodeUpdate{
		JobID: "j", NodeID: nodeID, BundleSHA256: "sha",
		FromSlot: proto.SlotA, ToSlot: proto.SlotB,
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	})

	// Precheck reports node came up on the *old* slot — rollback.
	preSub, _ := nc.Subscribe(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{
			OK: true, ActiveSlot: proto.SlotA, InactiveSlot: proto.SlotB,
			CurrentVersion: "v0",
		})
		_ = m.Respond(ack)
	})
	defer func() { _ = preSub.Unsubscribe() }()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = nc.Publish(proto.NodeRegisteredSubject(nodeID), []byte(`{}`))
			time.Sleep(20 * time.Millisecond)
		}
	}()

	tctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sc := newUpdaterCtx("j", specJSON(nodeID, "sha"), nc)
	sc.Ctx = tctx
	if _, err := updateWaitOnlineAndVerifySlot(store)(sc); err == nil {
		t.Error("rollback: want error")
	}
	// Row should now be marked rolled_back.
	row, _ := store.GetNodeUpdate(ctx, "j")
	if row == nil || row.Status != NodeUpdateRolledBack {
		t.Errorf("status after rollback: %+v", row)
	}
}

func TestUpdateWaitOnlineAndVerifySlot_BadSpec(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	sc := newUpdaterCtx("j", `{}`, nc)
	if _, err := updateWaitOnlineAndVerifySlot(store)(sc); err == nil {
		t.Error("bad spec: want error")
	}
}

func TestUpdateWaitOnlineAndVerifySlot_NoRegisterEvent_CtxCancel(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	tctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	sc := newUpdaterCtx("j", specJSON("n", "sha"), nc)
	sc.Ctx = tctx
	if _, err := updateWaitOnlineAndVerifySlot(store)(sc); err == nil {
		t.Error("ctx deadline: want error")
	}
}

// ============================================================================
// updateHealthCheckAndCommit — happy + sad paths.
// ============================================================================

func TestUpdateHealthCheckAndCommit_HappyPath(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	const nodeID = "n"
	_ = store.CreateNodeUpdate(ctx, &NodeUpdate{
		JobID: "j", NodeID: nodeID, BundleSHA256: "sha",
		FromSlot: proto.SlotA, ToSlot: proto.SlotB, ToVersion: "v1",
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	})

	pingSub, _ := nc.Subscribe(proto.NodeCmdSubject(nodeID, "diag.ping"), func(m *nats.Msg) {
		_ = m.Respond([]byte(`{"ok":true}`))
	})
	defer func() { _ = pingSub.Unsubscribe() }()
	mgSub, _ := nc.Subscribe(proto.UpdateMarkGoodSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdateMarkGoodAck{OK: true})
		_ = m.Respond(ack)
	})
	defer func() { _ = mgSub.Unsubscribe() }()

	sc := newUpdaterCtx("j", specJSON(nodeID, "sha"), nc)
	if _, err := updateHealthCheckAndCommit(store)(sc); err != nil {
		t.Fatalf("updateHealthCheckAndCommit: %v", err)
	}
	row, _ := store.GetNodeUpdate(ctx, "j")
	if row == nil || row.Status != NodeUpdateCommitted {
		t.Errorf("row after commit: %+v", row)
	}
}

func TestUpdateHealthCheckAndCommit_HealthCheckFails(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	const nodeID = "n"
	_ = store.CreateNodeUpdate(ctx, &NodeUpdate{
		JobID: "j", NodeID: nodeID, BundleSHA256: "sha",
		FromSlot: proto.SlotA, ToSlot: proto.SlotB, ToVersion: "v1",
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	})

	// No diag.ping subscriber → RPC times out. Mark-bad subscriber acks.
	mbSub, _ := nc.Subscribe(proto.UpdateMarkBadSubject(nodeID), func(m *nats.Msg) {
		_ = m.Respond([]byte(`{"ok":true}`))
	})
	defer func() { _ = mbSub.Unsubscribe() }()

	tctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	sc := newUpdaterCtx("j", specJSON(nodeID, "sha"), nc)
	sc.Ctx = tctx
	if _, err := updateHealthCheckAndCommit(store)(sc); err == nil {
		t.Error("health failure: want error")
	}
	row, _ := store.GetNodeUpdate(ctx, "j")
	if row == nil || row.Status != NodeUpdateRolledBack {
		t.Errorf("row after health-fail: %+v", row)
	}
}

func TestUpdateHealthCheckAndCommit_BadSpec(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	sc := newUpdaterCtx("j", `{}`, nc)
	if _, err := updateHealthCheckAndCommit(store)(sc); err == nil {
		t.Error("bad spec: want error")
	}
}

func TestUpdateHealthCheckAndCommit_MarkGoodRejected(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	const nodeID = "n"
	_ = store.CreateNodeUpdate(ctx, &NodeUpdate{
		JobID: "j", NodeID: nodeID, BundleSHA256: "sha",
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	})
	pingSub, _ := nc.Subscribe(proto.NodeCmdSubject(nodeID, "diag.ping"), func(m *nats.Msg) {
		_ = m.Respond([]byte(`{}`))
	})
	defer func() { _ = pingSub.Unsubscribe() }()
	mgSub, _ := nc.Subscribe(proto.UpdateMarkGoodSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdateMarkGoodAck{OK: false, Detail: "boot count not bumped"})
		_ = m.Respond(ack)
	})
	defer func() { _ = mgSub.Unsubscribe() }()

	sc := newUpdaterCtx("j", specJSON(nodeID, "sha"), nc)
	if _, err := updateHealthCheckAndCommit(store)(sc); err == nil {
		t.Error("mark-good rejected: want error")
	}
}

// ============================================================================
// system_jobs: systemPlan, systemCascade, systemSummarize, waitForChild
// ============================================================================

func newJobsStore(t *testing.T) *jobs.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := jobs.OpenStore(context.Background(), filepath.Join(dir, "jobs.db"))
	if err != nil {
		t.Fatalf("jobs OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSystemPlan_HappyPath(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)

	// Two online compute nodes + one self node.
	for _, id := range []string{"a", "b", "self"} {
		if err := inv.Insert(ctx, &proto.Node{
			ID: id, Role: proto.RoleCompute, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("inv %s: %v", id, err)
		}
	}
	if err := store.CreateBundle(ctx, &Bundle{
		SHA256: "sha-sys", Version: "v9", UploadedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("bundle: %v", err)
	}

	spec := `{"bundleSha256":"sha-sys"}`
	sc := newUpdaterCtx("parent", spec, nc)
	out, err := systemPlan(store, inv, SystemUpdateConfig{SelfNodeID: "self"})(sc)
	if err != nil {
		t.Fatalf("systemPlan: %v", err)
	}
	var state systemPlanState
	_ = json.Unmarshal(out, &state)
	if len(state.Targets) != 2 {
		t.Errorf("targets: want 2, got %v", state.Targets)
	}
}

func TestSystemPlan_BadSpec(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)
	sc := newUpdaterCtx("parent", `not-json`, nc)
	if _, err := systemPlan(store, inv, SystemUpdateConfig{})(sc); err == nil {
		t.Error("bad spec: want error")
	}
}

func TestSystemPlan_MissingBundle(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)
	sc := newUpdaterCtx("parent", `{"bundleSha256":"missing"}`, nc)
	if _, err := systemPlan(store, inv, SystemUpdateConfig{})(sc); err == nil {
		t.Error("missing bundle: want error")
	}
}

func TestSystemPlan_MissingSHA(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)
	sc := newUpdaterCtx("parent", `{}`, nc)
	if _, err := systemPlan(store, inv, SystemUpdateConfig{})(sc); err == nil {
		t.Error("missing sha: want error")
	}
}

func TestSystemSummarize_NoChildren(t *testing.T) {
	nc := startNATS(t)
	jobStore := newJobsStore(t)
	sc := newUpdaterCtx("parent", `{}`, nc)
	out, err := systemSummarize(jobStore, nc)(sc)
	if err != nil {
		t.Fatalf("systemSummarize: %v", err)
	}
	var counts proto.SystemUpdateCounts
	_ = json.Unmarshal(out, &counts)
	if counts.Total != 0 || counts.Succeeded != 0 || counts.Failed != 0 {
		t.Errorf("empty counts: got %+v", counts)
	}
}

func TestSystemSummarize_MixedOutcomes(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	jobStore := newJobsStore(t)

	// Parent + three children: one succeeded, one failed, one cancelled.
	parent := "parent"
	if err := jobStore.CreateJob(ctx, &jobs.Job{
		ID: parent, Kind: "system.update", Status: jobs.StatusRunning, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create parent: %v", err)
	}
	for i, kind := range []struct {
		id     string
		status jobs.Status
	}{
		{"c-ok", jobs.StatusSucceeded},
		{"c-fail", jobs.StatusFailed},
		{"c-cancel", jobs.StatusCancelled},
	} {
		_ = i
		p := parent
		c := &jobs.Job{
			ID: kind.id, Kind: "node.update", Status: jobs.StatusQueued,
			ParentID: &p, CreatedAt: time.Now().UTC(),
		}
		if err := jobStore.CreateJob(ctx, c); err != nil {
			t.Fatalf("create child: %v", err)
		}
		now := time.Now().UTC()
		switch kind.status {
		case jobs.StatusSucceeded:
			_ = jobStore.MarkJobSucceeded(ctx, kind.id, now)
		case jobs.StatusFailed:
			_ = jobStore.MarkJobFailed(ctx, kind.id, "x", now)
		case jobs.StatusCancelled:
			_ = jobStore.MarkJobFailed(ctx, kind.id, "cancelled", now)
		}
	}

	sc := newUpdaterCtx(parent, `{}`, nc)
	out, err := systemSummarize(jobStore, nc)(sc)
	if err != nil {
		t.Fatalf("systemSummarize: %v", err)
	}
	var counts proto.SystemUpdateCounts
	_ = json.Unmarshal(out, &counts)
	if counts.Total != 3 {
		t.Errorf("total: want 3, got %d", counts.Total)
	}
	if counts.Succeeded != 1 {
		t.Errorf("succeeded: want 1, got %d", counts.Succeeded)
	}
}

func TestWaitForChild_TerminalSucceeded(t *testing.T) {
	ctx := context.Background()
	jobStore := newJobsStore(t)
	parent := "p"
	if err := jobStore.CreateJob(ctx, &jobs.Job{
		ID: "child", Kind: "node.update", Status: jobs.StatusRunning,
		CreatedAt: time.Now().UTC(), ParentID: &parent,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Mark succeeded right away — the polling loop will pick it up on the
	// next tick (1s).
	_ = jobStore.MarkJobSucceeded(ctx, "child", time.Now().UTC())

	status, err := waitForChild(context.Background(), jobStore, nil, "child", 5*time.Second)
	if err != nil {
		t.Fatalf("waitForChild: %v", err)
	}
	if status != jobs.StatusSucceeded {
		t.Errorf("status: %q", status)
	}
}

// TestWaitForChild_WakesOnTerminalEvent proves the subscribe-not-poll
// implementation: a JobSucceeded event published AFTER waitForChild
// starts (so it can't be caught by the initial store read) wakes the
// caller within ~50ms instead of paying the 1s fallback tick.
func TestWaitForChild_WakesOnTerminalEvent(t *testing.T) {
	ctx := context.Background()
	jobStore := newJobsStore(t)
	nc := startNATS(t)
	parent := "p"
	if err := jobStore.CreateJob(ctx, &jobs.Job{
		ID: "child", Kind: "node.update", Status: jobs.StatusRunning,
		CreatedAt: time.Now().UTC(), ParentID: &parent,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	type result struct {
		status jobs.Status
		err    error
		dur    time.Duration
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		st, err := waitForChild(ctx, jobStore, nc, "child", 5*time.Second)
		done <- result{status: st, err: err, dur: time.Since(start)}
	}()

	// Give the goroutine time to subscribe + initial store read.
	time.Sleep(50 * time.Millisecond)

	// Mark + publish — the order matters; the store write must be
	// visible before the event so the wake-and-re-read picks it up.
	if err := jobStore.MarkJobSucceeded(ctx, "child", time.Now().UTC()); err != nil {
		t.Fatalf("mark: %v", err)
	}
	payload, _ := json.Marshal(proto.JobEvent{Type: proto.JobSucceeded, JobID: "child"})
	if err := nc.Publish(proto.JobEventsSubject("child"), payload); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("waitForChild: %v", r.err)
		}
		if r.status != jobs.StatusSucceeded {
			t.Errorf("status: %q", r.status)
		}
		// Should be well under the 1s fallback tick — gives margin for
		// scheduler jitter while still proving the bus path fired.
		if r.dur > 500*time.Millisecond {
			t.Errorf("waitForChild took %v — bus wake didn't fire", r.dur)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waitForChild never returned")
	}
}

func TestWaitForChild_NotFound(t *testing.T) {
	jobStore := newJobsStore(t)
	_, err := waitForChild(context.Background(), jobStore, nil, "no-such", 3*time.Second)
	if err == nil {
		t.Error("missing child: want error")
	}
}

func TestWaitForChild_CtxCancel(t *testing.T) {
	jobStore := newJobsStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := waitForChild(ctx, jobStore, nil, "x", 5*time.Second)
	if err == nil {
		t.Error("cancelled ctx: want error")
	}
}

// ============================================================================
// systemCascade — exercises the cascade with a real Runner. We register a
// trivial node.update workflow so children succeed immediately. The system
// then walks all targets.
// ============================================================================

func TestSystemCascade_AllNodesSucceed(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)
	jobStore := newJobsStore(t)
	runner := jobs.NewRunner(jobStore, nc)

	// Trivial child workflow.
	runner.Register(jobs.Workflow{
		Kind: "node.update",
		Steps: []jobs.WorkflowStep{{
			Name: "noop", Timeout: time.Second,
			Do: func(sc *jobs.StepCtx) (json.RawMessage, error) { return nil, nil },
		}},
	})

	for _, id := range []string{"x"} {
		if err := inv.Insert(ctx, &proto.Node{
			ID: id, Role: proto.RoleCompute, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("inv: %v", err)
		}
	}
	_ = store.CreateBundle(ctx, &Bundle{SHA256: "sha", Version: "v", UploadedAt: time.Now().UTC()})

	sc := newUpdaterCtx("parent", `{"bundleSha256":"sha"}`, nc)
	if _, err := systemCascade(store, inv, jobStore, runner, nc, SystemUpdateConfig{})(sc); err != nil {
		t.Fatalf("systemCascade: %v", err)
	}
	runner.Wait()
}

func TestSystemCascade_BadSpec(t *testing.T) {
	nc := startNATS(t)
	store := newStoreFixture(t).store
	inv := newInventory(t)
	jobStore := newJobsStore(t)
	runner := jobs.NewRunner(jobStore, nc)
	sc := newUpdaterCtx("parent", `not-json`, nc)
	if _, err := systemCascade(store, inv, jobStore, runner, nc, SystemUpdateConfig{})(sc); err == nil {
		t.Error("bad spec: want error")
	}
}
