package updater

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/inventory"
	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// Inventory version-integrity (ADR-0005 Decision 4, first half).
//
// Before this, nodes.image_version was a pure last-write-wins cache of the
// agent's registration, and the updater only ever READ inventory. So a node
// that registered on the new slot and was then rolled back kept reporting the
// version it was MEANT to reach — forever, if it never re-registered. That is
// bench node c08 on 2026-07-12, and releases/check.go reads that column, so the
// stranded node rendered as up to date.

// verifyStep drives step 6 against a fake agent whose post-reboot precheck
// reports bootedSlot + runningVersion, with the node_update row targeting
// toSlot. Returns the step's error (nil on a clean verify).
func verifyStep(t *testing.T, inv *inventory.Store, nodeID string,
	toSlot, bootedSlot proto.UpdateSlot, runningVersion string) error {

	t.Helper()
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store

	if err := store.CreateNodeUpdate(ctx, &NodeUpdate{
		JobID: "j", NodeID: nodeID, BundleSHA256: "sha",
		FromSlot: proto.SlotA, ToSlot: toSlot,
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateNodeUpdate: %v", err)
	}

	preSub, _ := nc.Subscribe(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{
			OK: true, ActiveSlot: bootedSlot, InactiveSlot: otherSlot(bootedSlot),
			CurrentVersion: runningVersion,
		})
		_ = m.Respond(ack)
	})
	t.Cleanup(func() { _ = preSub.Unsubscribe() })

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
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
	t.Cleanup(cancel)
	sc := newUpdaterCtx("j", specJSON(nodeID, "sha"), nc)
	sc.Ctx = tctx
	_, err := updateWaitOnlineAndVerifySlot(store, inv)(sc)
	return err
}

func otherSlot(s proto.UpdateSlot) proto.UpdateSlot {
	if s == proto.SlotA {
		return proto.SlotB
	}
	return proto.SlotA
}

// seedInventoryAt puts a node in inventory already reporting version — i.e. the
// optimistic value its registration on the new slot wrote.
func seedInventoryAt(t *testing.T, nodeID, version string) *inventory.Store {
	t.Helper()
	inv := newInventory(t)
	if err := inv.Insert(context.Background(), &proto.Node{
		ID: nodeID, Role: proto.RoleCompute, Hostname: nodeID + ".test",
		ImageVersion: version,
		FirstSeen:    time.Now().UTC(), LastSeen: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("inv insert: %v", err)
	}
	return inv
}

func invVersion(t *testing.T, inv *inventory.Store, nodeID string) string {
	t.Helper()
	n, err := inv.Get(context.Background(), nodeID)
	if err != nil || n == nil {
		t.Fatalf("inv.Get(%s): %v, %+v", nodeID, err, n)
	}
	return n.ImageVersion
}

// confirmed reports whether inventory currently vouches for the node's version.
func confirmed(t *testing.T, inv *inventory.Store, nodeID string) bool {
	t.Helper()
	n, err := inv.Get(context.Background(), nodeID)
	if err != nil || n == nil {
		t.Fatalf("inv.Get(%s): %v, %+v", nodeID, err, n)
	}
	return n.ImageVersionConfirmedAt != nil
}

// THE c08 REGRESSION. The node registered on the new slot (inventory says
// dev.104), the bootloader then reverted it, and it is now running dev.101.
// Inventory must follow the update outcome, not the stale self-report.
func TestVerify_RollbackReconcilesInventoryToTheRunningVersion(t *testing.T) {
	const nodeID = "c08"
	inv := seedInventoryAt(t, nodeID, "2026.07.0-dev.104")

	// Target was slot B; it came up on slot A running the OLD version.
	if err := verifyStep(t, inv, nodeID, proto.SlotB, proto.SlotA, "2026.07.0-dev.101"); err == nil {
		t.Fatal("a rollback must still fail the step")
	}
	if got := invVersion(t, inv, nodeID); got != "2026.07.0-dev.101" {
		t.Errorf("inventory = %q, want the version the node is ACTUALLY running", got)
	}
}

// The success branch reconciles too — one invariant ("the update outcome is
// authoritative at the moment it is decided") rather than a rollback special
// case. The precheck answer is also fresher evidence than the registration
// event that preceded it.
func TestVerify_SuccessReconcilesInventoryToTheVerifiedVersion(t *testing.T) {
	const nodeID = "c09"
	inv := seedInventoryAt(t, nodeID, "2026.07.0-dev.101")

	if err := verifyStep(t, inv, nodeID, proto.SlotB, proto.SlotB, "2026.07.0-dev.104"); err != nil {
		t.Fatalf("clean verify: %v", err)
	}
	if got := invVersion(t, inv, nodeID); got != "2026.07.0-dev.104" {
		t.Errorf("inventory = %q, want the verified running version", got)
	}
}

// An agent that reports no version at all must leave the column alone. Blanking
// it would replace a wrong answer with a differently-wrong one; the doubt is
// expressed by dropping the confirmation instead — see
// TestVerify_EmptyReportedVersionUnconfirms for that half.
func TestVerify_EmptyReportedVersionDoesNotBlankInventory(t *testing.T) {
	const nodeID = "c10"
	inv := seedInventoryAt(t, nodeID, "2026.07.0-dev.101")

	if err := verifyStep(t, inv, nodeID, proto.SlotB, proto.SlotB, ""); err != nil {
		t.Fatalf("clean verify: %v", err)
	}
	if got := invVersion(t, inv, nodeID); got != "2026.07.0-dev.101" {
		t.Errorf("inventory = %q, want the previous value left intact", got)
	}
}

// A node that vanished from inventory between the update starting and verify
// finishing must not fail the saga — the write is best-effort by design.
func TestVerify_MissingInventoryRowDoesNotFailTheStep(t *testing.T) {
	inv := newInventory(t) // deliberately empty
	if err := verifyStep(t, inv, "ghost", proto.SlotB, proto.SlotB, "2026.07.0-dev.104"); err != nil {
		t.Errorf("a missing inventory row must not fail verify: %v", err)
	}
}

// The mark-bad path asserts no version — the node is still on the new slot but
// about to revert, so every value available is about to be wrong. It drops the
// CONFIRMATION instead, which is the state #72 added. (#57 left this path
// untouched because the schema could not yet say "unconfirmed"; this test is
// that one, flipped.)
func TestHealthCheckFailure_UnconfirmsInventoryVersion(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	const nodeID = "c11"
	inv := seedInventoryAt(t, nodeID, "2026.07.0-dev.104")

	if err := store.CreateNodeUpdate(ctx, &NodeUpdate{
		JobID: "j", NodeID: nodeID, BundleSHA256: "sha",
		FromSlot: proto.SlotA, ToSlot: proto.SlotB,
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateNodeUpdate: %v", err)
	}

	hSub, _ := nc.Subscribe(proto.NodeCmdSubject(nodeID, "diag.health"), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.DiagHealthAck{OK: false, Detail: "nats down"})
		_ = m.Respond(ack)
	})
	defer func() { _ = hSub.Unsubscribe() }()
	bSub, _ := nc.Subscribe(proto.UpdateMarkBadSubject(nodeID), func(m *nats.Msg) {
		_ = m.Respond([]byte(`{"ok":true}`))
	})
	defer func() { _ = bSub.Unsubscribe() }()

	tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := healthCheckAndCommit(tctx, nc, store, inv, nodeID, "sha", "j", nil); err == nil {
		t.Fatal("failed health check must fail the step")
	}
	if got := invVersion(t, inv, nodeID); got != "2026.07.0-dev.104" {
		t.Errorf("inventory = %q; the mark-bad path must not write a version it cannot confirm", got)
	}
	if confirmed(t, inv, nodeID) {
		t.Error("mark-bad must leave the version UNCONFIRMED — the node is about to revert away from it")
	}
}

// ============================================================================
// image_version_confirmed_at (ADR-0005 Decision 4, second half)
//
// #57 made the updater WRITE inventory. This half makes "we don't know"
// representable, so a terminal outcome that could not establish the running
// version stops leaving a confident-looking lie behind.
// ============================================================================

// A verified outcome confirms. Reconciling and stamping are one write on
// purpose — a version and the time it was confirmed must never be able to
// describe different versions.
func TestVerify_SuccessConfirmsTheVersion(t *testing.T) {
	const nodeID = "c20"
	inv := seedUnconfirmedAt(t, nodeID, "2026.07.0-dev.101")

	if err := verifyStep(t, inv, nodeID, proto.SlotB, proto.SlotB, "2026.07.0-dev.104"); err != nil {
		t.Fatalf("clean verify: %v", err)
	}
	if !confirmed(t, inv, nodeID) {
		t.Error("a verified outcome must confirm the version")
	}
}

// A rollback we could OBSERVE is still knowledge: the node answered, told us
// which slot and version it is on, and that is confirmed — the rollback is the
// bad news, not the uncertainty.
func TestVerify_ObservedRollbackConfirmsTheOldVersion(t *testing.T) {
	const nodeID = "c21"
	inv := seedInventoryAt(t, nodeID, "2026.07.0-dev.104")

	if err := verifyStep(t, inv, nodeID, proto.SlotB, proto.SlotA, "2026.07.0-dev.101"); err == nil {
		t.Fatal("a rollback must still fail the step")
	}
	if !confirmed(t, inv, nodeID) {
		t.Error("an OBSERVED rollback is knowledge; the version it reported is confirmed")
	}
}

// THE c08 CASE. The node never came back to answer, so the version inventory
// holds is from a boot that may no longer exist. Keep the value — it is the
// only clue an operator has — and drop the confidence.
func TestVerify_UnreachableNodeUnconfirmsWithoutBlankingTheVersion(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	const nodeID = "c08"
	inv := seedInventoryAt(t, nodeID, "2026.07.0-dev.104")

	if err := store.CreateNodeUpdate(ctx, &NodeUpdate{
		JobID: "j", NodeID: nodeID, BundleSHA256: "sha",
		FromSlot: proto.SlotA, ToSlot: proto.SlotB,
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateNodeUpdate: %v", err)
	}

	// No precheck responder at all — the node is gone.
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	if _, err := verifyBootedSlot(tctx, nc, store, inv, verifyRequest{NodeID: nodeID, BundleSHA256: "sha", JobID: "j"}, nil); err == nil {
		t.Fatal("an unreachable node must fail verify")
	}
	if confirmed(t, inv, nodeID) {
		t.Error("a node that never answered must not leave a CONFIRMED version behind")
	}
	if got := invVersion(t, inv, nodeID); got != "2026.07.0-dev.104" {
		t.Errorf("inventory = %q; the last-known value is the operator's only clue and must survive", got)
	}
}

// An agent that answers but names no version is the same epistemic state as one
// that did not answer: we know nothing new. It must not read as confirmed.
func TestVerify_EmptyReportedVersionUnconfirms(t *testing.T) {
	const nodeID = "c22"
	inv := seedInventoryAt(t, nodeID, "2026.07.0-dev.101")

	if err := verifyStep(t, inv, nodeID, proto.SlotB, proto.SlotB, ""); err != nil {
		t.Fatalf("clean verify: %v", err)
	}
	if confirmed(t, inv, nodeID) {
		t.Error("an agent that reported no version cannot have confirmed one")
	}
	if got := invVersion(t, inv, nodeID); got != "2026.07.0-dev.101" {
		t.Errorf("inventory = %q, want the previous value left intact", got)
	}
}

// seedUnconfirmedAt is seedInventoryAt with the confirmation explicitly
// cleared — the state a row is in after a failed verify, and the state every
// pre-migration row starts in.
func seedUnconfirmedAt(t *testing.T, nodeID, version string) *inventory.Store {
	t.Helper()
	inv := seedInventoryAt(t, nodeID, version)
	if err := inv.UnconfirmImageVersion(context.Background(), nodeID); err != nil {
		t.Fatalf("UnconfirmImageVersion: %v", err)
	}
	return inv
}
