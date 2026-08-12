package updater

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/proto"
	"github.com/nats-io/nats.go"
)

// The verify contract, ADR-0005 Decision 2. Every conjunct is three-valued;
// "unknown" degrades the verdict rather than failing it, because a
// mixed-version fleet is this feature's normal case (Decision 3).

func TestClassifyBoot(t *testing.T) {
	cases := []struct {
		name, prior, current string
		want                 bootIdentity
	}{
		{"rebooted", "old", "new", bootDiffers},
		{"never rebooted", "same", "same", bootSame},
		{"pre-bootId agent answered", "old", "", bootUnknown},
		{"capture was lost", "", "new", bootUnknown},
		{"neither side has one", "", "", bootUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyBoot(c.prior, c.current); got != c.want {
				t.Errorf("classifyBoot(%q,%q) = %q, want %q", c.prior, c.current, got, c.want)
			}
		})
	}
	// The asymmetry that matters: an absent identity must NEVER read as a
	// mismatch, or no existing cluster could adopt the feature.
	if classifyBoot("old", "") == bootSame || classifyBoot("", "new") == bootSame {
		t.Error("an absent boot id must be unknown, never a same-boot verdict")
	}
}

func TestClassifyVersion(t *testing.T) {
	cases := []struct {
		name, expected, reported string
		want                     versionMatch
	}{
		{"agrees", "2026.08.2", "2026.08.2", versionMatches},
		{"disagrees", "2026.08.2", "2026.08.1", versionMismatch},
		{"node reported none", "2026.08.2", "", versionUnknown},
		{"we expected none", "", "2026.08.2", versionUnknown},
		{"neither", "", "", versionUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyVersion(c.expected, c.reported); got != c.want {
				t.Errorf("classifyVersion(%q,%q) = %q, want %q", c.expected, c.reported, got, c.want)
			}
		})
	}
}

// Degraded is what #71 will put on the wire, so it has to mean exactly "some
// conjunct could not be evaluated" — not "something went wrong".
func TestVerifyResult_Degraded(t *testing.T) {
	full := verifyResult{Boot: bootDiffers, Version: versionMatches}
	if full.Degraded() {
		t.Error("a fully-evaluated verdict is not degraded")
	}
	for _, r := range []verifyResult{
		{Boot: bootUnknown, Version: versionMatches},
		{Boot: bootDiffers, Version: versionUnknown},
		{Boot: bootUnknown, Version: versionUnknown},
	} {
		if !r.Degraded() {
			t.Errorf("%+v should be degraded", r)
		}
	}
}

// waitForNewBoot must not be satisfiable by the boot it was told to wait past,
// however many times that boot answers or re-registers.
func TestWaitForNewBoot_OldBootNeverSatisfies(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n"
	sub, _ := nc.Subscribe(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{OK: true, BootID: "old"})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	got, err := waitForNewBoot(ctx, nc, verifyRequest{NodeID: nodeID, PriorBootID: "old"}, nil, nil)
	if err == nil {
		t.Fatal("the old boot must never satisfy the wait")
	}
	if got != bootSame {
		t.Errorf("verdict = %q, want %q — 'alive but never rebooted' is a different diagnosis from 'never came back'", got, bootSame)
	}
}

// A node that never answers at all is a DIFFERENT failure from one that
// answers on the old boot, and the two must not collapse into one message.
func TestWaitForNewBoot_SilentNodeIsNotTheSameAsAnOldBoot(t *testing.T) {
	nc := startNATS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	got, err := waitForNewBoot(ctx, nc, verifyRequest{NodeID: "gone", PriorBootID: "old"}, nil, nil)
	if err == nil {
		t.Fatal("a silent node must time out")
	}
	if got == bootSame {
		t.Error("a node that never answered must not be reported as 'still on the old boot'")
	}
}

// An agent that predates bootId cannot ever produce an identity, so waiting
// longer is pointless — return promptly and degrade (Decision 3).
func TestWaitForNewBoot_PreBootIDAgentDegradesImmediately(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "old-agent"
	sub, _ := nc.Subscribe(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{OK: true}) // no BootID
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	got, err := waitForNewBoot(ctx, nc, verifyRequest{NodeID: nodeID, PriorBootID: "old"}, nil, nil)
	if err != nil {
		t.Fatalf("a pre-bootId agent must not fail the wait: %v", err)
	}
	if got != bootUnknown {
		t.Errorf("verdict = %q, want %q", got, bootUnknown)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v — waiting for an identity that will never be sent is pointless", elapsed)
	}
}

// With no prior identity there is nothing to compare, so this degrades to the
// old behaviour: wait for the agent to answer at all. That path is every
// existing cluster's first rollout after the feature ships.
func TestWaitForNewBoot_NoPriorIDWaitsOnlyForTheAgent(t *testing.T) {
	nc := startNATS(t)
	const nodeID = "n"
	sub, _ := nc.Subscribe(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{OK: true, BootID: "whatever"})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := waitForNewBoot(ctx, nc, verifyRequest{NodeID: nodeID, PriorBootID: ""}, nil, nil)
	if err != nil {
		t.Fatalf("no prior id must still proceed: %v", err)
	}
	if got != bootUnknown {
		t.Errorf("verdict = %q, want %q", got, bootUnknown)
	}
}

// ----- conjunct (c): the version cross-check ------------------------------
//
// Free evidence: verifyBootedSlot has always had the reported version in hand
// and simply discarded it (ADR-0005 Decision 2).

// verifyOnce drives verifyBootedSlot directly against a fake agent — no
// waiting, so these tests are about the verdict rather than the timing.
func verifyOnce(t *testing.T, expectedVersion, reportedVersion string, priorBoot, currentBoot string) (verifyResult, error) {
	t.Helper()
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	const nodeID = "n"
	if err := store.CreateNodeUpdate(ctx, &NodeUpdate{
		JobID: "j", NodeID: nodeID, BundleSHA256: "sha",
		FromSlot: proto.SlotA, ToSlot: proto.SlotB, ToVersion: expectedVersion,
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateNodeUpdate: %v", err)
	}
	sub, _ := nc.Subscribe(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{
			OK: true, ActiveSlot: proto.SlotB, InactiveSlot: proto.SlotA,
			CurrentVersion: reportedVersion, BootID: currentBoot,
		})
		_ = m.Respond(ack)
	})
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel)
	return verifyBootedSlot(tctx, nc, store, nil, verifyRequest{
		NodeID: nodeID, BundleSHA256: "sha", JobID: "j", PriorBootID: priorBoot,
	}, nil)
}

// A node on the right slot running the WRONG version is neither a success nor
// a rollback — most likely the slot was written by something other than this
// update. It must not pass verify.
func TestVerify_VersionMismatchFails(t *testing.T) {
	res, err := verifyOnce(t, "2026.08.2", "2026.08.1", "old", "new")
	if err == nil {
		t.Fatal("a version mismatch must fail verify")
	}
	if res.Version != versionMismatch {
		t.Errorf("Version = %q, want %q", res.Version, versionMismatch)
	}
	if !strings.Contains(err.Error(), "version_mismatch") {
		t.Errorf("error %q should name the conjunct that failed, not read as a rollback", err)
	}
}

func TestVerify_VersionMatchPassesUndegraded(t *testing.T) {
	res, err := verifyOnce(t, "2026.08.2", "2026.08.2", "old", "new")
	if err != nil {
		t.Fatalf("matching version must pass: %v", err)
	}
	if res.Version != versionMatches || res.Boot != bootDiffers {
		t.Errorf("verdict = %+v, want both conjuncts satisfied", res)
	}
	if res.Degraded() {
		t.Error("a fully-evaluated pass must not report as degraded")
	}
}

// The mixed-version fleet case: no boot id anywhere, and (on an OS node whose
// agent predates the image-version fallback) no version either. Verify still
// passes on the slot alone — refusing would mean no existing cluster could
// adopt the feature — but it says it is degraded.
func TestVerify_NoBootIDAndNoVersionPassesDegraded(t *testing.T) {
	res, err := verifyOnce(t, "", "", "", "")
	if err != nil {
		t.Fatalf("a pre-feature agent must still be able to update: %v", err)
	}
	if !res.Degraded() {
		t.Error("a verdict resting on the slot alone must report as degraded")
	}
	if res.Boot != bootUnknown || res.Version != versionUnknown {
		t.Errorf("verdict = %+v, want both conjuncts unknown", res)
	}
}

// ----- surfacing the degradation (ADR-0005 Decision 3) --------------------
//
// A degraded verify still passes and still fans out. What it must never do is
// look identical to a fully-verified one.

func TestVerifyResult_UnverifiedSplitsDegraded(t *testing.T) {
	cases := []struct {
		name              string
		res               verifyResult
		wantBoot, wantVer bool
	}{
		{"fully verified", verifyResult{Boot: bootDiffers, Version: versionMatches}, false, false},
		{"pre-bootId agent", verifyResult{Boot: bootUnknown, Version: versionMatches}, true, false},
		{"node named no version", verifyResult{Boot: bootDiffers, Version: versionUnknown}, false, true},
		{"neither knowable", verifyResult{Boot: bootUnknown, Version: versionUnknown}, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.res.UnverifiedBoot(); got != c.wantBoot {
				t.Errorf("UnverifiedBoot = %v, want %v", got, c.wantBoot)
			}
			if got := c.res.UnverifiedVersion(); got != c.wantVer {
				t.Errorf("UnverifiedVersion = %v, want %v", got, c.wantVer)
			}
			if got := c.res.Degraded(); got != (c.wantBoot || c.wantVer) {
				t.Errorf("Degraded = %v, want %v", got, c.wantBoot || c.wantVer)
			}
		})
	}
}

// The mixed-version case that Decision 3 is about: the whole fleet's first
// rollout after boot identity ships. Verify passes, and the per-node row says
// which conjuncts it could not evaluate.
func TestVerify_DegradedPassRecordsTheGapsOnTheRow(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	const nodeID = "pre-bootid"
	if err := store.CreateNodeUpdate(ctx, &NodeUpdate{
		JobID: "j", NodeID: nodeID, BundleSHA256: "sha",
		FromSlot: proto.SlotA, ToSlot: proto.SlotB, ToVersion: "2026.08.2",
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateNodeUpdate: %v", err)
	}
	// An agent that predates both fields: no boot id, no version.
	sub, _ := nc.Subscribe(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{
			OK: true, ActiveSlot: proto.SlotB, InactiveSlot: proto.SlotA,
		})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()

	tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	res, err := verifyBootedSlot(tctx, nc, store, nil, verifyRequest{
		NodeID: nodeID, BundleSHA256: "sha", JobID: "j",
	}, nil)
	if err != nil {
		t.Fatalf("a degraded verify must still PASS — refusing would strand every existing cluster: %v", err)
	}
	if !res.Degraded() {
		t.Fatal("verify on an agent with neither field must report degraded")
	}
	row, _ := store.GetNodeUpdate(ctx, "j")
	if row == nil || !row.UnverifiedBoot || !row.UnverifiedVersion {
		t.Errorf("row = %+v, want both gaps recorded", row)
	}
}

// A fully-verified update must leave the row clean, or the flag is noise.
func TestVerify_FullPassRecordsNoGaps(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	const nodeID = "modern"
	_ = store.CreateNodeUpdate(ctx, &NodeUpdate{
		JobID: "j", NodeID: nodeID, BundleSHA256: "sha",
		FromSlot: proto.SlotA, ToSlot: proto.SlotB, ToVersion: "2026.08.2",
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	})
	sub, _ := nc.Subscribe(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{
			OK: true, ActiveSlot: proto.SlotB, InactiveSlot: proto.SlotA,
			CurrentVersion: "2026.08.2", BootID: "new",
		})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()

	tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := verifyBootedSlot(tctx, nc, store, nil, verifyRequest{
		NodeID: nodeID, BundleSHA256: "sha", JobID: "j", PriorBootID: "old",
	}, nil); err != nil {
		t.Fatalf("verify: %v", err)
	}
	row, _ := store.GetNodeUpdate(ctx, "j")
	if row == nil || row.UnverifiedBoot || row.UnverifiedVersion {
		t.Errorf("row = %+v, want no gaps on a fully-verified update", row)
	}
}

// A ROLLED-BACK node's degradation matters too — it is how an operator tells
// "rolled back, and we could see everything" from "rolled back, and we were
// half blind". The gaps are recorded before the branch for exactly this.
func TestVerify_RollbackAlsoRecordsTheGaps(t *testing.T) {
	ctx := context.Background()
	nc := startNATS(t)
	store := newStoreFixture(t).store
	const nodeID = "rolled"
	_ = store.CreateNodeUpdate(ctx, &NodeUpdate{
		JobID: "j", NodeID: nodeID, BundleSHA256: "sha",
		FromSlot: proto.SlotA, ToSlot: proto.SlotB, ToVersion: "2026.08.2",
		Status: NodeUpdateInProgress, StartedAt: time.Now().UTC(),
	})
	sub, _ := nc.Subscribe(proto.UpdatePrecheckSubject(nodeID), func(m *nats.Msg) {
		ack, _ := json.Marshal(proto.UpdatePrecheckAck{
			OK: true, ActiveSlot: proto.SlotA, InactiveSlot: proto.SlotB, // rolled back
		})
		_ = m.Respond(ack)
	})
	defer func() { _ = sub.Unsubscribe() }()

	tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := verifyBootedSlot(tctx, nc, store, nil, verifyRequest{
		NodeID: nodeID, BundleSHA256: "sha", JobID: "j",
	}, nil); err == nil {
		t.Fatal("a rollback must fail verify")
	}
	row, _ := store.GetNodeUpdate(ctx, "j")
	if row == nil || !row.UnverifiedBoot {
		t.Errorf("row = %+v, want the boot gap recorded on a rollback too", row)
	}
}
