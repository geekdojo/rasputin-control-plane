package storage

import (
	"strings"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// CanHoldTarget is the ONE rule the picker, the claim handler, the saga and
// the target listing share (#397), and since §6 it answers per PURPOSE. These
// cases pin every role against every purpose — a matrix rather than a list,
// because the mistake to catch is a rule widened for one purpose leaking into
// the other — and they pin the WORDS, because those words are what the
// operator reads on four surfaces and the UI mirror repeats verbatim.
func TestCanHoldTarget(t *testing.T) {
	tests := []struct {
		name    string
		role    proto.NodeRole
		purpose proto.StoragePurpose
		wantOK  bool
		// wantIn are substrings the refusal must contain.
		wantIn []string
	}{
		// backup: the controlplane and nothing else. #302 does NOT relax
		// this — it ships the disk machinery, not the ingest transport — so
		// these three refusals are as true after this change as before it.
		{name: "backup on the controlplane", role: proto.RoleControlPlane, purpose: proto.StoragePurposeBackup, wantOK: true},
		{
			name: "backup on a storage node", role: proto.RoleStorage, purpose: proto.StoragePurposeBackup,
			wantIn: []string{"a disk on shelf (storage) cannot receive backups yet", "controlplane's own ingest", "REMOTE node's mount", "§4.1"},
		},
		{
			name: "backup on a compute node", role: proto.RoleCompute, purpose: proto.StoragePurposeBackup,
			wantIn: []string{"a disk on shelf (compute) cannot receive backups yet", "controlplane's own ingest"},
		},
		{
			name: "backup on the firewall", role: proto.RoleFirewall, purpose: proto.StoragePurposeBackup,
			wantIn: []string{"a disk on shelf (firewall) cannot receive backups yet", "controlplane's own ingest"},
		},
		// data: where the agent actually registers the storage verbs, which
		// is the controlplane and the storage role. The storage role passing
		// here is §6's mount layer and nothing above it (§6.6).
		{name: "data on the controlplane", role: proto.RoleControlPlane, purpose: proto.StoragePurposeData, wantOK: true},
		{name: "data on a storage node", role: proto.RoleStorage, purpose: proto.StoragePurposeData, wantOK: true},
		{
			// A compute node runs apps, so placement is not what refuses it —
			// nobody there answers storage.claim. The refusal has to say that,
			// because an operator told "compute nodes are ineligible" goes
			// looking for a placement rule that does not exist.
			name: "data on a compute node", role: proto.RoleCompute, purpose: proto.StoragePurposeData,
			wantIn: []string{
				"a disk on shelf (compute) cannot hold app data yet",
				"the agent registers the storage verbs on the controlplane and storage roles only",
				"reaches no responder",
				"§6.4",
			},
		},
		{
			name: "data on the firewall", role: proto.RoleFirewall, purpose: proto.StoragePurposeData,
			wantIn: []string{"a disk on shelf (firewall) cannot hold app data", "runs none"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node := &proto.Node{ID: "n-1", Role: tc.role, Hostname: "shelf"}
			ok, reason := CanHoldTarget(node, tc.purpose)
			if tc.wantOK {
				if !ok || reason != "" {
					t.Fatalf("ok=%v reason=%q, want a plain yes", ok, reason)
				}
				return
			}
			if ok {
				t.Fatalf("a disk on a %s node was offered for %q", tc.role, tc.purpose)
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(reason, want) {
					t.Errorf("reason %q should say %q", reason, want)
				}
			}
		})
	}
	// Every role and every purpose is covered above: a purpose or role added
	// without a row here would leave one square of the matrix unasserted.
	if len(tests) != len(proto.AllRoles)*len(proto.AllStoragePurposes) {
		t.Errorf("%d cases for %d roles × %d purposes", len(tests), len(proto.AllRoles), len(proto.AllStoragePurposes))
	}
}

// The data rule and the agent's handler registration are ONE decision written
// in two repositories' worth of files, and this is the api's half of it: the
// roles that may hold a data disk are exactly the roles
// agent/cmd/rasputin-agent/main.go arms `storage.claim` on. A claim to any
// other node is published to a subject nothing is subscribed to.
//
// There is no import that can assert this — the agent is a separate module —
// so the list is spelled out, and a change here that is not matched there (or
// the reverse) fails on this line rather than as a no-responder timeout on a
// bench.
func TestDataEligibilityMatchesWhereTheAgentArmsTheVerb(t *testing.T) {
	armed := map[proto.NodeRole]bool{proto.RoleControlPlane: true, proto.RoleStorage: true}
	for _, role := range proto.AllRoles {
		ok, _ := CanHoldTarget(&proto.Node{ID: "n-1", Role: role, Hostname: "shelf"}, proto.StoragePurposeData)
		if ok != armed[role] {
			t.Errorf("data on %s: eligible=%v, but the agent registers the storage handlers there=%v — one of the two moved without the other", role, ok, armed[role])
		}
	}
}

// The two data refusals say different things because they ARE different
// things, and conflating them is the failure this pins. The firewall's is
// permanent — it runs no apps by design. A compute node's is a "not yet", and
// the sentence has to leave the door open and name what is behind it, or the
// next reader reads "compute is ineligible" as a placement rule and goes
// looking for one that was never written.
func TestDataRefusalSeparatesNotYetFromNever(t *testing.T) {
	node := func(role proto.NodeRole) *proto.Node {
		return &proto.Node{ID: "n-1", Role: role, Hostname: "shelf"}
	}
	_, compute := CanHoldTarget(node(proto.RoleCompute), proto.StoragePurposeData)
	_, firewall := CanHoldTarget(node(proto.RoleFirewall), proto.StoragePurposeData)

	if !strings.Contains(compute, "cannot hold app data yet") {
		t.Errorf("the compute refusal reads as permanent: %q", compute)
	}
	// Not the firewall's sentence. A compute node DOES run apps, so "the
	// firewall runs none" is not merely the wrong words, it is untrue of it.
	if strings.Contains(compute, "runs none") {
		t.Errorf("the compute refusal borrowed the firewall's reason: %q", compute)
	}
	// It names the obstacle (nothing is listening) and the prerequisite
	// (§6.4's placement field), which are the two things that have to move.
	for _, want := range []string{"reaches no responder", "storage.claim", "§6.4"} {
		if !strings.Contains(compute, want) {
			t.Errorf("the compute refusal should say %q: %q", want, compute)
		}
	}
	if strings.Contains(firewall, "yet") {
		t.Errorf("the firewall refusal promises a change that is never coming: %q", firewall)
	}
}

// The refusal names the node the way the operator sees it, and a nil node is
// refused per purpose rather than guessed at — the callers have all looked the
// node up in inventory first, and an unregistered node has no role to decide
// on.
func TestCanHoldTarget_NamesTheNodeTheOperatorSees(t *testing.T) {
	_, reason := CanHoldTarget(&proto.Node{ID: "n-2", Role: proto.RoleStorage}, proto.StoragePurposeBackup)
	if !strings.Contains(reason, "a disk on n-2 (storage)") {
		t.Errorf("with no hostname the id is the name: %q", reason)
	}
	for _, purpose := range proto.AllStoragePurposes {
		ok, reason := CanHoldTarget(nil, purpose)
		if ok || reason == "" {
			t.Errorf("%s: a nil node is refused with a reason, never guessed at: ok=%v reason=%q", purpose, ok, reason)
		}
		if !strings.Contains(reason, "unregistered node") {
			t.Errorf("%s: the refusal should say the node is unregistered: %q", purpose, reason)
		}
	}
}

// An unrecognised purpose is a refusal, the empty string included. Its
// "means backup" reading belongs to the wire type and is applied by
// EffectivePurpose before anything reaches this rule; a zero-valued purpose
// arriving here is a bug, and answering "yes, on the controlplane" would hide
// it behind a correct-looking answer.
func TestCanHoldTargetRefusesAnUnrecognisedPurpose(t *testing.T) {
	cp := &proto.Node{ID: "n-1", Role: proto.RoleControlPlane, Hostname: "cp1"}
	for _, purpose := range []proto.StoragePurpose{"", "scratch", "Backup", "RASPUTIN-DATA"} {
		ok, reason := CanHoldTarget(cp, purpose)
		if ok {
			t.Errorf("purpose %q was allowed on the controlplane", purpose)
		}
		if !strings.Contains(reason, "does not implement") {
			t.Errorf("purpose %q: reason %q should say the purpose is not implemented", purpose, reason)
		}
	}
}

// The corrected sentence, asserted as an absence: the old one promised the
// storage SKU (#302) would lift the backup restriction, and #302 ships the
// claim/format/mount machinery rather than the ingest transport that actually
// blocks it. An operator who reads "arrives with #302" waits for a release
// that will not deliver it.
func TestBackupRefusalPromisesNoRelease(t *testing.T) {
	_, reason := CanHoldTarget(&proto.Node{ID: "n-1", Role: proto.RoleStorage, Hostname: "shelf"}, proto.StoragePurposeBackup)
	for _, forbidden := range []string{"#302", "storage SKU", "arrives with"} {
		if strings.Contains(reason, forbidden) {
			t.Errorf("the backup refusal still promises a release (%q): %q", forbidden, reason)
		}
	}
	if !strings.Contains(reason, "ingest") {
		t.Errorf("the backup refusal should name the ingest, which is the actual blocker: %q", reason)
	}
}
