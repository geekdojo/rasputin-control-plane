package storage

import (
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Which nodes can hold a claimed disk, PER PURPOSE — THE ONE PLACE this is
// decided.
//
// # backup (§4.8): the controlplane, and only the controlplane
//
// A backup run seals the identity archive on the controlplane and hands the
// agent BESIDE IT a file name to find; app volumes on other nodes travel over
// the transport (#295/#296) to the api's ingest endpoint, which writes them
// under the mount the co-located agent reports. Both handoffs land on a disk
// attached to the controlplane. Nothing today can carry an archive to a disk
// on any other node, so a target there is a backup that will never happen.
//
// geekdojo-brain#397 found the dead end on e3bench: storage.claim is
// registered on the storage role too, so the picker would happily let an
// operator claim a storage-node disk in good faith, and only backup.run —
// at 3 a.m. — would say no. The choice taken was to refuse the CLAIM, not
// the run: a disk that cannot receive archives is not offered as a target.
//
// ⚠️ #302 DOES NOT RELAX THIS, and the refusal string used to promise it
// would. What #302 builds is the claim/format/mount machinery — the ability
// to format a disk on a storage node and mount it there. That is not the
// blocker. The blocker is that the api's ingest writes archive members to a
// disk ATTACHED TO THE CONTROLPLANE, and a target anywhere else needs that
// ingest to write to a remote node's mount: §4.1 transport work, in a
// different part of the system, which claiming a disk provides none of. So
// the sentence now names the ingest, and no release.
//
// # data (§6): the controlplane and the storage role — where the agent
// actually answers storage verbs
//
// A data disk holds app volumes for the apps deployed on ITS OWN node — no
// transport, no ingest, no handoff to anywhere else — so the PLACEMENT
// question is only "does this node run apps", and by that test a compute node
// would qualify. It is refused anyway, and placement is not why. The AGENT
// registers the storage handlers on RoleControlPlane and RoleStorage only
// (agent/cmd/rasputin-agent/main.go), so a data claim addressed to a compute
// node is published to a subject nothing is subscribed to and dies as a
// no-responder timeout. Allowing it here would offer the operator a dead end
// — the same mistake #397 found for backup on storage nodes, closed the same
// way: refuse the CLAIM, not the run.
//
// It is NOT closed the other way — by registering the handlers on compute —
// because `storage.claim` force-formats a disk, and arming it across a 23-node
// Pi 4 fleet buys a capability nothing can consume: §6.4's per-app placement
// field, the thing that would let an app ask for the data disk, does not exist
// in any package yet.
//
// ⚠️ So this is a "not yet", and TWO things move before it becomes a "yes", in
// this order:
//
//  1. something has to be able to USE a data disk on a compute node — §6.4's
//     per-app placement field, which nothing has built; and then
//  2. the agent's role gate in main.go has to be widened to arm the verb
//     there, which is a decision about pointing a force-format verb at every
//     compute node, not a refactor.
//
// This rule changes LAST, never first: widened on its own it re-opens exactly
// the dead end it exists to close. §6.6 is worth restating for the storage
// role, which passes today and is easy to over-read: `proto.RoleStorage` has
// no storage functionality behind it in either repo, and nothing above §6's
// mount layer follows from a data disk being claimable there.
//
// # What consumes this
//
// The candidate endpoint, the claim handler, the saga's step 1, the target
// listing and the UI's node selector all ask this rather than checking roles
// themselves, so a change here changes the answer everywhere at once. The UI
// carries a mirror of the rule for its node selector
// (components/storage/target-eligibility.ts), which exists because the api
// cannot answer for a node nobody has scanned yet; the two must agree
// sentence for sentence, and each side's tests assert the words.
//
// backup.run's own step-1 refusal (RunConfig.SelfNodeID) is deliberately NOT
// routed through here: it guards a different thing — that the staging root
// the api acts on comes from the agent sharing its filesystem — and stays
// exactly as PR #228 shipped it, wording aligned.

// targetTransportExplanation is the sentence every BACKUP refusal shares, so
// the picker, the claim, the saga and the run tell one story about why.
//
// It names the ingest, which is the actual obstacle, and no longer names a
// release: the version it used to point at ships the disk machinery and not
// the transport, so the promise was one nothing was going to keep.
const targetTransportExplanation = "archives are written by the controlplane's own ingest to a disk attached to the controlplane, and a target on any other node would need that ingest to write to a REMOTE node's mount — §4.1 transport work, which claiming a disk on that node does not provide"

// dataPlacementExplanation is the PERMANENT data refusal, and there is exactly
// one node that earns it. It is not a "yet": the firewall does not run apps by
// design, so no transport, placement field or later release makes a data disk
// on it mean anything.
const dataPlacementExplanation = "a data disk holds the app volumes of the apps deployed on its own node, and the firewall runs none"

// dataNoStorageVerbsExplanation is the CONTINGENT data refusal — a node that
// runs apps but answers no storage verb, which today is every compute node.
//
// It names the agent rather than the role on purpose. "Compute nodes are
// ineligible" would read as a property of the role and send the next reader
// looking for a placement rule that does not exist; what is actually true is
// that nothing over there is listening, and see CanHoldTarget's header for the
// two things that have to move before it is.
const dataNoStorageVerbsExplanation = "the agent registers the storage verbs on the controlplane and storage roles only, so a claim sent to this node reaches no responder — arming them there points the force-formatting storage.claim at every compute node in the fleet, and nothing could ask for the disk anyway until §6.4's per-app placement field exists"

// CanHoldTarget reports whether a disk attached to node can be claimed for
// purpose, and when it cannot, why — in the operator's words, ready to
// render.
//
// A nil node is refused rather than guessed at: the callers have all looked it
// up in inventory first, and an unregistered node has no role to decide on. An
// unrecognised purpose is refused for the same reason the agent's format path
// refuses one — the empty string included, whose "means backup" reading
// belongs to the wire type (proto.StorageClaimCmd.EffectivePurpose) and is
// applied there, before anything reaches this rule.
func CanHoldTarget(node *proto.Node, purpose proto.StoragePurpose) (ok bool, reason string) {
	if _, err := proto.StoragePurposeSpecFor(purpose); err != nil {
		return false, fmt.Sprintf("no disk can be claimed for a purpose this control plane does not implement: %v", err)
	}
	switch purpose {
	case proto.StoragePurposeBackup:
		if node == nil {
			return false, "a disk on an unregistered node cannot receive backups — " + targetTransportExplanation
		}
		if node.Role == proto.RoleControlPlane {
			return true, ""
		}
		return false, fmt.Sprintf("a disk on %s (%s) cannot receive backups yet — %s",
			nodeDisplayName(node), node.Role, targetTransportExplanation)
	case proto.StoragePurposeData:
		if node == nil {
			return false, "a disk on an unregistered node cannot hold app data — " + dataPlacementExplanation
		}
		switch node.Role {
		case proto.RoleControlPlane, proto.RoleStorage:
			return true, ""
		case proto.RoleFirewall:
			return false, fmt.Sprintf("a disk on %s (%s) cannot hold app data — %s",
				nodeDisplayName(node), node.Role, dataPlacementExplanation)
		}
		// Compute, and any role added later: the node may well run apps, but
		// nothing there answers a storage verb. "yet", because unlike the
		// firewall this one is waiting on work somebody could choose to do.
		return false, fmt.Sprintf("a disk on %s (%s) cannot hold app data yet — %s",
			nodeDisplayName(node), node.Role, dataNoStorageVerbsExplanation)
	}
	// Unreachable while the switch covers proto.AllStoragePurposes, and a
	// refusal anyway: a purpose that reached this line has a spec and no rule,
	// which is a claim nobody decided to allow.
	return false, fmt.Sprintf("a disk cannot be claimed for %q: this control plane has no placement rule for that purpose", purpose)
}

// nodeDisplayName is the name the operator sees for a node in the picker's
// selector — the hostname, or the id when there is none.
func nodeDisplayName(node *proto.Node) string {
	return firstNonEmpty(node.Hostname, node.ID)
}
