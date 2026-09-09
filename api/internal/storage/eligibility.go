package storage

import (
	"fmt"

	"github.com/geekdojo/rasputin-control-plane/proto"
)

// Which nodes can hold a backup target — THE ONE PLACE this is decided.
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
// # What relaxes this
//
// The storage SKU (geekdojo-brain#302) is where a storage-node target
// belongs, with either an ingest relay or an ingest on the storage node
// itself. When that ships, THIS FUNCTION is what changes — the candidate
// endpoint, the claim handler, the saga's step 1, the target listing and the
// UI's node selector all ask it rather than checking roles themselves, so
// widening the answer here widens it everywhere at once. The UI carries a
// mirror of the rule for its node selector (components/storage/
// target-eligibility.ts); #302 relaxes both, and the mirror says so.
//
// backup.run's own step-1 refusal (RunConfig.SelfNodeID) is deliberately NOT
// routed through here: it guards a different thing — that the staging root
// the api acts on comes from the agent sharing its filesystem — and stays
// exactly as PR #228 shipped it, wording aligned.

// targetTransportExplanation is the sentence every refusal shares, so the
// picker, the claim, the saga and the run tell one story about why.
const targetTransportExplanation = "archives are written by the controlplane's ingest to a disk attached to the controlplane; a storage-node target arrives with the storage SKU (#302)"

// CanHoldTarget reports whether a disk attached to node can be claimed as
// the cluster's backup target, and when it cannot, why — in the operator's
// words, ready to render.
//
// Today the answer is "controlplane only". A nil node is refused rather than
// guessed at: the callers have all looked it up in inventory first, and an
// unregistered node has no role to decide on.
func CanHoldTarget(node *proto.Node) (ok bool, reason string) {
	if node == nil {
		return false, "a disk on an unregistered node cannot receive backups — " + targetTransportExplanation
	}
	if node.Role == proto.RoleControlPlane {
		return true, ""
	}
	return false, fmt.Sprintf("a disk on %s (%s) cannot receive backups yet — %s",
		nodeDisplayName(node), node.Role, targetTransportExplanation)
}

// nodeDisplayName is the name the operator sees for a node in the picker's
// selector — the hostname, or the id when there is none.
func nodeDisplayName(node *proto.Node) string {
	return firstNonEmpty(node.Hostname, node.ID)
}
