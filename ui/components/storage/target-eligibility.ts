// Which nodes can hold a claimed disk, PER PURPOSE, as the Storage page needs
// to know it (#397, and #302's §6 data disk) — extracted so the copy can be
// executed rather than asserted in a comment; see backup-runs.ts for why
// nothing that matters lives in a .tsx.
//
// THE API IS THE AUTHORITY. `GET /api/backup/candidates` answers per node
// (`nodeEligible` / `nodeIneligibleReason`) and per disk (`eligible` /
// `ineligibleReason`), `POST /api/backup/targets` refuses with a 409, and the
// claim saga refuses again at step 1 — all from one Go function,
// storage.CanHoldTarget. Every control on THIS page that can start a claim
// reads the api's answer, never the mirror below.
//
// The mirror exists for one thing the api does not answer per request: the
// node SELECTOR, which lists every node before any of them has been scanned
// and wants to say up front which ones are worth scanning. It says exactly
// what the Go rule says, purpose for purpose and word for word — the Go tests
// and this module's tests each assert the sentences, which is what keeps the
// two from drifting. Get them out of step and the worst case is a node
// labelled "can't hold a target" whose scan then says otherwise; the api's
// answer wins on the row, so nothing is claimable that should not be.
//
// ⚠️ `backup` is controlplane-only and #302 DOES NOT RELAX IT. The claim,
// format and mount machinery #302 builds is not what blocks a backup target on
// another node: the api's ingest writes archive members to a disk attached to
// the controlplane, and a target elsewhere needs that ingest to write to a
// remote node's mount, which is separate transport work. The sentence below
// used to promise the storage SKU would lift it, and was corrected when the
// data-disk work made it clear it would not.

import type { BackupCandidate, BackupTarget, Node } from '../../lib/types';

/**
 * What a claimed disk is FOR — proto.StoragePurpose. A closed set: the api
 * refuses anything else rather than defaulting it, and so does this.
 *
 * There is no empty-means-backup default here. That reading belongs to the
 * wire type (proto.StorageClaimCmd.EffectivePurpose) so an api predating §6
 * keeps working, and it is applied there — a caller of this module says which
 * purpose it means.
 */
export type StoragePurpose = 'backup' | 'data';

/** The tail every BACKUP refusal shares — verbatim from storage.CanHoldTarget. */
export const TARGET_TRANSPORT_EXPLANATION =
  "archives are written by the controlplane's own ingest to a disk attached to the controlplane, and a target on any other node would need that ingest to write to a REMOTE node's mount — §4.1 transport work, which claiming a disk on that node does not provide";

/**
 * The PERMANENT data refusal — verbatim from storage.CanHoldTarget. Exactly
 * one node earns it: the firewall runs no apps by design, so no later work
 * makes a data disk on it mean anything.
 */
export const DATA_PLACEMENT_EXPLANATION =
  'a data disk holds the app volumes of the apps deployed on its own node, and the firewall runs none';

/**
 * The CONTINGENT data refusal — verbatim from storage.CanHoldTarget. A compute
 * node runs apps, so placement is not what refuses it: the agent registers the
 * storage handlers on the controlplane and storage roles only, so a claim sent
 * there reaches nothing. See the ⚠️ note below for what has to move first.
 */
export const DATA_NO_STORAGE_VERBS_EXPLANATION =
  'the agent registers the storage verbs on the controlplane and storage roles only, so a claim sent to this node reaches no responder — arming them there points the force-formatting storage.claim at every compute node in the fleet, and nothing could ask for the disk anyway until §6.4\'s per-app placement field exists';

/**
 * The short form the selector annotates a node with. One per REFUSAL rather
 * than one per purpose, because "can't hold app data" and "can't hold app data
 * yet" are the difference between a rule and a queue — canHoldTarget returns
 * the right one with the reason, so the selector never re-derives it.
 */
export const CANNOT_HOLD_TARGET_SHORT = "can't hold a backup target yet";
export const CANNOT_HOLD_DATA_SHORT = "can't hold app data";
export const CANNOT_HOLD_DATA_YET_SHORT = "can't hold app data yet";

export type NodeForEligibility = Pick<Node, 'id' | 'role' | 'hostname'>;

export type TargetEligibility =
  | { ok: true; reason?: undefined; short?: undefined }
  | { ok: false; reason: string; short: string };

/**
 * canHoldTarget mirrors storage.CanHoldTarget for the node selector. The
 * words are the api's, built the same way, so a node annotated here and a
 * row refused by the api read identically.
 *
 * `backup` is the controlplane only — see the file header for why #302 does
 * not change that. `data` is the controlplane and the storage role, which is
 * where the AGENT registers the storage handlers: a claim to any other node is
 * published to a subject nothing is subscribed to.
 *
 * ⚠️ A compute node is refused for that reason and NOT for a placement one —
 * it runs apps, and a data disk holds the volumes of the apps on its OWN node,
 * so there is no transport in the way. It is a "not yet" with two things
 * behind it, in order: §6.4's per-app placement field has to exist so
 * something can ask for the disk, and then the agent's role gate has to be
 * widened to arm `storage.claim` there. This mirror changes last, with the Go
 * rule it copies — never on its own.
 */
export function canHoldTarget(node: NodeForEligibility, purpose: StoragePurpose): TargetEligibility {
  const name = node.hostname?.trim() || node.id;
  switch (purpose) {
    case 'backup':
      if (node.role === 'controlplane') return { ok: true };
      return {
        ok: false,
        short: CANNOT_HOLD_TARGET_SHORT,
        reason: `a disk on ${name} (${node.role}) cannot receive backups yet — ${TARGET_TRANSPORT_EXPLANATION}`,
      };
    case 'data':
      if (node.role === 'controlplane' || node.role === 'storage') return { ok: true };
      if (node.role === 'firewall') {
        return {
          ok: false,
          short: CANNOT_HOLD_DATA_SHORT,
          reason: `a disk on ${name} (${node.role}) cannot hold app data — ${DATA_PLACEMENT_EXPLANATION}`,
        };
      }
      // Compute, and any role added later.
      return {
        ok: false,
        short: CANNOT_HOLD_DATA_YET_SHORT,
        reason: `a disk on ${name} (${node.role}) cannot hold app data yet — ${DATA_NO_STORAGE_VERBS_EXPLANATION}`,
      };
    default:
      // Unreachable through the type, and a refusal anyway: the api fails
      // closed on a purpose it does not implement and the selector must not
      // offer a node for one this build has never heard of.
      return {
        ok: false,
        short: "can't hold a claimed disk",
        reason: `no disk can be claimed for a purpose this control plane does not implement: ${purpose}`,
      };
  }
}

/** The selector's option text: "cp1 (controlplane)", "shelf (storage) — can't hold a backup target yet". */
export function nodeOptionLabel(node: NodeForEligibility, purpose: StoragePurpose): string {
  const base = `${node.hostname} (${node.role})`;
  const eligibility = canHoldTarget(node, purpose);
  if (eligibility.ok) return base;
  return `${base} — ${eligibility.short}`;
}

/**
 * candidateIneligibility is the reason THIS disk cannot be claimed, from the
 * api's answer, or null when it can. One field, whatever the cause: a boot
 * medium says why it is protected, a disk on a storage node says why the
 * node cannot hold a target.
 *
 * FAIL CLOSED on an api that predates `eligible`: a candidate with the field
 * absent falls back to `protected`, which is what the picker disabled on
 * before #397 — so an old api still renders exactly as it did.
 */
export function candidateIneligibility(c: BackupCandidate): string | null {
  if (c.eligible === undefined) {
    return c.protected ? c.protectedReason || 'Holds the currently-mounted boot or persistent partitions.' : null;
  }
  if (c.eligible) return null;
  return c.ineligibleReason || c.protectedReason || 'This disk cannot be claimed as a backup target.';
}

/**
 * targetRowNodeNote is what a claimed row on a node that cannot hold a
 * target says beside its status — an operator who hit the dead end before
 * #397. The api's words, so the row and the failed run tell one story; null
 * for every row on the controlplane.
 */
export function targetRowNodeNote(t: BackupTarget): string | null {
  return t.nodeIneligibleReason?.trim() || null;
}
