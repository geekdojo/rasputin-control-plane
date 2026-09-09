// Which nodes can hold a backup target, as the Storage page needs to know it
// (#397) — extracted so the copy can be executed rather than asserted in a
// comment; see backup-runs.ts for why nothing that matters lives in a .tsx.
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
// what the Go rule says today — controlplane only — and it is the second of
// two places the storage SKU (geekdojo-brain#302) relaxes when a storage-node
// target becomes possible. Get them out of step and the worst case is a node
// labelled "can't hold a target" whose scan then says otherwise; the api's
// answer wins on the row, so nothing is claimable that should not be.

import type { BackupCandidate, BackupTarget, Node } from '../../lib/types';

/** The tail every refusal shares — verbatim from storage.CanHoldTarget. */
export const TARGET_TRANSPORT_EXPLANATION =
  "archives are written by the controlplane's ingest to a disk attached to the controlplane; a storage-node target arrives with the storage SKU (#302)";

/** The short form the selector annotates a node with. */
export const CANNOT_HOLD_TARGET_SHORT = "can't hold a backup target yet";

export type NodeForEligibility = Pick<Node, 'id' | 'role' | 'hostname'>;

export type TargetEligibility = { ok: true; reason?: undefined } | { ok: false; reason: string };

/**
 * canHoldTarget mirrors storage.CanHoldTarget for the node selector. The
 * words are the api's, built the same way, so a node annotated here and a
 * row refused by the api read identically.
 */
export function canHoldTarget(node: NodeForEligibility): TargetEligibility {
  if (node.role === 'controlplane') return { ok: true };
  const name = node.hostname?.trim() || node.id;
  return {
    ok: false,
    reason: `a disk on ${name} (${node.role}) cannot receive backups yet — ${TARGET_TRANSPORT_EXPLANATION}`,
  };
}

/** The selector's option text: "cp1 (controlplane)", "shelf (storage) — can't hold a backup target yet". */
export function nodeOptionLabel(node: NodeForEligibility): string {
  const base = `${node.hostname} (${node.role})`;
  return canHoldTarget(node).ok ? base : `${base} — ${CANNOT_HOLD_TARGET_SHORT}`;
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
