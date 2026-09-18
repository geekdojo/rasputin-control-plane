// Bus join tokens, as the node grid reads them.
//
// A bound, unrevoked token whose node hasn't registered in inventory yet is a
// *pending enrollment*: a node that has been issued a credential but hasn't
// booted and joined. The grid gives each one a bay, and a click cancels it
// (DELETE /api/bus/tokens/{id}).
//
// One of those tokens must never be offered for cancellation: the one the api
// minted for THIS controlplane's own agent, which GET /api/bus/tokens marks
// `selfAgent` (geekdojo-brain#140, decided 2026-09-17). The controlplane
// occupies a pending bay itself until its agent registers, so the cancel click
// is reachable on exactly the credential that keeps the controlplane on the
// bus — and the api answers that revoke with a 409. Deciding it here, off the
// api's own flag rather than off a label or a guess at which node is the
// controlplane, keeps the button and the answer in agreement.

import type { BusTokenInfo } from './types';

export interface PendingEnrollment {
  // The node id the token is bound to — the bay's label.
  id: string;
  // The token's id (token_hash): the handle a cancel revokes.
  tokenId: string;
  // The token's label, which the caller maps to a short role for display.
  label: string;
  // False when the api refuses to revoke this token, so the grid must not
  // offer the action.
  cancelable: boolean;
  // Shown in the bay in place of the cancel affordance. Set only when
  // cancelable is false.
  reason?: string;
  // The longer form, for the bay's tooltip.
  reasonDetail?: string;
}

// What the bay shows instead of "CLICK TO CANCEL" for the controlplane's own
// token. Short enough for the hex, and it names the thing rather than the
// refusal ("can't cancel" alone reads as a bug).
export const SELF_AGENT_REASON = 'THIS CONTROLPLANE';
export const SELF_AGENT_REASON_DETAIL =
  "this controlplane's own bus credential — cancelling it would take its agent off the bus, so it can't be cancelled";

// pendingEnrollments turns the token ledger into the bays the grid draws:
// bound, unrevoked tokens whose node id is not in inventory yet. Once the node
// registers it drops out and becomes a live hex.
export function pendingEnrollments(
  tokens: readonly BusTokenInfo[],
  liveNodeIds: Iterable<string>,
): PendingEnrollment[] {
  const live = new Set(liveNodeIds);
  const out: PendingEnrollment[] = [];
  for (const t of tokens) {
    if (!t.nodeId || t.revokedAt || live.has(t.nodeId)) continue;
    out.push({
      id: t.nodeId,
      tokenId: t.id,
      label: t.label,
      cancelable: !t.selfAgent,
      ...(t.selfAgent
        ? { reason: SELF_AGENT_REASON, reasonDetail: SELF_AGENT_REASON_DETAIL }
        : {}),
    });
  }
  return out;
}
