import type { Node } from './types';

// Per-node BMC gating (wiki design/control-plane/bmc.md §2a): a node gets
// BMC power/console controls iff it appears in some registered BMC host's
// advertised bmc-targets list — no entry, no button, never a console that
// can't emit bytes. The names mirror proto's CapabilityBMCTargets /
// MetadataBMCTargets constants; the api enforces the same gate server-side.
export const BMC_TARGETS_CAPABILITY = 'bmc-targets';

// bmcReachableNodes returns the union of every advertising host's target
// list. On a cluster whose BMC host advertises nothing (no real backend
// configured) the set is empty and no BMC surface renders anywhere.
export function bmcReachableNodes(nodes: Node[]): Set<string> {
  const out = new Set<string>();
  for (const n of nodes) {
    if (!n.capabilities?.includes(BMC_TARGETS_CAPABILITY)) continue;
    const list = n.metadata?.bmcTargets;
    if (Array.isArray(list)) {
      for (const t of list) {
        if (typeof t === 'string') out.add(t);
      }
    }
  }
  return out;
}
