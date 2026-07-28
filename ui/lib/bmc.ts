import type { Node } from './types';

// Per-node BMC gating (wiki design/control-plane/bmc.md §2a): a node gets
// BMC controls iff some registered BMC host advertises it — and now, only
// the controls that host can actually honour. No entry, no button; no
// capability, no button for that capability. Never a console that can't
// emit bytes.
//
// The names mirror proto's CapabilityBMCTargets / MetadataBMCTargets /
// MetadataBMCCapabilities constants; the api enforces the same gate
// server-side via TargetSupports.
export const BMC_TARGETS_CAPABILITY = 'bmc-targets';

export const BMC_CAP_POWER = 'power';
export const BMC_CAP_RESET = 'reset';
export const BMC_CAP_CONSOLE = 'console';

export const BMC_CONSOLE_CHARACTER = 'character';
export const BMC_CONSOLE_LINE = 'line';

export type BmcConsoleInfo = { mode: string; lossy?: boolean };
export type BmcCaps = { caps: Set<string>; console?: BmcConsoleInfo };

// Backends that shipped before capabilities existed advertise only the
// node-id list. They really could do all three, so that's what a bare
// listing means — matching proto.LegacyBMCCaps. This keeps a rolling
// update working in both directions: the control plane and its nodes
// update independently.
const LEGACY_CAPS: BmcCaps = {
  caps: new Set([BMC_CAP_POWER, BMC_CAP_RESET, BMC_CAP_CONSOLE]),
  console: { mode: BMC_CONSOLE_CHARACTER },
};

function consoleRank(c: BmcConsoleInfo): number {
  return (c.mode === BMC_CONSOLE_CHARACTER ? 2 : 1) - (c.lossy ? 0.5 : 0);
}

// bmcCapabilityMap returns, for every node some host can reach, what that
// host can do for it. Union across hosts: a node reachable by two hosts
// gets the union of their capabilities and the better of their consoles.
export function bmcCapabilityMap(nodes: Node[]): Map<string, BmcCaps> {
  const out = new Map<string, BmcCaps>();
  const add = (id: string, entry: BmcCaps) => {
    const prev = out.get(id);
    if (!prev) {
      out.set(id, { caps: new Set(entry.caps), console: entry.console });
      return;
    }
    for (const c of entry.caps) prev.caps.add(c);
    if (entry.console && (!prev.console || consoleRank(entry.console) > consoleRank(prev.console))) {
      prev.console = entry.console;
    }
  };

  for (const n of nodes) {
    if (!n.capabilities?.includes(BMC_TARGETS_CAPABILITY)) continue;

    const rich = n.metadata?.bmcCapabilities;
    if (Array.isArray(rich) && rich.length > 0) {
      for (const t of rich) {
        if (!t || typeof t !== 'object') continue;
        const id = (t as { nodeId?: unknown }).nodeId;
        if (typeof id !== 'string' || !id) continue;
        const rawCaps = (t as { caps?: unknown }).caps;
        const caps = new Set<string>(
          Array.isArray(rawCaps) ? rawCaps.filter((c): c is string => typeof c === 'string') : [],
        );
        const rawConsole = (t as { console?: unknown }).console;
        let consoleInfo: BmcConsoleInfo | undefined;
        if (rawConsole && typeof rawConsole === 'object') {
          const mode = (rawConsole as { mode?: unknown }).mode;
          const lossy = (rawConsole as { lossy?: unknown }).lossy;
          consoleInfo = { mode: typeof mode === 'string' ? mode : '', lossy: lossy === true };
        }
        add(id, { caps, console: consoleInfo });
      }
      continue;
    }

    // Legacy host: bare node-id list.
    const list = n.metadata?.bmcTargets;
    if (Array.isArray(list)) {
      for (const t of list) {
        if (typeof t === 'string') add(t, LEGACY_CAPS);
      }
    }
  }
  return out;
}

// bmcReachableNodes answers "does this node have any BMC surface at all" —
// the section header. Individual controls gate on their own capability.
export function bmcReachableNodes(nodes: Node[]): Set<string> {
  return new Set(bmcCapabilityMap(nodes).keys());
}

export function bmcNodeCaps(nodes: Node[], nodeId: string | undefined): BmcCaps | undefined {
  if (!nodeId) return undefined;
  return bmcCapabilityMap(nodes).get(nodeId);
}
