import type { Node } from './types';

// Config faults — operator-configuration values a node REJECTED at startup.
//
// The agent used to exit on an unrecognised RASPUTIN_*_BACKEND or an invalid
// role. With Restart=always and a hand-edited node.env on a read-only rootfs,
// that permanently prevented the agent from starting on a box reachable only by
// SSH — confirmed on hardware 2026-07-28, where the control plane kept serving
// this very UI for a node that no longer had an agent. It now survives the bad
// value instead, disables the affected subsystem, and reports what it refused
// (agent/internal/configfault, proto.MetadataConfigFaults).
//
// A node also reports a fault of the SECOND kind, added 2026-09-01: the real
// backend's prerequisites are absent and NOTHING was substituted for it. Those
// carry `missing` (the absent prerequisite) and an empty `value`, because the
// operator typed nothing — the machine is simply not equipped. They exist
// because a missing `wipefs` once made a real controlplane answer with fixture
// disks; mock backends are now opt-in and never inferred.
//
// ⚠️ Rendering it is the half that makes the rest honest. Degrading quietly
// would trade a dead node for a lying one — an operator who pinned a backend
// and silently got none has been misled in a quieter way. Until this surfaced
// in the UI the fault reached nodes.metadata and stopped there, which is only
// marginally better than the journal nobody was tailing.

export type ConfigFault = {
  /** The environment variable that carried the bad value, or names the knob. */
  variable: string;
  /** What the operator actually typed. Empty when nothing was set — see `missing`. */
  value: string;
  /** Values that would have been accepted. May be empty. */
  expected: string[];
  /**
   * The absent prerequisite, when this fault is the SECOND kind: the operator
   * asked for nothing and the real backend cannot run here ("not on PATH:
   * wipefs"). Empty for a rejected value.
   *
   * Added 2026-09-01. Agents predating it never send it, and `effect` always
   * carries the same detail in prose, so treat it as a nicety and never as the
   * thing that decides whether to render the fault.
   */
  missing?: string;
  /** What this node can no longer do, in the operator's terms. */
  effect: string;
};

const KEY = 'configFaults';

/**
 * configFaults reads the faults a node reported, defensively.
 *
 * Everything here arrives from an agent that may be older or newer than this
 * UI, so every field is validated and anything malformed is dropped rather than
 * rendered as `undefined`. Absence and an empty list both mean "healthy" — the
 * agent omits the key entirely on a clean node, so `[]` is what callers get
 * either way and no caller has to distinguish them.
 */
export function configFaults(node: Node | null | undefined): ConfigFault[] {
  const raw = node?.metadata?.[KEY];
  if (!Array.isArray(raw)) return [];

  const out: ConfigFault[] = [];
  for (const f of raw) {
    if (!f || typeof f !== 'object') continue;
    const variable = (f as { variable?: unknown }).variable;
    if (typeof variable !== 'string' || !variable) continue;

    const value = (f as { value?: unknown }).value;
    const effect = (f as { effect?: unknown }).effect;
    const expected = (f as { expected?: unknown }).expected;
    const missing = (f as { missing?: unknown }).missing;

    const fault: ConfigFault = {
      variable,
      value: typeof value === 'string' ? value : '',
      effect: typeof effect === 'string' ? effect : '',
      expected: Array.isArray(expected)
        ? expected.filter((e): e is string => typeof e === 'string')
        : [],
    };
    if (typeof missing === 'string' && missing) fault.missing = missing;
    out.push(fault);
  }
  return out;
}

/** hasConfigFaults is the cheap check for badging a node in a list. */
export function hasConfigFaults(node: Node | null | undefined): boolean {
  return configFaults(node).length > 0;
}
