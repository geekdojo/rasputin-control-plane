// Which node the Add App drawers pick by default, and how they label each
// choice — geekdojo/geekdojo-brain#426.
//
// On the #415 bench run the custom-app drawer defaulted to the first node in
// the list, cp-compute1, which was off the mesh (`mesh.state: 'absent'` in
// GET /api/nodes, from inventory.ApplyMesh). An owner accepting that default
// deploys a tailnet-only app onto a node with no tailnet interface.
//
// The api stays the enforcement: it refuses a tailnet-only install on a node
// whose membership is KNOWN absent (tailnetOnlyOffMeshMsg in
// api/internal/api/apps_handlers.go). This module only makes the default the
// choice that works, and says which choices will not.
//
// THE DEFAULT RULE, in order:
//
//   1. an ONLINE node whose mesh state is `joined`;
//   2. otherwise an ONLINE node whose mesh membership is undetermined (no
//      `mesh` block, or `unknown`) — a cluster with no mesh service has no
//      node that is joined, and the api does not refuse there either;
//   3. otherwise nothing: no default, and the owner picks.
//
// Within a tier, the node that joined the cluster first (earliest
// `firstSeen`), then the lowest id — never the order the list happened to
// arrive in. A node that is known off the mesh, stale or off-bus is never the
// default, though it stays selectable.
//
// Pure functions, so the rule executes under `npm test`.

import type { Node } from './types';

type TargetNode = Pick<Node, 'id' | 'status' | 'firstSeen' | 'mesh'>;

/** A positive determination that the node is not on the mesh — the api's KnownAbsent. */
export function isOffMesh(n: Pick<Node, 'mesh'>): boolean {
  return n.mesh?.state === 'absent';
}

function tier(n: TargetNode): number {
  if (n.status !== 'online') return 0;
  if (n.mesh?.state === 'joined') return 2;
  if (!n.mesh || n.mesh.state === 'unknown') return 1;
  return 0; // known absent
}

function firstJoined(a: TargetNode, b: TargetNode): number {
  const ta = Date.parse(a.firstSeen);
  const tb = Date.parse(b.firstSeen);
  const va = Number.isNaN(ta) ? Infinity : ta;
  const vb = Number.isNaN(tb) ? Infinity : tb;
  if (va !== vb) return va < vb ? -1 : 1;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

/**
 * The default target's id, or '' when no node qualifies (the owner must
 * choose). `targets` is the drawer's list of deployable nodes.
 */
export function defaultDeployTarget(targets: readonly TargetNode[]): string {
  let best: TargetNode | null = null;
  for (const n of targets) {
    const t = tier(n);
    if (t === 0) continue;
    if (!best || t > tier(best) || (t === tier(best) && firstJoined(n, best) < 0)) best = n;
  }
  return best?.id ?? '';
}

/** The picker's label for one node; an off-mesh node says so. */
export function deployTargetLabel(n: Pick<Node, 'id' | 'role' | 'architecture' | 'status' | 'mesh'>): string {
  const facts = [n.role, n.architecture, n.status, isOffMesh(n) ? 'OFF MESH' : ''].filter(Boolean);
  return `${n.id} (${facts.join(', ')})`;
}

/**
 * The warning under the picker when the chosen node is off the mesh; null
 * otherwise. Only for a tailnet-only app — a LAN-exposed one does not need
 * the tailnet. The two drawers say different things because the api treats
 * them differently: POST /api/apps (the custom drawer) refuses a tailnet-only
 * app on a known-absent node, while the catalog install route has no such
 * refusal today, so there the app would install and be unreachable.
 */
export function offMeshTargetWarning(
  n: Pick<Node, 'id' | 'mesh'> | undefined,
  opts: { exposeLan: boolean; route: 'custom' | 'catalog' },
): string | null {
  if (!n || opts.exposeLan || !isOffMesh(n)) return null;
  if (opts.route === 'custom') {
    return `${n.id} is not on the mesh, so a tailnet-only app is refused there. Choose a node on the mesh.`;
  }
  return `${n.id} is not on the mesh, so a tailnet-only app there cannot be reached over the tailnet. Choose a node on the mesh, or allow LAN access.`;
}
