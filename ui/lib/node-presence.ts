// Node presence as the nodes page says it: the badge, its hover, the drawer
// explainer and the header count, from the api's derived `status` and `mesh`.
//
// The api makes the join (inventory.DeriveStatus): the page never fetches
// mesh devices itself. This module only renders the result, and exists as a
// plain module so the copy is unit-testable (geekdojo/geekdojo-brain#401).

import type { MeshMembership, NodeStatus } from './types';
import { timeAgo } from './time';

/** How a status renders on the hex grid / as a tone for colouring. */
export type PresenceView = 'online' | 'offline' | 'warning' | 'offbus';

export interface PresenceBadge {
  /** The LAN row's text, e.g. "OFF BUS · on mesh". */
  label: string;
  tone: PresenceView;
  /** Hover text, e.g. "bus last heard 3h ago · mesh seen 40s ago". */
  title?: string;
}

export function presenceView(status: NodeStatus): PresenceView {
  switch (status) {
    case 'online':
      return 'online';
    case 'offline':
      return 'offline';
    case 'off-bus':
      return 'offbus';
    default:
      return 'warning'; // stale
  }
}

/**
 * The LAN badge. Off-bus says both facts the operator would otherwise have
 * to cross-reference across the nodes and mesh pages: the bus went quiet
 * hours ago, the mesh saw the machine seconds ago.
 */
export function presenceBadge(
  node: { status: NodeStatus; lastSeen: string; mesh?: MeshMembership },
  now: number = Date.now(),
): PresenceBadge {
  const bus = timeAgo(node.lastSeen, now);
  const busHeard = bus ? `bus last heard ${bus}` : 'bus never heard';
  switch (node.status) {
    case 'off-bus': {
      const mesh = node.mesh?.lastSeen ? timeAgo(node.mesh.lastSeen, now) : '';
      const meshSeen = mesh ? `mesh seen ${mesh}` : 'mesh online';
      return { label: 'OFF BUS · on mesh', tone: 'offbus', title: `${busHeard} · ${meshSeen}` };
    }
    case 'offline':
      return { label: 'OFFLINE', tone: 'offline', title: busHeard };
    case 'stale':
      return { label: 'STALE', tone: 'warning', title: busHeard };
    default:
      return { label: 'ONLINE', tone: 'online' };
  }
}

/**
 * What the state means and what to do — shown in the drawer under STATUS.
 * Only off-bus has one: it is the state whose cause a flat OFFLINE hid.
 */
export function presenceExplainer(status: NodeStatus): string | null {
  if (status !== 'off-bus') return null;
  return (
    'This machine is reachable over the mesh but its agent is not on the bus, so the ' +
    'controlplane cannot drive it, back it up or update it. Restart the agent on the node, ' +
    'or check its log.'
  );
}

/**
 * The header's NODES ON LAN count. Off-bus does NOT count: the tile counts
 * nodes the bus can hear, and an off-bus node is by definition one it cannot
 * — counting it because the machine answers over the mesh would fold two
 * facts into one number again, the exact error #202 took apart. The ON MESH
 * tile beside it is where an off-bus node still counts, so the pair reads
 * "ON LAN 4 / 5 · ON MESH 5 / 5": one node the mesh can reach and the bus
 * cannot.
 */
export function countOnLan(nodes: ReadonlyArray<{ status: NodeStatus }>): number {
  return nodes.filter((n) => n.status === 'online').length;
}
