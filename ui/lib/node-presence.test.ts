import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { countOnLan, presenceBadge, presenceExplainer, presenceView } from './node-presence';
import type { Node } from './types';

// The nodes page's rendering of OFF BUS · on mesh (geekdojo/geekdojo-brain#401):
// the badge, the hover with both timestamps, the drawer explainer, and the
// header count that deliberately leaves an off-bus node out.

const NOW = Date.parse('2026-09-04T12:00:00Z');
const iso = (secondsAgo: number) => new Date(NOW - secondsAgo * 1000).toISOString();

function node(status: Node['status'], busAgo: number, mesh?: Node['mesh']): Pick<Node, 'status' | 'lastSeen' | 'mesh'> {
  return { status, lastSeen: iso(busAgo), mesh };
}

describe('presenceBadge', () => {
  test('off-bus: OFF BUS · on mesh, amber, both timestamps on hover', () => {
    const b = presenceBadge(
      node('off-bus', 3 * 3600, { state: 'joined', enrolled: true, online: true, lastSeen: iso(40) }),
      NOW,
    );
    assert.equal(b.label, 'OFF BUS · on mesh');
    assert.equal(b.tone, 'offbus');
    assert.equal(b.title, 'bus last heard 3h ago · mesh seen 40s ago');
  });

  test('off-bus without a mesh last-seen still says the mesh is online', () => {
    const b = presenceBadge(node('off-bus', 200, { state: 'joined', enrolled: true, online: true }), NOW);
    assert.equal(b.title, 'bus last heard 3m ago · mesh online');
  });

  test('offline stays OFFLINE, dim, with the bus timestamp', () => {
    const b = presenceBadge(node('offline', 3 * 3600, { state: 'absent', enrolled: true, online: false, lastSeen: iso(3600) }), NOW);
    assert.equal(b.label, 'OFFLINE');
    assert.equal(b.tone, 'offline');
    assert.equal(b.title, 'bus last heard 3h ago');
  });

  test('stale and online are unchanged by mesh state', () => {
    const on = { state: 'joined', enrolled: true, online: true, lastSeen: iso(5) } as const;
    assert.deepEqual(presenceBadge(node('stale', 60, on), NOW), { label: 'STALE', tone: 'warning', title: 'bus last heard 1m ago' });
    assert.deepEqual(presenceBadge(node('online', 5, on), NOW), { label: 'ONLINE', tone: 'online' });
  });
});

describe('presenceView', () => {
  test('maps every status to a grid tone', () => {
    assert.equal(presenceView('online'), 'online');
    assert.equal(presenceView('stale'), 'warning');
    assert.equal(presenceView('offline'), 'offline');
    assert.equal(presenceView('off-bus'), 'offbus');
  });
});

describe('presenceExplainer', () => {
  test('off-bus says what it means and what to do; nothing else has one', () => {
    const text = presenceExplainer('off-bus');
    assert.ok(text);
    assert.match(text, /reachable over the mesh/);
    assert.match(text, /agent is not on the bus/);
    assert.match(text, /Restart the agent/);
    assert.match(text, /check its log/);
    for (const s of ['online', 'stale', 'offline'] as const) assert.equal(presenceExplainer(s), null);
  });
});

describe('countOnLan', () => {
  test('off-bus is not on the LAN count — the bus cannot hear it', () => {
    const nodes = [
      { status: 'online' as const },
      { status: 'online' as const },
      { status: 'stale' as const },
      { status: 'off-bus' as const },
      { status: 'offline' as const },
    ];
    assert.equal(countOnLan(nodes), 2);
  });
});
