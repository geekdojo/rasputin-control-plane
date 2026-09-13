// geekdojo/geekdojo-brain#426: the Add App drawers' default target, executed.
//
//   - an online node on the mesh wins over the first node in the list;
//   - an off-mesh node is never the default, and is labelled OFF MESH;
//   - with no mesh service (membership undetermined) an online node is still
//     the default, as the api still installs there;
//   - ties go to the node that joined first, then the lowest id, whatever
//     order the list arrived in;
//   - nothing qualifies → no default.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { defaultDeployTarget, deployTargetLabel, isOffMesh, offMeshTargetWarning } from './deploy-target';
import type { MeshMembership, Node, NodeStatus } from './types';

function node(id: string, over: { status?: NodeStatus; firstSeen?: string; mesh?: MeshMembership } = {}) {
  return {
    id,
    role: 'compute' as const,
    architecture: 'arm64',
    status: over.status ?? ('online' as NodeStatus),
    firstSeen: over.firstSeen ?? '2026-09-01T00:00:00Z',
    mesh: 'mesh' in over ? over.mesh : { state: 'joined' as const },
  } satisfies Partial<Node>;
}

const ABSENT: MeshMembership = { state: 'absent', enrolled: true, online: false };
const JOINED: MeshMembership = { state: 'joined', enrolled: true, online: true };

describe('defaultDeployTarget', () => {
  test('the #415 bench: cp-compute1 off the mesh sorts first, cp-compute2 on it is the default', () => {
    const nodes = [node('cp-compute1', { mesh: ABSENT }), node('cp-compute2', { mesh: JOINED })];
    assert.equal(defaultDeployTarget(nodes), 'cp-compute2');
  });

  test('an off-mesh node is never the default, even when it is the only online node', () => {
    assert.equal(defaultDeployTarget([node('c1', { mesh: ABSENT })]), '');
    assert.equal(defaultDeployTarget([node('c1', { mesh: ABSENT }), node('c2', { status: 'stale' })]), '');
  });

  test('online AND on the mesh: a stale or off-bus joined node is not the default', () => {
    const nodes = [node('c1', { status: 'stale' }), node('c2', { status: 'off-bus' }), node('c3', { firstSeen: '2026-09-10T00:00:00Z' })];
    assert.equal(defaultDeployTarget(nodes), 'c3');
  });

  test('joined beats undetermined', () => {
    const nodes = [node('c1', { mesh: undefined, firstSeen: '2026-01-01T00:00:00Z' }), node('c2', { mesh: JOINED })];
    assert.equal(defaultDeployTarget(nodes), 'c2');
  });

  test('no mesh service: an online node with undetermined membership is still the default', () => {
    assert.equal(defaultDeployTarget([node('c1', { mesh: undefined }), node('c0', { mesh: ABSENT })]), 'c1');
    assert.equal(defaultDeployTarget([node('c1', { mesh: { state: 'unknown' } })]), 'c1');
  });

  test('ties go to the node that joined the cluster first, whatever the list order', () => {
    const early = node('zeta', { firstSeen: '2026-08-01T00:00:00Z' });
    const late = node('alpha', { firstSeen: '2026-09-01T00:00:00Z' });
    assert.equal(defaultDeployTarget([late, early]), 'zeta');
    assert.equal(defaultDeployTarget([early, late]), 'zeta');
  });

  test('then the lowest id', () => {
    const a = node('c2');
    const b = node('c1');
    assert.equal(defaultDeployTarget([a, b]), 'c1');
    assert.equal(defaultDeployTarget([b, a]), 'c1');
  });

  test('no nodes, no default', () => {
    assert.equal(defaultDeployTarget([]), '');
  });
});

describe('the picker', () => {
  test('an off-mesh node is labelled OFF MESH', () => {
    assert.equal(deployTargetLabel(node('cp-compute1', { mesh: ABSENT })), 'cp-compute1 (compute, arm64, online, OFF MESH)');
  });

  test('a joined or undetermined node is not', () => {
    assert.equal(deployTargetLabel(node('cp-compute2')), 'cp-compute2 (compute, arm64, online)');
    assert.equal(deployTargetLabel(node('c1', { mesh: undefined })), 'c1 (compute, arm64, online)');
  });

  test('isOffMesh is the api\'s KnownAbsent: undetermined is not off the mesh', () => {
    assert.equal(isOffMesh({ mesh: ABSENT }), true);
    assert.equal(isOffMesh({ mesh: undefined }), false);
    assert.equal(isOffMesh({ mesh: { state: 'unknown' } }), false);
    assert.equal(isOffMesh({ mesh: JOINED }), false);
  });

  test('choosing an off-mesh node for a tailnet-only app warns, naming it', () => {
    const off = node('cp-compute1', { mesh: ABSENT });
    assert.match(offMeshTargetWarning(off, { exposeLan: false, route: 'custom' })!, /^cp-compute1 is not on the mesh, so a tailnet-only app is refused there/);
    assert.match(offMeshTargetWarning(off, { exposeLan: false, route: 'catalog' })!, /cannot be reached over the tailnet/);
  });

  test('no warning for a node on the mesh, an undetermined one, a LAN-exposed app, or no choice', () => {
    assert.equal(offMeshTargetWarning(node('cp-compute2'), { exposeLan: false, route: 'custom' }), null);
    assert.equal(offMeshTargetWarning(node('c1', { mesh: undefined }), { exposeLan: false, route: 'custom' }), null);
    assert.equal(offMeshTargetWarning(node('cp-compute1', { mesh: ABSENT }), { exposeLan: true, route: 'catalog' }), null);
    assert.equal(offMeshTargetWarning(undefined, { exposeLan: false, route: 'custom' }), null);
  });
});
