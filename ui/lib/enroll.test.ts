// The Add-node wizard's node-name rule, executed. It must agree with the api's
// busauth.ValidNodeID (a lowercase RFC 1123 label): the api answers anything
// else with a 400, and the wizard should say so before the operator submits.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { clusterPrefixOf, suggestNodeId, validNodeId } from './enroll';

describe('validNodeId', () => {
  test('accepts lowercase DNS labels', () => {
    for (const id of ['alpha', 'e3bench-controlplane1', 'node-9bbaa24a', 'a', '0', 'a-b', 'a'.repeat(63)]) {
      assert.equal(validNodeId(id), true, id);
    }
  });

  test('refuses everything else', () => {
    for (const id of [
      '', '*', '>', 'a.b', 'a b', 'a\tb', ' alpha', 'alpha\n', 'Alpha', 'ALPHA', 'node_1', 'a/b',
      '-alpha', 'alpha-', '-', 'ålpha', 'a'.repeat(64),
    ]) {
      assert.equal(validNodeId(id), false, JSON.stringify(id));
    }
  });
});

describe('suggestNodeId', () => {
  test('follows the cluster prefix and skips taken ids', () => {
    const taken = new Set(['e3bench-controlplane1', 'e3bench-compute1', 'e3bench-compute2']);
    const prefix = clusterPrefixOf([...taken]);
    assert.equal(prefix, 'e3bench-');
    assert.equal(suggestNodeId(prefix, 'compute', taken), 'e3bench-compute3');
    assert.equal(suggestNodeId(prefix, 'firewall', taken), 'e3bench-firewall1');
  });

  test('bare role names on an empty cluster', () => {
    assert.equal(suggestNodeId('', 'compute', new Set()), 'compute1');
  });

  test('never suggests an invalid id, even from a non-conforming inventory', () => {
    const cases: [string[], string][] = [
      [['Lab-controlplane1', 'Lab-compute1'], 'compute'], // uppercase prefix
      [['my_lab-controlplane1', 'my_lab-compute1'], 'compute'], // underscore prefix
      [[`${'x'.repeat(58)}-controlplane1`, `${'x'.repeat(58)}-compute1`], 'firewall'], // too long with the role
    ];
    for (const [ids, role] of cases) {
      const taken = new Set(ids);
      const got = suggestNodeId(clusterPrefixOf(ids), role as 'compute' | 'firewall', taken);
      assert.equal(validNodeId(got), true, `${ids.join(',')} -> ${got}`);
      assert.equal(taken.has(got), false, got);
    }
  });
});
