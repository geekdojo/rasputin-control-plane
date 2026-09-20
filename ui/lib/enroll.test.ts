// The Add-node wizard's node-name rule, executed. It must agree with the api's
// busauth.ValidNodeID (a lowercase RFC 1123 label): the api answers anything
// else with a 400, and the wizard should say so before the operator submits.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { clusterPrefixOf, suggestNodeId, validNodeId, validOperatorSSHKey } from './enroll';

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

// The operator-SSH-key rule, executed on both sides of the language boundary.
//
// setup.ValidOperatorSSHKey in Go is the rule; validOperatorSSHKey here is a
// mirror, because a browser cannot call Go. Three copies of this rule existed
// before, each with a comment asking the next reader to keep them in sync, and
// they drifted. The vectors below are the contract: this file runs them
// against the TypeScript mirror and api/internal/setup/operatorkeys_test.go
// runs the SAME file against the Go rule, so a change on one side without the
// other fails a build. geekdojo/geekdojo-brain#545.
//
// __dirname is .test-out/lib at run time (tsconfig.test.json emits CommonJS
// there), so the vectors are two levels up in the source tree.
describe('the operator SSH key rule matches the Go rule', () => {
  const vectorsPath = path.join(__dirname, '..', '..', 'lib', 'operator-ssh-key-vectors.json');
  const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8')) as {
    valid: { why: string; key: string }[];
    invalid: { why: string; key: string }[];
  };

  test('the vectors are present and non-trivial', () => {
    assert.ok(vectors.valid.length >= 5, 'valid vectors');
    assert.ok(vectors.invalid.length >= 10, 'invalid vectors');
  });

  test('accepts every valid vector', () => {
    for (const v of vectors.valid) {
      assert.equal(validOperatorSSHKey(v.key), true, `${v.why}: ${JSON.stringify(v.key)}`);
    }
  });

  test('refuses every invalid vector', () => {
    for (const v of vectors.invalid) {
      assert.equal(validOperatorSSHKey(v.key), false, `${v.why}: ${JSON.stringify(v.key)}`);
    }
  });
});
