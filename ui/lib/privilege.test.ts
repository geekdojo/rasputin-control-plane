// geekdojo/geekdojo-brain#730: the co-located-secrets warning shown when an
// owner accepts the host-trusting tier, at install and at a tier-raising
// upgrade. Present for host-trusting only, a plain sentence, and vendor-neutral.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { coLocatedSecretsWarning } from './privilege';

describe('coLocatedSecretsWarning', () => {
  // TC-730-06
  test('TC-730-06: host-trusting gets a sentence naming secrets, other apps and the node', () => {
    const w = coLocatedSecretsWarning('host-trusting');
    assert.ok(w, 'host-trusting must carry the warning');
    assert.match(w, /secrets/);
    assert.match(w, /every other app/);
    assert.match(w, /this node/);
    assert.match(w, /^[A-Z]/, 'starts with a capital letter');
    assert.match(w, /\.$/, 'ends with a full stop');
  });

  // TC-730-07
  test('TC-730-07: routine and elevated carry no warning', () => {
    assert.equal(coLocatedSecretsWarning('routine'), null);
    assert.equal(coLocatedSecretsWarning('elevated'), null);
  });

  // TC-730-08
  test('TC-730-08: the sentence names no backend', () => {
    const w = coLocatedSecretsWarning('host-trusting');
    assert.ok(w);
    assert.doesNotMatch(w, /docker|compose|openbao|containerd|headscale/i);
  });
});
