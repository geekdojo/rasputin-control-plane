import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import {
  pendingEnrollments,
  SELF_AGENT_REASON,
  SELF_AGENT_REASON_DETAIL,
  type PendingEnrollment,
} from './bus-tokens';
import type { BusTokenInfo } from './types';

const CREATED = '2026-09-17T12:00:00Z';

function token(over: Partial<BusTokenInfo> & { id: string }): BusTokenInfo {
  return { label: 'compute', createdAt: CREATED, ...over };
}

function byId(list: PendingEnrollment[]): Record<string, PendingEnrollment> {
  return Object.fromEntries(list.map((p) => [p.id, p]));
}

test('a bound, unrevoked token whose node has not registered is a pending bay', () => {
  const pend = pendingEnrollments(
    [token({ id: 'h1', nodeId: 'compute-1' }), token({ id: 'h2', nodeId: 'storage-1' })],
    [],
  );
  assert.deepEqual(
    pend.map((p) => p.id),
    ['compute-1', 'storage-1'],
  );
  assert.equal(pend[0].tokenId, 'h1');
  assert.equal(pend[0].label, 'compute');
  assert.ok(pend.every((p) => p.cancelable));
  assert.ok(pend.every((p) => p.reason === undefined));
});

test('a registered node, a revoked token and an unbound token are not bays', () => {
  const pend = pendingEnrollments(
    [
      token({ id: 'h1', nodeId: 'compute-1' }), // registered below
      token({ id: 'h2', nodeId: 'compute-2', revokedAt: CREATED }),
      token({ id: 'h3' }), // legacy unbound: no node id
      token({ id: 'h4', nodeId: 'storage-1' }),
    ],
    ['compute-1'],
  );
  assert.deepEqual(
    pend.map((p) => p.id),
    ['storage-1'],
  );
});

// geekdojo-brain#140: the api refuses to revoke its own agent's token, so the
// bay must not offer the click. The reason takes its place.
test("the controlplane's own agent token is a bay that cannot be cancelled", () => {
  const pend = byId(
    pendingEnrollments(
      [
        token({ id: 'self', nodeId: 'cp-1', label: 'controlplane', selfAgent: true }),
        token({ id: 'h1', nodeId: 'compute-1' }),
      ],
      [],
    ),
  );
  assert.equal(pend['cp-1'].cancelable, false);
  assert.equal(pend['cp-1'].reason, SELF_AGENT_REASON);
  assert.equal(pend['cp-1'].reasonDetail, SELF_AGENT_REASON_DETAIL);
  assert.ok(SELF_AGENT_REASON.length <= 20, 'the reason has to fit in a hex');

  // Nothing else is affected: an ordinary node in the same list stays
  // cancelable and carries no reason.
  assert.equal(pend['compute-1'].cancelable, true);
  assert.equal(pend['compute-1'].reason, undefined);
  assert.equal(pend['compute-1'].reasonDetail, undefined);
});

// The flag comes from the api, never from the label — an operator can mint a
// token with any label, and the controlplane's role name is not a credential.
test('cancelability reads selfAgent, not the label or the node id', () => {
  const pend = byId(
    pendingEnrollments(
      [
        token({ id: 'h1', nodeId: 'cp-2', label: 'controlplane agent (minted by the api at start)' }),
        token({ id: 'h2', nodeId: 'cp-3', label: 'controlplane' }),
        token({ id: 'h3', nodeId: 'oddly-named', label: 'compute', selfAgent: true }),
      ],
      [],
    ),
  );
  assert.equal(pend['cp-2'].cancelable, true, 'a label lookalike is still cancelable');
  assert.equal(pend['cp-3'].cancelable, true, 'a controlplane-ish node id is still cancelable');
  assert.equal(pend['oddly-named'].cancelable, false, 'the flag alone decides');
});

// An api from before #140 sends no selfAgent field at all. Everything stays
// cancelable then, which is exactly the old behaviour — the UI never invents a
// refusal the api would not make.
test('a response with no selfAgent field leaves every bay cancelable', () => {
  const pend = pendingEnrollments(
    [token({ id: 'h1', nodeId: 'cp-1', label: 'controlplane' }), token({ id: 'h2', nodeId: 'compute-1' })],
    [],
  );
  assert.ok(pend.every((p) => p.cancelable));
});

test('selfAgent: false is cancelable', () => {
  const [only] = pendingEnrollments([token({ id: 'h1', nodeId: 'compute-1', selfAgent: false })], []);
  assert.equal(only.cancelable, true);
  assert.equal(only.reason, undefined);
});
