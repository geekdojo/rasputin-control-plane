import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { failedAppsOf, failureLine } from './job-failures';
import type { JobStep } from './types';

function step(name: string, result: unknown, status: JobStep['status'] = 'succeeded'): JobStep {
  return { jobId: 'j', seq: 0, name, status, attempt: 0, result };
}

describe('failedAppsOf', () => {
  test('reads failedApps out of the assemble result, one line per app', () => {
    const steps = [
      step('fan_out', { report: { volumes: [] } }),
      step('assemble', {
        appVolumesFailed: 2,
        failedApps: [
          { appId: 'app-im', app: 'immich', node: 'n-compute', class: 'state', volumes: ['immich-upload'], reason: 'node n-compute is OFFLINE' },
          { app: 'romm', volumes: ['romm-db', 'romm-assets'], reason: 'upload did not land' },
        ],
      }),
      step('prune', null, 'failed'),
    ];
    const got = failedAppsOf(steps);
    assert.equal(got.length, 2);
    assert.deepEqual(got[0], { app: 'immich', appId: 'app-im', node: 'n-compute', class: 'state', volumes: ['immich-upload'], reason: 'node n-compute is OFFLINE' });
    assert.deepEqual(got[1], { app: 'romm', appId: undefined, node: undefined, class: undefined, volumes: ['romm-db', 'romm-assets'], reason: 'upload did not land' });
  });

  test('ignores results without the field, malformed entries and non-object results', () => {
    const steps = [
      step('validate', { partUuid: 'x' }),
      step('assemble', { failedApps: 'nope' }),
      step('other', { failedApps: [{ volumes: ['v'] }, 42, null, { app: '' }] }),
      step('string', 'text'),
    ];
    assert.deepEqual(failedAppsOf(steps), []);
  });
});

describe('failureLine', () => {
  test('names the app, its node, its volumes and the reason', () => {
    assert.equal(
      failureLine({ app: 'immich', node: 'n-compute', volumes: ['immich-upload'], reason: 'node n-compute is OFFLINE' }),
      'immich on n-compute — immich-upload: node n-compute is OFFLINE',
    );
    assert.equal(failureLine({ app: 'romm', volumes: [], reason: '' }), 'romm — no reason recorded');
  });
});
