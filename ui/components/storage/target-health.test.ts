import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { HEALTH_DANGER, HEALTH_DIM, HEALTH_OK, elapsedSince, healthBadge, isFailing } from './target-health';
import type { BackupTarget, BackupTargetHealth } from '../../lib/types';

const NOW = Date.parse('2026-09-02T06:57:00Z');

function claimed(health?: BackupTargetHealth, status: BackupTarget['status'] = 'claimed'): BackupTarget {
  return { jobId: 'j', nodeId: 'cp', partUuid: 'part-1', label: 'e3bench-backup', status, hasWrappedKeys: true, createdAt: '2026-09-01T00:00:00Z', health };
}

describe('healthBadge', () => {
  it('says MISSING with the elapsed time since the first poll that noticed', () => {
    const b = healthBadge(
      claimed({
        state: 'missing',
        since: '2026-09-02T03:12:00Z',
        checkedAt: '2026-09-02T06:55:00Z',
        detail: 'nothing attached to cp carries partition UUID part-1; a DIFFERENT disk is at /dev/sda now',
      }),
      NOW,
    );
    assert.ok(b);
    assert.equal(b.text, 'MISSING · since 3h');
    assert.equal(b.color, HEALTH_DANGER);
    assert.equal(b.failing, true);
    // The detail rides on hover, with when it was checked.
    assert.match(b.title, /DIFFERENT disk/);
    assert.match(b.title, /checked 2m ago/);
  });

  it('renders every failing state red', () => {
    for (const state of ['missing', 'unmounted', 'unwritable', 'unreachable'] as const) {
      const b = healthBadge(claimed({ state, since: '2026-09-02T05:57:00Z', checkedAt: '2026-09-02T06:56:00Z' }), NOW);
      assert.ok(b, state);
      assert.equal(b.color, HEALTH_DANGER, state);
      assert.equal(b.text, `${state.toUpperCase()} · since 1h`, state);
      assert.equal(isFailing(state), true);
    }
  });

  it('is OK, green, and not failing on a passing probe', () => {
    const b = healthBadge(claimed({ state: 'ok', checkedAt: '2026-09-02T06:56:00Z', detail: 'wrote, read back, deleted' }), NOW);
    assert.ok(b);
    assert.equal(b.text, 'OK');
    assert.equal(b.color, HEALTH_OK);
    assert.equal(b.failing, false);
    assert.equal(isFailing('ok'), false);
  });

  it('says UNCHECKED, not OK, before the first poll — and when the api sends no health at all', () => {
    for (const t of [claimed({ state: 'unknown' }), claimed(undefined)]) {
      const b = healthBadge(t, NOW);
      assert.ok(b);
      assert.equal(b.text, 'UNCHECKED');
      assert.equal(b.color, HEALTH_DIM);
      assert.equal(b.failing, false);
      assert.match(b.title, /5 minutes/);
    }
  });

  it('falls back to checkedAt for the elapsed time when since is absent', () => {
    const b = healthBadge(claimed({ state: 'unwritable', checkedAt: '2026-09-02T06:50:00Z' }), NOW);
    assert.ok(b);
    assert.equal(b.text, 'UNWRITABLE · since 7m');
  });

  it('renders a state this build does not know in red rather than hiding it', () => {
    const b = healthBadge(claimed({ state: 'on-fire' as BackupTargetHealth['state'], since: '2026-09-02T06:56:00Z' }), NOW);
    assert.ok(b);
    assert.equal(b.color, HEALTH_DANGER);
    assert.equal(b.text, 'ON-FIRE · since 1m');
  });

  it('shows nothing on a row that is not in service', () => {
    for (const status of ['pending', 'replaced', 'failed'] as const) {
      assert.equal(healthBadge(claimed({ state: 'missing' }, status), NOW), null, status);
    }
  });
});

describe('elapsedSince', () => {
  it('is coarse and never negative', () => {
    assert.equal(elapsedSince('2026-09-02T06:56:30Z', NOW), '30s');
    assert.equal(elapsedSince('2026-09-02T06:50:00Z', NOW), '7m');
    assert.equal(elapsedSince('2026-09-02T03:12:00Z', NOW), '3h');
    assert.equal(elapsedSince('2026-08-30T03:12:00Z', NOW), '3d');
    assert.equal(elapsedSince('2026-09-02T07:30:00Z', NOW), '0s');
    assert.equal(elapsedSince('not a date', NOW), '');
    assert.equal(elapsedSince(undefined, NOW), '');
  });
});
