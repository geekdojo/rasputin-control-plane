import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { backupBadge, backupSummary, compactAge, sortAppsOverdueFirst } from './backup-state';
import type { AppBackupState } from './types';

const NOW = Date.parse('2026-09-05T12:00:00Z');
const DAY = 24 * 60 * 60 * 1000;

function state(partial: Partial<AppBackupState> & { state: AppBackupState['state'] }): AppBackupState {
  return { cadence: '168h0m0s', ...partial };
}

describe('compactAge', () => {
  test('one unit, the largest that fits', () => {
    assert.equal(compactAge(12_000), '12s');
    assert.equal(compactAge(40 * 60_000), '40m');
    assert.equal(compactAge(2 * 3_600_000 + 59 * 60_000), '2h');
    assert.equal(compactAge(9 * DAY + 4 * 3_600_000), '9d');
    assert.equal(compactAge(-5_000), '0s');
  });
});

describe('backupBadge', () => {
  test('overdue with a last success says how long since it', () => {
    const b = backupBadge(
      state({ state: 'overdue', lastSuccessAt: new Date(NOW - 9 * DAY).toISOString(), reason: 'node n-compute is OFFLINE' }),
      NOW,
    );
    assert.deepEqual(b, { label: 'OVERDUE · 9d', title: 'Backup overdue: node n-compute is OFFLINE', href: '/storage' });
  });

  test('overdue and never backed up says so in words', () => {
    const b = backupBadge(state({ state: 'overdue', reason: 'never backed up: installed 12d ago' }), NOW);
    assert.equal(b?.label, 'OVERDUE · never backed up');
    assert.match(b?.title ?? '', /never backed up/);
  });

  test('every other state renders no badge — including unconfigured, which is #299, and unknown', () => {
    for (const s of ['ok', 'never', 'unconfigured', 'none'] as const) {
      assert.equal(backupBadge(state({ state: s }), NOW), null, s);
    }
    assert.equal(backupBadge(undefined, NOW), null);
  });
});

describe('backupSummary', () => {
  test('one sentence per state', () => {
    assert.equal(backupSummary(state({ state: 'ok', lastSuccessAt: new Date(NOW - 2 * 3_600_000).toISOString() }), NOW), 'Backed up 2h ago.');
    assert.equal(backupSummary(state({ state: 'overdue' }), NOW), 'OVERDUE — never backed up.');
    assert.match(backupSummary(state({ state: 'never' }), NOW), /first scheduled backup/);
    assert.match(backupSummary(state({ state: 'unconfigured' }), NOW), /not configured/);
    assert.match(backupSummary(state({ state: 'none' }), NOW), /Nothing to back up/);
    assert.match(backupSummary(undefined, NOW), /unknown/);
  });
});

describe('sortAppsOverdueFirst', () => {
  test('overdue apps lead; everything else keeps its order', () => {
    const apps = [
      { id: 'a', backup: state({ state: 'ok' }) },
      { id: 'b', backup: state({ state: 'overdue' }) },
      { id: 'c', backup: undefined },
      { id: 'd', backup: state({ state: 'overdue' }) },
      { id: 'e', backup: state({ state: 'never' }) },
    ];
    assert.deepEqual(
      sortAppsOverdueFirst(apps).map((a) => a.id),
      ['b', 'd', 'a', 'c', 'e'],
    );
  });

  test('does not mutate its input', () => {
    const apps = [{ id: 'a', backup: state({ state: 'ok' }) }, { id: 'b', backup: state({ state: 'overdue' }) }];
    sortAppsOverdueFirst(apps);
    assert.deepEqual(apps.map((a) => a.id), ['a', 'b']);
  });
});
