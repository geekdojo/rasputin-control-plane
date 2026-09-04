import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { ApiError } from './api';
import { focusNote, locateFocus, resolveFocus } from './task-focus';
import type { Job } from './types';

// /tasks?id=<jobId>, executed: a job the page already shows is expanded in
// place and nothing is fetched; one the page does not hold is fetched by id
// and pinned; a 404 is "not found" and any other failure is not.

function job(id: string, appId?: string): Job {
  return {
    id,
    kind: appId ? 'app.restore' : 'diag.ping',
    spec: appId ? { appId } : { nodeId: 'node-dev' },
    status: 'running',
    createdBy: 'operator',
    createdAt: '2026-09-04T10:00:00Z',
    startedAt: '2026-09-04T10:00:01Z',
  };
}

const recent = job('01RECENT', 'app-a');
const other = job('01OTHER', 'app-b');
const older = job('01OLDER');
const loaded = [recent, other];

function neverFetch(id: string): Promise<Job> {
  throw new Error(`fetch must not be called (asked for ${id})`);
}

describe('locateFocus', () => {
  test('a job the page shows is listed', () => {
    assert.deepEqual(locateFocus(recent.id, loaded, loaded), { where: 'listed', job: recent });
  });

  test('a job the filter hides is hidden, not unknown', () => {
    const shown = loaded.filter((j) => (j.spec as { appId?: string }).appId === 'app-a');
    assert.deepEqual(locateFocus(other.id, loaded, shown), { where: 'hidden', job: other });
  });

  test('a job the page never loaded is unknown', () => {
    assert.deepEqual(locateFocus(older.id, loaded, loaded), { where: 'unknown' });
  });
});

describe('resolveFocus', () => {
  test('in the list → expanded in place, no fetch', async () => {
    const got = await resolveFocus(recent.id, loaded, loaded, neverFetch);
    assert.deepEqual(got, { state: 'listed', job: recent });
  });

  test('loaded but filtered out → pinned from the list, no fetch', async () => {
    const shown = loaded.filter((j) => (j.spec as { appId?: string }).appId === 'app-a');
    const got = await resolveFocus(other.id, loaded, shown, neverFetch);
    assert.deepEqual(got, { state: 'outside', job: other });
  });

  test('not in the list → fetched by id and pinned', async () => {
    const asked: string[] = [];
    const got = await resolveFocus(older.id, loaded, loaded, async (id) => {
      asked.push(id);
      return older;
    });
    assert.deepEqual(asked, [older.id]);
    assert.deepEqual(got, { state: 'outside', job: older });
  });

  test('404 → missing', async () => {
    const got = await resolveFocus('01NOPE', loaded, loaded, async (id) => {
      throw new ApiError(`/api/jobs/${id} → 404: not found`, 404);
    });
    assert.deepEqual(got, { state: 'missing', id: '01NOPE' });
  });

  test('a non-404 failure is an error, never "not found"', async () => {
    const got = await resolveFocus('01DOWN', loaded, loaded, async (id) => {
      throw new ApiError(`/api/jobs/${id} → 502`, 502);
    });
    assert.equal(got.state, 'error');
    assert.match((got as { message: string }).message, /502/);

    const thrown = await resolveFocus('01DOWN', loaded, loaded, async () => {
      throw new TypeError('Failed to fetch');
    });
    assert.deepEqual(thrown, { state: 'error', id: '01DOWN', message: 'Failed to fetch' });
  });
});

describe('focusNote', () => {
  test('a listed job needs no note', () => {
    assert.equal(focusNote({ state: 'listed', job: recent }, null), null);
  });

  test('an outside job names why it is pinned', () => {
    assert.match(focusNote({ state: 'outside', job: older }, null)!, /older than the list/);
    assert.match(focusNote({ state: 'outside', job: other }, 'app-a')!, /outside the current filter \(app app-a\)/);
  });

  test('missing and error say which task', () => {
    assert.equal(focusNote({ state: 'missing', id: '01NOPE' }, null), 'task 01NOPE not found');
    assert.equal(
      focusNote({ state: 'error', id: '01DOWN', message: 'boom' }, null),
      'task 01DOWN could not be loaded: boom',
    );
  });
});
