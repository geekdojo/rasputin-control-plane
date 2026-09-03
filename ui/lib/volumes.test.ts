// geekdojo/geekdojo-brain#399: the uninstall prompt's rules, executed.
//
//   - the "Delete volumes?" box defaults to unticked;
//   - ticking it over a `critical` volume with no backup produces the §4.4
//     warning, in words that name the volume and say "never been backed up";
//   - a `cache` volume with no backup produces no warning — nothing was ever
//     going to back it up;
//   - a protected volume WITH a retained capture produces no warning;
//   - the unticked (default) state never warns, whatever the volumes.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  DELETE_VOLUMES_DEFAULT,
  deleteWarning,
  describeCapture,
  isProtectedClass,
  unbackedProtected,
  type PromptVolume,
} from './volumes';

const NOW = Date.parse('2026-09-03T12:00:00Z');

const critical: PromptVolume = { name: 'vaultwarden-data', backup: 'critical', lastCaptured: null };
const state: PromptVolume = { name: 'immich-upload', backup: 'state', lastCaptured: null };
const cache: PromptVolume = { name: 'immich-model-cache', backup: 'cache', lastCaptured: null };
const backedUp: PromptVolume = {
  name: 'immich-db',
  backup: 'critical',
  lastCaptured: { generationId: 'gen-20260901', at: '2026-09-01T03:00:00Z' },
};

describe('the checkbox', () => {
  test('defaults to keep', () => {
    assert.equal(DELETE_VOLUMES_DEFAULT, false);
  });
});

describe('deleteWarning', () => {
  test('names a critical volume that has never been backed up', () => {
    const w = deleteWarning([critical], true);
    assert.ok(w, 'expected a warning');
    assert.match(w, /vaultwarden-data \(critical\)/);
    assert.match(w, /never been backed up/);
    assert.match(w, /only copy/);
  });

  test('says nothing for a cache volume', () => {
    assert.equal(deleteWarning([cache], true), null);
  });

  test('says nothing while the box is unticked', () => {
    assert.equal(deleteWarning([critical, state], false), null);
  });

  test('says nothing when the protected volume has a retained capture', () => {
    assert.equal(deleteWarning([backedUp, cache], true), null);
  });

  test('lists every unbacked protected volume and only those', () => {
    const w = deleteWarning([critical, state, cache, backedUp], true);
    assert.ok(w);
    assert.match(w, /vaultwarden-data \(critical\), immich-upload \(state\)/);
    assert.doesNotMatch(w, /immich-model-cache/);
    assert.doesNotMatch(w, /immich-db/);
    assert.match(w, /have never been backed up/);
  });

  test('treats an unclassified orphan as protected', () => {
    const unknown: PromptVolume = { name: 'rasp_x_data', backup: '', lastCaptured: null };
    const w = deleteWarning([unknown], true);
    assert.ok(w);
    assert.match(w, /rasp_x_data \(unclassified\)/);
  });
});

describe('describeCapture', () => {
  test('never', () => {
    assert.equal(describeCapture(critical, NOW), 'never');
  });
  test('generation and age', () => {
    assert.equal(describeCapture(backedUp, NOW), 'gen-20260901, 2d ago');
  });
});

describe('class rules', () => {
  test('critical and state are protected; cache and bulk are not; unknown is', () => {
    assert.equal(isProtectedClass('critical'), true);
    assert.equal(isProtectedClass('state'), true);
    assert.equal(isProtectedClass('cache'), false);
    assert.equal(isProtectedClass('bulk'), false);
    assert.equal(isProtectedClass(''), true);
  });
  test('unbackedProtected picks the right subset', () => {
    assert.deepEqual(
      unbackedProtected([critical, state, cache, backedUp]).map((v) => v.name),
      ['vaultwarden-data', 'immich-upload'],
    );
  });
});
