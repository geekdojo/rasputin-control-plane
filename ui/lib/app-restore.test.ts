import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  RESTORE_CONFIRM_DEFAULT,
  appRestoreRequestBody,
  blobsForSources,
  canSubmitRestore,
  confirmationCopy,
  generationLine,
  restoreBlocker,
  restorableVolumes,
} from './app-restore';
import type { App, AppRestoreGeneration, AppRestoreSources } from './types';

// The confirmation's rules, executed: the box starts unticked and nothing
// submits without it; the blockers are named in the operator's order; the
// request body carries the identifiers and the key and never a secret.

const app: App = {
  id: '01APP',
  name: 'vaultwarden',
  composeYaml: '',
  targetNode: 'compute1',
  sourceTile: 'vaultwarden',
  lastStatus: 'running',
  createdAt: '2026-09-01T00:00:00Z',
  updatedAt: '2026-09-01T00:00:00Z',
};

const generation: AppRestoreGeneration = {
  id: '20260904T041601Z-1WF3849B-full',
  createdAt: '2026-09-04T04:16:01Z',
  ageHuman: '2 day(s) ago',
  scope: 'full',
  complete: true,
  keyId: 'ak-1',
  matchedBy: 'appId',
  restorable: true,
  volumes: [
    { volume: 'vaultwarden-data', class: 'critical', sizeBytes: 4096, fileCount: 3, capturedFrom: 'compute1', restorable: true },
    { volume: 'vaultwarden-cache', class: 'cache', sizeBytes: 10, fileCount: 1, restorable: false, reason: 'classed `cache` by the tile' },
  ],
};

const sources: AppRestoreSources = {
  appId: app.id,
  appName: app.name,
  tileId: 'vaultwarden',
  installed: true,
  nodeId: 'compute1',
  nodeOnline: true,
  target: { jobId: 'j', nodeId: 'cp', partUuid: 'part-1', status: 'claimed', hasWrappedKeys: true, createdAt: '2026-09-01T00:00:00Z' },
  marker: {
    markerVersion: 1,
    keyId: 'ak-1',
    keyAlg: 'X25519;wrap=AES-256-GCM',
    publicKey: 'pub',
    wrappedByPassphrase: 'pp',
    wrappedByRecoveryCode: 'rc',
    createdAt: '2026-09-01T00:00:00Z',
  },
  declaredVolumes: [{ name: 'vaultwarden-data', backup: 'critical', quiesce: 'stop' }],
  generations: [generation],
};

describe('the confirmation defaults to NOT restoring', () => {
  test('the checkbox starts unticked', () => {
    assert.equal(RESTORE_CONFIRM_DEFAULT, false);
  });

  test('nothing submits until it is ticked, and everything else is ready', () => {
    const ready = { confirmed: true, src: sources, generation, secretReady: true, busy: false };
    assert.equal(canSubmitRestore({ ...ready, confirmed: RESTORE_CONFIRM_DEFAULT }), false);
    assert.equal(canSubmitRestore({ ...ready, secretReady: false }), false);
    assert.equal(canSubmitRestore({ ...ready, busy: true }), false);
    assert.equal(canSubmitRestore({ ...ready, generation: null }), false);
    assert.equal(canSubmitRestore({ ...ready, src: { ...sources, nodeOnline: false } }), false);
    assert.equal(canSubmitRestore({ ...ready, src: { ...sources, installed: false } }), false);
    assert.equal(canSubmitRestore({ ...ready, generation: { ...generation, restorable: false, problem: 'nothing to restore' } }), false);
    assert.equal(canSubmitRestore(ready), true);
  });
});

describe('restoreBlocker names what stops a restore, in the operator’s order', () => {
  test('the app first: not installed, then offline', () => {
    assert.match(restoreBlocker({ ...sources, installed: false }, generation) ?? '', /not deployed.*deploy it first/);
    assert.match(restoreBlocker({ ...sources, nodeOnline: false }, generation) ?? '', /compute1 .*offline.*not queued/);
  });
  test('then the disk, then the generation', () => {
    assert.equal(restoreBlocker({ ...sources, generations: [], problem: 'no retained generation holds a volume of this app' }, null), 'no retained generation holds a volume of this app');
    assert.equal(restoreBlocker(sources, null), 'Choose the backup to restore from.');
    assert.equal(restoreBlocker(sources, { ...generation, restorable: false, problem: 'sealed to another key' }), 'sealed to another key');
    assert.equal(restoreBlocker(sources, generation), null);
    assert.equal(restoreBlocker(null, generation), 'Reading the backup target…');
  });
});

describe('the request body', () => {
  test('carries the identifiers, the key base64url, the selected volumes, and nothing else', () => {
    const key = new Uint8Array(32).map((_, i) => i);
    const body = appRestoreRequestBody({ partUuid: 'part-1', generationId: generation.id, keyId: 'ak-1', volumes: ['vaultwarden-data'] }, key);
    assert.deepEqual(Object.keys(body).sort(), ['generationId', 'keyId', 'partUuid', 'privateKey', 'volumes']);
    assert.equal(body.privateKey, 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8');
    assert.ok(!body.privateKey.includes('='), 'unpadded');
    assert.deepEqual(body.volumes, ['vaultwarden-data']);
    assert.ok(!JSON.stringify(body).includes('passphrase') && !JSON.stringify(body).includes('recovery'), 'no custody secret rides along');
    const all = appRestoreRequestBody({ partUuid: 'part-1', generationId: generation.id, keyId: 'ak-1' }, key);
    assert.equal('volumes' in all, false);
  });
  test('refuses anything that is not a 32-byte key', () => {
    assert.throws(() => appRestoreRequestBody({ partUuid: 'p', generationId: 'g', keyId: 'k' }, new Uint8Array(16)));
  });
});

describe('blobsForSources', () => {
  test('reads the five strings off the marker', () => {
    assert.deepEqual(blobsForSources(sources), {
      keyId: 'ak-1',
      alg: 'X25519;wrap=AES-256-GCM',
      publicKey: 'pub',
      wrappedByPassphrase: 'pp',
      wrappedByRecoveryCode: 'rc',
    });
  });
  test('refuses a marker this build cannot open, in the api’s words', () => {
    assert.throws(() => blobsForSources({ ...sources, marker: { ...sources.marker!, publicKey: undefined }, problem: 'predates the keypair design' }), /predates the keypair design/);
    assert.throws(() => blobsForSources({ ...sources, marker: undefined }), /no archive key/);
  });
});

describe('the words', () => {
  test('the picker line says INCOMPLETE in capitals and counts restorable volumes only', () => {
    assert.ok(generationLine(generation).endsWith('complete · 1 volume'));
    assert.ok(generationLine({ ...generation, complete: false }).includes('INCOMPLETE'));
    assert.deepEqual(
      restorableVolumes(generation).map((v) => v.volume),
      ['vaultwarden-data'],
    );
  });
  test('the confirmation names the volumes, the age, REPLACED, the stop and the kept copy', () => {
    const c = confirmationCopy(app, sources, generation);
    assert.ok(c.checkbox.includes('Replace the current data of vaultwarden') && c.checkbox.includes('2 day(s) ago'));
    assert.ok(c.detail.includes('REPLACED') && c.detail.includes('vaultwarden-data (critical)') && c.detail.includes(generation.id));
    assert.ok(c.detail.includes('stopped') && c.detail.includes('moved aside') && c.detail.includes('compute1'));
    assert.ok(!c.detail.includes('vaultwarden-cache'), 'a skipped volume is not promised');
    assert.equal(c.reinstalled, null);
    assert.match(confirmationCopy(app, sources, { ...generation, matchedBy: 'tile+name' }).reinstalled ?? '', /earlier install/);
  });
});
