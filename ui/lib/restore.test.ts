// The browser half of restore (design/storage.md §4.5, #291), executed.
//
// The crypto is archive-key.test.ts's business; these hold the request the
// restore builds to its shape — three identifiers and the key, nothing else
// — and the words the wizard shows to their facts.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  appVolumeGap,
  blobsFor,
  clusterIdMismatch,
  generationHeadline,
  restoreRequestBody,
} from './restore';
import type { RestoreCandidate, RestoreGeneration } from './types';

const generation: RestoreGeneration = {
  id: '20260904T031500Z-abc12345-full',
  createdAt: '2026-09-04T03:15:00Z',
  scope: 'full',
  complete: false,
  keyId: 'ak-1',
  clusterId: 'home1',
  manifestVersion: 2,
  archiveBytes: 1234,
  identityEntries: 5,
  appVolumesPresent: [{ name: 'vaultwarden/data', class: 'critical', member: 'volumes/vaultwarden/data.rasputin-archive' }],
  appVolumesAbsent: [{ name: 'jellyfin/library', class: 'bulk', reason: 'bulk lane not built' }],
  restorable: true,
};

const candidate: RestoreCandidate = {
  nodeId: 'cp',
  devicePath: '/dev/sdb',
  sizeBytes: 1,
  transport: 'usb',
  removable: true,
  marker: {
    markerVersion: 1,
    clusterId: 'home1',
    partUuid: 'part-1',
    keyId: 'ak-1',
    keyAlg: 'X25519;wrap=AES-256-GCM',
    publicKey: 'pub',
    wrappedByPassphrase: 'pp',
    wrappedByRecoveryCode: 'rc',
    createdAt: '2026-09-01T00:00:00Z',
  },
  generations: [generation],
  restorable: true,
};

describe('restoreRequestBody', () => {
  test('carries exactly the three identifiers and the key, base64url', () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < 32; i++) key[i] = i;
    const body = restoreRequestBody({ partUuid: 'part-1', generationId: generation.id, keyId: 'ak-1' }, key);
    assert.deepEqual(Object.keys(body).sort(), ['generationId', 'keyId', 'partUuid', 'privateKey']);
    assert.equal(body.privateKey, 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8');
    assert.ok(!body.privateKey.includes('='), 'unpadded');
    assert.ok(!JSON.stringify(body).includes('passphrase'), 'no custody secret rides along');
  });

  test('refuses anything that is not a 32-byte key', () => {
    assert.throws(() => restoreRequestBody({ partUuid: 'p', generationId: 'g', keyId: 'k' }, new Uint8Array(16)));
  });
});

describe('blobsFor', () => {
  test('reads the five strings off the marker', () => {
    assert.deepEqual(blobsFor(candidate), {
      keyId: 'ak-1',
      alg: 'X25519;wrap=AES-256-GCM',
      publicKey: 'pub',
      wrappedByPassphrase: 'pp',
      wrappedByRecoveryCode: 'rc',
    });
  });

  test('refuses a symmetric-era marker in the api’s words', () => {
    const symmetric: RestoreCandidate = {
      ...candidate,
      marker: { ...candidate.marker!, publicKey: undefined },
      problem: 'this disk’s archive key predates the keypair design',
    };
    assert.throws(() => blobsFor(symmetric), /predates the keypair design/);
    assert.throws(() => blobsFor({ ...candidate, marker: undefined }), /no archive key/);
  });
});

describe('clusterIdMismatch', () => {
  test('is silent when the names agree or either is unknown', () => {
    assert.equal(clusterIdMismatch('home1', 'home1'), null);
    assert.equal(clusterIdMismatch('', 'home1'), null);
    assert.equal(clusterIdMismatch('home1', ''), null);
    assert.equal(clusterIdMismatch(undefined, 'home1'), null);
  });

  test('names both clusters and what breaks', () => {
    const msg = clusterIdMismatch('home1', 'lab2');
    assert.ok(msg && msg.includes('"home1"') && msg.includes('"lab2"') && msg.includes('home1.local'));
    assert.ok(msg.includes('Re-flash'));
  });
});

describe('the wizard’s words', () => {
  test('the headline says INCOMPLETE in capitals when the run missed something', () => {
    assert.ok(generationHeadline(generation).includes('INCOMPLETE'));
    assert.ok(generationHeadline({ ...generation, complete: true }).endsWith('complete'));
    assert.ok(generationHeadline(generation).includes('scope full'));
  });

  test('the app-volume gap names every volume the generation holds', () => {
    const gap = appVolumeGap(generation);
    assert.ok(gap.includes('vaultwarden/data'));
    assert.ok(gap.includes('NOT be restored'));
    assert.equal(appVolumeGap({ ...generation, appVolumesPresent: [] }), '');
  });
});
