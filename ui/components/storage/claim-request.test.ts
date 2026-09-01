// The §4.6 rule, asserted at the boundary it is about.
//
// "The plaintext data key and the passphrase never leave the browser" is a
// claim about one object: the body of POST /api/backup/targets. These tests
// serialise that body and go looking for anything secret in it — including on
// the adopt path, which is the one that now asks the operator to type a
// passphrase and could most plausibly leak one by accident.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { mintArchiveKey } from '../../lib/archive-key';
import type { BackupCandidate } from '../../lib/types';
import { archiveKeyFromMarker, buildClaimRequest, needsUnlock } from './claim-request';

const PASSPHRASE = 'correct horse battery staple';

function blankDisk(): BackupCandidate {
  return {
    devicePath: '/dev/nvme1n1',
    model: 'CT2000P3SSD8',
    serial: 'SN-SPARE-0002',
    sizeBytes: 2_000_398_934_016,
    transport: 'nvme',
    removable: false,
    hasBackupSet: false,
    protected: false,
    fingerprint: 'fp-spare',
  };
}

/** A disk carrying a §4.6-keyed backup set — what an adopt actually meets. */
function keyedDisk(): BackupCandidate {
  return {
    ...blankDisk(),
    hasBackupSet: true,
    wipeToken: 'wt-abc',
    backupSet: {
      markerVersion: 1,
      clusterId: 'bitscope',
      partUuid: 'aaaa-1111',
      keyId: 'ak-DEADBEEF',
      keyAlg: 'AES-256-GCM;pp=argon2id-m65536-t3-p1;rc=hkdf-sha256',
      wrappedByPassphrase: 'cGFzc3BocmFzZS1ibG9i',
      wrappedByRecoveryCode: 'cmVjb3ZlcnktYmxvYg',
      label: 'weekly archive',
      createdAt: '2026-08-30T03:00:00Z',
      generations: 4,
    },
  };
}

/** The shape every disk claimed before the marker learned to carry the key has. */
function keylessAdoptableDisk(): BackupCandidate {
  const c = keyedDisk();
  return {
    ...c,
    backupSet: {
      ...c.backupSet!,
      keyAlg: undefined,
      wrappedByPassphrase: undefined,
      wrappedByRecoveryCode: undefined,
    },
  };
}

describe('needsUnlock', () => {
  test('a disk carrying both sealed copies must be unlocked', () => {
    assert.equal(needsUnlock(keyedDisk()), true);
  });

  test('a blank disk has nothing to unlock', () => {
    assert.equal(needsUnlock(blankDisk()), false);
  });

  test('a set whose marker carries no wrappings has nothing to unlock', () => {
    // Demanding a secret here would strand the disk: there is no blob on it to
    // open, so no passphrase could ever succeed.
    assert.equal(needsUnlock(keylessAdoptableDisk()), false);
  });

  test('one wrapping is not enough — both or neither', () => {
    const half = keyedDisk();
    half.backupSet!.wrappedByRecoveryCode = undefined;
    assert.equal(needsUnlock(half), false);
    assert.equal(archiveKeyFromMarker(half), undefined);
  });
});

describe('archiveKeyFromMarker', () => {
  test('carries the disk’s own wrappings across verbatim', () => {
    const c = keyedDisk();
    assert.deepEqual(archiveKeyFromMarker(c), {
      keyId: 'ak-DEADBEEF',
      alg: 'AES-256-GCM;pp=argon2id-m65536-t3-p1;rc=hkdf-sha256',
      wrappedByPassphrase: 'cGFzc3BocmFzZS1ibG9i',
      wrappedByRecoveryCode: 'cmVjb3ZlcnktYmxvYg',
    });
  });

  // Adopt PRESERVES, never re-wraps. The api enforces the same thing from the
  // other side (checkAdoptedKeyCustody), and the reason is that a re-wrap
  // reaching the database and not the disk leaves the restore path — which has
  // only the disk — holding a passphrase the operator was told to forget.
  test('the adopt body submits exactly what the marker holds', () => {
    const c = keyedDisk();
    const req = buildClaimRequest({
      candidate: c,
      nodeId: 'node-1',
      action: 'adopt',
      label: 'weekly archive',
      replace: false,
      archiveKey: archiveKeyFromMarker(c),
    });
    assert.equal(req.adopt, true);
    assert.equal(req.wipe, undefined);
    assert.deepEqual(req.archiveKey, archiveKeyFromMarker(c));
  });
});

describe('the request body carries no key material', () => {
  test('adopt: neither the passphrase nor anything plaintext-shaped', async () => {
    const c = keyedDisk();
    const req = buildClaimRequest({
      candidate: c,
      nodeId: 'node-1',
      action: 'adopt',
      label: 'weekly archive',
      replace: false,
      archiveKey: archiveKeyFromMarker(c),
    });
    const body = JSON.stringify(req);
    assert.ok(!body.includes(PASSPHRASE), 'the passphrase must not reach the request body');
    for (const forbidden of ['dataKey', 'plaintext', 'recoveryCode"', '"passphrase"', '"secret"']) {
      assert.ok(!body.includes(forbidden), `the body contains ${forbidden}: ${body}`);
    }
    // The api decodes with DisallowUnknownFields, so the body must contain
    // ONLY fields it declares — an exact whitelist rather than a scan.
    const allowed = new Set([
      'nodeId',
      'devicePath',
      'fingerprint',
      'label',
      'replace',
      'adopt',
      'wipe',
      'archiveKey',
    ]);
    for (const k of Object.keys(req)) {
      assert.ok(allowed.has(k), `unknown field ${k} would be a 400`);
    }
    const keyFields = new Set(['keyId', 'alg', 'wrappedByPassphrase', 'wrappedByRecoveryCode']);
    for (const k of Object.keys(req.archiveKey!)) {
      assert.ok(keyFields.has(k), `archiveKey grew field ${k}`);
    }
  });

  test('format: the freshly minted key travels sealed, and the code does not travel', {
    timeout: 30_000,
  }, async () => {
    const minted = await mintArchiveKey(new TextEncoder().encode(PASSPHRASE));
    const req = buildClaimRequest({
      candidate: blankDisk(),
      nodeId: 'node-1',
      action: 'format',
      label: '',
      replace: false,
      archiveKey: minted.archiveKey,
    });
    const body = JSON.stringify(req);
    assert.ok(!body.includes(PASSPHRASE));
    assert.ok(
      !body.includes(minted.recoveryCode.replace(/-/g, '')),
      'the recovery code is shown to the operator and sent nowhere',
    );
    assert.ok(!body.includes(minted.recoveryCode));
    assert.equal(req.adopt, undefined);
    assert.equal(req.label, undefined, 'an empty label is omitted, not sent blank');
  });

  test('wipe: the token is echoed and adopt is not set', () => {
    const req = buildClaimRequest({
      candidate: keyedDisk(),
      nodeId: 'node-1',
      action: 'wipe',
      label: 'fresh start',
      replace: true,
      archiveKey: undefined,
    });
    assert.deepEqual(req.wipe, { token: 'wt-abc' });
    assert.equal(req.adopt, undefined);
    assert.equal(req.replace, true);
    assert.equal(req.archiveKey, undefined);
  });

  test('a wipe with no token from the picker sends no wipe at all', () => {
    const c = keyedDisk();
    c.wipeToken = undefined;
    const req = buildClaimRequest({
      candidate: c,
      nodeId: 'node-1',
      action: 'wipe',
      label: '',
      replace: false,
    });
    // Absence is a refusal, never a default — the api refuses a tokenless wipe,
    // and the body must not pretend to carry one.
    assert.equal(req.wipe, undefined);
  });
});
