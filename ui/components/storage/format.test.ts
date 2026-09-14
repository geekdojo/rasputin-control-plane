import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { disposition } from './format';
import type { BackupCandidate, StorageBackupSet } from '../../lib/types';

function candidate(over: Partial<BackupCandidate>): BackupCandidate {
  return {
    devicePath: '/dev/sdb',
    sizeBytes: 1e12,
    transport: 'usb',
    removable: true,
    hasBackupSet: false,
    protected: false,
    fingerprint: 'fp',
    eligible: true,
    ...over,
  };
}

function marker(partUuid: string | undefined): StorageBackupSet {
  return { markerVersion: 1, partUuid, createdAt: '2026-09-01T00:00:00Z', generations: 3 };
}

function withSet(partUuid: string | undefined): BackupCandidate {
  return candidate({ hasBackupSet: true, backupSet: marker(partUuid) });
}

describe('disposition', () => {
  it('keeps the four answers it gave before a claimed target was an input', () => {
    assert.equal(disposition(candidate({ protected: true, hasBackupSet: true })), 'protected');
    assert.equal(disposition(candidate({})), 'format');
    assert.equal(disposition(withSet('p-1')), 'adopt');
    assert.equal(disposition(candidate({ hasBackupSet: true })), 'unreadable');
  });

  // geekdojo-brain#439: the claimed target's own disk was offered for adoption
  // ("Adopt it to keep it", REVIEW…) because nothing told disposition which
  // set was already the target.
  it('marks the disk whose backup set IS the claimed target as current', () => {
    assert.equal(disposition(withSet('p-1'), { partUuid: 'p-1' }), 'current');
  });

  it('still offers adoption of a backup set that is not the claimed target', () => {
    assert.equal(disposition(withSet('p-2'), { partUuid: 'p-1' }), 'adopt');
  });

  it('never matches on a missing partition UUID', () => {
    // A pending claim has no partUuid until step 5, and an older marker may
    // carry none: two absences are not the same disk.
    assert.equal(disposition(withSet(undefined), { partUuid: undefined }), 'adopt');
    assert.equal(disposition(withSet(''), { partUuid: '' }), 'adopt');
    assert.equal(disposition(withSet('p-1'), null), 'adopt');
  });

  it('lets protection and an unreadable marker outrank the claimed target', () => {
    assert.equal(
      disposition(candidate({ protected: true, hasBackupSet: true, backupSet: marker('p-1') }), { partUuid: 'p-1' }),
      'protected',
    );
    assert.equal(disposition(candidate({ hasBackupSet: true }), { partUuid: 'p-1' }), 'unreadable');
  });
});
