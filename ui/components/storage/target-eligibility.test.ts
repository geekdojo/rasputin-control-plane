import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  CANNOT_HOLD_TARGET_SHORT,
  TARGET_TRANSPORT_EXPLANATION,
  candidateIneligibility,
  canHoldTarget,
  nodeOptionLabel,
  targetRowNodeNote,
} from './target-eligibility';
import type { BackupCandidate, BackupTarget, NodeRole } from '../../lib/types';

function node(role: NodeRole, hostname = 'shelf', id = 'n-1') {
  return { id, role, hostname };
}

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

describe('canHoldTarget (mirror of storage.CanHoldTarget)', () => {
  it('lets the controlplane hold a target and nothing else, today', () => {
    assert.deepEqual(canHoldTarget(node('controlplane')), { ok: true });
    for (const role of ['storage', 'compute', 'firewall'] as const) {
      const r = canHoldTarget(node(role));
      assert.equal(r.ok, false, role);
      // The api's sentence, word for word: the selector and the refused
      // row must read the same.
      assert.equal(
        r.reason,
        `a disk on shelf (${role}) cannot receive backups yet — ${TARGET_TRANSPORT_EXPLANATION}`,
      );
    }
  });

  it('names the node the way the selector does — hostname, else id', () => {
    const r = canHoldTarget(node('storage', '', 'n-9'));
    assert.equal(r.ok, false);
    assert.match(r.reason!, /^a disk on n-9 \(storage\)/);
  });

  it('points at the storage SKU as what relaxes it', () => {
    assert.match(TARGET_TRANSPORT_EXPLANATION, /storage SKU \(#302\)/);
  });
});

describe('nodeOptionLabel', () => {
  it('annotates a node that cannot hold a target, and leaves the controlplane alone', () => {
    assert.equal(nodeOptionLabel(node('controlplane', 'cp1')), 'cp1 (controlplane)');
    assert.equal(nodeOptionLabel(node('storage')), `shelf (storage) — ${CANNOT_HOLD_TARGET_SHORT}`);
  });
});

describe('candidateIneligibility', () => {
  it('is null for a disk the api called eligible', () => {
    assert.equal(candidateIneligibility(candidate({})), null);
  });

  it('is the api reason on a disk on a node that cannot hold a target — the boot medium included', () => {
    const reason = 'a disk on shelf (storage) cannot receive backups yet — ' + TARGET_TRANSPORT_EXPLANATION;
    assert.equal(candidateIneligibility(candidate({ eligible: false, ineligibleReason: reason })), reason);
    assert.equal(
      candidateIneligibility(
        candidate({ eligible: false, ineligibleReason: reason, protected: true, protectedReason: 'holds /boot' }),
      ),
      reason,
    );
  });

  it('is the protected reason on the controlplane boot medium', () => {
    assert.equal(
      candidateIneligibility(candidate({ eligible: false, ineligibleReason: 'holds /boot', protected: true, protectedReason: 'holds /boot' })),
      'holds /boot',
    );
  });

  it('falls back to `protected` against an api that predates `eligible`', () => {
    const legacy = candidate({ protected: true, protectedReason: 'holds /boot' });
    delete (legacy as Partial<BackupCandidate>).eligible;
    assert.equal(candidateIneligibility(legacy), 'holds /boot');
    const legacyBlank = candidate({});
    delete (legacyBlank as Partial<BackupCandidate>).eligible;
    assert.equal(candidateIneligibility(legacyBlank), null);
  });
});

describe('targetRowNodeNote', () => {
  const row = (nodeIneligibleReason?: string): BackupTarget => ({
    jobId: 'j',
    nodeId: 'n-1',
    status: 'claimed',
    hasWrappedKeys: false,
    createdAt: '2026-09-01T00:00:00Z',
    nodeIneligibleReason,
  });
  it('repeats the api reason on a row the picker would refuse today, and says nothing on the controlplane', () => {
    assert.equal(targetRowNodeNote(row('a disk on shelf (storage) cannot receive backups yet — x')), 'a disk on shelf (storage) cannot receive backups yet — x');
    assert.equal(targetRowNodeNote(row()), null);
    assert.equal(targetRowNodeNote(row('  ')), null);
  });
});
