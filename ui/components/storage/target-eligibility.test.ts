import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  CANNOT_HOLD_DATA_SHORT,
  CANNOT_HOLD_DATA_YET_SHORT,
  CANNOT_HOLD_TARGET_SHORT,
  DATA_NO_STORAGE_VERBS_EXPLANATION,
  DATA_PLACEMENT_EXPLANATION,
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
  it('lets the controlplane hold a backup target and nothing else', () => {
    assert.deepEqual(canHoldTarget(node('controlplane'), 'backup'), { ok: true });
    for (const role of ['storage', 'compute', 'firewall'] as const) {
      const r = canHoldTarget(node(role), 'backup');
      assert.equal(r.ok, false, role);
      // The api's sentence, word for word: the selector and the refused
      // row must read the same.
      assert.equal(
        r.reason,
        `a disk on shelf (${role}) cannot receive backups yet — ${TARGET_TRANSPORT_EXPLANATION}`,
      );
    }
  });

  it('lets a data disk live where the agent answers storage verbs, and nowhere else', () => {
    // The controlplane and the storage role, which is exactly where
    // agent/cmd/rasputin-agent/main.go registers the storage handlers.
    for (const role of ['controlplane', 'storage'] as const) {
      assert.deepEqual(canHoldTarget(node(role), 'data'), { ok: true }, role);
    }
    const firewall = canHoldTarget(node('firewall'), 'data');
    assert.equal(firewall.ok, false);
    assert.equal(
      firewall.reason,
      `a disk on shelf (firewall) cannot hold app data — ${DATA_PLACEMENT_EXPLANATION}`,
    );
    const compute = canHoldTarget(node('compute'), 'data');
    assert.equal(compute.ok, false);
    assert.equal(
      compute.reason,
      `a disk on shelf (compute) cannot hold app data yet — ${DATA_NO_STORAGE_VERBS_EXPLANATION}`,
    );
  });

  it('separates the "not yet" from the "never" — compute is waiting, the firewall is not', () => {
    // A compute node DOES run apps, so borrowing the firewall's sentence
    // would not merely be the wrong words, it would be untrue of it. The
    // refusal names the actual obstacle — nothing over there is listening —
    // and the prerequisite that has to land before anyone widens it.
    assert.match(DATA_NO_STORAGE_VERBS_EXPLANATION, /reaches no responder/);
    assert.match(DATA_NO_STORAGE_VERBS_EXPLANATION, /storage\.claim/);
    assert.match(DATA_NO_STORAGE_VERBS_EXPLANATION, /§6\.4/);
    assert.doesNotMatch(DATA_NO_STORAGE_VERBS_EXPLANATION, /runs none/);
    assert.doesNotMatch(DATA_PLACEMENT_EXPLANATION, /yet/);
  });

  it('keeps the two purposes apart — a storage node holds app data, never a backup target', () => {
    assert.equal(canHoldTarget(node('storage'), 'data').ok, true);
    assert.equal(canHoldTarget(node('storage'), 'backup').ok, false);
    // And a compute node holds neither, for two entirely different reasons.
    assert.equal(canHoldTarget(node('compute'), 'data').ok, false);
    assert.equal(canHoldTarget(node('compute'), 'backup').ok, false);
  });

  it('names the node the way the selector does — hostname, else id', () => {
    const r = canHoldTarget(node('storage', '', 'n-9'), 'backup');
    assert.equal(r.ok, false);
    assert.match(r.reason!, /^a disk on n-9 \(storage\)/);
  });

  it('names the ingest as the blocker, and promises no release', () => {
    // #302 ships the claim/format/mount machinery, not the ingest transport
    // this refusal is actually waiting on — the old sentence promised it
    // would lift the restriction, and an operator who read that would be
    // waiting for a release that does not deliver it.
    assert.match(TARGET_TRANSPORT_EXPLANATION, /ingest/);
    assert.doesNotMatch(TARGET_TRANSPORT_EXPLANATION, /#302|storage SKU/);
  });
});

describe('nodeOptionLabel', () => {
  it('annotates a node that cannot hold a target, and leaves the controlplane alone', () => {
    assert.equal(nodeOptionLabel(node('controlplane', 'cp1'), 'backup'), 'cp1 (controlplane)');
    assert.equal(nodeOptionLabel(node('storage'), 'backup'), `shelf (storage) — ${CANNOT_HOLD_TARGET_SHORT}`);
  });

  it('annotates per purpose — a storage node can hold app data', () => {
    assert.equal(nodeOptionLabel(node('storage'), 'data'), 'shelf (storage)');
    assert.equal(nodeOptionLabel(node('firewall'), 'data'), `shelf (firewall) — ${CANNOT_HOLD_DATA_SHORT}`);
  });

  it('annotates a compute node as waiting, not as ineligible', () => {
    // The selector is the one surface with no room for the full sentence, so
    // the single word it does have room for has to be the right one.
    assert.equal(nodeOptionLabel(node('compute'), 'data'), `shelf (compute) — ${CANNOT_HOLD_DATA_YET_SHORT}`);
    assert.notEqual(CANNOT_HOLD_DATA_YET_SHORT, CANNOT_HOLD_DATA_SHORT);
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
