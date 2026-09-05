import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  backupAckLine,
  backupsConfigured,
  criticalVolumes,
  installAllowed,
  installNeedsAck,
  isNoBackupHold,
  noBackupAckCopy,
  noBackupBadge,
} from './backup-gate';
import { backupBadge } from './backup-state';
import type { AppBackupState, BackupTarget } from './types';

function state(partial: Partial<AppBackupState> & { state: AppBackupState['state'] }): AppBackupState {
  return { cadence: '168h0m0s', ...partial };
}

function target(status: BackupTarget['status']): BackupTarget {
  return { jobId: 'j', nodeId: 'n1', status, hasWrappedKeys: true, createdAt: '2026-09-01T00:00:00Z' } as BackupTarget;
}

const vaultwarden = {
  name: 'Vaultwarden',
  volumes: [{ name: 'vaultwarden-data', backup: 'critical', quiesce: 'stop' }],
};
const jellyfin = {
  name: 'Jellyfin',
  volumes: [
    { name: 'jellyfin-config', backup: 'state', quiesce: 'stop' },
    { name: 'jellyfin-cache', backup: 'cache', quiesce: 'none' },
  ],
};

describe('criticalVolumes', () => {
  test('names only the critical class; state/cache/bulk and a volume-less tile give none', () => {
    assert.deepEqual(criticalVolumes(vaultwarden), ['vaultwarden-data']);
    assert.deepEqual(criticalVolumes(jellyfin), []);
    assert.deepEqual(criticalVolumes({}), []);
  });
});

describe('backupsConfigured', () => {
  test('a claimed target and a schedule that is on', () => {
    assert.deepEqual(backupsConfigured([target('claimed')], { enabled: true }), { configured: true, reason: '' });
  });
  test('no claimed target — a pending or failed claim does not count', () => {
    for (const rows of [[], [target('pending')], [target('failed')], [target('replaced')]]) {
      const c = backupsConfigured(rows, { enabled: true });
      assert.equal(c.configured, false);
      assert.match(c.reason, /No backup target is claimed/);
    }
  });
  test('schedule off is the other half', () => {
    const c = backupsConfigured([target('claimed')], { enabled: false });
    assert.equal(c.configured, false);
    assert.match(c.reason, /turned off/);
  });
});

describe('installNeedsAck / installAllowed — disabled until ticked', () => {
  test('a critical tile on an unconfigured cluster is asked, and install waits for the tick', () => {
    const needsAck = installNeedsAck({ criticalVolumes: ['vaultwarden-data'], configured: false, apiHeld: false });
    assert.equal(needsAck, true);
    assert.equal(installAllowed({ needsAck, acknowledged: false }), false, 'starts unticked and disabled');
    assert.equal(installAllowed({ needsAck, acknowledged: true }), true);
  });
  test('not asked when backups are configured', () => {
    assert.equal(installNeedsAck({ criticalVolumes: ['vaultwarden-data'], configured: true, apiHeld: false }), false);
  });
  test('not asked for a state-only or volume-less tile, whatever the cluster', () => {
    assert.equal(installNeedsAck({ criticalVolumes: [], configured: false, apiHeld: false }), false);
    assert.equal(installNeedsAck({ criticalVolumes: [], configured: false, apiHeld: true }), false);
  });
  test('unknown configuration does not invent a gate — but the api holding the install does', () => {
    assert.equal(installNeedsAck({ criticalVolumes: ['v'], configured: null, apiHeld: false }), false);
    assert.equal(installNeedsAck({ criticalVolumes: ['v'], configured: null, apiHeld: true }), true);
  });
  test('an ack alone never enables an install nothing else allows', () => {
    assert.equal(installAllowed({ needsAck: false, acknowledged: false }), true);
  });
});

describe('isNoBackupHold', () => {
  test('recognises the api 409 that names the flag, and nothing else', () => {
    assert.equal(isNoBackupHold({ status: 409, message: '/api/catalog/x/install → 409: … send acknowledgeNoBackup: true …' }), true);
    assert.equal(isNoBackupHold({ status: 409, message: 'an app with that name already exists' }), false);
    assert.equal(isNoBackupHold({ status: 400, message: 'acknowledgeNoBackup' }), false);
    assert.equal(isNoBackupHold(new Error('network')), false);
    assert.equal(isNoBackupHold(null), false);
  });
});

describe('noBackupAckCopy — the wording', () => {
  test('says the data will not be backed up, names the volume, links to /storage, and does not refuse', () => {
    const c = noBackupAckCopy(vaultwarden, ['vaultwarden-data'], 'No backup target is claimed.');
    assert.match(c.body, /Vaultwarden keeps critical data in its volume \(vaultwarden-data\)\./);
    assert.match(c.body, /No backup target is claimed\./);
    assert.match(c.body, /will not be backed up anywhere/);
    assert.match(c.body, /You can install now and claim a disk afterwards/);
    assert.equal(c.checkbox, "I understand Vaultwarden's data will not be backed up until a backup target exists");
    assert.equal(c.href, '/storage');
    assert.doesNotMatch(c.body, /cannot install|refused|blocked/i);
  });
  test('plural volumes, and no reason when the api did not give one', () => {
    const c = noBackupAckCopy({ name: 'X' }, ['a', 'b'], '');
    assert.match(c.body, /volumes \(a, b\)\. Until a backup target/);
  });
});

describe('noBackupBadge — never both badges', () => {
  test('only unconfigured earns NO BACKUP TARGET, with the reason on hover', () => {
    const b = noBackupBadge(state({ state: 'unconfigured', class: 'critical', reason: 'no backup target is claimed' }));
    assert.deepEqual(b, { label: 'NO BACKUP TARGET', title: 'No backup target: no backup target is claimed', href: '/storage' });
    // A state-only app gets the badge too; only the alert is critical-only.
    assert.equal(noBackupBadge(state({ state: 'unconfigured', class: 'state' }))?.label, 'NO BACKUP TARGET');
  });
  test('every state wears at most one of OVERDUE / NO BACKUP TARGET', () => {
    for (const s of ['ok', 'overdue', 'never', 'unconfigured', 'none'] as const) {
      const st = state({ state: s, class: 'critical' });
      const worn = [backupBadge(st), noBackupBadge(st)].filter(Boolean).length;
      assert.ok(worn <= 1, `${s} wears ${worn} badges`);
      if (s === 'overdue') assert.equal(noBackupBadge(st), null);
      if (s === 'unconfigured') assert.equal(backupBadge(st), null);
    }
    assert.equal(noBackupBadge(undefined), null);
  });
});

describe('backupAckLine', () => {
  test('the drawer sentence, dated, naming who', () => {
    assert.equal(
      backupAckLine({ backupAck: { at: '2026-09-05T10:12:00Z', by: 'bryce' } }),
      'installed 2026-09-05 with no backup target — acknowledged by bryce',
    );
    assert.equal(backupAckLine({ backupAck: { at: '2026-09-05T10:12:00Z', by: '' } }), 'installed 2026-09-05 with no backup target — acknowledged');
    assert.equal(backupAckLine({}), null);
  });
});
