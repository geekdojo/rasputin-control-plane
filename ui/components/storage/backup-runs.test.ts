import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  CADENCE_OFF,
  appVolumeSummary,
  cadenceRequest,
  cadenceValue,
  runScopeTitle,
  scopeHeadline,
  shouldWarnIncomplete,
} from './backup-runs';
import type { BackupRunsResponse, BackupSchedule } from '../../lib/types';

function runsResponse(scope: BackupRunsResponse['scope']): BackupRunsResponse {
  return { runs: [], lastSuccess: null, scope, scopeWarning: 'no app data', retain: 4 };
}

describe('shouldWarnIncomplete', () => {
  it('warns for an identity-only archive', () => {
    assert.equal(shouldWarnIncomplete(runsResponse('identity-only')), true);
  });

  it('warns for a controlplane-local archive — app volumes on other nodes are not in it', () => {
    // What this build writes. It captures real app data for the first time and
    // it still is not a complete backup of the cluster, so the banner stays.
    assert.equal(shouldWarnIncomplete(runsResponse('controlplane-local')), true);
  });

  it('warns when the response has not arrived', () => {
    // Fail loud. A page mid-load must not spend a moment implying the archive
    // is complete.
    assert.equal(shouldWarnIncomplete(null), true);
  });

  it('warns when the api sends no scope at all', () => {
    // An older api, or one this build does not recognise. The banner going away
    // is a positive claim, and only `scope: "full"` earns it.
    const noScope = { runs: [], lastSuccess: null, scopeWarning: '', retain: 4 } as unknown as BackupRunsResponse;
    assert.equal(shouldWarnIncomplete(noScope), true);
  });

  it('warns for a scope value it does not recognise', () => {
    const odd = { ...runsResponse('identity-only'), scope: 'partial' } as unknown as BackupRunsResponse;
    assert.equal(shouldWarnIncomplete(odd), true);
  });

  it('stops warning only for an explicit full scope', () => {
    // The day the fan-out stops being empty (#295/#296 landed and wired), the api starts
    // sending `full` and this banner disappears with no UI change.
    assert.equal(shouldWarnIncomplete(runsResponse('full')), false);
  });
});

describe('scopeHeadline', () => {
  it('takes the scope from the api rather than hard-coding one', () => {
    // The six surfaces all read one exported string. A headline typed in here
    // is the seventh, and it is the one that goes stale.
    assert.equal(scopeHeadline(runsResponse('controlplane-local')), 'CONTROLPLANE-LOCAL — NOT A COMPLETE BACKUP');
  });

  it('says the scope is unknown rather than inventing one', () => {
    assert.equal(scopeHeadline(null), 'SCOPE UNKNOWN — NOT A COMPLETE BACKUP');
  });
});

describe('runScopeTitle', () => {
  it('names what was NOT captured beside what was', () => {
    // "2 app volumes captured" alone reads as success on a run that missed four.
    assert.equal(
      runScopeTitle({ appVolumesCaptured: 2, appVolumesSkipped: 4 }),
      '2 app volumes captured · 4 NOT captured',
    );
  });

  it('carries a run warning into the tooltip', () => {
    assert.equal(
      runScopeTitle({ appVolumesCaptured: 1, appVolumesSkipped: 0, warning: 'vaultwarden did not restart' }),
      '1 app volume captured · vaultwarden did not restart',
    );
  });

  it('says zero rather than nothing when a run captured none', () => {
    assert.equal(runScopeTitle({ appVolumesCaptured: 0 }), '0 app volumes captured');
  });

  it('puts FAILED volumes first, apart from the ones the run never tried', () => {
    // §4.4: a node offline at backup time is a FAILED backup, not a skipped
    // one. Of four not captured, two failed and two (bulk, unclassified) were
    // never attempted; the row must not fold the two together.
    assert.equal(
      runScopeTitle({ appVolumesCaptured: 2, appVolumesSkipped: 4, appVolumesFailed: 2 }),
      '2 app volumes captured · 2 FAILED · 2 NOT captured',
    );
  });

  it('reads an older row with no failed count as nothing failed', () => {
    assert.equal(
      runScopeTitle({ appVolumesCaptured: 1, appVolumesSkipped: 1 }),
      '1 app volume captured · 1 NOT captured',
    );
  });
});

describe('cadenceValue', () => {
  const base: BackupSchedule = {
    enabled: true,
    every: '168h',
    everySeconds: 604800,
    nextDue: null,
    defaultEvery: '168h',
    minEvery: '1h',
    maxEvery: '8760h',
  };

  it('shows the operator’s cadence when the schedule is on', () => {
    assert.equal(cadenceValue({ ...base, every: '24h' }), '24h');
  });

  it('falls back to the default when no cadence is stored', () => {
    assert.equal(cadenceValue({ ...base, every: undefined }), '168h');
  });

  it('renders a disabled schedule as an explicit off, never as a blank', () => {
    // §4.4: the absence of backups must never look like ordinary green. An
    // operator has to be able to see that nothing is scheduled.
    assert.equal(cadenceValue({ ...base, enabled: false }), CADENCE_OFF);
  });

  it('renders an unloaded schedule as off rather than inventing a cadence', () => {
    assert.equal(cadenceValue(null), CADENCE_OFF);
  });
});

describe('cadenceRequest', () => {
  it('turns the off sentinel into a disable, carrying no cadence', () => {
    assert.deepEqual(cadenceRequest(CADENCE_OFF), { enabled: false });
  });

  it('turns a duration into an enable with that cadence', () => {
    assert.deepEqual(cadenceRequest('72h'), { enabled: true, every: '72h' });
  });
});

describe('appVolumeSummary', () => {
  it('spells out zero rather than rendering nothing', () => {
    assert.equal(appVolumeSummary(0), '0 app volumes captured');
  });

  it('is singular for one', () => {
    assert.equal(appVolumeSummary(1), '1 app volume captured');
  });
});
