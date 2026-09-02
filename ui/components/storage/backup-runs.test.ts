import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  CADENCE_OFF,
  appVolumeSummary,
  cadenceRequest,
  cadenceValue,
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
    // The day #293 lands and the fan-out stops being empty, the api starts
    // sending `full` and this banner disappears with no UI change.
    assert.equal(shouldWarnIncomplete(runsResponse('full')), false);
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
