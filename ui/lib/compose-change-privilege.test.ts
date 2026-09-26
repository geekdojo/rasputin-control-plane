// geekdojo/geekdojo-brain#522 (auth-methodology §9 dec 12): the Apps page's
// consent prompt for a catalog upgrade that raises the app's privilege tier.
//
//   - the raise comes from the API's own answer (upgradeRaisesPrivilege), and
//     an upgrade that keeps or lowers the tier asks nothing;
//   - the upgrade cannot be confirmed until the owner consents, and the body
//     carries acceptPrivilegeTier only then;
//   - a dropped-volume resubmit keeps the consent already given;
//   - the server's 409 refusal is read into the same prompt, in its own words;
//   - the prompt says what is escalated, from what to what.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  PRIVILEGE_CONSENT_DEFAULT,
  bodyFor,
  canConfirmUpgrade,
  consentedTier,
  parseComposeResponse,
  privilegeConsentLabel,
  privilegeRaiseStatement,
  upgradeBody,
  upgradeRaiseOf,
  withDeleteVolumes,
  type PrivilegeRaise,
} from './compose-change';
import type { App } from './types';

const HT: PrivilegeRaise = {
  fromTier: 'routine',
  fromTierRecorded: true,
  tier: 'host-trusting',
  dockerSocket: false,
  grants: ['privileged'],
  why: 'talks to USB radios',
};

function app(over: Partial<App>): App {
  return {
    id: 'a',
    name: 'ha',
    composeYaml: '',
    targetNode: 'n1',
    sourceTile: 'homeassistant',
    lastStatus: 'running',
    createdAt: '',
    updatedAt: '',
    upgradeAvailable: true,
    ...over,
  } as App;
}

describe('upgradeRaiseOf', () => {
  test('a raise the API reports is described from the row', () => {
    const r = upgradeRaiseOf(
      app({
        privilegeTier: 'routine',
        upgradeRaisesPrivilege: true,
        upgradePrivilege: { tier: 'host-trusting', grants: ['privileged'], why: 'talks to USB radios' },
      }),
    );
    assert.deepEqual(r, HT);
  });

  test('an unrecorded installed tier reads as routine, and says so', () => {
    const r = upgradeRaiseOf(app({ upgradeRaisesPrivilege: true, upgradePrivilege: { tier: 'elevated', grants: ['host-network'] } }));
    assert.equal(r?.fromTier, 'routine');
    assert.equal(r?.fromTierRecorded, false);
  });

  test('keeping or lowering the tier asks nothing — the API decides, not the page', () => {
    // host-trusting → routine and host-trusting → host-trusting both arrive
    // with upgradeRaisesPrivilege false.
    assert.equal(upgradeRaiseOf(app({ privilegeTier: 'host-trusting', upgradeRaisesPrivilege: false, upgradePrivilege: { tier: 'routine' } })), null);
    assert.equal(upgradeRaiseOf(app({ privilegeTier: 'host-trusting', upgradeRaisesPrivilege: false, upgradePrivilege: { tier: 'host-trusting' } })), null);
  });

  test('no upgrade on offer, no raise', () => {
    assert.equal(upgradeRaiseOf(app({ upgradeAvailable: false, upgradeRaisesPrivilege: true, upgradePrivilege: { tier: 'host-trusting' } })), null);
  });
});

describe('consent gates the confirm and the body', () => {
  test('nothing is consented by default', () => {
    assert.equal(PRIVILEGE_CONSENT_DEFAULT, false);
  });

  test('a raise cannot be confirmed without consent; no raise always can', () => {
    assert.equal(canConfirmUpgrade(HT, false), false);
    assert.equal(canConfirmUpgrade(HT, true), true);
    assert.equal(canConfirmUpgrade(null, false), true);
  });

  test('the body carries acceptPrivilegeTier only with consent to a raise', () => {
    assert.deepEqual(bodyFor('upgrade', app({}), undefined, consentedTier(HT, true)), { source: 'catalog', acceptPrivilegeTier: 'host-trusting' });
    assert.deepEqual(bodyFor('upgrade', app({}), undefined, consentedTier(HT, false)), { source: 'catalog' });
    assert.deepEqual(bodyFor('upgrade', app({}), undefined, consentedTier(null, true)), { source: 'catalog' });
    assert.deepEqual(upgradeBody(), { source: 'catalog' });
  });

  test('a dropped-volume resubmit keeps the consent already given', () => {
    assert.deepEqual(withDeleteVolumes(upgradeBody('host-trusting'), ['rasp_a_x']), {
      source: 'catalog',
      acceptPrivilegeTier: 'host-trusting',
      deleteVolumes: ['rasp_a_x'],
    });
    assert.deepEqual(withDeleteVolumes(upgradeBody(), ['rasp_a_x']), { source: 'catalog', deleteVolumes: ['rasp_a_x'] });
  });
});

describe('the 409 privilege refusal', () => {
  const error =
    'this upgrade raises the app\'s privilege from ROUTINE to HOST-TRUSTING (it takes: privileged), and it needs your consent: send the upgrade again with "acceptPrivilegeTier": "host-trusting"';

  test('is read into the prompt, keeping the server’s words', () => {
    const o = parseComposeResponse(409, {
      error,
      privilegeRaise: { fromTier: 'routine', fromTierRecorded: true, tier: 'host-trusting', dockerSocket: false, grants: ['privileged'], why: 'talks to USB radios', catalogVersion: 7 },
    });
    assert.equal(o.kind, 'privilege');
    if (o.kind !== 'privilege') return;
    assert.deepEqual(o.raise, HT);
    assert.ok(o.message.includes('HOST-TRUSTING'), o.message);
    assert.ok(o.message.includes('acceptPrivilegeTier'), o.message);
  });

  test('a shape this build cannot read is still a plain refusal', () => {
    const o = parseComposeResponse(409, { error, privilegeRaise: { tier: 'root-plus', fromTier: 'routine' } });
    assert.equal(o.kind, 'error');
    if (o.kind === 'error') assert.ok(o.message.includes('HOST-TRUSTING'));
  });
});

describe('what the prompt says', () => {
  test('names the app, both tiers and the summary of the new one', () => {
    const s = privilegeRaiseStatement('ha', HT);
    assert.ok(s.includes('"ha"') && s.includes('ROUTINE') && s.includes('HOST-TRUSTING') && s.includes('root'), s);
  });

  test('an unrecorded installed tier is said plainly', () => {
    assert.ok(privilegeRaiseStatement('ha', { ...HT, fromTierRecorded: false }).includes('no tier was recorded'));
  });

  test('the runtime socket is called out on its own', () => {
    assert.ok(privilegeRaiseStatement('ha', { ...HT, dockerSocket: true }).includes('container runtime socket'));
    assert.ok(!privilegeRaiseStatement('ha', HT).includes('container runtime socket'));
  });

  test('the checkbox says exactly what ticking it accepts', () => {
    assert.equal(privilegeConsentLabel('ha', HT, 'n1'), 'I accept that "ha" will run as HOST-TRUSTING on n1.');
  });
});
