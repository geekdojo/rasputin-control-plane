// TC-988-14: the message bundle's copy (geekdojo/geekdojo-brain#988, ui.md
// §4.3, §4.4).
import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { forbiddenList } from '../../test/forbidden-list';
import { findForbidden } from '../../lib/forbidden-words';
import { formatMessage, properties, read, SRC } from './theme-files';

const bundle = properties(read(path.join(SRC, 'messages', 'messages_en.properties')));
const text = (key: string, ...args: string[]) => {
  const v = bundle.get(key);
  assert.ok(v !== undefined, `the bundle has no ${key}`);
  return formatMessage(v, ...args);
};

test('TC-988-14: every apostrophe is doubled, as MessageFormat needs', () => {
  for (const [k, v] of bundle) assert.doesNotMatch(v.replace(/''/g, ''), /'/, `${k} has a lone apostrophe, which MessageFormat would drop`);
});

// ui.md §4.4's samples a theme key carries (the not-ready sentence is the
// api's own door page, §4.6, not a theme key).
const SAMPLES: [string, string, string[]?][] = [
  ['rasputinSignInTo', 'Sign in to Hoodoo Home', ['Hoodoo Home']],
  ['rasputinCertificateWarning', "A certificate warning on this page means it isn't your Rasputin. Don't sign in."],
  ['invalidUserMessage', 'Wrong sign-in name or password.'],
  ['rasputinDeviceTooManyFailures', 'Too many failed sign-ins from this device. Wait a few minutes and try again, or sign in from another device.'],
  ['accountTemporarilyDisabledMessage', 'This account is locked after too many failed sign-ins. Ask an administrator to unlock it.'],
  ['accountPermanentlyDisabledMessage', 'This account is locked after too many failed sign-ins. Ask an administrator to unlock it.'],
  ['rasputinDenyNoAppAccess', "Your account doesn't have access to apps yet. Ask an administrator."],
  ['rasputinDenyNoSecondStepHere', 'This account signs in with two steps, and none of its second steps works here. Ask another administrator to reset your sign-in.'],
  ['rasputinDenyOutsideServerSecondStep', 'Signing in to this app needs a second step. Add a passkey, security key or authenticator app in Your account, then try again.'],
  ['rasputinDenyAdminsFirst', 'This app is waiting for an administrator to sign in to it first. Try again later.'],
  ['rasputinDenyNoNetworkGrant', "Your account doesn't have access to network devices. Ask an administrator."],
  ['rasputinDenyOldPasskey', "That passkey was made before Rasputin's sign-in changed and no longer works. Use your newer passkey or your password."],
  ['rasputinDenyClockNotSet', "Authenticator apps need this system's clock. It sets itself once Rasputin reaches the internet."],
  ['rasputinRecoveryCodesUse', "Each code works once. Use one when you're asked for your second step, or to choose a new password."],
  ['rasputinUsernameFixed', "Your sign-in name can't be changed later."],
  ['rasputinDenyAppSignInPaused', "Signing in to this app is paused while the cluster's secret store is unavailable."],
  ['rasputinNoEmail', 'Rasputin never sends you email.'],
  ['rasputinCreateAtHome', 'No account yet? Create one on your home network at https://bench.local.', ['https://bench.local']],
];

for (const [key, want, args] of SAMPLES) {
  test(`TC-988-14: ${key} holds its sample`, () => {
    assert.equal(text(key, ...(args ?? [])), want);
  });
}

test('TC-988-14: no value promises email', () => {
  for (const k of ['emailInstruction', 'emailInstructionUsername']) {
    assert.doesNotMatch(text(k), /email/i, `${k} mentions email`);
  }
  for (const [k] of bundle) {
    assert.doesNotMatch(text(k), /\b(we|will|we'll)\b[^.]*\b(send|email)\b/i, `${k} promises to send something`);
  }
});

test('TC-988-14: each Deny access key is a sentence a person reads: a capital first, a full stop last', () => {
  const deny = [...bundle.keys()].filter((k) => k.startsWith('rasputinDeny'));
  assert.equal(deny.length, 8);
  for (const k of deny) {
    const v = text(k);
    assert.match(v, /^[A-Z]/, `${k} starts with a capital`);
    assert.match(v, /\.$/, `${k} ends with a full stop`);
    assert.doesNotMatch(v, /\n/, `${k} is one line`);
  }
});

test('TC-988-14: the authenticator-app page keys name no app', () => {
  const totp = [...bundle.keys()].filter((k) => /^(loginTotp|totpApp|loginOtp)/.test(k));
  assert.ok(totp.length > 10);
  for (const k of totp) assert.deepEqual(findForbidden(forbiddenList, text(k)), [], k);
  for (const k of ['totpAppFreeOTPName', 'totpAppGoogleName', 'totpAppMicrosoftAuthenticatorName']) {
    assert.equal(text(k), 'An authenticator app');
  }
});
