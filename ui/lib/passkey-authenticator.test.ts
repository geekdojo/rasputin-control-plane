// The wire half of the authenticator choice, executed. These three strings
// are a cross-language contract: the api's parseAuthenticatorChoice
// (api/internal/auth/handlers.go) answers anything else with a 400, so a typo
// here is a dead button that no type checker would catch.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { PASSKEY_AUTHENTICATORS, type PasskeyAuthenticator } from './passkey-authenticator';

describe('PASSKEY_AUTHENTICATORS', () => {
  test('offers exactly the three values the api accepts', () => {
    const wire: PasskeyAuthenticator[] = ['platform', 'hybrid', 'security-key'];
    assert.deepEqual(
      PASSKEY_AUTHENTICATORS.map((a) => a.value),
      wire,
    );
  });

  test('every choice carries copy for its button and its hint', () => {
    for (const a of PASSKEY_AUTHENTICATORS) {
      assert.ok(a.label.length > 0, `${a.value}: label`);
      assert.ok(a.hint.length > 0, `${a.value}: hint`);
    }
  });
});
