// The operator SSH key setting holds one key and applies to nodes enrolled
// from now on (geekdojo/geekdojo-brain#246). These are the two decisions the
// UI makes about it: when an enrollment saves its key, and when Settings
// offers a save.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import type { OperatorKey } from './api';
import { ENROLLED_NODE_KEY_PROCEDURE_URL, keyToRemember, operatorKeyDraft } from './operator-key';

const A = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2AcGjrl5kW bryce@laptop';
const B = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB other@host';

const never: OperatorKey = { key: '', captured: false, ignoredKeys: 0 };
const cleared: OperatorKey = { key: '', captured: true, ignoredKeys: 0 };
const saved: OperatorKey = { key: A, captured: true, ignoredKeys: 0 };
const legacy: OperatorKey = { key: A, captured: true, ignoredKeys: 2 };

describe('keyToRemember', () => {
  test('the first enrollment with a key captures it', () => {
    assert.equal(keyToRemember(never, A), A);
    assert.equal(keyToRemember(cleared, A), A);
  });

  test('never replaces a saved key, whatever was typed for this node', () => {
    assert.equal(keyToRemember(saved, B), null);
    assert.equal(keyToRemember(saved, A), null);
    assert.equal(keyToRemember(legacy, B), null);
  });

  test('writes nothing when no key was used or the setting never loaded', () => {
    assert.equal(keyToRemember(never, ''), null);
    assert.equal(keyToRemember(null, A), null);
  });
});

describe('operatorKeyDraft', () => {
  test('offers a save for a valid key that differs from the saved one', () => {
    assert.deepEqual(operatorKeyDraft(saved, `  ${B}  `), { key: B, canSave: true });
    assert.deepEqual(operatorKeyDraft(never, A), { key: A, canSave: true });
  });

  test('no save for the key already saved', () => {
    assert.equal(operatorKeyDraft(saved, A).canSave, false);
  });

  test('re-saving the saved key is offered while legacy extras remain', () => {
    assert.equal(operatorKeyDraft(legacy, A).canSave, true);
  });

  test('blank and invalid drafts never save, and say why when invalid', () => {
    assert.deepEqual(operatorKeyDraft(saved, '   '), { key: '', canSave: false });
    const bad = operatorKeyDraft(saved, 'not-a-key');
    assert.equal(bad.canSave, false);
    assert.ok(bad.error);
    assert.equal(operatorKeyDraft(saved, `${A}\n${B}`).canSave, false);
  });
});

describe('ENROLLED_NODE_KEY_PROCEDURE_URL', () => {
  // Settings always renders this as a link, so it has to be the published
  // docs page itself: https on the public site, a /docs/ page, and the
  // canonical trailing-slash form Hugo publishes (no redirect, no fragment or
  // query that could point at an anchor the page does not have).
  test('is the canonical URL of the published procedure page', () => {
    const u = new URL(ENROLLED_NODE_KEY_PROCEDURE_URL);
    assert.equal(u.protocol, 'https:');
    assert.equal(u.host, 'rasputin.geekdojo.com');
    assert.equal(u.pathname, '/docs/replace-or-revoke-an-ssh-key/');
    assert.equal(u.search, '');
    assert.equal(u.hash, '');
    assert.equal(u.href, ENROLLED_NODE_KEY_PROCEDURE_URL);
  });
});
