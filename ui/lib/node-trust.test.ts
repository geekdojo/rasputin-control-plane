import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { staleTrustTitle, trustFingerprintLabel } from './node-trust';

// TC-741-23 (UI half): a node reporting "reload-pending" is labelled
// "reload pending", never a truncated fingerprint.
describe('trustFingerprintLabel', () => {
  test('reload-pending reads as reload pending', () => {
    assert.equal(trustFingerprintLabel('reload-pending'), 'reload pending');
  });
  test('none reads as NONE', () => {
    assert.equal(trustFingerprintLabel('none'), 'NONE');
  });
  test('a fingerprint is its first 12 characters', () => {
    assert.equal(trustFingerprintLabel('0123456789abcdef0123'), '0123456789ab');
  });
  test('an absent fingerprint is ?', () => {
    assert.equal(trustFingerprintLabel(undefined), '?');
    assert.equal(trustFingerprintLabel(''), '?');
  });
});

describe('staleTrustTitle', () => {
  test('reload pending says the reload, not a fingerprint', () => {
    const t = staleTrustTitle({ fingerprint: 'reload-pending' });
    assert.match(t, /reload pending/);
    assert.doesNotMatch(t, /reload-pen/);
  });
  test('a stale fingerprint names it and the controlplane CA', () => {
    const t = staleTrustTitle({ fingerprint: '0123456789abcdef' });
    assert.match(t, /controlplane CA 0123456789ab,/);
  });
});
