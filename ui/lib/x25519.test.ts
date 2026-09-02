// lib/x25519.ts, executed.
//
// This module is small and entirely load-bearing: it is the only place in the
// UI that knows what an X25519 key IS, and design/storage.md §4.6's amendment
// rests on two claims it makes. First, that the public key it publishes really
// is the public half of the private key it sealed — if that were ever wrong,
// every archive would be encrypted to a key nobody holds, and nothing would
// notice until a restore. Second, that the private scalar it slices out of a
// PKCS#8 export is the actual scalar and not 32 bytes from the wrong offset.
//
// Both are checked here against WebCrypto's own answers rather than against
// fixtures, because a fixture only proves this build agrees with itself.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  generateX25519Keypair,
  publicKeyFromPrivateScalar,
  publicKeysEqual,
  X25519_KEY_BYTES,
  X25519Error,
} from './x25519';

describe('generateX25519Keypair', () => {
  test('produces a 32-byte public key and a 32-byte private key', async () => {
    const kp = await generateX25519Keypair();
    assert.equal(kp.publicKey.length, X25519_KEY_BYTES);
    assert.equal(kp.privateKey.length, X25519_KEY_BYTES);
    assert.ok(!kp.privateKey.every((b) => b === 0), 'the private key must not be zeroes');
  });

  test('never repeats a keypair', async () => {
    const seen = new Set<string>();
    for (let i = 0; i < 10; i++) {
      const kp = await generateX25519Keypair();
      seen.add(Buffer.from(kp.publicKey).toString('hex'));
      kp.privateKey.fill(0);
    }
    assert.equal(seen.size, 10);
  });

  // The claim the whole amendment rests on. WebCrypto told us the public key;
  // this recomputes it from the private half, so a slicing bug or a swapped
  // export would show up as a mismatch rather than as unreadable archives.
  test('the public key it reports is the public half of the private key it returns', async () => {
    const kp = await generateX25519Keypair();
    const derived = await publicKeyFromPrivateScalar(kp.privateKey);
    assert.ok(publicKeysEqual(derived, kp.publicKey));
    kp.privateKey.fill(0);
  });
});

describe('publicKeyFromPrivateScalar', () => {
  test('is deterministic for a given scalar', async () => {
    const scalar = new Uint8Array(X25519_KEY_BYTES).fill(3);
    const a = await publicKeyFromPrivateScalar(scalar);
    const b = await publicKeyFromPrivateScalar(scalar);
    assert.ok(publicKeysEqual(a, b));
    assert.equal(a.length, X25519_KEY_BYTES);
  });

  test('different scalars give different public keys', async () => {
    const a = await publicKeyFromPrivateScalar(new Uint8Array(X25519_KEY_BYTES).fill(3));
    const b = await publicKeyFromPrivateScalar(new Uint8Array(X25519_KEY_BYTES).fill(4));
    assert.ok(!publicKeysEqual(a, b));
  });

  // The caller owns the scalar and zeroes it in its own `finally`. A second
  // owner here would make that contract ambiguous, and — worse — would break
  // mintArchiveKey, which derives nothing but seals the same buffer twice.
  test('does not consume the caller’s scalar', async () => {
    const scalar = new Uint8Array(X25519_KEY_BYTES).fill(5);
    await publicKeyFromPrivateScalar(scalar);
    assert.ok(scalar.every((b) => b === 5), 'the scalar must be left exactly as it was handed over');
  });

  test('refuses a scalar that is not 32 bytes', async () => {
    await assert.rejects(
      () => publicKeyFromPrivateScalar(new Uint8Array(16)),
      (e: unknown) => e instanceof X25519Error,
    );
  });
});

describe('publicKeysEqual', () => {
  test('compares by content and refuses different lengths', () => {
    assert.ok(publicKeysEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])));
    assert.ok(!publicKeysEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])));
    assert.ok(!publicKeysEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2])));
  });
});
