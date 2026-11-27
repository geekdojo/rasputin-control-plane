// Known-answer tests for the archive-key passphrase KDF (design/storage.md §4.6).
//
// ============================================================================
// DO NOT UPDATE THE EXPECTED VALUES IN THIS FILE TO MAKE IT PASS.
//
// Every archive key ever minted has its private key wrapped under a KEK that
// this derivation produced from the operator's passphrase. If the derivation's
// output changes — a hash-wasm upgrade with rebuilt WASM, a parameter edited
// in passphrase-kdf.ts, an argument dropped on the way to argon2id() — then
// every passphrase-wrapped archive key already on a disk STOPS UNLOCKING, and
// the operator is told their correct passphrase is wrong. A failure here is
// that outage caught before it ships. The fix is to the code or the
// dependency, never to these numbers.
//
// A deliberate parameter bump is the one legitimate change, and it does not
// edit these values either: it ships a NEW derivation with a NEW id beside
// this one (see "A note on shape" in passphrase-kdf.ts), keeps this one
// resolvable for old blobs, and adds its own known answers here.
// ============================================================================
//
// Two kinds of vector, because they catch different breakages:
//
//   1. Published Argon2id reference vectors, run through hash-wasm directly.
//      These pin the LIBRARY against the reference implementation, so a
//      hash-wasm build that computes Argon2id differently fails here even if
//      our wrapper is untouched.
//
//      RFC 9106 §5.3's Argon2id vector cannot be expressed: it uses
//      associated data (12 bytes of 0x04), and hash-wasm's IArgon2Options has
//      `password`, `salt` and `secret` but no associated-data field. Its
//      output without the AD is not a published value, so it proves nothing.
//      The closest expressible vectors are the Argon2id v1.3 cases in the
//      reference implementation's own test suite (P-H-C/phc-winner-argon2,
//      src/test.c, by the RFC's authors): password "password", salt
//      "somesalt", 32-byte tag, no secret, no AD. All eight below match it.
//
//   2. Known answers for the PRODUCTION parameters (m=64 MiB, t=3, p=1,
//      32 bytes), through the real code path: ARGON2ID.deriveKek, and the
//      same derivation rebuilt from its id by resolvePassphraseKdf, which is
//      what an unlock of a blob off a disk calls. The expected KEKs were
//      computed by this code with hash-wasm 4.13.0 on 2026-11-27 and agree
//      byte-for-byte with Go's independent golang.org/x/crypto/argon2 IDKey
//      (v0.59.0) on the same inputs.
//
// The KEK comes back as a NON-EXTRACTABLE CryptoKey, so it cannot be read and
// compared directly. Instead the expected 32 bytes are imported as an AES-GCM
// key, and both keys encrypt the same block under the same IV: AES-GCM is
// deterministic for a fixed key, IV and plaintext, so equal output means equal
// keys. The fixed IV is fine here and nowhere else — nothing is being kept
// secret, the encryption is only a fingerprint of the key.
//
// Passphrases are UTF-8 bytes via TextEncoder, which is how the claim and
// unlock flows hand them to deriveKek.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { argon2id } from 'hash-wasm';
import { ARGON2ID, PASSPHRASE_KDF, resolvePassphraseKdf, subtle, type Bytes, type PassphraseKdf } from './passphrase-kdf';

function utf8(s: string): Bytes {
  return new TextEncoder().encode(s);
}

function hexBytes(h: string): Bytes {
  return new Uint8Array(Buffer.from(h, 'hex'));
}

function filled(n: number, b: number): Bytes {
  return new Uint8Array(n).fill(b);
}

const FINGERPRINT_IV = new Uint8Array(12);
const FINGERPRINT_PLAINTEXT = new Uint8Array(32);

async function fingerprint(key: CryptoKey): Promise<string> {
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv: FINGERPRINT_IV }, key, FINGERPRINT_PLAINTEXT);
  return Buffer.from(ct).toString('hex');
}

/** Asserts that `kdf` turns (passphrase, salt) into exactly the 32 bytes `expectedHex`. */
async function assertKek(kdf: PassphraseKdf, passphrase: Bytes, salt: Bytes, expectedHex: string): Promise<void> {
  const derived = await kdf.deriveKek(passphrase, salt);
  const expected = await subtle().importKey('raw', hexBytes(expectedHex), { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
  ]);
  assert.equal(
    await fingerprint(derived),
    await fingerprint(expected),
    `${kdf.id} no longer derives the known KEK. Existing passphrase-wrapped archive keys will NOT unlock. ` +
      'Fix the code or the hash-wasm build; do not change the expected value.',
  );
}

// ---------------------------------------------------------------------------
// 1. Reference vectors (phc-winner-argon2 src/test.c, Argon2id v1.3)
// ---------------------------------------------------------------------------

interface ReferenceVector {
  iterations: number;
  memoryKiB: number;
  parallelism: number;
  password: string;
  salt: string;
  hash: string;
}

const REFERENCE: readonly ReferenceVector[] = [
  { iterations: 2, memoryKiB: 1 << 16, parallelism: 1, password: 'password', salt: 'somesalt', hash: '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7' },
  { iterations: 2, memoryKiB: 1 << 18, parallelism: 1, password: 'password', salt: 'somesalt', hash: '78fe1ec91fb3aa5657d72e710854e4c3d9b9198c742f9616c2f085bed95b2e8c' },
  { iterations: 2, memoryKiB: 1 << 8, parallelism: 1, password: 'password', salt: 'somesalt', hash: '9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe' },
  { iterations: 2, memoryKiB: 1 << 8, parallelism: 2, password: 'password', salt: 'somesalt', hash: '6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037' },
  { iterations: 1, memoryKiB: 1 << 16, parallelism: 1, password: 'password', salt: 'somesalt', hash: 'f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98' },
  { iterations: 4, memoryKiB: 1 << 16, parallelism: 1, password: 'password', salt: 'somesalt', hash: '9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c' },
  { iterations: 2, memoryKiB: 1 << 16, parallelism: 1, password: 'differentpassword', salt: 'somesalt', hash: '0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde' },
  { iterations: 2, memoryKiB: 1 << 16, parallelism: 1, password: 'password', salt: 'diffsalt', hash: 'bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c' },
];

describe('hash-wasm Argon2id against the reference implementation', () => {
  for (const v of REFERENCE) {
    test(`t=${v.iterations} m=${v.memoryKiB} p=${v.parallelism} ${v.password}/${v.salt}`, async () => {
      const got = await argon2id({
        password: v.password,
        salt: v.salt,
        iterations: v.iterations,
        parallelism: v.parallelism,
        memorySize: v.memoryKiB,
        hashLength: 32,
        outputType: 'hex',
      });
      assert.equal(got, v.hash);
    });
  }

  test('our wrapper agrees with the reference on its first vector', async () => {
    // Same vector, through deriveArgon2idKek rather than hash-wasm directly,
    // so the argument mapping (memorySize vs memoryKiB and the rest) is tied
    // to the reference and not only to values this code computed itself.
    const v = REFERENCE[0];
    const kdf = resolvePassphraseKdf(`argon2id-m${v.memoryKiB}-t${v.iterations}-p${v.parallelism}`);
    assert.ok(kdf);
    await assertKek(kdf, utf8(v.password), utf8(v.salt), v.hash);
  });
});

// ---------------------------------------------------------------------------
// 2. Production parameters, through the real derivation
// ---------------------------------------------------------------------------

interface ProductionVector {
  name: string;
  passphrase: string;
  salt: Bytes;
  kek: string;
}

const PRODUCTION: readonly ProductionVector[] = [
  {
    name: 'ASCII passphrase, counting salt',
    passphrase: 'correct horse battery staple',
    salt: Uint8Array.from({ length: 16 }, (_, i) => i),
    kek: '0d1a3c6523c8f06e4e0af9c515aa5b5448cfebd6838f2d52c3d8b6ef8ddc3c2e',
  },
  {
    name: 'non-ASCII passphrase (multi-byte UTF-8 and an astral code point)',
    passphrase: 'pässwörd · 日本語 · 🔑',
    salt: filled(16, 0xa5),
    kek: '543cab22e10b947fa72c1a9f95ea373ece41a4db89081a753bb7855665418c51',
  },
  {
    name: 'the round-trip fixture passphrase, all-ones salt',
    passphrase: 'round-trip fixture passphrase',
    salt: filled(16, 0xff),
    kek: '0a0fc341046039f4b178cd3250964e641c5ca90ea7fd95c57e3a5a2aa47039e1',
  },
];

describe('the production passphrase KDF (known answers)', () => {
  test('is still argon2id-m65536-t3-p1 with a 16-byte salt', () => {
    // The id is written into every wrapped blob; the vectors below are only
    // meaningful for this exact id.
    assert.equal(PASSPHRASE_KDF, ARGON2ID);
    assert.equal(ARGON2ID.id, 'argon2id-m65536-t3-p1');
    assert.deepEqual(ARGON2ID.params, { memoryKiB: 65536, iterations: 3, parallelism: 1, dkLen: 32 });
    assert.equal(ARGON2ID.saltBytes, 16);
  });

  for (const v of PRODUCTION) {
    test(`ARGON2ID.deriveKek: ${v.name}`, async () => {
      assert.equal(v.salt.length, ARGON2ID.saltBytes);
      await assertKek(ARGON2ID, utf8(v.passphrase), v.salt, v.kek);
    });
  }

  test('resolvePassphraseKdf rebuilds the same derivation from the id on a blob', async () => {
    const kdf = resolvePassphraseKdf(ARGON2ID.id, ARGON2ID.params);
    assert.ok(kdf);
    const v = PRODUCTION[0];
    await assertKek(kdf, utf8(v.passphrase), v.salt, v.kek);
  });
});
