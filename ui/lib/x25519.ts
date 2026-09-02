// X25519, for design/storage.md §4.6 as amended 2026-09-02.
//
// # Why this file exists at all
//
// §4.6 used to be one random 256-bit symmetric data key, wrapped twice. The
// amendment replaced it with a KEYPAIR, and the forcing question was
// `backup.run` (#290): a weekly 3 a.m. job has nobody at a keyboard, so to
// write an ENCRYPTED archive under a symmetric key the controlplane would have
// to cache that key in the clear — which is precisely the exposure §4.6 exists
// to close. Bryce refused the premise: "We're not storing a key."
//
// So the browser mints an X25519 keypair. The PUBLIC key travels in clear, is
// stored by the api and goes in the on-disk marker — a public key at rest is
// harmless, and it is all `backup.run` needs to seal a new generation to. The
// PRIVATE key is wrapped under the two custody paths (archive-key.ts) and never
// exists outside this browser session.
//
// # No dependency
//
// WebCrypto implements X25519 natively (Chrome 133+, Node 18.4+), so unlike
// Argon2id — which needed hash-wasm because WebCrypto has no memory-hard KDF —
// there is nothing to add to package.json for this. §4.6 says as much: "both
// are cheap (crypto/ecdh in the Go standard library; WebCrypto has X25519
// natively) and neither adds a dependency."
//
// # What must never leave this module in a form that cannot be zeroed
//
// The private scalar. WebCrypto will hand a private key back as JWK — whose `d`
// member is a STRING, and a JavaScript string cannot be overwritten — or as
// PKCS#8 bytes, which can. So this module exports PKCS#8 and slices, and every
// buffer that ever held the scalar is zeroed before the call returns. That is
// the only reason the DER handling below is here rather than a two-line JWK
// read.

import { subtle, type Bytes } from './passphrase-kdf';

/** Raw X25519 keys are 32 bytes, public and private alike (RFC 7748). */
export const X25519_KEY_BYTES = 32;

/**
 * The fixed PKCS#8 header for an X25519 private key (RFC 8410 §7):
 *
 *   SEQUENCE(46) { INTEGER 0, SEQUENCE { OID 1.3.101.110 }, OCTET STRING(34) {
 *     OCTET STRING(32) { <scalar> } } }
 *
 * It is a CONSTANT — the structure has no variable-length part, because the
 * key length is fixed by the algorithm — which is what makes slicing the last
 * 32 bytes off an export sound. The prefix is checked rather than assumed on
 * every export: if a future implementation ever emits the optional `publicKey`
 * attribute or a different encoding, this refuses instead of returning 32 bytes
 * from the wrong offset, which would be a silently wrong key.
 */
const PKCS8_X25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

/**
 * The Curve25519 base point, u = 9 (RFC 7748 §4.1), little-endian.
 *
 * Used as the peer public key in a single ECDH, which is the definition of the
 * public key: pub = X25519(scalar, 9). See publicKeyFromPrivateScalar.
 */
const BASE_POINT = new Uint8Array([
  9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

/** A freshly minted keypair, both halves raw. The private half is the caller's to zero. */
export interface X25519Keypair {
  /** 32 raw bytes. Travels in clear, by design. */
  publicKey: Bytes;
  /**
   * The 32-byte private scalar. The CALLER owns this and must zero it — this
   * module holds no copy after the call returns.
   */
  privateKey: Bytes;
}

/** Thrown when WebCrypto produced something this module refuses to interpret. */
export class X25519Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'X25519Error';
  }
}

function bytesOf(buf: ArrayBuffer): Bytes {
  return new Uint8Array(buf);
}

/**
 * generateX25519Keypair mints §4.6's archive keypair.
 *
 * `extractable: true` is deliberate and is the whole point: the private key has
 * to come out as bytes so it can be sealed under the passphrase and under the
 * recovery code. It comes out once, into a buffer the caller zeroes, and the
 * CryptoKey handle is dropped here.
 */
export async function generateX25519Keypair(): Promise<X25519Keypair> {
  const s = subtle();
  const pair = (await s.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair;
  const publicKey = bytesOf(await s.exportKey('raw', pair.publicKey));
  if (publicKey.length !== X25519_KEY_BYTES) {
    throw new X25519Error(`X25519 public key is ${publicKey.length} bytes; expected ${X25519_KEY_BYTES}`);
  }
  const pkcs8 = bytesOf(await s.exportKey('pkcs8', pair.privateKey));
  try {
    return { publicKey, privateKey: scalarFromPKCS8(pkcs8) };
  } finally {
    // The export buffer held the scalar. It is the caller's copy that lives on.
    pkcs8.fill(0);
  }
}

/** scalarFromPKCS8 checks the fixed header and copies out the 32-byte scalar. */
function scalarFromPKCS8(pkcs8: Bytes): Bytes {
  const want = PKCS8_X25519_PREFIX.length + X25519_KEY_BYTES;
  if (pkcs8.length !== want) {
    throw new X25519Error(`X25519 PKCS#8 export is ${pkcs8.length} bytes; expected exactly ${want}`);
  }
  for (let i = 0; i < PKCS8_X25519_PREFIX.length; i++) {
    if (pkcs8[i] !== PKCS8_X25519_PREFIX[i]) {
      throw new X25519Error('X25519 PKCS#8 export does not carry the RFC 8410 header this build slices by');
    }
  }
  const scalar: Bytes = new Uint8Array(X25519_KEY_BYTES);
  scalar.set(pkcs8.subarray(PKCS8_X25519_PREFIX.length));
  return scalar;
}

/**
 * publicKeyFromPrivateScalar DERIVES the public half of a private key.
 *
 * This is what makes an unwrap verifiable in a way the symmetric design could
 * not be. Under one symmetric key, a correct secret was proven by the AEAD tag
 * and nothing else — the recovered bytes were opaque, and any 32 bytes looked
 * as good as any other. Now the disk carries the public key in clear, so a
 * recovered private key can be checked AGAINST it: derive, compare, and a
 * mismatch is a corrupt or mismatched target rather than a wrong secret.
 *
 * The derivation is one ECDH against the base point, which is the definition of
 * an X25519 public key (RFC 7748 §6.1: "the public key is X25519(a, 9)"). There
 * is no WebCrypto call that says "give me the public key for this private key",
 * so this says it in the arithmetic instead.
 *
 * `scalar` belongs to the caller and is neither retained nor zeroed here — the
 * caller is already zeroing it in a `finally` and a second owner would only
 * make that contract ambiguous.
 */
export async function publicKeyFromPrivateScalar(scalar: Bytes): Promise<Bytes> {
  if (scalar.length !== X25519_KEY_BYTES) {
    throw new X25519Error(`an X25519 private key is ${X25519_KEY_BYTES} bytes; got ${scalar.length}`);
  }
  const s = subtle();
  const pkcs8: Bytes = new Uint8Array(PKCS8_X25519_PREFIX.length + X25519_KEY_BYTES);
  pkcs8.set(PKCS8_X25519_PREFIX, 0);
  pkcs8.set(scalar, PKCS8_X25519_PREFIX.length);
  try {
    const priv = await s.importKey('pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits']);
    const base = await s.importKey('raw', BASE_POINT, { name: 'X25519' }, false, []);
    return bytesOf(await s.deriveBits({ name: 'X25519', public: base }, priv, X25519_KEY_BYTES * 8));
  } finally {
    pkcs8.fill(0);
  }
}

/**
 * publicKeysEqual compares two raw public keys.
 *
 * A plain loop rather than a constant-time primitive, and that is not an
 * oversight: BOTH operands are public keys. One came off the disk in clear and
 * the other was just derived from it; there is no secret whose length or
 * content a timing difference could disclose. The loop is fixed-length anyway
 * because the length check comes first.
 */
export function publicKeysEqual(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
