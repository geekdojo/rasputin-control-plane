// Passphrase → key-encryption key, for design/storage.md §4.6.
//
// §4.6 is RATIFIED (Bryce, 2026-08-31) and names the KDF explicitly:
// **Argon2id**. WebCrypto does not implement it — `deriveBits` offers PBKDF2,
// HKDF and ECDH and nothing else — so this is the one place in the ceremony
// that needs a dependency. `hash-wasm` (MIT, zero transitive dependencies,
// pinned exactly in package.json) provides it; the WASM is base64-inlined in
// the module, so nothing is fetched at runtime and the static export ships
// self-contained.
//
// PBKDF2 is deliberately NOT used here. It is not memory-hard, so against an
// offline attack on a stolen backup disk it buys far less per unit of honest
// user latency than Argon2id does — and the threat §4.6 exists for is exactly
// that: a portable archive of every cluster secret, attacked at the attacker's
// leisure. Argon2id is what was decided; Argon2id is what runs.
//
// # A note on shape
//
// The derivation sits behind an interface with a stable `id` because the id is
// written into every wrapped blob AND into `ArchiveKey.alg` (persisted by the
// api as `BackupTarget.keyAlg`). A future parameter bump gets a NEW id, and a
// restore path meeting an old blob reads which parameters it needs rather than
// assuming today's. §4.6 already says what such a re-wrap costs: the KEYPAIR is
// unchanged, so the key-id is unchanged, so none of the four retained
// generations (§4.4) need re-encrypting.
//
// §4.6's 2026-09-02 amendment made the wrapped secret an X25519 private key
// rather than a symmetric data key. Nothing in this file changed with it: what
// a KEK wraps is not this module's business, both are 32 bytes, and "the two
// custody paths are unchanged" is precisely the property that let the amendment
// be as small as it was.

import { argon2id } from 'hash-wasm';

/**
 * Byte arrays backed by a plain ArrayBuffer.
 *
 * The explicit type argument is load-bearing under TypeScript 5.7+: a bare
 * `Uint8Array` widens to `ArrayBufferLike`, which includes SharedArrayBuffer,
 * and WebCrypto's `BufferSource` refuses it. Naming the buffer once here keeps
 * that out of every signature downstream.
 */
export type Bytes = Uint8Array<ArrayBuffer>;

/** How a passphrase becomes a 256-bit key-encryption key. */
export interface PassphraseKdf {
  /**
   * Stable identifier for this derivation, written into every wrapped blob and
   * into `ArchiveKey.alg`. Changing an implementation's parameters MUST change
   * its id — the id is the only thing a future unwrap has to go on.
   */
  readonly id: string;
  /** Cost parameters, echoed into the blob so an unwrap can reproduce them. */
  readonly params: Readonly<Record<string, number>>;
  /** Bytes of fresh random salt this derivation wants, per wrapping. */
  readonly saltBytes: number;
  /**
   * Derives the AES-GCM key-encryption key.
   *
   * `passphrase` is the operator's secret as UTF-8 bytes and `salt` is fresh
   * CSPRNG output for THIS wrapping. Both belong to the caller, which zeroes
   * them; nothing here retains either.
   *
   * The returned CryptoKey is NON-EXTRACTABLE — it can wrap the archive
   * private key, and nothing can read it back out afterwards, not even us.
   */
  deriveKek(passphrase: Bytes, salt: Bytes): Promise<CryptoKey>;
}

export function subtle(): SubtleCrypto {
  // crypto.subtle exists only in a secure context (https, or localhost). The
  // authed UI is served over https once the CA is installed, but say so plainly
  // rather than throwing "cannot read properties of undefined" at an operator
  // who is one click from formatting a disk.
  const s = globalThis.crypto?.subtle;
  if (!s) {
    throw new Error(
      'WebCrypto is unavailable — this page must be served over https (or localhost) to mint an archive key.',
    );
  }
  return s;
}

// Argon2id cost parameters, and why these.
//
// OWASP's 2024 password-storage guidance gives m=19 MiB, t=2, p=1 as the
// MINIMUM acceptable Argon2id configuration. This goes above it, because the
// asymmetry here is unusually favourable: the derivation runs exactly twice in
// the life of a backup target (once at claim time, once at restore), so a cost
// a user would refuse to pay on every login is free here.
//
// Measured with this exact build (hash-wasm 4.12.0, WASM, single thread):
//
//   m=19 MiB  t=2  →  ~65 ms      (OWASP floor — too cheap for a one-shot)
//   m=64 MiB  t=3  →  ~250 ms     ← chosen
//   m=128 MiB t=3  →  ~500 ms
//
// on an Apple-silicon Mac. A modest laptop runs roughly 3–4× slower, which puts
// the chosen setting at well under a second — the target was "unmistakably
// deliberate, still instant enough that nobody thinks the page hung".
//
// parallelism 1 rather than the 4 a server-side deployment would use:
// hash-wasm's Argon2 is single-threaded, so p>1 changes the KDF's output
// without buying any wall-clock benefit — it would advertise a parallelism the
// implementation does not have.
//
// 64 MiB is also chosen with the OTHER end in mind. §4.6 puts the restore-time
// prompt before the api starts, so this derivation may one day have to run
// somewhere much smaller than a laptop; 64 MiB is affordable on the Pi 4 class
// hardware in the fleet, where 128+ MiB starts being a real allocation.
const ARGON2ID_MEMORY_KIB = 65536; // 64 MiB
const ARGON2ID_ITERATIONS = 3;
const ARGON2ID_PARALLELISM = 1;
const ARGON2ID_DK_LEN = 32; // 256-bit KEK, matching the 256-bit AES-GCM wrapping key

/**
 * §4.6's ratified derivation.
 *
 * The salt is NEVER fixed and never derived from anything: `archive-key.ts`
 * draws `saltBytes` of fresh `crypto.getRandomValues` per wrapping and stores
 * it beside the ciphertext.
 */
export const ARGON2ID: PassphraseKdf = {
  id: `argon2id-m${ARGON2ID_MEMORY_KIB}-t${ARGON2ID_ITERATIONS}-p${ARGON2ID_PARALLELISM}`,
  params: {
    memoryKiB: ARGON2ID_MEMORY_KIB,
    iterations: ARGON2ID_ITERATIONS,
    parallelism: ARGON2ID_PARALLELISM,
    dkLen: ARGON2ID_DK_LEN,
  },
  saltBytes: 16,
  deriveKek(passphrase: Bytes, salt: Bytes): Promise<CryptoKey> {
    return deriveArgon2idKek(
      passphrase,
      salt,
      ARGON2ID_MEMORY_KIB,
      ARGON2ID_ITERATIONS,
      ARGON2ID_PARALLELISM,
      ARGON2ID_DK_LEN,
    );
  },
};

/** The derivation the claim flow uses. */
export const PASSPHRASE_KDF: PassphraseKdf = ARGON2ID;

// ---------------------------------------------------------------------------
// Reading a derivation back out of a wrapped blob
// ---------------------------------------------------------------------------

/**
 * The shape of an argon2id id: `argon2id-m<memoryKiB>-t<iterations>-p<parallelism>`.
 *
 * The id is the authority on the parameters, which is the whole reason it is
 * built out of them — a blob written years ago names its own cost, and the
 * unwrap reproduces it rather than assuming today's.
 */
const ARGON2ID_ID = /^argon2id-m(\d+)-t(\d+)-p(\d+)$/;

/**
 * Cost ceilings, and why an unwrap needs them at all.
 *
 * The blob these numbers come from is read OFF A DISK. On the adopt path that
 * disk was plugged in by whoever plugged it in, and its marker file is
 * attacker-controlled input in exactly the way a request body is. A blob
 * claiming `argon2id-m8388608-t1000-p1` is not a slow unwrap — it is 8 GiB of
 * WASM memory and a browser tab that dies, or a machine that swaps itself to a
 * halt, from a disk nobody has agreed to trust yet.
 *
 * So the ceilings are refusals, checked BEFORE any derivation is attempted.
 * They sit far above anything this product mints (64 MiB / t=3) and far below
 * anything a browser should be asked to do, and a blob outside them is reported
 * as unreadable rather than attempted.
 */
const MAX_MEMORY_KIB = 1024 * 1024; // 1 GiB
const MAX_ITERATIONS = 64;
const MAX_PARALLELISM = 16;

/**
 * resolvePassphraseKdf rebuilds the derivation a wrapped blob was made with.
 *
 * Returns null when the id names something this build cannot reproduce, or
 * names costs outside the ceilings above. Null is "this blob is unreadable
 * here", never "carry on with the current parameters" — deriving a KEK with
 * parameters other than the ones the blob was sealed under produces a wrong key
 * and an AEAD failure that would read to the operator as a wrong passphrase.
 *
 * `params` is cross-checked rather than trusted: the id and the params object
 * are two copies of the same numbers, and a blob whose copies disagree has been
 * edited or corrupted. Refuse it instead of picking a winner.
 */
export function resolvePassphraseKdf(
  id: string,
  params?: Readonly<Record<string, unknown>>,
): PassphraseKdf | null {
  const m = ARGON2ID_ID.exec(id);
  if (!m) return null;
  const memoryKiB = Number(m[1]);
  const iterations = Number(m[2]);
  const parallelism = Number(m[3]);
  if (
    !(memoryKiB > 0 && memoryKiB <= MAX_MEMORY_KIB) ||
    !(iterations > 0 && iterations <= MAX_ITERATIONS) ||
    !(parallelism > 0 && parallelism <= MAX_PARALLELISM)
  ) {
    return null;
  }
  const dkLen = ARGON2ID_DK_LEN;
  if (params) {
    const disagrees =
      (params.memoryKiB !== undefined && params.memoryKiB !== memoryKiB) ||
      (params.iterations !== undefined && params.iterations !== iterations) ||
      (params.parallelism !== undefined && params.parallelism !== parallelism) ||
      (params.dkLen !== undefined && params.dkLen !== dkLen);
    if (disagrees) return null;
  }
  if (id === ARGON2ID.id) return ARGON2ID;
  return {
    id,
    params: { memoryKiB, iterations, parallelism, dkLen },
    saltBytes: ARGON2ID.saltBytes,
    deriveKek: (passphrase, salt) =>
      deriveArgon2idKek(passphrase, salt, memoryKiB, iterations, parallelism, dkLen),
  };
}

/**
 * The one Argon2id derivation in this module, parameterised.
 *
 * Both callers reach it: the shipped ARGON2ID above, and resolvePassphraseKdf
 * rebuilding a derivation named by an older blob. One implementation, so a
 * blob's parameters cannot take a different code path from today's.
 */
async function deriveArgon2idKek(
  passphrase: Bytes,
  salt: Bytes,
  memoryKiB: number,
  iterations: number,
  parallelism: number,
  dkLen: number,
): Promise<CryptoKey> {
  const derived = await argon2id({
    password: passphrase,
    salt,
    iterations,
    parallelism,
    memorySize: memoryKiB,
    hashLength: dkLen,
    outputType: 'binary',
  });
  // Copied into an ArrayBuffer-backed view because hash-wasm hands back a bare
  // Uint8Array (ArrayBufferLike), which WebCrypto's BufferSource will not take.
  // Both copies are zeroed below — the derived KEK bytes must not outlive the
  // import that turns them into an opaque CryptoKey.
  const raw: Bytes = new Uint8Array(derived.length);
  raw.set(derived);
  derived.fill(0);
  try {
    return await subtle().importKey(
      'raw',
      raw,
      { name: 'AES-GCM', length: 256 },
      false, // non-extractable: the KEK can wrap, and can never be read back
      ['encrypt', 'decrypt'],
    );
  } finally {
    raw.fill(0);
  }
}
