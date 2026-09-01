// design/storage.md §4.6 — the archive data key, minted in the browser.
//
// # Why the browser
//
// A backup exists to survive the controlplane's death, so the key cannot live
// on the controlplane: any key the api generates and stores under
// /var/lib/rasputin is INSIDE the archive it encrypts, and re-flash wipes the
// original. §4.6's answer is one random 256-bit data key with two custody
// paths — an operator passphrase and a generated recovery code — and both of
// those exist only where the operator is typing. So the key is minted here,
// wrapped here, and only the two sealed copies ever cross the wire.
//
// `api/internal/storage.ArchiveKey` is the receiving end and says the same
// thing from the other side: it has no field for a plaintext key, and POST
// /api/backup/targets decodes with DisallowUnknownFields, so a stray plaintext
// field is a 400 rather than a secret in the job ledger.
//
// # What must never leave this module
//
//   - the plaintext data key. It exists as one Uint8Array, is wrapped twice,
//     and is zeroed in a `finally` before this module returns;
//   - the passphrase. Callers hand it over as bytes, this module reads it and
//     zeroes it. It is never stored, never logged, never put in an error.
//
// Errors thrown from here are deliberately generic. An error message is the
// one string in a crypto path that reliably ends up in a console, a screenshot
// or a bug report, so none of them carry inputs.

import { PASSPHRASE_KDF, subtle, type Bytes } from './passphrase-kdf';

/** The version tag on every blob this module writes. */
const BLOB_VERSION = 1;

/** Domain separator, so a blob from here can never be read as anything else. */
const AAD_DOMAIN = 'rasputin.archive-key.v1';

/**
 * The recovery-code KDF, and why it is NOT Argon2id.
 *
 * Argon2id's cost is what makes a GUESSABLE secret expensive to search. The
 * recovery code is not guessable: it is 160 bits of `crypto.getRandomValues`
 * (see generateRecoveryCode), so the search space is 2^160 and no KDF cost
 * meaningfully changes an attacker's problem — the entropy already did.
 *
 * What the recovery path actually needs is a correct extract-and-expand of a
 * uniformly random secret into an AES key, with domain separation and a fresh
 * salt. That is precisely HKDF, it is WebCrypto-native, and it keeps this path
 * free of the WASM dependency — which matters because §4.6 puts the restore
 * prompt BEFORE the api starts, in whatever minimal context that turns out to
 * be. Mixing KDFs is a reasoned split here, not an oversight: memory-hardness
 * is priced against human-chosen entropy, and there is none on this path.
 */
const RECOVERY_KDF_ID = 'hkdf-sha256';
const RECOVERY_SALT_BYTES = 16;

/** AES-GCM standard nonce length. */
const IV_BYTES = 12;

/** 256-bit data key — §4.6's "random 256-bit data key". */
const DATA_KEY_BYTES = 32;

/**
 * 160 bits of entropy in the recovery code: 20 random bytes, which base32
 * encodes to exactly 32 characters with no padding and no partial group.
 */
const RECOVERY_CODE_BYTES = 20;

/**
 * Crockford base32 — no I, L, O or U, so there is no 1/I, 0/O or rn/m to
 * mistranscribe. The recovery code is meant to be written on paper by hand and
 * typed back in years later, possibly by someone who did not write it.
 */
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * ArchiveKeyPayload is exactly `api/internal/storage.ArchiveKey` — the two
 * sealed copies plus an identifier, and nothing else. There is no field here
 * for the key, on either side of the wire.
 */
export interface ArchiveKeyPayload {
  keyId: string;
  alg: string;
  wrappedByPassphrase: string;
  wrappedByRecoveryCode: string;
}

/**
 * What mintArchiveKey hands back: the payload to POST, and the recovery code to
 * show the operator EXACTLY ONCE.
 */
export interface MintedArchiveKey {
  archiveKey: ArchiveKeyPayload;
  /** Grouped for reading aloud and writing down. Never sent anywhere. */
  recoveryCode: string;
}

function b64url(bytes: Bytes): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function utf8(s: string): Bytes {
  return new TextEncoder().encode(s);
}

function random(n: number): Bytes {
  const out: Bytes = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/**
 * The additional authenticated data on both wrappings.
 *
 * Binding the key-id and the custody path into the AEAD means a blob cannot be
 * moved between targets, and the passphrase copy cannot be presented as the
 * recovery copy. Neither is a likely attack; both are plausible ACCIDENTS in a
 * store that holds two near-identical opaque strings per row.
 */
function aad(keyId: string, purpose: 'passphrase' | 'recovery-code'): Bytes {
  return utf8(`${AAD_DOMAIN}|${keyId}|${purpose}`);
}

/**
 * A wrapped blob is SELF-DESCRIBING: it carries the KDF that made its KEK and
 * that KDF's parameters, so an unwrap years from now reads what it needs
 * instead of assuming whatever the code does at that moment. Base64url of
 * compact JSON — a few hundred bytes, opaque to the api by design.
 */
function encodeBlob(fields: {
  kdf: string;
  params: Record<string, number>;
  salt: Bytes;
  iv: Bytes;
  ct: Bytes;
}): string {
  return b64url(
    utf8(
      JSON.stringify({
        v: BLOB_VERSION,
        cipher: 'AES-256-GCM',
        kdf: fields.kdf,
        params: fields.params,
        salt: b64url(fields.salt),
        iv: b64url(fields.iv),
        ct: b64url(fields.ct),
      }),
    ),
  );
}

async function seal(kek: CryptoKey, dataKey: Bytes, additional: Bytes): Promise<Bytes> {
  const iv = random(IV_BYTES);
  const ct: Bytes = new Uint8Array(
    await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: additional }, kek, dataKey),
  );
  // The IV is not secret and must travel with the ciphertext; the caller
  // splices it into the blob. Returned joined so the two can't be paired wrong.
  const out: Bytes = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return out;
}

/**
 * generateRecoveryCode returns §4.6's "generated recovery code, displayed once
 * with a forced acknowledgement" — 160 bits, Crockford base32, in eight groups
 * of four.
 *
 * The groups are PRESENTATION ONLY. Everything cryptographic runs on the
 * canonical form (see canonicalRecoveryCode), so an operator who writes it
 * without dashes, or in lower case, still holds a working code.
 */
export function generateRecoveryCode(): string {
  const bytes = random(RECOVERY_CODE_BYTES);
  let bits = 0;
  let acc = 0;
  let chars = '';
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      chars += CROCKFORD[(acc >> bits) & 31];
    }
  }
  bytes.fill(0);
  return (chars.match(/.{1,4}/g) ?? []).join('-');
}

/**
 * canonicalRecoveryCode is what the KDF actually consumes: upper case, and
 * stripped of everything that is not a base32 character.
 *
 * Exported because the RESTORE path must use this exact function. A recovery
 * code that unlocks nothing because it was typed in lower case is
 * indistinguishable, to the person holding it, from having lost it.
 */
export function canonicalRecoveryCode(code: string): string {
  return code.toUpperCase().replace(/[^0-9A-Z]/g, '');
}

/**
 * mintArchiveKey performs the whole §4.6 ceremony and returns the two sealed
 * copies plus the recovery code to display.
 *
 * BOTH WRAPPINGS OR NEITHER. Any failure throws, and nothing partial is
 * returned — a target holding only the passphrase wrapping is one forgotten
 * passphrase away from an archive nobody can read, and the operator would not
 * find out until the day they needed the backup. The api refuses a partial
 * ArchiveKey for the same reason; this is the same rule enforced before the
 * request is even built.
 *
 * `passphrase` is consumed: it is zeroed before this function returns, on every
 * path. Callers must not reuse the array.
 */
export async function mintArchiveKey(passphrase: Bytes): Promise<MintedArchiveKey> {
  if (passphrase.length === 0) throw new Error('a passphrase is required to wrap the archive key');

  // The key-id identifies the DATA KEY (§4.6): it changes on a re-format, never
  // on a passphrase change, and it is what lets a restore tell which key a
  // given generation needs instead of guessing.
  const keyId = `ak-${b64url(random(16))}`;
  const dataKey = random(DATA_KEY_BYTES);
  const recoveryCode = generateRecoveryCode();

  try {
    // --- custody path 1: the operator's passphrase (Argon2id) --------------
    const ppSalt = random(PASSPHRASE_KDF.saltBytes);
    const ppKek = await PASSPHRASE_KDF.deriveKek(passphrase, ppSalt);
    const ppSealed = await seal(ppKek, dataKey, aad(keyId, 'passphrase'));

    // --- custody path 2: the recovery code (HKDF-SHA256) ------------------
    const rcSalt = random(RECOVERY_SALT_BYTES);
    const rcKek = await deriveRecoveryKek(recoveryCode, rcSalt);
    const rcSealed = await seal(rcKek, dataKey, aad(keyId, 'recovery-code'));

    return {
      recoveryCode,
      archiveKey: {
        keyId,
        // One string naming the whole construction, so `BackupTarget.keyAlg`
        // answers "what is this, and what would it take to read it" without
        // anyone having to open a blob.
        alg: `AES-256-GCM;pp=${PASSPHRASE_KDF.id};rc=${RECOVERY_KDF_ID}`,
        wrappedByPassphrase: encodeBlob({
          kdf: PASSPHRASE_KDF.id,
          params: PASSPHRASE_KDF.params as Record<string, number>,
          salt: ppSalt,
          iv: ppSealed.subarray(0, IV_BYTES),
          ct: ppSealed.subarray(IV_BYTES),
        }),
        wrappedByRecoveryCode: encodeBlob({
          kdf: RECOVERY_KDF_ID,
          params: { dkLen: 32 },
          salt: rcSalt,
          iv: rcSealed.subarray(0, IV_BYTES),
          ct: rcSealed.subarray(IV_BYTES),
        }),
      },
    };
  } finally {
    // The two things that must not outlive this call. Zeroed on the throw path
    // too — a failed mint is exactly when a stale key is most likely to sit in
    // a heap snapshot while someone debugs the failure.
    dataKey.fill(0);
    passphrase.fill(0);
  }
}

async function deriveRecoveryKek(code: string, salt: Bytes): Promise<CryptoKey> {
  const s = subtle();
  const secret = utf8(canonicalRecoveryCode(code));
  try {
    const material = await s.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
    return await s.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: utf8(`${AAD_DOMAIN}/recovery-code`) },
      material,
      { name: 'AES-GCM', length: 256 },
      false, // non-extractable
      ['encrypt', 'decrypt'],
    );
  } finally {
    secret.fill(0);
  }
}
