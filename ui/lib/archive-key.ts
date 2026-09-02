// design/storage.md §4.6 — the archive KEYPAIR, minted in the browser.
//
// # Why the browser
//
// A backup exists to survive the controlplane's death, so the key cannot live
// on the controlplane: any key the api generates and stores under
// /var/lib/rasputin is INSIDE the archive it encrypts, and re-flash wipes the
// original. §4.6's answer is two custody paths — an operator passphrase and a
// generated recovery code — and both of those exist only where the operator is
// typing. So the key is minted here, wrapped here, and only the public half
// plus the two sealed copies of the private half ever cross the wire.
//
// # Why a keypair, since 2026-09-02
//
// §4.6 originally minted ONE random 256-bit symmetric data key. The forcing
// problem was `backup.run` (#290): a weekly 3 a.m. job has nobody at a
// keyboard, so writing an encrypted archive under a symmetric key means the
// controlplane caches that key in the clear — the exact exposure §4.6 exists to
// close. The amendment makes the key an X25519 keypair instead:
//
//   - the PUBLIC key travels in clear, is stored by the api, and goes in the
//     on-disk marker. A public key at rest is harmless, and it is everything an
//     unattended run needs in order to seal a new generation to it;
//   - the PRIVATE key is wrapped under the passphrase (Argon2id) and under the
//     recovery code (HKDF-SHA-256) — the two custody paths are UNCHANGED; only
//     what they wrap changed — and both wrapped copies live on the disk.
//
// The cost, stated plainly by §4.6: the controlplane can write archives and
// cannot read them back without a human. That is acceptable because restore is
// interactive by construction.
//
// `api/internal/storage.ArchiveKey` is the receiving end and says the same
// thing from the other side: it has a field for the PUBLIC key and none for the
// private one, and POST /api/backup/targets decodes with DisallowUnknownFields,
// so a stray private-key field is a 400 rather than a secret in the job ledger.
//
// # What must never leave this module
//
//   - the private key. It exists as one Uint8Array, is wrapped twice, and is
//     zeroed in a `finally` before this module returns;
//   - the passphrase. Callers hand it over as bytes, this module reads it and
//     zeroes it. It is never stored, never logged, never put in an error.
//
// Errors thrown from here are deliberately generic. An error message is the
// one string in a crypto path that reliably ends up in a console, a screenshot
// or a bug report, so none of them carry inputs.

import { PASSPHRASE_KDF, resolvePassphraseKdf, subtle, type Bytes } from './passphrase-kdf';
import {
  generateX25519Keypair,
  publicKeyFromPrivateScalar,
  publicKeysEqual,
  X25519_KEY_BYTES,
} from './x25519';

/**
 * The version tag on every blob this module writes, and why the asymmetric
 * change is a VERSION BUMP rather than only a new `alg` string.
 *
 * The two are not interchangeable here. `alg` is a target-level summary — it is
 * what `BackupTarget.keyAlg` shows an operator, and it is advisory. `v` is what
 * decodeBlob GATES on, before any derivation, and gating is the thing this
 * change actually needs: a v1 blob sealed a 32-byte symmetric data key and a v2
 * blob seals a 32-byte X25519 private scalar. Identical length, identical
 * cipher, identical KDFs. Nothing about a v1 blob's bytes distinguishes it from
 * a v2 blob's, so a v1 blob presented to this build would decrypt SUCCESSFULLY
 * — tag and all — and yield 32 bytes that are not a private key for anything.
 * Length checking cannot catch it and the public-key check cannot catch it
 * either, because a v1 marker carries no public key to check against.
 *
 * So the version is the only place the refusal can live, and it has to be
 * explicit. Two bench disks carry v1 markers today; §4.6 does not ask for them
 * to be migrated, but a disk this build cannot use has to say so in those words
 * rather than fail somewhere in the crypto.
 */
const BLOB_VERSION = 2;

/** The symmetric-era blob version, refused by name so the message can be specific. */
const LEGACY_SYMMETRIC_BLOB_VERSION = 1;

/**
 * Domain separator, so a blob from here can never be read as anything else.
 *
 * Bumped to v2 alongside BLOB_VERSION. Belt and braces: the version check above
 * is what produces the READABLE refusal, and this is what makes a v1 blob with
 * its version field edited to 2 fail cryptographically as well, rather than
 * unwrap into 32 bytes of the wrong thing.
 */
const AAD_DOMAIN = 'rasputin.archive-key.v2';

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

/**
 * The sealed plaintext is §4.6's X25519 PRIVATE key — 32 bytes, the same size
 * the symmetric data key used to be, which is exactly why BLOB_VERSION had to
 * move rather than lean on a length check.
 */
const PRIVATE_KEY_BYTES = X25519_KEY_BYTES;

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
 * ArchiveKeyPayload is exactly `api/internal/storage.ArchiveKey` — an
 * identifier, the public key in clear, and the two sealed copies of the private
 * key. There is no field here for the PRIVATE key, on either side of the wire.
 */
export interface ArchiveKeyPayload {
  keyId: string;
  alg: string;
  /**
   * The X25519 public key, base64url of 32 raw bytes. IN CLEAR, deliberately:
   * §4.6's amendment turns on a public key at rest being harmless, and this is
   * the field that lets an unattended `backup.run` (#290) seal a generation
   * with no secret and no human.
   */
  publicKey: string;
  wrappedByPassphrase: string;
  wrappedByRecoveryCode: string;
}

/**
 * What mintArchiveKey hands back: the payload to POST, and the recovery code to
 * show the operator EXACTLY ONCE. The private key is not among them — it was
 * wrapped and zeroed before this returned.
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

async function seal(kek: CryptoKey, privateKey: Bytes, additional: Bytes): Promise<Bytes> {
  const iv = random(IV_BYTES);
  const ct: Bytes = new Uint8Array(
    await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: additional }, kek, privateKey),
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
 * mintArchiveKey performs the whole §4.6 ceremony and returns the public key
 * plus the two sealed copies of the private key, and the recovery code to
 * display.
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

  // The key-id identifies the KEYPAIR (§4.6): it changes on a re-format, never
  // on a passphrase change, and it is what lets a restore tell which key a
  // given generation needs instead of guessing.
  const keyId = `ak-${b64url(random(16))}`;
  const { publicKey, privateKey } = await generateX25519Keypair();
  const recoveryCode = generateRecoveryCode();

  try {
    // --- custody path 1: the operator's passphrase (Argon2id) --------------
    const ppSalt = random(PASSPHRASE_KDF.saltBytes);
    const ppKek = await PASSPHRASE_KDF.deriveKek(passphrase, ppSalt);
    const ppSealed = await seal(ppKek, privateKey, aad(keyId, 'passphrase'));

    // --- custody path 2: the recovery code (HKDF-SHA256) ------------------
    const rcSalt = random(RECOVERY_SALT_BYTES);
    const rcKek = await deriveRecoveryKek(recoveryCode, rcSalt);
    const rcSealed = await seal(rcKek, privateKey, aad(keyId, 'recovery-code'));

    return {
      recoveryCode,
      archiveKey: {
        keyId,
        // One string naming the whole construction, so `BackupTarget.keyAlg`
        // answers "what is this, and what would it take to read it" without
        // anyone having to open a blob. It leads with X25519 because that is
        // the load-bearing difference from the symmetric era, whose alg led
        // with AES-256-GCM — the two are unmistakable side by side in a ledger.
        alg: `X25519;wrap=AES-256-GCM;pp=${PASSPHRASE_KDF.id};rc=${RECOVERY_KDF_ID}`,
        publicKey: b64url(publicKey),
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
    // a heap snapshot while someone debugs the failure. The PUBLIC key is not
    // zeroed and does not need to be; that is the whole amendment.
    privateKey.fill(0);
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

// ---------------------------------------------------------------------------
// Unwrapping — design/storage.md §4.6's other half, and §4.8's adopt path
// ---------------------------------------------------------------------------
//
// Minting is what happens when a disk is formatted. ADOPTING is what happens
// when a disk that already carries a backup set is taken over as it stands, and
// until 2026-09-01 that path did nothing with the key at all: the generations
// on the disk were already sealed under the key its marker names, minting a
// fresh one would have recorded a key that unlocks nothing there, and so the
// flow simply stopped.
//
// Bryce's ruling, 2026-09-01: "Is there no way to prompt for the key or
// recovery code during recovery? It's perfectly fine to expect the user to
// supply something during a recovery operation." So adopt prompts, and this is
// what it prompts INTO.
//
// # ADOPT STILL PROMPTS, AND THE REASON CHANGED (2026-09-02)
//
// The old reason was capability: under the symmetric design, writing a new
// generation needed the data key, so a controlplane that had not been handed an
// openable key held a target it could never write to. Asymmetric removes that
// argument entirely. Writing needs only the PUBLIC key, which sits on the disk
// in clear, so a replacement controlplane could technically resume backups
// having proved nothing at all.
//
// The prompt stays anyway, because it is now the ONLY thing that proves the
// custody secrets actually open THIS disk. Without it an operator adopts a
// target whose private key nobody can unwrap, the schedule cheerfully seals
// four generations to a public key with no matching secret in the world, and
// the discovery happens on restore day. That is the same hazard the "both
// wrappings or neither" rule already guards against, one level up: a target
// that reads as configured in every listing and is unreadable in the only case
// it exists for. Adopt is also the one moment in the product's life where the
// operator is present, holding the disk, and can be asked — so it is where the
// check belongs.
//
// # What this half does NOT do
//
// It does not return the private key. `unlockArchiveKey` recovers it, checks it
// against the disk's public key, derives a one-way proof from it and zeroes it
// in a `finally`, and the proof is the only thing that comes back. The rule the
// mint path set — the plaintext key exists as one Uint8Array and does not
// outlive the call — is the same rule here, and making it a return value would
// be the easiest way to break it. The private key is at least as sensitive as
// the symmetric key it replaced: it opens every generation ever written to this
// disk, not one.
//
// It does not re-wrap. §4.8's adopt takes the disk over EXACTLY AS IT STANDS;
// the wrappings that go to the api are the ones that were already on the disk.
// See the api's checkAdoptedKeyCustody for the other half of that argument.

/** Which of §4.6's two custody paths the operator is supplying. */
export type CustodyPath = 'passphrase' | 'recovery-code';

/**
 * The secret the operator typed. Either one is sufficient — that is the whole
 * point of §4.6's two paths, and an operator who forgot the passphrase but kept
 * the printed recovery code must be able to adopt.
 *
 * `passphrase` is CONSUMED: zeroed before unlockArchiveKey returns, on every
 * path, exactly as mintArchiveKey consumes it.
 */
export type CustodySecret =
  | { path: 'passphrase'; passphrase: Bytes }
  | { path: 'recovery-code'; code: string };

/**
 * What a successful unlock hands back — deliberately not the key.
 *
 * `keyDigest` is SHA-256 over a domain-separated encoding of the recovered
 * PRIVATE key. It is a one-way digest of 256 bits of CSPRNG output, so it
 * discloses nothing about the key, and it exists for exactly one reason: two
 * custody paths can be shown to recover the SAME key without either the test or
 * the UI ever holding the key to compare.
 *
 * `publicKey` is the public half, echoed back because it is not secret and
 * because a caller that wants to say "this is the key on the disk" should be
 * able to, without re-parsing the payload. It is the value that was CHECKED,
 * not the one that was supplied: unlockArchiveKey derives it from the recovered
 * private key and refuses if it disagrees with the disk.
 */
export interface CustodyProof {
  keyId: string;
  path: CustodyPath;
  keyDigest: string;
  publicKey: string;
}

/**
 * ArchiveKeyBlobs is what the ADOPT path finds on the disk: the same five
 * strings mintArchiveKey produced — id, alg, public key, and the two sealed
 * copies of the private key — read back out of the marker file
 * (proto.StorageBackupSet) rather than built here.
 *
 * Structurally identical to ArchiveKeyPayload, and named separately because the
 * direction of travel is the thing worth being able to see at a call site.
 */
export type ArchiveKeyBlobs = ArchiveKeyPayload;

/** Every distinct way an unwrap can fail, so a caller can branch on the cause. */
export type ArchiveKeyErrorKind = 'wrong-secret' | 'unreadable' | 'key-mismatch';

/** Every error thrown out of the unwrap path, so a caller can branch. */
export class ArchiveKeyError extends Error {
  /**
   * `wrong-secret` — the AEAD rejected the unwrap. The blob is intact and the
   * passphrase or recovery code does not open it. This is the ONLY outcome that
   * should read to an operator as "try again".
   *
   * `unreadable` — the blob itself could not be parsed, or names a construction
   * this build cannot reproduce. Trying again with a different passphrase will
   * not help.
   *
   * `key-mismatch` — the blob opened, and the private key inside it does not
   * belong to the public key this disk carries. This is the outcome the
   * symmetric design could not report at all, because there was nothing to
   * check a recovered key against: any 32 bytes that passed the tag were
   * accepted. Telling an operator "wrong passphrase" here would send them
   * hunting for a secret they are already holding; the disk is what is wrong.
   */
  readonly kind: ArchiveKeyErrorKind;
  constructor(kind: ArchiveKeyErrorKind, message: string) {
    super(message);
    this.name = 'ArchiveKeyError';
    this.kind = kind;
  }
}

/** Base64url → bytes. Strict: anything outside the alphabet is a refusal. */
function unb64url(s: string, what = 'blob'): Bytes {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new ArchiveKeyError('unreadable', `malformed ${what} encoding`);
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out: Bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * A decoded blob, after the shape checks and before any derivation.
 *
 * Everything in here came off a disk. It is parsed defensively for the same
 * reason a request body is: on the adopt path the marker file was written by
 * whoever wrote it, and the browser is about to spend real memory on what it
 * says. Nothing is defaulted — a field this cannot read is a refusal.
 */
interface DecodedBlob {
  kdf: string;
  params: Record<string, unknown>;
  salt: Bytes;
  iv: Bytes;
  ct: Bytes;
}

/** Ciphertext bound: the private key is 32 bytes and GCM adds a 16-byte tag. */
const MAX_CT_BYTES = 256;
/** Salt bound: no derivation here asks for more than 32 bytes of salt. */
const MAX_SALT_BYTES = 64;

function decodeBlob(blob: string): DecodedBlob {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(unb64url(blob)));
  } catch {
    throw new ArchiveKeyError('unreadable', 'the wrapped key on this disk could not be decoded');
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new ArchiveKeyError('unreadable', 'the wrapped key on this disk is not a key blob');
  }
  const o = parsed as Record<string, unknown>;
  if (o.v === LEGACY_SYMMETRIC_BLOB_VERSION) {
    // Named separately from "some other version" because this one exists on
    // real disks and the operator needs to be told what to DO about it. §4.6's
    // amendment does not migrate v1 targets: the archives on such a disk are
    // sealed under a symmetric key this build no longer mints, and re-claiming
    // the disk is the answer.
    throw new ArchiveKeyError(
      'unreadable',
      "this disk's archive key was written under the earlier symmetric design (key blob version 1). This build's archive key is an X25519 keypair, and there is no way to convert one into the other. Claim the disk fresh to give it a new key — which destroys the generations already on it — or keep it as it is and claim a different disk",
    );
  }
  if (o.v !== BLOB_VERSION) {
    throw new ArchiveKeyError(
      'unreadable',
      `this disk's key blob is version ${String(o.v)}; this build writes and reads version ${BLOB_VERSION}`,
    );
  }
  if (o.cipher !== 'AES-256-GCM') {
    throw new ArchiveKeyError('unreadable', 'this disk’s key blob names a cipher this build does not implement');
  }
  if (typeof o.kdf !== 'string' || typeof o.salt !== 'string' || typeof o.iv !== 'string' || typeof o.ct !== 'string') {
    throw new ArchiveKeyError('unreadable', 'the wrapped key on this disk is missing a required field');
  }
  const salt = unb64url(o.salt);
  const iv = unb64url(o.iv);
  const ct = unb64url(o.ct);
  if (salt.length === 0 || salt.length > MAX_SALT_BYTES || iv.length !== IV_BYTES || ct.length === 0 || ct.length > MAX_CT_BYTES) {
    throw new ArchiveKeyError('unreadable', 'the wrapped key on this disk has implausible field sizes');
  }
  const params =
    typeof o.params === 'object' && o.params !== null ? (o.params as Record<string, unknown>) : {};
  return { kdf: o.kdf, params, salt, iv, ct };
}

/**
 * unlockArchiveKey proves custody of an existing target's §4.6 private key.
 *
 * It takes the payload AS IT SITS ON THE DISK plus whichever secret the
 * operator supplied, opens the matching wrapping, and returns a proof. Three
 * distinct failures, and keeping them distinct is the point:
 *
 *   - `wrong-secret` — the AEAD rejected the unwrap, which is why an AEAD is
 *     used here at all. A wrong passphrase fails VISIBLY, at unlock time, in
 *     the browser. It cannot produce a target that silently seals nothing,
 *     because the only way past this function is a tag that verified;
 *   - `unreadable` — the blob could not be parsed, or names a construction this
 *     build cannot reproduce (a symmetric-era v1 blob among them);
 *   - `key-mismatch` — the blob opened and the private key inside it does not
 *     derive this disk's public key. NEW with the asymmetric design, and the
 *     thing the symmetric one could not express: a tag that verifies proves the
 *     secret was right, and now the public key proves the DISK is right too.
 *     An operator told "wrong passphrase" here would go looking for a secret
 *     they already have.
 *
 * The AAD does the rest of the work. It binds the key-id and the custody path
 * into every wrapping (see `aad`), so a blob lifted from a different target
 * fails here even with the right passphrase, and the passphrase copy cannot be
 * presented as the recovery-code copy.
 *
 * Errors never carry the passphrase, the recovery code or the private key.
 */
export async function unlockArchiveKey(
  blobs: ArchiveKeyBlobs,
  secret: CustodySecret,
): Promise<CustodyProof> {
  const keyId = blobs.keyId?.trim() ?? '';
  try {
    if (!keyId) {
      throw new ArchiveKeyError('unreadable', 'this disk names no archive key to unlock');
    }
    // The public key is what the recovered private key is checked against, so
    // its absence is not a detail to work around — it is the check going
    // missing. A marker with wrappings and no public key is a symmetric-era
    // disk; say so here too, because this path can be reached without going
    // through decodeBlob's version refusal first.
    const expectedPublic = decodePublicKey(blobs.publicKey);
    const wrapped =
      secret.path === 'passphrase' ? blobs.wrappedByPassphrase : blobs.wrappedByRecoveryCode;
    if (!wrapped) {
      throw new ArchiveKeyError(
        'unreadable',
        secret.path === 'passphrase'
          ? 'this disk carries no passphrase-wrapped copy of its archive key'
          : 'this disk carries no recovery-code-wrapped copy of its archive key',
      );
    }
    const blob = decodeBlob(wrapped);
    const kek = await kekFor(blob, secret);
    const privateKey = await open(kek, blob, aad(keyId, secret.path));
    try {
      if (privateKey.length !== PRIVATE_KEY_BYTES) {
        // A blob that decrypts to the wrong length is not a wrong secret — the
        // tag verified. It is a blob this build cannot use, and saying "wrong
        // passphrase" would send the operator hunting for a secret they have.
        throw new ArchiveKeyError(
          'unreadable',
          `this disk's archive key is ${privateKey.length} bytes; §4.6 private keys are ${PRIVATE_KEY_BYTES}`,
        );
      }
      // The verification the symmetric design could not do: derive the public
      // half from what was just recovered and require it to be the public half
      // the disk carries. Everything up to here proved the SECRET; this proves
      // the secret belongs to THIS TARGET.
      const derived = await publicKeyFromPrivateScalar(privateKey);
      if (!publicKeysEqual(derived, expectedPublic)) {
        throw new ArchiveKeyError(
          'key-mismatch',
          "that secret opened this disk's wrapped key, but the key inside it is not the one this disk's archives are encrypted to. The passphrase or recovery code is right and the disk's records disagree with each other — its marker has been edited, corrupted, or assembled from two different targets. Do not adopt it; nothing written under this key would be readable",
        );
      }
      return {
        keyId,
        path: secret.path,
        keyDigest: await digestOf(keyId, privateKey),
        publicKey: b64url(derived),
      };
    } finally {
      privateKey.fill(0);
    }
  } finally {
    // Same contract as mintArchiveKey: the caller's passphrase bytes do not
    // outlive this call, on the throw path as much as the success path.
    if (secret.path === 'passphrase') secret.passphrase.fill(0);
  }
}

/**
 * decodePublicKey reads the disk's public key, refusing anything that is not a
 * 32-byte X25519 key.
 *
 * The all-zero key is refused by name. It is the one public key with a
 * catastrophic property — every ECDH against it yields zero, so every archive
 * sealed to it would be encrypted under a key an attacker also derives — and it
 * is what a zeroed or partially-written marker field decodes to. Refusing it at
 * the door costs nothing and closes the case where a corrupt disk reads as a
 * working target.
 */
function decodePublicKey(encoded: string | undefined): Bytes {
  const raw = (encoded ?? '').trim();
  if (!raw) {
    throw new ArchiveKeyError(
      'unreadable',
      "this disk carries a sealed archive key but no public key, which is the shape every target claimed under the earlier symmetric design has. This build's archive key is an X25519 keypair and cannot use it. Claim the disk fresh to give it a new key — which destroys the generations already on it — or keep it as it is and claim a different disk",
    );
  }
  const bytes = unb64url(raw, 'public key');
  if (bytes.length !== X25519_KEY_BYTES) {
    throw new ArchiveKeyError(
      'unreadable',
      `this disk's public key is ${bytes.length} bytes; an X25519 public key is ${X25519_KEY_BYTES}`,
    );
  }
  if (bytes.every((b) => b === 0)) {
    throw new ArchiveKeyError('unreadable', "this disk's public key is all zeroes, which is not a usable X25519 key");
  }
  return bytes;
}

async function kekFor(blob: DecodedBlob, secret: CustodySecret): Promise<CryptoKey> {
  if (secret.path === 'recovery-code') {
    if (blob.kdf !== RECOVERY_KDF_ID) {
      throw new ArchiveKeyError(
        'unreadable',
        `this disk's recovery-code wrapping uses ${blob.kdf}, which this build cannot reproduce`,
      );
    }
    return deriveRecoveryKek(secret.code, blob.salt);
  }
  const kdf = resolvePassphraseKdf(blob.kdf, blob.params);
  if (!kdf) {
    // Covers both "we do not implement this" and "the cost it names is one no
    // browser should be asked to pay" — see resolvePassphraseKdf's ceilings.
    throw new ArchiveKeyError(
      'unreadable',
      `this disk's passphrase wrapping uses ${blob.kdf}, which this build cannot reproduce`,
    );
  }
  return kdf.deriveKek(secret.passphrase, blob.salt);
}

async function open(kek: CryptoKey, blob: DecodedBlob, additional: Bytes): Promise<Bytes> {
  try {
    return new Uint8Array(
      await subtle().decrypt({ name: 'AES-GCM', iv: blob.iv, additionalData: additional }, kek, blob.ct),
    );
  } catch {
    // WebCrypto throws an OperationError with no detail on a tag failure, and
    // that is the right amount of detail: whether the secret was wrong, the
    // blob was edited, or it belongs to another target, the answer is the same
    // and none of the three should be distinguishable to a guesser.
    throw new ArchiveKeyError(
      'wrong-secret',
      'that does not open this disk’s archive key — check which passphrase or recovery code belongs to this disk',
    );
  }
}

/**
 * digestOf turns the recovered private key into something safe to hold.
 *
 * Domain-separated and bound to the key-id, so the digest is specific to this
 * target and cannot be compared against a digest computed anywhere else for
 * another purpose. SHA-256 over 256 bits of CSPRNG output is not invertible and
 * not searchable; this is a proof that two unwraps agree, not a credential.
 */
async function digestOf(keyId: string, privateKey: Bytes): Promise<string> {
  const label = utf8(`${AAD_DOMAIN}|${keyId}|custody-proof|`);
  const buf: Bytes = new Uint8Array(label.length + privateKey.length);
  buf.set(label, 0);
  buf.set(privateKey, label.length);
  try {
    return b64url(new Uint8Array(await subtle().digest('SHA-256', buf)));
  } finally {
    buf.fill(0);
  }
}
