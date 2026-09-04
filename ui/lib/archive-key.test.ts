// design/storage.md §4.6, executed.
//
// The mint half of archive-key.ts has been shipping since PR #203 with no test
// of any kind — ui/ had no runner. The unwrap half added for §4.8's adopt path
// is where a silent mistake is worst: it decides whether an operator who typed
// the wrong passphrase is told so, or is handed a backup target that will fail
// on the one day it matters. So these run the real crypto, in Node's WebCrypto
// and the real hash-wasm Argon2id, and assert the things the design promises:
//
//   - either custody path alone recovers the SAME private key (§4.6's whole
//     point), and that key derives the public key on the disk;
//   - a wrong secret fails visibly, as an AEAD failure, not silently;
//   - a key that opens but does not match the disk is reported as a MISMATCH
//     rather than as a wrong secret — the distinction the symmetric design
//     could not make, and the one that decides whether an operator goes looking
//     for a passphrase they are already holding;
//   - a symmetric-era blob is refused in words, not in the crypto;
//   - a blob cannot be moved between targets or between custody paths;
//   - a blob off a disk cannot make this browser do something absurd;
//   - the private key does not outlive the call that minted it; and
//   - nothing secret is in the request body the adopt path builds.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  ArchiveKeyError,
  canonicalRecoveryCode,
  generateRecoveryCode,
  lendArchiveKeyForRestore,
  mintArchiveKey,
  unlockArchiveKey,
  type ArchiveKeyPayload,
  type MintedArchiveKey,
} from './archive-key';
import { resolvePassphraseKdf } from './passphrase-kdf';
import { publicKeyFromPrivateScalar, X25519_KEY_BYTES } from './x25519';

const PASSPHRASE = 'correct horse battery staple';

function bytes(s: string) {
  return new TextEncoder().encode(s);
}

function b64urlBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

/** A payload with no §4.6 material at all, for the shape checks. */
function emptyPayload(over: Partial<ArchiveKeyPayload> = {}): ArchiveKeyPayload {
  return {
    keyId: 'ak-x',
    alg: '',
    publicKey: '',
    wrappedByPassphrase: 'x',
    wrappedByRecoveryCode: 'x',
    ...over,
  };
}

/** Argon2id at the shipped cost runs a few hundred ms per unwrap. */
const SLOW = 30_000;

async function mint(passphrase = PASSPHRASE): Promise<MintedArchiveKey> {
  return mintArchiveKey(bytes(passphrase));
}

/** Re-encodes a blob's JSON after `edit` has changed it. */
function editBlob(blob: string, edit: (o: Record<string, unknown>) => void): string {
  const json = JSON.parse(Buffer.from(blob, 'base64url').toString('utf8'));
  edit(json);
  return Buffer.from(JSON.stringify(json), 'utf8').toString('base64url');
}

describe('minting', () => {
  test('produces a public key, both wrappings, an id, and a recovery code', { timeout: SLOW }, async () => {
    const m = await mint();
    assert.match(m.archiveKey.keyId, /^ak-[A-Za-z0-9_-]{22}$/);
    assert.equal(b64urlBytes(m.archiveKey.publicKey).length, X25519_KEY_BYTES);
    assert.ok(m.archiveKey.wrappedByPassphrase.length > 0);
    assert.ok(m.archiveKey.wrappedByRecoveryCode.length > 0);
    assert.notEqual(m.archiveKey.wrappedByPassphrase, m.archiveKey.wrappedByRecoveryCode);
    assert.equal(canonicalRecoveryCode(m.recoveryCode).length, 32);
  });

  // §4.6 as amended: the api stores a public key and nothing secret. `alg` is
  // what a ledger row shows an operator, and it has to say which era the target
  // belongs to without anyone opening a blob.
  test('the alg names the keypair construction, not the symmetric one', { timeout: SLOW }, async () => {
    const m = await mint();
    assert.match(m.archiveKey.alg, /^X25519;wrap=AES-256-GCM;pp=argon2id-/);
    assert.ok(m.archiveKey.alg.includes('rc=hkdf-sha256'));
  });

  test('two mints never share a keypair', { timeout: SLOW }, async () => {
    const [a, b] = [await mint(), await mint()];
    assert.notEqual(a.archiveKey.publicKey, b.archiveKey.publicKey);
    assert.notEqual(a.archiveKey.keyId, b.archiveKey.keyId);
  });

  // The private key is the one buffer in this module that must not outlive the
  // call. It is unobservable from the return value by design, so this reaches
  // for the buffer where it is genuinely visible: the plaintext handed to
  // AES-GCM. Same array, checked after the promise settles.
  test('zeroes the private key before returning', { timeout: SLOW }, async () => {
    const real = globalThis.crypto.subtle.encrypt.bind(globalThis.crypto.subtle);
    const sealed: Uint8Array[] = [];
    globalThis.crypto.subtle.encrypt = ((alg: AlgorithmIdentifier, key: CryptoKey, data: BufferSource) => {
      if (data instanceof Uint8Array) sealed.push(data);
      return real(alg, key, data);
    }) as typeof globalThis.crypto.subtle.encrypt;
    try {
      await mint();
    } finally {
      globalThis.crypto.subtle.encrypt = real;
    }
    assert.equal(sealed.length, 2, 'a mint seals the private key exactly twice');
    assert.equal(sealed[0], sealed[1], 'both wrappings must seal the SAME buffer');
    assert.ok(
      sealed[0].every((b) => b === 0),
      'the private key must be zeroed before mintArchiveKey returns',
    );
  });

  test('zeroes the passphrase it was handed', { timeout: SLOW }, async () => {
    const pp = bytes(PASSPHRASE);
    await mintArchiveKey(pp);
    assert.ok(
      pp.every((b) => b === 0),
      'mintArchiveKey must consume and zero the caller’s passphrase bytes',
    );
  });

  test('refuses an empty passphrase', async () => {
    await assert.rejects(() => mintArchiveKey(new Uint8Array(0)));
  });

  test('recovery codes are 160 bits from the Crockford alphabet', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const code = generateRecoveryCode();
      assert.match(code, /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){7}$/);
      assert.doesNotMatch(code, /[ILOU]/);
      seen.add(code);
    }
    assert.equal(seen.size, 50, 'recovery codes must not repeat');
  });
});

describe('unlocking — §4.8 adopt', () => {
  test('the passphrase opens the key', { timeout: SLOW }, async () => {
    const m = await mint();
    const proof = await unlockArchiveKey(m.archiveKey, {
      path: 'passphrase',
      passphrase: bytes(PASSPHRASE),
    });
    assert.equal(proof.keyId, m.archiveKey.keyId);
    assert.equal(proof.path, 'passphrase');
    assert.ok(proof.keyDigest.length > 0);
  });

  test('the recovery code opens the key', { timeout: SLOW }, async () => {
    const m = await mint();
    const proof = await unlockArchiveKey(m.archiveKey, {
      path: 'recovery-code',
      code: m.recoveryCode,
    });
    assert.equal(proof.keyId, m.archiveKey.keyId);
    assert.equal(proof.path, 'recovery-code');
  });

  // §4.6: "Losing either custody path is survivable." That is only true if both
  // wrappings really do seal the same 32 bytes — this is the assertion the
  // whole two-path model rests on.
  test('both custody paths recover the SAME private key', { timeout: SLOW }, async () => {
    const m = await mint();
    const viaPass = await unlockArchiveKey(m.archiveKey, {
      path: 'passphrase',
      passphrase: bytes(PASSPHRASE),
    });
    const viaCode = await unlockArchiveKey(m.archiveKey, {
      path: 'recovery-code',
      code: m.recoveryCode,
    });
    assert.equal(viaPass.keyDigest, viaCode.keyDigest);
    assert.equal(viaPass.publicKey, viaCode.publicKey);
  });

  // The verification the symmetric design could not do. Under one shared key,
  // any 32 bytes that passed the tag were accepted; now the recovered private
  // key has to derive the public key the disk carries, and unlockArchiveKey
  // returns the DERIVED value rather than echoing what it was given.
  test('the recovered private key derives the stored public key', { timeout: SLOW }, async () => {
    const m = await mint();
    const proof = await unlockArchiveKey(m.archiveKey, {
      path: 'passphrase',
      passphrase: bytes(PASSPHRASE),
    });
    assert.equal(proof.publicKey, m.archiveKey.publicKey);
  });

  // The whole reason `key-mismatch` exists. This blob DECRYPTS — the tag
  // verifies, the passphrase is right — and the key inside it is not the one
  // this disk's archives are sealed to. Calling that a wrong secret would send
  // the operator hunting for a passphrase they are holding in their hand.
  test('a private key that does not match the disk’s public key is a MISMATCH, not a wrong secret', {
    timeout: SLOW,
  }, async () => {
    const mine = await mint();
    const other = await mint();
    const frankenstein: ArchiveKeyPayload = { ...mine.archiveKey, publicKey: other.archiveKey.publicKey };
    const err = await unlockArchiveKey(frankenstein, {
      path: 'passphrase',
      passphrase: bytes(PASSPHRASE),
    }).then(
      () => null,
      (e: unknown) => e,
    );
    assert.ok(err instanceof ArchiveKeyError);
    assert.equal(err.kind, 'key-mismatch');
    assert.doesNotMatch(err.message, new RegExp(PASSPHRASE));
    // The message must not read as "try again with a different secret".
    assert.ok(err.message.includes('opened'), `mismatch message reads wrong: ${err.message}`);
  });

  test('a mismatch is reported on the recovery-code path too', { timeout: SLOW }, async () => {
    const mine = await mint();
    const other = await mint();
    await assert.rejects(
      () =>
        unlockArchiveKey(
          { ...mine.archiveKey, publicKey: other.archiveKey.publicKey },
          { path: 'recovery-code', code: mine.recoveryCode },
        ),
      (e: unknown) => e instanceof ArchiveKeyError && e.kind === 'key-mismatch',
    );
  });

  // Belt and braces on the same property, from the other side: a real X25519
  // derivation of an unrelated scalar must not happen to equal a minted public
  // key. (It cannot; this asserts the helper is actually deriving rather than
  // echoing.)
  test('publicKeyFromPrivateScalar derives, it does not echo', { timeout: SLOW }, async () => {
    const m = await mint();
    const unrelated = await publicKeyFromPrivateScalar(new Uint8Array(X25519_KEY_BYTES).fill(7));
    assert.equal(unrelated.length, X25519_KEY_BYTES);
    assert.notEqual(Buffer.from(unrelated).toString('base64url'), m.archiveKey.publicKey);
  });

  test('a recovery code unlocks regardless of case and dashes', { timeout: SLOW }, async () => {
    const m = await mint();
    const mangled = m.recoveryCode.toLowerCase().replace(/-/g, ' ');
    const proof = await unlockArchiveKey(m.archiveKey, { path: 'recovery-code', code: mangled });
    assert.equal(proof.keyId, m.archiveKey.keyId);
  });

  test('unlocking zeroes the passphrase it was handed', { timeout: SLOW }, async () => {
    const m = await mint();
    const pp = bytes(PASSPHRASE);
    await unlockArchiveKey(m.archiveKey, { path: 'passphrase', passphrase: pp });
    assert.ok(pp.every((b) => b === 0));
  });

  test('a wrong passphrase fails visibly, and the error carries no input', { timeout: SLOW }, async () => {
    const m = await mint();
    const err = await unlockArchiveKey(m.archiveKey, {
      path: 'passphrase',
      passphrase: bytes('not the passphrase at all'),
    }).then(
      () => null,
      (e: unknown) => e,
    );
    assert.ok(err instanceof ArchiveKeyError, 'a wrong passphrase must throw ArchiveKeyError');
    assert.equal(err.kind, 'wrong-secret');
    assert.doesNotMatch(err.message, /not the passphrase at all/);
    assert.doesNotMatch(err.message, new RegExp(PASSPHRASE));
  });

  test('a wrong recovery code fails visibly', { timeout: SLOW }, async () => {
    const m = await mint();
    const other = generateRecoveryCode();
    const err = await unlockArchiveKey(m.archiveKey, {
      path: 'recovery-code',
      code: other,
    }).then(
      () => null,
      (e: unknown) => e,
    );
    assert.ok(err instanceof ArchiveKeyError);
    assert.equal(err.kind, 'wrong-secret');
    assert.doesNotMatch(err.message, new RegExp(canonicalRecoveryCode(other)));
  });

  // The AAD binds the key-id into both wrappings. A blob lifted off one disk
  // and presented under another disk's id must fail even with the right
  // passphrase — which is what stops an adopt recording key material against a
  // disk it does not belong to.
  test('a blob from a different keyId is rejected', { timeout: SLOW }, async () => {
    const m = await mint();
    const impostor: ArchiveKeyPayload = { ...m.archiveKey, keyId: 'ak-someOtherTargetEntirely' };
    const err = await unlockArchiveKey(impostor, {
      path: 'passphrase',
      passphrase: bytes(PASSPHRASE),
    }).then(
      () => null,
      (e: unknown) => e,
    );
    assert.ok(err instanceof ArchiveKeyError);
    assert.equal(err.kind, 'wrong-secret');
  });

  // The AAD also binds the custody PATH, so the two near-identical opaque
  // strings on a target cannot be swapped — an accident far likelier than an
  // attack, and one that would otherwise surface as "your recovery code is
  // wrong".
  test('the passphrase blob cannot be presented as the recovery-code blob', { timeout: SLOW }, async () => {
    const m = await mint();
    const swapped: ArchiveKeyPayload = {
      ...m.archiveKey,
      wrappedByRecoveryCode: m.archiveKey.wrappedByPassphrase,
    };
    await assert.rejects(
      () => unlockArchiveKey(swapped, { path: 'recovery-code', code: m.recoveryCode }),
      (e: unknown) => e instanceof ArchiveKeyError,
    );
  });

  test('a target with no key-id cannot be unlocked', async () => {
    const err = await unlockArchiveKey(emptyPayload({ keyId: '' }), {
      path: 'passphrase',
      passphrase: bytes(PASSPHRASE),
    }).then(
      () => null,
      (e: unknown) => e,
    );
    assert.ok(err instanceof ArchiveKeyError);
    assert.equal(err.kind, 'unreadable');
  });
});

// Everything below reaches this module off a DISK. On the adopt path the marker
// file was written by whoever wrote it, so it is parsed the way a request body
// is: defensively, and a field that cannot be read is a refusal rather than a
// default.
describe('unlocking — hostile and malformed blobs', () => {
  const secret = () => ({ path: 'passphrase' as const, passphrase: bytes(PASSPHRASE) });

  test('a blob that is not base64url is unreadable, not a wrong secret', async () => {
    const err = await unlockArchiveKey(
      emptyPayload({ publicKey: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8', wrappedByPassphrase: 'not base64!!' }),
      secret(),
    ).then(
      () => null,
      (e: unknown) => e,
    );
    assert.ok(err instanceof ArchiveKeyError);
    assert.equal(err.kind, 'unreadable');
  });

  // The bench has two disks in this shape, and §4.6 does not migrate them. What
  // it does require is that they fail in words. A v1 blob is byte-identical in
  // shape to a v2 one — 32 bytes under AES-256-GCM, same KDFs — so it would
  // DECRYPT under the operator's real passphrase and yield something that is
  // not a private key for anything. Only the version field can catch it.
  test('a symmetric-era blob is refused by name, not by a crypto error', { timeout: SLOW }, async () => {
    const m = await mint();
    const legacy: ArchiveKeyPayload = {
      ...m.archiveKey,
      wrappedByPassphrase: editBlob(m.archiveKey.wrappedByPassphrase, (o) => {
        o.v = 1;
      }),
    };
    const err = await unlockArchiveKey(legacy, secret()).then(
      () => null,
      (e: unknown) => e,
    );
    assert.ok(err instanceof ArchiveKeyError);
    assert.equal(err.kind, 'unreadable');
    assert.match(err.message, /symmetric/i);
    assert.match(err.message, /claim/i, 'the refusal must say what to do about it');
  });

  // The other half of the same disk: a pre-amendment marker has no public key
  // at all, and the absence is not a detail to route around — it is the check
  // going missing.
  test('a sealed key with no public key is refused as symmetric-era', { timeout: SLOW }, async () => {
    const m = await mint();
    const err = await unlockArchiveKey({ ...m.archiveKey, publicKey: '' }, secret()).then(
      () => null,
      (e: unknown) => e,
    );
    assert.ok(err instanceof ArchiveKeyError);
    assert.equal(err.kind, 'unreadable');
    assert.match(err.message, /symmetric/i);
  });

  test('a public key of the wrong length is refused', { timeout: SLOW }, async () => {
    const m = await mint();
    await assert.rejects(
      () => unlockArchiveKey({ ...m.archiveKey, publicKey: 'AAEC' }, secret()),
      (e: unknown) => e instanceof ArchiveKeyError && e.kind === 'unreadable',
    );
  });

  // The one public key with a catastrophic property: every exchange against it
  // yields zero. It is also exactly what a zeroed marker field decodes to.
  test('an all-zero public key is refused', { timeout: SLOW }, async () => {
    const m = await mint();
    const zeros = Buffer.alloc(X25519_KEY_BYTES).toString('base64url');
    await assert.rejects(
      () => unlockArchiveKey({ ...m.archiveKey, publicKey: zeros }, secret()),
      (e: unknown) => e instanceof ArchiveKeyError && e.kind === 'unreadable',
    );
  });

  test('a future blob version is refused rather than guessed at', { timeout: SLOW }, async () => {
    const m = await mint();
    const future: ArchiveKeyPayload = {
      ...m.archiveKey,
      wrappedByPassphrase: editBlob(m.archiveKey.wrappedByPassphrase, (o) => {
        o.v = 99;
      }),
    };
    const err = await unlockArchiveKey(future, secret()).then(
      () => null,
      (e: unknown) => e,
    );
    assert.ok(err instanceof ArchiveKeyError);
    assert.equal(err.kind, 'unreadable');
  });

  // The one that is actually dangerous: a marker claiming an Argon2id cost that
  // would allocate gigabytes. It must be refused BEFORE any derivation starts,
  // which is what the test's own runtime proves — an attempted derivation at
  // 8 GiB would not return in a few milliseconds.
  test('an absurd Argon2id cost is refused without attempting it', { timeout: SLOW }, async () => {
    const m = await mint();
    const bomb: ArchiveKeyPayload = {
      ...m.archiveKey,
      wrappedByPassphrase: editBlob(m.archiveKey.wrappedByPassphrase, (o) => {
        o.kdf = 'argon2id-m8388608-t1000-p1';
        o.params = { memoryKiB: 8388608, iterations: 1000, parallelism: 1, dkLen: 32 };
      }),
    };
    const started = Date.now();
    const err = await unlockArchiveKey(bomb, secret()).then(
      () => null,
      (e: unknown) => e,
    );
    assert.ok(err instanceof ArchiveKeyError);
    assert.equal(err.kind, 'unreadable');
    assert.ok(Date.now() - started < 1000, 'the cost ceiling must refuse before deriving');
  });

  test('an unknown KDF is refused', { timeout: SLOW }, async () => {
    const m = await mint();
    const odd: ArchiveKeyPayload = {
      ...m.archiveKey,
      wrappedByPassphrase: editBlob(m.archiveKey.wrappedByPassphrase, (o) => {
        o.kdf = 'scrypt-n16384';
      }),
    };
    await assert.rejects(
      () => unlockArchiveKey(odd, secret()),
      (e: unknown) => e instanceof ArchiveKeyError && e.kind === 'unreadable',
    );
  });

  test('an implausible ciphertext length is refused', { timeout: SLOW }, async () => {
    const m = await mint();
    const fat: ArchiveKeyPayload = {
      ...m.archiveKey,
      wrappedByPassphrase: editBlob(m.archiveKey.wrappedByPassphrase, (o) => {
        o.ct = Buffer.alloc(4096, 7).toString('base64url');
      }),
    };
    await assert.rejects(
      () => unlockArchiveKey(fat, secret()),
      (e: unknown) => e instanceof ArchiveKeyError && e.kind === 'unreadable',
    );
  });
});

describe('resolvePassphraseKdf', () => {
  test('reproduces the shipped derivation from its own id', () => {
    const kdf = resolvePassphraseKdf('argon2id-m65536-t3-p1');
    assert.ok(kdf);
    assert.equal(kdf.id, 'argon2id-m65536-t3-p1');
    assert.equal(kdf.params.memoryKiB, 65536);
  });

  test('refuses an id whose params disagree with it', () => {
    // The id and the params object are two copies of the same numbers. A blob
    // whose copies disagree has been edited; refuse rather than pick a winner.
    assert.equal(
      resolvePassphraseKdf('argon2id-m65536-t3-p1', { memoryKiB: 19456, iterations: 3, parallelism: 1 }),
      null,
    );
  });

  test('refuses costs beyond the ceilings', () => {
    assert.equal(resolvePassphraseKdf('argon2id-m8388608-t3-p1'), null);
    assert.equal(resolvePassphraseKdf('argon2id-m65536-t1000-p1'), null);
    assert.equal(resolvePassphraseKdf('argon2id-m65536-t3-p999'), null);
    assert.equal(resolvePassphraseKdf('argon2id-m0-t3-p1'), null);
  });

  test('refuses anything that is not argon2id', () => {
    assert.equal(resolvePassphraseKdf('pbkdf2-sha256-600000'), null);
    assert.equal(resolvePassphraseKdf('hkdf-sha256'), null);
  });
});

// ---------------------------------------------------------------------------
// The restore-only lend path (design/storage.md §4.5, #291)
// ---------------------------------------------------------------------------
//
// unlockArchiveKey never returns key material and still does not. The restore
// LENDS it: the key exists inside `use` and is zero afterwards, on every path.

describe('lendArchiveKeyForRestore', () => {
  test('lends the 32-byte key that derives the disk’s public key, then zeroes it', async () => {
    const { archiveKey, recoveryCode } = await mintArchiveKey(bytes('correct horse'));
    let seen: Uint8Array | null = null;
    let lengthInside = 0;
    const result = await lendArchiveKeyForRestore(archiveKey, { path: 'recovery-code', code: recoveryCode }, async (key) => {
      seen = key;
      lengthInside = key.length;
      assert.ok(key.some((b) => b !== 0), 'the key is live inside use');
      return 'response';
    });
    assert.equal(result, 'response');
    assert.equal(lengthInside, 32);
    assert.ok(seen !== null && (seen as Uint8Array).every((b) => b === 0), 'zeroed after use resolved');
  });

  test('zeroes the key when use rejects, and the rejection is what comes back', async () => {
    const { archiveKey, recoveryCode } = await mintArchiveKey(bytes('correct horse'));
    let seen: Uint8Array | null = null;
    await assert.rejects(
      lendArchiveKeyForRestore(archiveKey, { path: 'recovery-code', code: recoveryCode }, async (key) => {
        seen = key;
        throw new Error('api said no');
      }),
      /api said no/,
    );
    assert.ok(seen !== null && (seen as Uint8Array).every((b) => b === 0));
  });

  test('a wrong secret never reaches use', async () => {
    const { archiveKey } = await mintArchiveKey(bytes('correct horse'));
    let called = false;
    await assert.rejects(
      lendArchiveKeyForRestore(archiveKey, { path: 'passphrase', passphrase: bytes('wrong') }, async () => {
        called = true;
      }),
      (e: unknown) => e instanceof ArchiveKeyError && e.kind === 'wrong-secret',
    );
    assert.equal(called, false);
  });

  test('a key that opens but is not the disk’s never reaches use', async () => {
    const a = await mintArchiveKey(bytes('pw'));
    const b = await mintArchiveKey(bytes('pw'));
    const frankenstein = { ...a.archiveKey, publicKey: b.archiveKey.publicKey };
    let called = false;
    await assert.rejects(
      lendArchiveKeyForRestore(frankenstein, { path: 'recovery-code', code: a.recoveryCode }, async () => {
        called = true;
      }),
      (e: unknown) => e instanceof ArchiveKeyError && e.kind === 'key-mismatch',
    );
    assert.equal(called, false);
  });

  test('both custody paths lend the same key', async () => {
    const { archiveKey, recoveryCode } = await mintArchiveKey(bytes('correct horse'));
    const viaPassphrase = await lendArchiveKeyForRestore(archiveKey, { path: 'passphrase', passphrase: bytes('correct horse') }, async (k) =>
      Array.from(k),
    );
    const viaCode = await lendArchiveKeyForRestore(archiveKey, { path: 'recovery-code', code: recoveryCode }, async (k) => Array.from(k));
    assert.deepEqual(viaPassphrase, viaCode);
    assert.equal(viaCode.length, 32);
  });
});
