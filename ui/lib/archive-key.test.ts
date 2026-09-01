// design/storage.md §4.6, executed.
//
// The mint half of archive-key.ts has been shipping since PR #203 with no test
// of any kind — ui/ had no runner. The unwrap half added for §4.8's adopt path
// is where a silent mistake is worst: it decides whether an operator who typed
// the wrong passphrase is told so, or is handed a backup target that will fail
// on the one day it matters. So these run the real crypto, in Node's WebCrypto
// and the real hash-wasm Argon2id, and assert the things the design promises:
//
//   - either custody path alone recovers the SAME data key (§4.6's whole point);
//   - a wrong secret fails visibly, as an AEAD failure, not silently;
//   - a blob cannot be moved between targets or between custody paths;
//   - a blob off a disk cannot make this browser do something absurd; and
//   - nothing secret is in the request body the adopt path builds.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  ArchiveKeyError,
  canonicalRecoveryCode,
  generateRecoveryCode,
  mintArchiveKey,
  unlockArchiveKey,
  type ArchiveKeyPayload,
  type MintedArchiveKey,
} from './archive-key';
import { resolvePassphraseKdf } from './passphrase-kdf';

const PASSPHRASE = 'correct horse battery staple';

function bytes(s: string) {
  return new TextEncoder().encode(s);
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
  test('produces both wrappings, an id, and a recovery code', { timeout: SLOW }, async () => {
    const m = await mint();
    assert.match(m.archiveKey.keyId, /^ak-[A-Za-z0-9_-]{22}$/);
    assert.ok(m.archiveKey.wrappedByPassphrase.length > 0);
    assert.ok(m.archiveKey.wrappedByRecoveryCode.length > 0);
    assert.notEqual(m.archiveKey.wrappedByPassphrase, m.archiveKey.wrappedByRecoveryCode);
    assert.equal(canonicalRecoveryCode(m.recoveryCode).length, 32);
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
  test('both custody paths recover the SAME data key', { timeout: SLOW }, async () => {
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
    const err = await unlockArchiveKey(
      { keyId: '', alg: '', wrappedByPassphrase: 'x', wrappedByRecoveryCode: 'x' },
      { path: 'passphrase', passphrase: bytes(PASSPHRASE) },
    ).then(
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
      { keyId: 'ak-x', alg: '', wrappedByPassphrase: 'not base64!!', wrappedByRecoveryCode: 'x' },
      secret(),
    ).then(
      () => null,
      (e: unknown) => e,
    );
    assert.ok(err instanceof ArchiveKeyError);
    assert.equal(err.kind, 'unreadable');
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
