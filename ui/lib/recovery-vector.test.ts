// The cross-language custody fixture, pinned from the browser's side.
//
// api/internal/storage/testdata/recovery-code-vector.json was produced by
// THIS code (scripts/gen-recovery-code-vector.sh) and is opened in Go by the
// restore round-trip (api/internal/storage/restore_roundtrip_test.go). This
// test opens the same committed bytes here, so a change to the wrapping
// format on either side breaks one of the two suites rather than neither —
// design/storage.md §4.6's "known-vector fixture test, not an assumption".

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, test } from 'node:test';
import { lendArchiveKeyForRestore, unlockArchiveKey } from './archive-key';

interface Vector {
  keyId: string;
  alg: string;
  publicKey: string;
  wrappedByPassphrase: string;
  wrappedByRecoveryCode: string;
  recoveryCode: string;
  privateKey: string;
}

function loadVector(): Vector {
  // Compiled tests run from ui/.test-out/lib; the source tree is two levels
  // up from there and the fixture lives beside the Go test that shares it.
  const candidates = [
    join(__dirname, '..', '..', '..', 'api', 'internal', 'storage', 'testdata', 'recovery-code-vector.json'),
    join(process.cwd(), '..', 'api', 'internal', 'storage', 'testdata', 'recovery-code-vector.json'),
  ];
  for (const p of candidates) {
    try {
      return JSON.parse(readFileSync(p, 'utf8')) as Vector;
    } catch {
      // try the next
    }
  }
  throw new Error('recovery-code-vector.json not found; regenerate with scripts/gen-recovery-code-vector.sh');
}

describe('the committed recovery-code vector', () => {
  test('opens with the recovery code and derives its own public key', async () => {
    const v = loadVector();
    const proof = await unlockArchiveKey(v, { path: 'recovery-code', code: v.recoveryCode });
    assert.equal(proof.keyId, v.keyId);
    assert.equal(proof.publicKey, v.publicKey);
  });

  test('lends exactly the private key the fixture records', async () => {
    const v = loadVector();
    const lent = await lendArchiveKeyForRestore(v, { path: 'recovery-code', code: v.recoveryCode }, async (k) =>
      Buffer.from(k).toString('base64url'),
    );
    assert.equal(lent, v.privateKey);
  });

  test('the passphrase wrapping still opens with the fixture passphrase', async () => {
    const v = loadVector();
    const proof = await unlockArchiveKey(v, {
      path: 'passphrase',
      passphrase: new TextEncoder().encode('round-trip fixture passphrase'),
    });
    assert.equal(proof.publicKey, v.publicKey);
  });
});
