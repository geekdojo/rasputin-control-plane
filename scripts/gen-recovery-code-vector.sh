#!/usr/bin/env bash
# gen-recovery-code-vector.sh — regenerate the cross-language custody fixture
# api/internal/storage/testdata/recovery-code-vector.json from the REAL
# browser code (ui/lib/archive-key.ts, compiled by the ui test build).
#
# design/storage.md §4.6: "The cross-language ... interop between the browser
# and the restore path's Go implementation wants a known-vector fixture test,
# not an assumption." The restore round-trip (scripts/test-restore-roundtrip.sh)
# opens this fixture's recovery-code wrapping in Go and restores with the key
# inside it; ui/lib/recovery-vector.test.ts opens the same fixture with the
# browser code. One vector, both sides.
#
# The fixture carries a TEST keypair and its recovery code in clear — it is
# a test vector, not a secret. Regenerate only when the wrapping format
# changes; the committed one is what both suites pin.

set -euo pipefail
cd "$(dirname "$0")/../ui"

rm -rf .test-out
npx tsc -p tsconfig.test.json
node --input-type=module - <<'JS'
import { createRequire } from 'node:module';
import { writeFileSync } from 'node:fs';
const require = createRequire(import.meta.url);
const ak = require('./.test-out/lib/archive-key.js');
const passphrase = new TextEncoder().encode('round-trip fixture passphrase');
const { archiveKey, recoveryCode } = await ak.mintArchiveKey(passphrase);
// The private key, lent by the restore path, so Go can assert its unwrap
// recovers exactly these bytes.
const privateKey = await ak.lendArchiveKeyForRestore(
  archiveKey,
  { path: 'recovery-code', code: recoveryCode },
  async (k) => Buffer.from(k).toString('base64url'),
);
const out = {
  comment: 'TEST VECTOR — a throwaway keypair wrapped by ui/lib/archive-key.ts. Regenerate with scripts/gen-recovery-code-vector.sh.',
  ...archiveKey,
  recoveryCode,
  privateKey,
};
writeFileSync('../api/internal/storage/testdata/recovery-code-vector.json', JSON.stringify(out, null, 2) + '\n');
console.log('wrote api/internal/storage/testdata/recovery-code-vector.json (keyId ' + archiveKey.keyId + ')');
JS
