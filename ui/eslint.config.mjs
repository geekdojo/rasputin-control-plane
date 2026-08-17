import { dirname } from 'path';
import { fileURLToPath } from 'url';
import { FlatCompat } from '@eslint/eslintrc';

// eslint flat config (eslint 9). Kept minimal on purpose: this repo had NINE
// eslint-disable comments and no eslint, so the first job of this config is to
// find out what the codebase actually looks like to a linter — not to encode
// opinions before anyone has seen the answer.
//
// `next/core-web-vitals` is Next's own recommended set plus the Core Web Vitals
// rules; `next/typescript` layers the TypeScript rules on top. Both come from
// eslint-config-next, pinned to the exact Next minor in package.json so the
// linter and the framework cannot drift.

const compat = new FlatCompat({
  baseDirectory: dirname(fileURLToPath(import.meta.url)),
});

// Named rather than exported anonymously — eslint's own
// import/no-anonymous-default-export fires on the array form, and a config that
// cannot lint itself cleanly is a poor advertisement for the gate it defines.
const config = [
  {
    // Build output and dependencies. `out/` is the static export the release
    // tarballs ship, and `.next/` is the build cache — both are generated, and
    // linting generated code reports on decisions nobody made.
    ignores: ['.next/**', 'out/**', 'node_modules/**', 'next-env.d.ts'],
  },
  ...compat.extends('next/core-web-vitals', 'next/typescript'),
  {
    // lib/qrcodegen.ts is Project Nayuki's QR encoder (MIT), vendored verbatim.
    //
    // STYLE rules only are switched off here, and the reason is the reason the
    // file is vendored at all: it is upstream-identical apart from one
    // module-export line, so it can be re-verified by diffing against Nayuki.
    // `prefer-const` and `no-namespace` would rewrite 19 lines of it and
    // destroy that property permanently, in exchange for nothing — every one of
    // those findings is stylistic, none is correctness or security.
    //
    // This is NOT a "vendor code is exempt" carve-out. Copied code is our code
    // (2026-08-16): qrcodegen.ts is analysed by CodeQL with no exclusion at all
    // — it was scanned on the run that landed the CodeQL gate and produced no
    // findings — and it is covered by every security gate the rest of the tree
    // is. What is suppressed is house style on a file whose value is being
    // byte-identical to a reviewed upstream.
    //
    // It was vendored rather than installed because Nayuki publishes no npm
    // package (@nayuki/qr-code-generator is a 404, and the `qrcodegen` name on
    // npm is an unrelated 0.0.1 placeholder). Checked 2026-08-16.
    //
    // If this file is ever EDITED beyond the export line, this block should go:
    // once it is a fork, "identical to upstream" has already been spent.
    files: ['lib/qrcodegen.ts'],
    rules: {
      'prefer-const': 'off',
      '@typescript-eslint/no-namespace': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
    },
  },
];

export default config;
