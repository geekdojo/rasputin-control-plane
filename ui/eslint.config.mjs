import coreWebVitals from 'eslint-config-next/core-web-vitals';
import typescript from 'eslint-config-next/typescript';

// eslint flat config (eslint 9).
//
// eslint-config-next 16 exports native flat-config arrays, so these are spread
// directly. The 15.x version did not, and needed FlatCompat from
// @eslint/eslintrc to translate its eslintrc-style config — that shim and its
// dependency are gone with the Next 16 upgrade.
//
// Kept deliberately minimal: this repo had NINE eslint-disable comments and no
// eslint installed at all until 2026-08-16, so the job of this config is to
// show what the codebase actually looks like to a linter, not to encode house
// opinions before anyone has seen the answer.
//
// Errors fail CI; warnings print and do not. That split is deliberate — the
// react-hooks/exhaustive-deps warnings are kept visible as pointers to
// investigate if the UI misbehaves, and making them blockers is how they would
// end up suppressed again, which is the state this replaced.

const config = [
  {
    // Build output and dependencies. `out/` is the static export the release
    // tarballs ship and `.next/` is the build cache — both generated, and
    // linting generated code reports on decisions nobody made.
    ignores: ['.next/**', 'out/**', 'node_modules/**', 'next-env.d.ts'],
  },
  ...coreWebVitals,
  ...typescript,
  {
    // React Compiler rules, new in eslint-config-next 16 — downgraded from
    // error to WARNING on arrival, deliberately and temporarily.
    //
    // The Next 15 -> 16 upgrade was taken to clear four HIGH npm advisories
    // (2026-08-16), and it did: audit goes to zero. But 16's config also turns
    // on the React Compiler rule set, which reports 27 findings across 20
    // files — 23 of them set-state-in-effect, i.e. the fetch-then-setState
    // idiom this entire UI is built on.
    //
    // Fixing those is a data-fetching refactor of every page, not a lint
    // cleanup. Folding it into a security upgrade would produce an unreviewable
    // diff and risk a regression on every screen, so it is tracked separately.
    //
    // This is NOT the baseline pattern this repo has twice rejected. These
    // print on every CI run rather than being recorded and forgotten, they are
    // React correctness and style rather than security findings, and it is the
    // same treatment react-hooks/exhaustive-deps already has here. The rules
    // return to error as the refactor lands.
    //
    // set-state-in-effect can indicate a real render loop, so treat a NEW one
    // as worth reading rather than noise.
    rules: {
      'react-hooks/set-state-in-effect': 'warn',
      'react-hooks/immutability': 'warn',
      'react-hooks/purity': 'warn',
    },
  },
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
    // and produced no findings, and it is covered by every security gate the
    // rest of the tree is. What is suppressed is house style on a file whose
    // value is being byte-identical to a reviewed upstream.
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
