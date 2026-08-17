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
];

export default config;
