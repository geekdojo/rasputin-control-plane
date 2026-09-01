import coreWebVitals from 'eslint-config-next/core-web-vitals';
import typescript from 'eslint-config-next/typescript';
import jsxA11y from 'eslint-plugin-jsx-a11y';

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

// eslint-plugin-jsx-a11y ships with eslint-config-next, but core-web-vitals
// turns on only six of its ~35 rules (alt-text, the aria-* pair, and the role
// checks). The rest were dark until the 2026-08 18-app bench run, where the
// browser agents driving the UI hit the same wall over and over: a click by
// accessibility-tree reference did nothing and they fell back to pixel
// coordinates. The full recommended set catches a real slice of that — the
// undismissable modal scrims in particular — so it runs here at error, and
// control-has-associated-label on top of it for the icon-only buttons.
//
// Severity is bumped, not the rules' own options, which are preserved. Fix the
// findings; a rule shipped as an error stays an error, and a false positive
// gets a narrow inline disable that says why.
const a11yRules = Object.fromEntries(
  Object.entries(jsxA11y.flatConfigs.recommended.rules).map(([name, level]) => [
    name,
    Array.isArray(level) ? ['error', ...level.slice(1)] : 'error',
  ]),
);

const config = [
  {
    // Build output and dependencies. `out/` is the static export the release
    // tarballs ship, `.next/` is the build cache, and `.test-out/` is the
    // CommonJS `npm test` compiles for node --test — all generated, and linting
    // generated code reports on decisions nobody made. (`.test-out/` in
    // particular is CJS by design, so every file in it trips
    // no-require-imports; the rule is right and the target is not source.)
    ignores: ['.next/**', 'out/**', '.test-out/**', 'node_modules/**', 'next-env.d.ts'],
  },
  ...coreWebVitals,
  ...typescript,
  {
    // Rules only — core-web-vitals already registers the plugin itself, and
    // spreading flatConfigs.recommended wholesale re-declares it ("Cannot
    // redefine plugin jsx-a11y").
    rules: {
      ...a11yRules,
      // depth 3, not the default 2: an actions cell wraps its buttons in a
      // flex <div>, which puts the button text one level past the default and
      // reports the <td> itself as an unlabelled control.
      'jsx-a11y/control-has-associated-label': ['error', { depth: 3 }],
      // Both of these stay errors. What changes is what they know about this
      // codebase: fields are wrapped (kit.tsx Input/Select/Textarea), so
      // without controlComponents the rule sees a <label> containing no
      // control and reports every correctly-nested field in settings/updates.
      'jsx-a11y/label-has-associated-control': [
        'error',
        { controlComponents: ['Input', 'Select', 'Textarea'] },
      ],
      // label-has-for is the deprecated predecessor of the rule above and has
      // no controlComponents escape hatch, so it can never see a control it
      // reaches through one of ours. `some` leaves it checking the half it CAN
      // see — the htmlFor/id pairing, which every label here now carries on
      // top of nesting. Nothing is waved through; the nesting half is checked
      // by label-has-associated-control, also an error.
      'jsx-a11y/label-has-for': ['error', { required: { some: ['nesting', 'id'] } }],
    },
  },
];

export default config;
