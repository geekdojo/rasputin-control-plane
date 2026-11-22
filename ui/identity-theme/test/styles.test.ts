// TC-988-04: component styles generated from the kit, and sign-in sizing;
// F-988-12: no hard-coded colour in the theme's CSS
// (geekdojo/geekdojo-brain#988, ui.md §4.2).
import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { BTN_COLORS } from '../../components/kit';
import { COMPONENTS_CSS, generate } from '../styles';
import { hardCodedColours } from './colours';
import { read, SRC, templates, UI } from './theme-files';

const committed = () => read(path.join(UI, COMPONENTS_CSS));

test('TC-988-04: components.css is what the kit generates', () => {
  assert.equal(generate(), committed(), 'components.css is stale: run npm run identity-theme:styles');
});

test("TC-988-04: :hover rules carry the kit's BTN_COLORS hover values", () => {
  const css = committed();
  for (const v of ['primary', 'danger', 'ghost'] as const) {
    assert.ok(css.includes(`.rasp-btn-${v}:hover:not(:disabled) {\n  background: ${BTN_COLORS[v].hover};`), v);
  }
});

test('TC-988-04: changing one kit constant fails until the file is regenerated', () => {
  const was = BTN_COLORS.primary.hover;
  BTN_COLORS.primary.hover = 'rgba(var(--rasp-accent-rgb), 0.5)';
  try {
    const now = generate().split('\n');
    const old = committed().split('\n');
    const changed = now.filter((l, i) => l !== old[i]);
    assert.deepEqual(changed, ['  background: rgba(var(--rasp-accent-rgb), 0.5);']);
  } finally {
    BTN_COLORS.primary.hover = was;
  }
});

test('TC-988-04: signin.css sets inputs and buttons to at least 16 px', () => {
  const css = read(path.join(SRC, 'resources', 'css', 'signin.css')).replace(/\/\*[\s\S]*?\*\//g, '');
  const m = /([^{}]+)\{\s*font-size:\s*(\d+)px;\s*\}/g;
  const rules = [...css.matchAll(m)].map((r) => ({ selectors: r[1].split(',').map((s) => s.trim()), px: Number(r[2]) }));
  const sizing = rules.find((r) => r.selectors.includes('.rasp-signin input') && r.selectors.includes('.rasp-signin button'));
  assert.ok(sizing, 'no rule sizes .rasp-signin input and button');
  assert.ok(sizing.px >= 16, `inputs and buttons are ${sizing.px} px`);
  for (const s of ['.rasp-field', '.rasp-btn', '.rasp-signin select', '.rasp-signin textarea']) assert.ok(sizing.selectors.includes(s), s);
});

// F-988-12.
test('F-988-12: signin.css and components.css hold no hard-coded colour', () => {
  const problems = [
    ...hardCodedColours('signin.css', read(path.join(SRC, 'resources', 'css', 'signin.css'))),
    ...hardCodedColours('components.css', committed()),
  ];
  assert.deepEqual(problems, []);
});

test('F-988-12: the colour check catches a hex, a literal rgba and a named colour', () => {
  const css = '.a {\n  color: #fa3c04;\n}\n.b {\n  background: rgba(250, 60, 4, 0.1);\n}\n.c {\n  border: 1px solid white;\n}\n.d {\n  color: var(--rasp-fg);\n  background: rgba(var(--rasp-fg-rgb), 0.1);\n}\n';
  assert.deepEqual(hardCodedColours('fixture.css', css), [
    'fixture.css:2: the hex colour #fa3c04',
    'fixture.css:5: rgba() with a literal channel (250)',
    'fixture.css:8: the named colour white in border',
  ]);
});

test("F-988-12: no template or script sets or reads data-theme or the console's theme key", () => {
  const theme = read(path.join(UI, 'lib', 'theme.tsx'));
  const storageKey = /export const STORAGE_KEY = '([^']+)'/.exec(theme)?.[1];
  assert.ok(storageKey, 'lib/theme.tsx names no STORAGE_KEY');
  const files = [...templates(SRC).entries()];
  for (const f of ['rasputin-page.js', 'rasputin-passkeys.js', 'rasputin-webauthn.js', 'rasputin-webauthn-authenticate.js',
    'rasputin-recovery-codes.js', 'rasputin-frontchannel-logout.js', 'rasputin-autosubmit.js', 'webauthnRegister.js', 'webauthnAuthenticate.js']) {
    files.push([f, read(path.join(SRC, 'resources', 'js', f))]);
  }
  for (const [name, src] of files) {
    assert.doesNotMatch(src, /data-theme|dataset\.theme/, `${name} touches data-theme`);
    assert.ok(!src.includes(storageKey), `${name} names the console's theme key ${storageKey}`);
    assert.doesNotMatch(src, /localStorage/, `${name} reads browser storage`);
  }
});
