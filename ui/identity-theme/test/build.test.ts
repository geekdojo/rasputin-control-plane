// TC-988-09: build.mjs and the resource allowlist the door proxy reads
// (Identity 4.3, geekdojo/geekdojo-brain#985), including the bare-specifier
// refusal (F-988-02) (geekdojo/geekdojo-brain#988).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { readJSON, THEME, UI } from './theme-files';

const scratch: string[] = [];
after(() => scratch.forEach((d) => rmSync(d, { recursive: true, force: true })));

function tmp(): string {
  const d = mkdtempSync(path.join(tmpdir(), 'identity-theme-'));
  scratch.push(d);
  return d;
}

/** A copy of ui/identity-theme and ui/styles in a fresh tree, to break. */
function copyTree(): string {
  const root = tmp();
  cpSync(THEME, path.join(root, 'ui', 'identity-theme'), { recursive: true, filter: (s) => !s.includes(`${path.sep}test`) });
  cpSync(path.join(UI, 'styles'), path.join(root, 'ui', 'styles'), { recursive: true });
  return path.join(root, 'ui');
}

function run(ui: string, ...args: string[]) {
  const r = spawnSync(process.execPath, [path.join(ui, 'identity-theme', 'build.mjs'), ...args], { encoding: 'utf8' });
  return { status: r.status, stderr: r.stderr.trim() };
}

test('TC-988-09: the build writes the tree, the tokens, the fonts and the allowlist', () => {
  const out = path.join(tmp(), 'theme');
  const r = run(UI, out);
  assert.equal(r.status, 0, r.stderr);
  for (const f of ['login/theme.properties', 'login/template.ftl', 'login/messages/messages_en.properties',
    'login/resources/css/tokens.css', 'login/resources/css/signin.css', 'login/resources/css/components.css',
    'login/resources/css/fonts/JetBrainsMono-Regular.woff2', 'login/resources/css/fonts/OFL.txt']) {
    assert.ok(existsSync(path.join(out, f)), f);
  }
  // tokens.css names its fonts by ./fonts/, which is where they are.
  const tokens = readFileSync(path.join(out, 'login/resources/css/tokens.css'), 'utf8');
  for (const m of tokens.matchAll(/url\('\.\/fonts\/([^']+)'\)/g)) {
    assert.ok(existsSync(path.join(out, 'login/resources/css/fonts', m[1])), m[1]);
  }
  const allow = readJSON<{ keycloak: string; login: string[]; common: string[] }>(path.join(out, 'resource-allowlist.json'));
  assert.equal(allow.keycloak, '26.8.2');
  assert.deepEqual(allow.common, ['vendor/rfc4648/rfc4648.js']);
  for (const f of ['css/signin.css', 'css/tokens.css', 'js/rasputin-page.js', 'js/webauthnRegister.js', 'img/key.svg',
    // parent-base resources a template or module references
    'js/passwordVisibility.js', 'js/menu-button-links.js', 'js/passkeysConditionalAuth.js']) {
    assert.ok(allow.login.includes(f), f);
  }
  assert.ok(!allow.login.includes('js/authChecker.js'), 'a base module nothing references is not allowed');
});

test('TC-988-09: a wrong argument count exits 2 with a usage sentence', () => {
  for (const args of [[], ['a', 'b']]) {
    const r = run(UI, ...args);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /^Usage: node build\.mjs <OUT>/);
  }
});

const refusals: [string, (ui: string) => void, RegExp][] = [
  ['a missing source', (ui) => unlinkSync(path.join(ui, 'identity-theme/src/login/theme.properties')), /theme source .*theme\.properties is missing/],
  ['a missing token file', (ui) => unlinkSync(path.join(ui, 'styles/tokens.css')), /token file .*tokens\.css is missing/],
  ['a missing font', (ui) => unlinkSync(path.join(ui, 'styles/fonts/JetBrainsMono-Medium.woff2')), /font .*JetBrainsMono-Medium\.woff2 that tokens\.css names is missing/],
  ['a dangling template reference', (ui) => {
    const f = path.join(ui, 'identity-theme/src/login/error.ftl');
    writeFileSync(f, readFileSync(f, 'utf8') + '<script type="module" src="${url.resourcesPath}/js/nowhere.js"></script>\n');
  }, /The template error\.ftl references js\/nowhere\.js, which is neither a theme file nor a base file/],
  ['a bare import in our module', (ui) => {
    const f = path.join(ui, 'identity-theme/src/login/resources/js/rasputin-page.js');
    writeFileSync(f, 'import { base64url } from "rfc4648";\n' + readFileSync(f, 'utf8'));
  }, /The module js\/rasputin-page\.js imports the bare specifier "rfc4648"/],
  ['a referenced base module with a bare import', (ui) => {
    // Load base's own webauthnRegister.js instead of our fork.
    unlinkSync(path.join(ui, 'identity-theme/src/login/resources/js/webauthnRegister.js'));
  }, /The base module js\/webauthnRegister\.js, which the theme loads, imports the bare specifier "rfc4648"/],
];

for (const [what, breakIt, want] of refusals) {
  test(`TC-988-09: ${what} exits 1 with one sentence naming the file`, () => {
    const ui = copyTree();
    breakIt(ui);
    const r = run(ui, path.join(tmp(), 'theme'));
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stderr, want);
    assert.equal(r.stderr.split('\n').length, 1, r.stderr);
  });
}
