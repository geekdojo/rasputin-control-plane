// TC-988-05 (the matcher) and TC-988-07 (the console scan), over
// ui/forbidden-words.json (geekdojo/geekdojo-brain#988, ui.md §4.4).
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { findForbidden } from '../lib/forbidden-words';
import { scanSource } from './console-scan';
import { forbiddenList, UI_ROOT } from './forbidden-list';

// TC-988-05: case-insensitive from a word start, multi-word entries across a
// line break, exemptions only as their exact string in their named file.
test('TC-988-05: the matcher hits from a word start, across white space', () => {
  const words = (text: string, file?: string) => findForbidden(forbiddenList, text, file).map((h) => h.word);
  assert.deepEqual(words('Keycloak is down'), ['Keycloak']);
  assert.deepEqual(words('two REALMS'), ['realm']);
  assert.deepEqual(words('restart tailscaled'), ['Tailscale']);
  assert.deepEqual(words('use Google \n Authenticator'), ['Google Authenticator']);
  assert.deepEqual(words('set RASPUTIN_HEADSCALE_URL'), [], 'a word inside an identifier-like name is not at a word start');
  assert.deepEqual(words('myrealm'), [], 'not at a word start');
  const ex = forbiddenList.exemptions[0];
  assert.deepEqual(words(ex.text, ex.file), [], 'the exemption covers its exact string in its file');
  assert.deepEqual(words(ex.text, 'app/other.tsx'), ['Tailscale'], 'the exemption covers nothing in another file');
  assert.deepEqual(words('tailscale up', ex.file), ['Tailscale'], 'the exemption covers nothing but its exact string');
});

test('TC-988-05: an identifier and a code comment naming an engine are not read', () => {
  const src = `// Keycloak serves this\nconst keycloakClient = 1;\nexport const x = keycloakClient;\n`;
  assert.deepEqual(scanSource(forbiddenList, 'lib/fixture.ts', src), []);
});

// TC-988-07: JSX text and aria-label hit; a comment and an identifier don't.
test('TC-988-07: the console scan reads JSX text and the read attributes only', () => {
  const src = [
    "import { headscaleThing } from './headscale';",
    '// Headscale owns the devices',
    'export function P({ mode }: { mode: string }) {',
    "  if (mode === 'headscale') return null;",
    '  return (',
    '    <div className="headscale">',
    '      Headscale is down',
    '      <button aria-label="Restart Keycloak" data-x="keycloak" onClick={headscaleThing}>go</button>',
    '    </div>',
    '  );',
    '}',
  ].join('\n');
  const hits = scanSource(forbiddenList, 'components/Fixture.tsx', src);
  assert.deepEqual(
    hits.map((h) => `${h.line} ${h.where} ${h.word}`),
    ['7 text Headscale', '8 aria-label Keycloak'],
  );
});

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const ent of readdirSync(path.join(UI_ROOT, dir), { withFileTypes: true })) {
    const rel = path.join(dir, ent.name);
    if (ent.isDirectory()) out.push(...sources(rel));
    else if (/\.tsx?$/.test(ent.name) && !/\.test\.tsx?$/.test(ent.name)) out.push(rel);
  }
  return out;
}

// TC-988-07: the real app/, components/ and non-test lib/ name no engine.
test('TC-988-07: the console names no engine and no authenticator brand', () => {
  const files = [...sources('app'), ...sources('components'), ...sources('lib')];
  assert.ok(files.length > 50, `scanned ${files.length} files`);
  const hits = files.flatMap((f) => scanSource(forbiddenList, f.split(path.sep).join('/'), readFileSync(path.join(UI_ROOT, f), 'utf8')));
  assert.deepEqual(
    hits.map((h) => `${h.file}:${h.line} ${h.where} reads "${h.match}"`),
    [],
  );
});
