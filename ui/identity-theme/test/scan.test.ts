// TC-988-06: the theme scan over the effective merged message bundle (ours
// over base's) and our templates' literal text and read attributes
// (geekdojo/geekdojo-brain#988, ui.md §4.4).
import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { forbiddenList } from '../../test/forbidden-list';
import { themeScanProblems } from './checks';
import { FIXTURES, properties, read, SRC, templates, THEME } from './theme-files';

function merged(): Map<string, string> {
  const base = properties(read(path.join(THEME, 'upstream', '26.8.2', 'login', 'messages', 'messages_en.properties')));
  for (const [k, v] of properties(read(path.join(SRC, 'messages', 'messages_en.properties')))) base.set(k, v);
  return base;
}

test('TC-988-06: the real merged bundle and templates pass', () => {
  assert.deepEqual(themeScanProblems(forbiddenList, merged(), templates(SRC)), []);
});

test('TC-988-06: a base key naming the engine that we do not override fails, naming the key', () => {
  const m = merged();
  for (const [k, v] of properties(read(path.join(FIXTURES, 'scan', 'base-key-keycloak.properties')))) m.set(k, v);
  assert.deepEqual(themeScanProblems(forbiddenList, m, new Map()), [
    'the message key rasputinFixtureEngineKey reads "Keycloak" (forbidden: Keycloak)',
  ]);
});

for (const [f, where] of [
  ['realm-in-text.ftl', 'text'],
  ['realm-in-title.ftl', 'title'],
  ['realm-in-aria-label.ftl', 'aria-label'],
  ['realm-in-placeholder.ftl', 'placeholder'],
  ['realm-in-alt.ftl', 'alt'],
] as const) {
  test(`TC-988-06: "realm" in a template's ${where} fails, naming the template and attribute`, () => {
    const problems = themeScanProblems(forbiddenList, new Map(), new Map([[f, read(path.join(FIXTURES, 'scan', f))]]));
    assert.deepEqual(problems, [`${f}:1: the ${where} reads "realm" (forbidden: realm)`]);
  });
}

test('TC-988-06: the same word inside a FreeMarker comment, or as a variable, passes', () => {
  const f = 'realm-in-comment.ftl';
  assert.deepEqual(themeScanProblems(forbiddenList, new Map(), new Map([[f, read(path.join(FIXTURES, 'scan', f))]])), []);
});
