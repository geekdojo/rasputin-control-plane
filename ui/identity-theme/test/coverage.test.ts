// TC-988-02 and TC-988-03: coverage, not samples, held against the pinned
// base theme's snapshot; F-988-05: each override and fork is tied to the
// upstream file it was copied from (geekdojo/geekdojo-brain#988).
import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { coverageProblems, sha256, type CoverageInput } from './checks';
import { FIXTURES, loadBaseSums, loadCoverage, pinnedKeycloak, properties, read, SRC, templates, THEME } from './theme-files';

function input(): CoverageInput {
  const coverage = loadCoverage(path.join(THEME, 'coverage.json'));
  const upstream = path.join(THEME, 'upstream', coverage.keycloak);
  return {
    pinVersion: pinnedKeycloak(),
    snapshotVersion: coverage.keycloak,
    coverage,
    baseKeys: new Set(properties(read(path.join(upstream, 'login', 'messages', 'messages_en.properties'))).keys()),
    baseTemplates: templates(path.join(upstream, 'login')),
    baseScripts: loadBaseSums(path.join(upstream, 'resources-sha256.json')),
    ourKeys: new Set(properties(read(path.join(SRC, 'messages', 'messages_en.properties'))).keys()),
    ourTemplates: templates(SRC),
    themeProperties: new Set(properties(read(path.join(SRC, 'theme.properties'))).keys()),
  };
}

const fixture = (f: string) => read(path.join(FIXTURES, 'snapshot', f));

test('TC-988-02: the real tree is covered at the pin', () => {
  assert.deepEqual(coverageProblems(input()), []);
});

test('TC-988-02: the snapshot plus one unreviewed key fails, naming the key', () => {
  const c = input();
  for (const k of properties(fixture('unreviewed-key.properties')).keys()) c.baseKeys.add(k);
  assert.deepEqual(coverageProblems(c), [
    'the base key rasputinFixtureUnreviewedKey is neither in our bundle nor listed as never rendered',
  ]);
});

test('TC-988-02: the snapshot plus one unreviewed template fails, naming it', () => {
  const c = input();
  c.baseTemplates.set('unreviewed-template.ftl', fixture('unreviewed-template.ftl'));
  assert.deepEqual(coverageProblems(c), ['the base template unreviewed-template.ftl is neither overridden nor reviewed']);
});

test('TC-988-02: the snapshot plus one unmapped hook fails, naming it', () => {
  const c = input();
  c.baseTemplates.set('footer.ftl', fixture('unmapped-hook.ftl'));
  assert.deepEqual(coverageProblems(c), [
    'the style hook kcFixtureUnmappedClass is read by a template but theme.properties does not map it',
  ]);
});

test('TC-988-02: a listed entry no longer in base fails, naming it', () => {
  const c = input();
  c.baseKeys.delete('doImpersonate');
  c.baseTemplates.delete('terms.ftl');
  assert.deepEqual(coverageProblems(c), [
    'coverage.json lists the key doImpersonate, which base no longer has',
    'coverage.json names the template terms.ftl, which base no longer has',
  ]);
});

test('TC-988-02: a snapshot version other than pin.go fails', () => {
  const c = input();
  c.pinVersion = '26.9.0';
  assert.deepEqual(coverageProblems(c), ['the snapshot is 26.8.2 and coverage.json reviews 26.8.2, but pin.go pins 26.9.0']);
});

// F-988-05: a bump whose upstream changed a file we override or fork fails
// until the copy is re-reviewed.
test('TC-988-02 (F-988-05): an override whose upstream source changed fails, naming it', () => {
  const c = input();
  const changed = c.baseTemplates.get('login.ftl') + '\n<#-- changed upstream -->\n';
  c.baseTemplates.set('login.ftl', changed);
  assert.deepEqual(coverageProblems(c), [
    `the base template login.ftl changed upstream since our override was copied (sha256 ${sha256(changed)}, coverage.json records ${c.coverage.overriddenTemplates['login.ftl']}); re-review the override`,
  ]);
});

test('TC-988-02 (F-988-05): a fork whose upstream script changed fails, naming it', () => {
  const c = input();
  c.baseScripts['login/resources/js/webauthnRegister.js'] = '0'.repeat(64);
  assert.deepEqual(coverageProblems(c), [
    `the base script webauthnRegister.js changed upstream since our fork was copied (sha256 ${'0'.repeat(64)}, coverage.json records ${c.coverage.forkedScripts['webauthnRegister.js']}); re-review the fork`,
  ]);
});

test('TC-988-03: a reviewed base template with an inline script fails, naming it', () => {
  const c = input();
  c.baseTemplates.set('terms.ftl', fixture('reviewed-inline-script.ftl'));
  assert.deepEqual(coverageProblems(c), [
    'the reviewed base template terms.ftl carries an inline script or handler; override it and move that code to a file',
  ]);
});
