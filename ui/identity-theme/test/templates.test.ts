// TC-988-01: template safety (CVE-2026-107889), the template accessibility
// duties, and the template-variables list (geekdojo/geekdojo-brain#988).
import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { templateProblems, type TemplateVariables } from './checks';
import { FIXTURES, read, readJSON, SRC, templates, THEME } from './theme-files';

const vars = readJSON<TemplateVariables>(path.join(THEME, 'template-variables.json'));

test('TC-988-01: every template the theme ships passes', () => {
  const problems = [...templates(SRC)].flatMap(([name, src]) => templateProblems(name, src, vars));
  assert.deepEqual(problems, []);
});

test('TC-988-01: the frame announces its message block', () => {
  const frame = read(path.join(SRC, 'template.ftl'));
  assert.match(frame, /<div id="kc-feedback" role="alert"[^>]*>/);
  assert.match(frame, /kc-feedback-text/);
});

for (const [fixture, rule] of [
  ['no-esc.ftl', /no-esc\.ftl:1: \?no_esc/],
  ['display-name-html.ftl', /display-name-html\.ftl:1: displayNameHtml/],
  ['unlisted-root.ftl', /unlisted-root\.ftl: reads the root somethingNobodyListed/],
  ['positive-tabindex.ftl', /positive-tabindex\.ftl:1: a positive tabindex/],
  ['inline-script.ftl', /inline-script\.ftl:1: an inline <script>/],
  ['inline-handler.ftl', /inline-handler\.ftl:1: an on\* handler/],
  ['javascript-url.ftl', /javascript-url\.ftl:1: a javascript: URL/],
  ['no-alert-role.ftl', /no-alert-role\.ftl: the frame's message block must carry role="alert"/],
] as const) {
  test(`TC-988-01: the fixture ${fixture} fails, naming the file, rule and line`, () => {
    const problems = templateProblems(fixture, read(path.join(FIXTURES, 'templates', fixture)), vars);
    assert.ok(problems.some((p) => rule.test(p)), `problems: ${JSON.stringify(problems)}`);
  });
}

// Keycloak injects an inline history script in front of the head end tag of a
// page it answers a POST with (BrowserHistoryHelper); the frame writes none,
// so it injects nothing (found by the CI walk, TC-988-18).
test('TC-988-01: the frame writes no head end tag, so Keycloak injects no inline script', () => {
  const frame = read(path.join(SRC, 'template.ftl')).replace(/<#--[\s\S]*?-->/g, '');
  assert.doesNotMatch(frame, /<\/head\s*>/i);
  assert.match(frame, /<body /);
});
