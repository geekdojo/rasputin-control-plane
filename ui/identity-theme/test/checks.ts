// The theme's checks, as functions that return the problems they find, so a
// test runs each over the real tree (no problem) and over a must-fail
// fixture (the problem named) (geekdojo/geekdojo-brain#988).
import { createHash } from 'node:crypto';
import { findForbidden, type ForbiddenList } from '../../lib/forbidden-words';
import { literalText, reads, scan, stripComments } from './ftl';
import type { Coverage } from './theme-files';

export interface TemplateVariables {
  roots: Record<string, string[]>;
}

/**
 * TC-988-01: a template we ship escapes everything (CVE-2026-107889), carries
 * no inline script, handler, javascript: URL or positive tabindex, reads only
 * listed roots and fields, and the frame announces its message block.
 */
export function templateProblems(name: string, src: string, vars: TemplateVariables): string[] {
  const out: string[] = [];
  const s = stripComments(src);
  const lines = s.split('\n');
  const each = (re: RegExp, rule: string) =>
    lines.forEach((l, i) => {
      if (re.test(l)) out.push(`${name}:${i + 1}: ${rule}`);
    });
  each(/\?no_esc\b/, '?no_esc turns off escaping (CVE-2026-107889)');
  each(/displayNameHtml/, 'displayNameHtml is HTML an administrator wrote (CVE-2026-107889); use the install name as text');
  each(/tabindex\s*=\s*"\s*[1-9]/, 'a positive tabindex reorders the keyboard path');
  each(/<script\b(?![^>]*\bsrc=)[^>]*>/i, 'an inline <script>, which the doors\' script policy refuses');
  each(/\son[a-z]+\s*=/i, 'an on* handler attribute, which the doors\' script policy refuses');
  each(/javascript:/i, 'a javascript: URL');
  if (/<#macro\s+registrationLayout\b/.test(s)) {
    if (!/role="alert"/.test(s) || !/kc-feedback-text/.test(s)) {
      out.push(`${name}: the frame's message block must carry role="alert" and kc-feedback-text`);
    }
  }
  for (const [root, fields] of reads(src)) {
    const listed = vars.roots[root];
    if (!listed) {
      out.push(`${name}: reads the root ${root}, which template-variables.json does not list`);
      continue;
    }
    if (listed.includes('*')) continue;
    for (const f of fields) {
      if (!listed.includes(f)) out.push(`${name}: reads ${root}.${f}, which template-variables.json does not list`);
    }
  }
  return out;
}

/** Whether a template carries an inline script or an on* handler. */
export function hasInlineCode(src: string): boolean {
  const s = stripComments(src);
  return /<script\b(?![^>]*\bsrc=)[^>]*>/i.test(s) || /\son[a-z]+\s*=/i.test(s);
}

/** Every properties.kc* hook a template reads, literally. */
export function hooks(src: string): Set<string> {
  const out = new Set<string>();
  const { interpolations, tags } = scan(src);
  for (const t of [...interpolations.map((e) => e.text), ...tags.map((t) => t.body)]) {
    for (const m of t.matchAll(/properties\.(kc\w+)/g)) out.add(m[1]);
  }
  return out;
}

export function sha256(text: string | Buffer): string {
  return createHash('sha256').update(text).digest('hex');
}

export interface CoverageInput {
  /** The Keycloak release pin.go pins. */
  pinVersion: string;
  /** The snapshot's version directory name. */
  snapshotVersion: string;
  coverage: Coverage;
  /** Base's English bundle keys, from the snapshot. */
  baseKeys: Set<string>;
  /** Base's templates, from the snapshot, by name. */
  baseTemplates: Map<string, string>;
  /** Base's module sha256s, by login/resources/js/<name>. */
  baseScripts: Record<string, string>;
  ourKeys: Set<string>;
  ourTemplates: Map<string, string>;
  /** theme.properties' keys. */
  themeProperties: Set<string>;
}

/** TC-988-02, TC-988-03 and F-988-05: coverage, not samples. */
export function coverageProblems(c: CoverageInput): string[] {
  const out: string[] = [];
  if (c.snapshotVersion !== c.pinVersion || c.coverage.keycloak !== c.pinVersion) {
    out.push(`the snapshot is ${c.snapshotVersion} and coverage.json reviews ${c.coverage.keycloak}, but pin.go pins ${c.pinVersion}`);
  }
  // Keys.
  const listed = new Set(c.coverage.neverRenderedKeys.flatMap((g) => g.keys));
  for (const k of c.baseKeys) {
    if (!c.ourKeys.has(k) && !listed.has(k)) out.push(`the base key ${k} is neither in our bundle nor listed as never rendered`);
  }
  for (const k of listed) {
    if (!c.baseKeys.has(k)) out.push(`coverage.json lists the key ${k}, which base no longer has`);
    if (c.ourKeys.has(k)) out.push(`coverage.json lists the key ${k} as never rendered, but our bundle overrides it`);
  }
  for (const g of c.coverage.neverRenderedKeys) {
    if (!g.reason.trim()) out.push(`coverage.json lists keys ${g.keys.join(', ')} with no reason`);
  }
  // Templates.
  const overridden = c.coverage.overriddenTemplates;
  const reviewed = c.coverage.reviewedTemplates;
  for (const [t, src] of c.baseTemplates) {
    if (t in overridden) {
      if (!c.ourTemplates.has(t)) out.push(`coverage.json says the template ${t} is overridden, but the theme has no ${t}`);
      if (sha256(src) !== overridden[t]) {
        out.push(`the base template ${t} changed upstream since our override was copied (sha256 ${sha256(src)}, coverage.json records ${overridden[t]}); re-review the override`);
      }
    } else if (t in reviewed) {
      if (!reviewed[t].trim()) out.push(`coverage.json reviews the template ${t} with no reason`);
      if (hasInlineCode(src)) out.push(`the reviewed base template ${t} carries an inline script or handler; override it and move that code to a file`);
    } else {
      out.push(`the base template ${t} is neither overridden nor reviewed`);
    }
  }
  for (const t of [...Object.keys(overridden), ...Object.keys(reviewed)]) {
    if (!c.baseTemplates.has(t)) out.push(`coverage.json names the template ${t}, which base no longer has`);
  }
  for (const t of c.ourTemplates.keys()) {
    if (!(t in overridden)) out.push(`the theme's template ${t} is not recorded in coverage.json's overriddenTemplates`);
  }
  // Forked scripts.
  for (const [f, sum] of Object.entries(c.coverage.forkedScripts)) {
    const now = c.baseScripts[`login/resources/js/${f}`];
    if (!now) out.push(`coverage.json records the fork ${f}, which base no longer has`);
    else if (now !== sum) out.push(`the base script ${f} changed upstream since our fork was copied (sha256 ${now}, coverage.json records ${sum}); re-review the fork`);
  }
  // Hooks: every one base's templates or ours read is mapped.
  const used = new Set<string>();
  for (const src of [...c.baseTemplates.values(), ...c.ourTemplates.values()]) hooks(src).forEach((h) => used.add(h));
  for (const h of [...used].sort()) {
    if (!c.themeProperties.has(h)) out.push(`the style hook ${h} is read by a template but theme.properties does not map it`);
  }
  return out;
}

/**
 * TC-988-06: the effective merged bundle (ours over base's) and our
 * templates' literal text and read attributes name no forbidden word.
 */
export function themeScanProblems(list: ForbiddenList, merged: Map<string, string>, templates: Map<string, string>): string[] {
  const out: string[] = [];
  for (const [k, v] of merged) {
    for (const h of findForbidden(list, v)) out.push(`the message key ${k} reads "${h.match}" (forbidden: ${h.word})`);
  }
  for (const [name, src] of templates) {
    for (const t of literalText(src)) {
      for (const h of findForbidden(list, t.text)) out.push(`${name}:${t.line}: the ${t.where} reads "${h.match}" (forbidden: ${h.word})`);
    }
  }
  return out;
}
