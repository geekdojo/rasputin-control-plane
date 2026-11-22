// Paths and readers the theme tests share (geekdojo/geekdojo-brain#988).
// __dirname is .test-out/identity-theme/test at run time
// (tsconfig.test.json), so ui/ is three up.
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

export const UI = path.join(__dirname, '..', '..', '..');
export const THEME = path.join(UI, 'identity-theme');
export const SRC = path.join(THEME, 'src', 'login');
export const FIXTURES = path.join(THEME, 'fixtures');

export function read(file: string): string {
  return readFileSync(file, 'utf8');
}

export function readJSON<T>(file: string): T {
  return JSON.parse(read(file)) as T;
}

/** The .ftl files in a directory, by name. */
export function templates(dir: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const f of readdirSync(dir).sort()) if (f.endsWith('.ftl')) out.set(f, read(path.join(dir, f)));
  return out;
}

/**
 * A .properties file's keys and values, as java.util.Properties reads the
 * plain one-line form these bundles use (\\uXXXX escapes decoded).
 */
export function properties(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of text.split('\n')) {
    const m = /^([A-Za-z0-9_.\-${}]+)=(.*)$/.exec(line);
    if (m) out.set(m[1], m[2].replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16))));
  }
  return out;
}

/**
 * The text java.text.MessageFormat makes of a value with these arguments:
 * '' is one apostrophe, {n} is argument n. (A lone apostrophe would start a
 * quoted run; messages.test.ts refuses one in our bundle.)
 */
export function formatMessage(value: string, ...args: string[]): string {
  return value.replace(/\{(\d+)\}/g, (all, n) => args[Number(n)] ?? all).replace(/''/g, "'");
}

/** coverage.json, with its hash lists read into maps by name. */
export interface Coverage {
  keycloak: string;
  neverRenderedKeys: { reason: string; keys: string[] }[];
  overriddenTemplates: Record<string, string>;
  reviewedTemplates: Record<string, string>;
  forkedScripts: Record<string, string>;
}

/** The Keycloak release pin.go pins, "26.8.2". */
export function pinnedKeycloak(): string {
  const pin = read(path.join(UI, '..', 'api', 'internal', 'identitytest', 'pin.go'));
  const m = /^\s*KeycloakRelease\s*=\s*"keycloak\/keycloak:([^"]+)"\s*$/m.exec(pin);
  if (!m) throw new Error('pin.go has no KeycloakRelease');
  return m[1];
}

interface RawCoverage {
  keycloak: string;
  neverRenderedKeys: { reason: string; keys: string[] }[];
  overriddenTemplates: { upstreamSha256: string; template: string }[];
  reviewedTemplates: Record<string, string>;
  forkedScripts: { upstreamSha256: string; script: string }[];
}

/** coverage.json. Its hashes are listed one object per file. */
export function loadCoverage(file: string): Coverage {
  const raw = readJSON<RawCoverage>(file);
  return {
    keycloak: raw.keycloak,
    neverRenderedKeys: raw.neverRenderedKeys,
    overriddenTemplates: Object.fromEntries(raw.overriddenTemplates.map((o) => [o.template, o.upstreamSha256])),
    reviewedTemplates: raw.reviewedTemplates,
    forkedScripts: Object.fromEntries(raw.forkedScripts.map((o) => [o.script, o.upstreamSha256])),
  };
}

/** upstream/<v>/resources-sha256.json, as path -> sha256. */
export function loadBaseSums(file: string): Record<string, string> {
  const raw = readJSON<{ files: { sha256: string; path: string }[] }>(file);
  return Object.fromEntries(raw.files.map((f) => [f.path, f.sha256]));
}
