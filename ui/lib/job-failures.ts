// Per-app failure lines for the Tasks page (design/storage.md §4.4, #298).
//
// A backup.run that could not capture an app's volumes ends FAILED, and its
// `assemble` step result carries `failedApps`: one entry per app naming the
// node, the volumes and the fan-out's own reason. This reads that structure
// out of a job's steps so the page renders a line per app above the raw JSON
// — the third of §4.4's three surfaces, in the shape the issue asks for.
// Extracted so it is executed by `npm test`, not only compiled.

import type { JobStep } from './types';

export interface AppFailureLine {
  app: string;
  appId?: string;
  node?: string;
  class?: string;
  volumes: string[];
  reason: string;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

/**
 * Every `failedApps` entry across a job's step results, in step order. An
 * entry with no app name is dropped rather than rendered as a blank line;
 * anything else missing renders as absent. Steps are read whatever their
 * status: the result is what the api wrote, and a later step failing does
 * not unsay it.
 */
export function failedAppsOf(steps: readonly JobStep[]): AppFailureLine[] {
  const out: AppFailureLine[] = [];
  for (const s of steps) {
    if (!isRecord(s.result) || !Array.isArray(s.result.failedApps)) continue;
    for (const raw of s.result.failedApps) {
      if (!isRecord(raw) || typeof raw.app !== 'string' || !raw.app) continue;
      out.push({
        app: raw.app,
        appId: typeof raw.appId === 'string' ? raw.appId : undefined,
        node: typeof raw.node === 'string' && raw.node ? raw.node : undefined,
        class: typeof raw.class === 'string' && raw.class ? raw.class : undefined,
        volumes: asStringArray(raw.volumes),
        reason: typeof raw.reason === 'string' ? raw.reason : '',
      });
    }
  }
  return out;
}

/** One line: "immich on n-compute — immich-upload: node n-compute is OFFLINE". */
export function failureLine(f: AppFailureLine): string {
  const where = f.node ? ` on ${f.node}` : '';
  const vols = f.volumes.length ? `${f.volumes.join(', ')}: ` : '';
  return `${f.app}${where} — ${vols}${f.reason || 'no reason recorded'}`;
}
