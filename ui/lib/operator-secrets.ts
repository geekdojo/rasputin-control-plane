// Owner-supplied app secrets in the UI (geekdojo/geekdojo-brain#781, S20/S21).
//
// #604 shipped the api half: GET /api/apps/{id}/secrets lists each declared
// secret as set or unset (never a value) and PUT /api/apps/{id}/secrets/{name}
// stores one, write-only. This module is everything the Apps drawer and the
// install footer decide, kept out of the TSX so it is executed by tests:
// which fields to write, in what order, when a deploy follows, and the one
// sentence each outcome gets on screen.
//
// No string built here is ever made from a value: a value goes from its input
// to setAppSecret's request body and nowhere else (LOG-SECRETS).

import { errorSentence } from './api';
import type { AppStatus, Job, OperatorSecretStatus } from './types';

export interface SecretFieldView {
  marker: 'SET' | 'NOT SET';
  need: 'required' | 'optional';
  placeholder: string;
}

/** What a secret's row shows: its marker, whether it is needed, and the input's placeholder. */
export function secretFieldView(s: Pick<OperatorSecretStatus, 'set' | 'required'>): SecretFieldView {
  const need = s.required ? 'required' : 'optional';
  if (s.set) return { marker: 'SET', need, placeholder: 'Set — leave blank to keep' };
  return {
    marker: 'NOT SET',
    need,
    placeholder: s.required ? 'Not set — required before this app can deploy' : 'Not set — optional',
  };
}

export interface SecretWrite {
  name: string;
  label: string;
  value: string;
}

/**
 * The writes a save sends: one per declared secret whose draft is non-empty,
 * in declaration order. An empty field sends nothing, which is how a blank
 * field keeps the stored value (the api refuses an empty value anyway). Only
 * '' is empty: the store keeps a value as given, so a space is a value.
 */
export function pendingWrites(statuses: OperatorSecretStatus[], drafts: Record<string, string>): SecretWrite[] {
  const out: SecretWrite[] = [];
  for (const s of statuses) {
    const value = drafts[s.name];
    if (value !== undefined && value !== '') out.push({ name: s.name, label: s.label, value });
  }
  return out;
}

/**
 * Whether a save in the Apps drawer redeploys the app so the change reaches
 * it. Only for an app that is up or came up and failed:
 *   - running: the new value must reach the running app.
 *   - failed: an app that came up and then failed (a rejected key, say) gets
 *     the corrected key applied.
 * Never for the rest:
 *   - stopped / unknown: a secret change never starts an app its owner stopped
 *     or never deployed. This includes a first deploy #780 refused for a
 *     missing secret — that leaves the app stopped, not failed — so the owner
 *     deploys it again.
 *   - deploying / stopping: a job is already in flight; don't stack another.
 *     An upgrade #780 refused stays deploying, so it is in this group too.
 */
export function redeployAfterSave(status: AppStatus): boolean {
  return status === 'running' || status === 'failed';
}

export interface SaveDeps {
  put: (name: string, value: string) => Promise<void>;
  deploy: () => Promise<Job>;
}

export interface SaveResult {
  /** Names whose value was stored. */
  saved: string[];
  /** The refused name and every name after it: their drafts are kept. */
  unsaved: string[];
  /** The write that was refused, by label, with the sentence to show. */
  failed?: { label: string; sentence: string };
  /** The deploy job, when one started. */
  job?: Job;
  /** Why the deploy did not start, when it was asked for and refused. */
  deployError?: string;
}

const SAVE_FAILED = 'The secret could not be saved.';
const DEPLOY_FAILED = 'The deploy request did not reach the control plane.';

// save writes one at a time, stops at the first refusal, and calls deploy at
// most once, only after every write succeeded and only when deployWhen says so.
async function save(
  writes: SecretWrite[],
  deps: SaveDeps,
  deployWhen: (savedCount: number) => boolean,
): Promise<SaveResult> {
  const saved: string[] = [];
  for (let i = 0; i < writes.length; i++) {
    const w = writes[i];
    try {
      await deps.put(w.name, w.value);
    } catch (e) {
      return {
        saved,
        unsaved: writes.slice(i).map((x) => x.name),
        failed: { label: w.label, sentence: errorSentence(e, SAVE_FAILED) },
      };
    }
    saved.push(w.name);
  }
  if (!deployWhen(saved.length)) return { saved, unsaved: [] };
  try {
    return { saved, unsaved: [], job: await deps.deploy() };
  } catch (e) {
    return { saved, unsaved: [], deployError: errorSentence(e, DEPLOY_FAILED) };
  }
}

/** The Apps drawer's SAVE: writes, then one redeploy when `redeploy` and something was written. */
export function saveOperatorSecrets(writes: SecretWrite[], redeploy: boolean, deps: SaveDeps): Promise<SaveResult> {
  return save(writes, deps, (n) => redeploy && n > 0);
}

/**
 * The install footer's DEPLOY NOW: saves whatever was typed, then deploys once
 * — with nothing typed too. A refused write deploys nothing and keeps its
 * draft, so a typed value is never thrown away (F-781-01).
 */
export function saveThenDeploy(writes: SecretWrite[], deps: SaveDeps): Promise<SaveResult> {
  return save(writes, deps, () => true);
}

/** The drawer's one sentence for a save's outcome. */
export function saveNote(r: SaveResult): string {
  if (r.failed) return `${r.failed.label} was not saved. ${r.failed.sentence}`;
  if (r.deployError) return `Saved, but the redeploy did not start: ${r.deployError} Deploy the app to apply it.`;
  if (r.job) return 'Saved. A redeploy has started so the app picks up the change.';
  return 'Saved. It takes effect the next time the app is deployed.';
}

/** The footer's sentence when DEPLOY NOW did not deploy; null when it did. */
export function footerNote(r: SaveResult): string | null {
  if (r.failed) return `${r.failed.label} was not saved. ${r.failed.sentence}`;
  if (r.deployError) return `The deploy did not start: ${r.deployError}`;
  return null;
}

/** The SECRETS section's text when the list could not be read: the api's sentence alone. */
export function listFailureText(e: unknown): string {
  return errorSentence(e, "This app's secrets could not be listed.");
}

/**
 * The drafts left after a save: a saved name's draft is cleared, so its input
 * empties; every other draft is kept, the refused one included.
 */
export function draftsAfterSave(drafts: Record<string, string>, r: Pick<SaveResult, 'saved'>): Record<string, string> {
  const next = { ...drafts };
  for (const n of r.saved) delete next[n];
  return next;
}
