// Changing an installed app's compose from the Apps page —
// geekdojo/geekdojo-brain#414, driving PUT /api/apps/{id}/compose (#409–#412).
//
// One route carries every change, and the body names the compose the app
// should run in exactly one of three ways:
//
//   {"source":"catalog"}   upgrade a catalog app to its tile's compose
//   {"composeYaml":"…"}    replace a custom app's compose
//   {"sha256":"…"}         re-apply the previous compose (revert)
//
// optionally beside `deleteVolumes`, the named volumes the owner agrees to
// delete because the change no longer declares them (#412).
//
// The answers the UI tells apart:
//
//   202  a job started
//   200  nothing to change — the body names what is already installed
//   409  refused; either a plain {error}, or the dropped-volume shape
//        {error, droppedVolumes:[…], notDropped:[…]}
//   400  malformed body
//   413  body over 1 MiB
//
// Every decision below is a pure function, so `npm test` executes it (see
// tsconfig.test.json for why this frontend's tests look like this).
//
// A custom compose can inline secrets. Nothing here logs one, stores one, or
// puts one anywhere but the body of the request in flight.

import type { App, DroppedVolume, Job } from './types';

/**
 * The only warning the upgrade confirm carries, verbatim (Bryce, 2026-09-12).
 * No image diff, no privilege diff, no database warning.
 */
export const UPGRADE_WARNING = 'Be sure you have reviewed changes on GitHub before upgrading!';

/** The revert confirm's one static prompt, verbatim (Bryce, 2026-09-12). */
export const REVERT_PROMPT = 'Reverting does not restore your data and may cause unexpected behavior. Proceed?';

/** The API's PUT body cap (maxComposeBody in apps_handlers.go). */
export const MAX_COMPOSE_BODY_BYTES = 1 << 20;

export type ComposeChangeKind = 'upgrade' | 'edit' | 'revert';

export type ComposeChangeBody =
  | { source: 'catalog'; deleteVolumes?: string[] }
  | { composeYaml: string; deleteVolumes?: string[] }
  | { sha256: string; deleteVolumes?: string[] };

// ----- which actions an app offers ------------------------------------------

/** A custom app is one not installed from a catalog tile. */
export function isCustomApp(app: Pick<App, 'sourceTile'>): boolean {
  return !app.sourceTile;
}

function isTransient(app: Pick<App, 'lastStatus'>): boolean {
  return app.lastStatus === 'deploying' || app.lastStatus === 'stopping';
}

export interface ComposeActions {
  /** UPDATE AVAILABLE badge beside the name. */
  updateBadge: boolean;
  /** The explicit UPGRADE action. */
  upgrade: boolean;
  /** EDIT COMPOSE, for a custom app. */
  edit: boolean;
  /** REVERT: re-apply the previous compose of a failed app. */
  revert: boolean;
}

/**
 * What the Apps page offers for one app. The API's flags decide; the UI adds
 * only that nothing new is started while a deploy or stop is mid-flight.
 *
 *   - the badge and UPGRADE: a catalog app whose tile carries a newer compose;
 *   - EDIT COMPOSE: a custom app (no source tile);
 *   - REVERT: a FAILED app that has a previous compose, and its hash.
 */
export function composeActions(
  app: Pick<App, 'sourceTile' | 'lastStatus' | 'upgradeAvailable' | 'revertAvailable' | 'previousComposeSha256'>,
): ComposeActions {
  const catalog = !isCustomApp(app);
  const updateBadge = catalog && app.upgradeAvailable === true;
  const idle = !isTransient(app);
  return {
    updateBadge,
    upgrade: updateBadge && idle,
    edit: !catalog && idle,
    revert: app.lastStatus === 'failed' && app.revertAvailable === true && !!app.previousComposeSha256,
  };
}

// ----- request bodies --------------------------------------------------------

export function upgradeBody(): ComposeChangeBody {
  return { source: 'catalog' };
}

export function editBody(composeYaml: string): ComposeChangeBody {
  return { composeYaml };
}

/** The re-apply body. Throws when the app has no previous compose to name. */
export function revertBody(app: Pick<App, 'revertAvailable' | 'previousComposeSha256'>): ComposeChangeBody {
  if (!app.revertAvailable || !app.previousComposeSha256) {
    throw new Error('this app has no previous compose to re-apply');
  }
  return { sha256: app.previousComposeSha256 };
}

/** The body for a change of `kind`, for the app as the page last read it. */
export function bodyFor(
  kind: ComposeChangeKind,
  app: Pick<App, 'revertAvailable' | 'previousComposeSha256'>,
  composeYaml?: string,
): ComposeChangeBody {
  switch (kind) {
    case 'upgrade':
      return upgradeBody();
    case 'edit':
      return editBody(composeYaml ?? '');
    case 'revert':
      return revertBody(app);
  }
}

/**
 * The same body, resubmitted naming `names` for deletion. The variant key and
 * its value are carried over untouched; any deleteVolumes the body already
 * had is replaced, not merged, so a resubmit names exactly what the owner
 * selected this time.
 */
export function withDeleteVolumes(body: ComposeChangeBody, names: readonly string[]): ComposeChangeBody {
  const deleteVolumes = [...new Set(names)];
  if ('source' in body) return { source: body.source, deleteVolumes };
  if ('composeYaml' in body) return { composeYaml: body.composeYaml, deleteVolumes };
  return { sha256: body.sha256, deleteVolumes };
}

/** An edit the API would refuse as empty (400) is not sent. */
export function canSubmitEdit(composeYaml: string): boolean {
  return composeYaml.trim().length > 0;
}

// ----- responses -------------------------------------------------------------

export type ComposeOutcome =
  /** 202: the change started as this job. */
  | { kind: 'started'; job: Job }
  /** 200: the body names what is already installed. Nothing started. */
  | { kind: 'noop'; app: App }
  /** 409 with droppedVolumes: the change would orphan these volumes. */
  | { kind: 'dropped'; message: string; dropped: DroppedVolume[]; notDropped: string[] }
  /** Any other refusal, in words an owner can act on. */
  | { kind: 'error'; status: number; message: string };

function errorText(body: unknown): string {
  if (body && typeof body === 'object' && typeof (body as { error?: unknown }).error === 'string') {
    return (body as { error: string }).error;
  }
  return '';
}

function isDroppedVolume(v: unknown): v is DroppedVolume {
  if (!v || typeof v !== 'object') return false;
  const o = v as Record<string, unknown>;
  return typeof o.name === 'string' && typeof o.volume === 'string';
}

/**
 * The owner-facing sentence for a refused change. The API's own reason is
 * kept, because it is specific ("tile X is not in the catalog in effect");
 * what is added is which kind of refusal it was.
 */
export function composeErrorMessage(status: number, apiError: string): string {
  const why = apiError ? `: ${apiError}` : '.';
  switch (status) {
    case 400:
      return `The change was not accepted — the request was malformed${why}`;
    case 404:
      return 'This app no longer exists.';
    case 409:
      return `The change was refused${why}`;
    case 413:
      return `The compose is too large to submit — the limit is 1 MiB${apiError ? ` (${apiError})` : ''}.`;
    default:
      return `The change failed (HTTP ${status})${why}`;
  }
}

/**
 * Reads a PUT /api/apps/{id}/compose answer. `body` is the parsed JSON, or
 * undefined when the response had none.
 */
export function parseComposeResponse(status: number, body: unknown): ComposeOutcome {
  if (status === 202) return { kind: 'started', job: body as Job };
  if (status === 200) return { kind: 'noop', app: body as App };
  const message = errorText(body);
  if (status === 409 && body && typeof body === 'object' && Array.isArray((body as { droppedVolumes?: unknown }).droppedVolumes)) {
    const raw = body as { droppedVolumes: unknown[]; notDropped?: unknown };
    const dropped = raw.droppedVolumes.filter(isDroppedVolume).map((v) => ({
      name: v.name,
      volume: v.volume,
      ...(typeof v.backup === 'string' && v.backup ? { backup: v.backup } : {}),
      lastCaptured: v.lastCaptured ?? null,
    }));
    const notDropped = Array.isArray(raw.notDropped) ? raw.notDropped.filter((n): n is string => typeof n === 'string') : [];
    if (dropped.length > 0) return { kind: 'dropped', message, dropped, notDropped };
    // Nothing is dropped, but deleteVolumes named volumes the change keeps:
    // there is nothing to ask the owner, only a refusal to explain.
    const kept = notDropped.length ? ` (still declared or not on the node: ${notDropped.join(', ')})` : '';
    return { kind: 'error', status, message: composeErrorMessage(status, message) + kept };
  }
  return { kind: 'error', status, message: composeErrorMessage(status, message) };
}

// ----- the dropped-volume refusal ---------------------------------------------

/** Nothing is selected for deletion until the owner selects it. */
export const DROP_SELECTION_DEFAULT: readonly string[] = [];

/**
 * The API deletes only when deleteVolumes is exactly the dropped set (a
 * partial set is another 409), so resubmitting is possible only once every
 * listed volume is selected, and nothing else is.
 */
export function canResubmitWithDeletions(dropped: readonly DroppedVolume[], selected: readonly string[]): boolean {
  if (dropped.length === 0) return false;
  const want = new Set(dropped.map((v) => v.name));
  const got = new Set(selected);
  if (got.size !== want.size) return false;
  for (const n of got) if (!want.has(n)) return false;
  return true;
}

/** Toggles one volume in the selection, preserving the dropped list's order. */
export function toggleDropSelection(dropped: readonly DroppedVolume[], selected: readonly string[], name: string): string[] {
  const next = new Set(selected);
  if (next.has(name)) next.delete(name);
  else next.add(name);
  return dropped.map((v) => v.name).filter((n) => next.has(n));
}

/**
 * The statement shown beside the selection: whose data goes. null while
 * nothing is selected — the default is not deleting.
 */
export function dropDeletionStatement(dropped: readonly DroppedVolume[], selected: readonly string[]): string | null {
  const chosen = dropped.filter((v) => selected.includes(v.name));
  if (chosen.length === 0) return null;
  const names = chosen.map((v) => v.volume || v.name).join(', ');
  return `The data in ${names} will be permanently deleted once the change is applied. This cannot be undone.`;
}

// ----- what the page says afterwards ------------------------------------------

const VERB: Record<ComposeChangeKind, string> = {
  upgrade: 'Upgrade',
  edit: 'Redeploy',
  revert: 'Revert',
};

/** The quiet line for a 200: nothing started, nothing to watch. */
export function noopNote(kind: ComposeChangeKind, appName: string): string {
  switch (kind) {
    case 'upgrade':
      return `${appName} is already up to date.`;
    case 'edit':
      return `${appName} already runs this compose — nothing to redeploy.`;
    case 'revert':
      return `${appName} already runs that compose — nothing to revert.`;
  }
}

/** The line for a 202, beside the way through to the job. */
export function startedNote(kind: ComposeChangeKind, appName: string): string {
  return `${VERB[kind]} of ${appName} started.`;
}

// ----- orphan rows (#274's anonymous volumes) ---------------------------------

/**
 * How an orphan volume is named in the list and the reclaim prompt. A named
 * volume is its compose key. An anonymous volume has none — `volume` is empty
 * — so it is named by where it was mounted: service and path.
 */
export function orphanVolumeLabel(v: { name: string; volume: string; anonymous?: boolean; service?: string; path?: string }): string {
  if (v.volume) return v.volume;
  const where = v.service && v.path ? `${v.service}:${v.path}` : v.service || v.path || '';
  if (where) return `${where} (anonymous)`;
  return `anonymous ${v.name.slice(0, 12)}`;
}
