// The health badge beside a claimed target's status (#398), extracted so the
// copy can be executed rather than asserted in a comment — see backup-runs.ts
// for why nothing that matters lives in a .tsx file.
//
// The claim status stays CLAIMED when a disk leaves the bus: the operator's
// intent has not changed. What changes is what the disk is doing, and this
// badge says that beside the status rather than instead of it. Get it wrong in
// the safe direction and an operator sees a red badge on a disk that is fine;
// get it wrong in the other and they believe they have a backup target for six
// days while nothing can be written to it — which is exactly what e3bench did
// on 2026-09-02, and why this exists.

import type { BackupTarget, BackupTargetHealth, BackupTargetHealthState } from '../../lib/types';

export const HEALTH_DANGER = '#f87171';
export const HEALTH_OK = '#4ade80';
export const HEALTH_DIM = '#6b7280';

export interface HealthBadge {
  /** The badge text: "MISSING · since 3h", "OK", "UNCHECKED". */
  text: string;
  color: string;
  /** The hover text: the probe's finding, plus when it was checked. */
  title: string;
  /** True for every state that fails a backup run. */
  failing: boolean;
}

/**
 * Elapsed time as the row shows it, coarse on purpose: "3h", "2d", "4m".
 * `now` is a parameter so the copy is testable without freezing the clock.
 */
export function elapsedSince(iso: string | undefined, now: number = Date.now()): string {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return '';
  const s = Math.max(0, Math.floor((now - t) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}

/** Whether a state fails every backup run until it changes. */
export function isFailing(state: BackupTargetHealthState | undefined): boolean {
  return state === 'missing' || state === 'unmounted' || state === 'unwritable' || state === 'unreachable';
}

/**
 * The badge for a target row, or null when the row has no health to show — a
 * failed, replaced or still-pending claim has no disk to be healthy.
 *
 * FAIL LOUD. Anything the api did not positively call `ok` is either red
 * (a failing state) or grey-and-said (`unknown`, before the first poll). A
 * state this build does not recognise renders as its own upper-cased name in
 * red rather than being hidden: a new failure mode from a newer api must not
 * read as green here.
 */
export function healthBadge(target: BackupTarget, now: number = Date.now()): HealthBadge | null {
  if (target.status !== 'claimed') return null;
  const h: BackupTargetHealth = target.health ?? { state: 'unknown' };
  const checked = h.checkedAt ? `checked ${elapsedSince(h.checkedAt, now)} ago` : 'not checked yet';
  const title = [h.detail, checked].filter(Boolean).join('\n');

  if (h.state === 'ok') {
    return { text: 'OK', color: HEALTH_OK, title, failing: false };
  }
  if (h.state === 'unknown') {
    return {
      text: 'UNCHECKED',
      color: HEALTH_DIM,
      title: h.detail || 'The first health check runs within 5 minutes of the api starting',
      failing: false,
    };
  }
  const since = elapsedSince(h.since ?? h.checkedAt, now);
  return {
    text: since ? `${h.state.toUpperCase()} · since ${since}` : h.state.toUpperCase(),
    color: HEALTH_DANGER,
    title,
    failing: true,
  };
}

/**
 * What the check can and cannot promise, under the table. The api serves the
 * canonical sentence (proto.BackupTargetHealthCaveat); this is the fallback
 * for a response that carries none, in the same words.
 */
export const HEALTH_CAVEAT =
  'Health is checked every 5 min with a small write (create, fsync, read back, delete). ' +
  'That catches a disk that has left the bus or stopped taking writes between backups; ' +
  'it cannot promise the next full run will succeed — a disk can still fail mid-run, and the run’s own result is the record of that.';
