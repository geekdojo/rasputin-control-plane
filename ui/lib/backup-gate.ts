// design/storage.md §4.4's install-time gate and its persistent nag
// (geekdojo/geekdojo-brain#299), as pure decisions the pages render — so the
// rules execute under `npm test` rather than living in JSX. Companion to
// backup-state.ts (#298), which owns OVERDUE; this file owns "there is
// nowhere for a backup to go yet", and the two never both apply to one app
// because the api's states are exclusive.
//
// The gate is deliberately not a block. A first-run user has not plugged a
// disk in yet; refusing the install would teach them the product is broken
// rather than that their vault is unprotected. So: plain words, a link to
// where the fix is, a checkbox that starts unticked, and install waits.

import type { App, AppBackupState, BackupSchedule, BackupTarget, CatalogTile } from './types';

/** Where the fix lives, for every link this file produces. */
export const STORAGE_HREF = '/storage';

/** The names of the tile's `critical` volumes, in declared order. */
export function criticalVolumes(tile: Pick<CatalogTile, 'volumes'>): string[] {
  return (tile.volumes ?? []).filter((v) => v.backup === 'critical').map((v) => v.name);
}

/** Whether backups are set up: a claimed target AND a schedule that is on. */
export interface BackupConfiguration {
  configured: boolean;
  /** Which half is missing, in words, when not configured. */
  reason: string;
}

/**
 * The same judgement the api's derivation makes before it decides anything
 * else (storage.BackupStates.Configured): no claimed target, or the schedule
 * off, is unconfigured. The claimed check goes first because it is the one a
 * first-run user hits.
 */
export function backupsConfigured(targets: readonly BackupTarget[], schedule: Pick<BackupSchedule, 'enabled'>): BackupConfiguration {
  if (!targets.some((t) => t.status === 'claimed')) {
    return { configured: false, reason: 'No backup target is claimed.' };
  }
  if (!schedule.enabled) {
    return { configured: false, reason: 'Scheduled backups are turned off.' };
  }
  return { configured: true, reason: '' };
}

/**
 * Whether the install dialog shows the acknowledgement. Only a tile with a
 * critical volume is ever asked; it is asked when the UI can see backups are
 * unconfigured, and also when the api has already said so (a 409 — the api
 * is the authority, and a dialog that could not read the ledger must still
 * offer the way through rather than a dead button).
 */
export function installNeedsAck(args: { criticalVolumes: readonly string[]; configured: boolean | null; apiHeld: boolean }): boolean {
  if (args.criticalVolumes.length === 0) return false;
  return args.configured === false || args.apiHeld;
}

/** Install is enabled only once a needed acknowledgement is ticked. */
export function installAllowed(args: { needsAck: boolean; acknowledged: boolean }): boolean {
  return !args.needsAck || args.acknowledged;
}

/** True when an install error is the api's §4.4 hold rather than any other refusal. */
export function isNoBackupHold(e: unknown): boolean {
  if (typeof e !== 'object' || e === null) return false;
  const { status, message } = e as { status?: unknown; message?: unknown };
  return status === 409 && typeof message === 'string' && message.includes('acknowledgeNoBackup');
}

/** The dialog's words. One place, so the test pins them and the page renders them. */
export interface NoBackupAckCopy {
  /** The sentence that says what is true. */
  body: string;
  /** The checkbox label — what the operator is agreeing to. */
  checkbox: string;
  /** The link text beside it. */
  link: string;
  href: string;
}

export function noBackupAckCopy(tile: Pick<CatalogTile, 'name'>, volumes: readonly string[], reason: string): NoBackupAckCopy {
  const noun = volumes.length === 1 ? 'volume' : 'volumes';
  const what = volumes.length > 0 ? ` (${volumes.join(', ')})` : '';
  const why = reason ? ` ${reason}` : '';
  return {
    body:
      `${tile.name} keeps critical data in its ${noun}${what}.${why} ` +
      `Until a backup target is claimed and the schedule is on, this app's data will not be backed up anywhere: ` +
      `if this node's disk fails, it is gone. You can install now and claim a disk afterwards.`,
    checkbox: `I understand ${tile.name}'s data will not be backed up until a backup target exists`,
    link: 'CLAIM A BACKUP TARGET',
    href: STORAGE_HREF,
  };
}

/** What the NO BACKUP TARGET badge says. null = no badge. */
export interface NoBackupBadge {
  label: 'NO BACKUP TARGET';
  /** The api's reason, for the tooltip. */
  title: string;
  href: string;
}

/**
 * The amber badge for an app row: only the `unconfigured` state earns it —
 * an installed app with a critical or state volume and nowhere to back it up
 * to. Every other state, `overdue` included, renders nothing here; OVERDUE is
 * backup-state.ts's red badge, and the api's states are exclusive, so a row
 * never wears both.
 */
export function noBackupBadge(backup: AppBackupState | undefined): NoBackupBadge | null {
  if (!backup || backup.state !== 'unconfigured') return null;
  return {
    label: 'NO BACKUP TARGET',
    title: backup.reason ? `No backup target: ${backup.reason}` : 'No backup target is claimed',
    href: STORAGE_HREF,
  };
}

/**
 * The drawer's record of the acknowledgement: "installed 2026-09-05 with no
 * backup target — acknowledged by bryce". null when none was given. Shown
 * whatever the current state — a target claimed since does not unsay it.
 */
export function backupAckLine(app: Pick<App, 'backupAck'>): string | null {
  const ack = app.backupAck;
  if (!ack) return null;
  const day = new Date(ack.at).toISOString().slice(0, 10);
  const by = ack.by ? ` — acknowledged by ${ack.by}` : ' — acknowledged';
  return `installed ${day} with no backup target${by}`;
}
