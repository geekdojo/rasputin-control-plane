// The Apps page's backup decisions (design/storage.md §4.4, #298), extracted
// so they execute under `npm test` rather than being asserted in a comment —
// the same rule components/storage/backup-runs.ts follows, for the same
// reason: a tile that reads green over an app nobody has backed up in a month
// is the failure this whole feature exists to prevent.

import type { App, AppBackupState } from './types';

/** What the OVERDUE badge says and shows on hover. null = no badge. */
export interface BackupBadge {
  /** "OVERDUE · 9d" or "OVERDUE · never backed up". */
  label: string;
  /** The api's reason, for the tooltip. */
  title: string;
  /** Where the badge links: the runs table that names which app failed. */
  href: string;
}

/**
 * Compact elapsed time: "9d", "2h", "40m", "12s". Days once past a day,
 * hours once past an hour — a badge has room for one unit.
 */
export function compactAge(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}

/**
 * The badge for an app row. Only an OVERDUE state earns one: §4.4's red is
 * for a backup that did not happen. `never` (a fresh install inside its
 * grace), `unconfigured` (#299's nag — no target, schedule off) and `none`
 * (nothing to back up) render nothing here, and an absent `backup` field —
 * an api that does not derive it — is unknown, never fine, and also
 * renders nothing rather than inventing a state.
 */
export function backupBadge(backup: AppBackupState | undefined, now: number = Date.now()): BackupBadge | null {
  if (!backup || backup.state !== 'overdue') return null;
  const elapsed = backup.lastSuccessAt ? compactAge(now - new Date(backup.lastSuccessAt).getTime()) : 'never backed up';
  return {
    label: `OVERDUE · ${elapsed}`,
    title: backup.reason ? `Backup overdue: ${backup.reason}` : 'Backup overdue',
    href: '/storage',
  };
}

/**
 * The quiet line for the detail drawer: what the state is in words. Every
 * state has one — the drawer is where an operator asking "is this backed
 * up?" gets a full sentence rather than a badge.
 */
export function backupSummary(backup: AppBackupState | undefined, now: number = Date.now()): string {
  if (!backup) return 'Backup state unknown — this api does not report it.';
  switch (backup.state) {
    case 'ok':
      return backup.lastSuccessAt
        ? `Backed up ${compactAge(now - new Date(backup.lastSuccessAt).getTime())} ago.`
        : 'Backed up.';
    case 'overdue':
      return backup.lastSuccessAt
        ? `OVERDUE — last backed up ${compactAge(now - new Date(backup.lastSuccessAt).getTime())} ago.`
        : 'OVERDUE — never backed up.';
    case 'never':
      return 'Not backed up yet — the first scheduled backup is still ahead.';
    case 'unconfigured':
      return 'Backups are not configured on this cluster.';
    case 'none':
      return 'Nothing to back up — no volume of this app is classed critical or state.';
    default:
      return `Backup state: ${backup.state}.`;
  }
}

/**
 * Overdue apps first — §4.4's top billing — then the rest in the order the api
 * listed them (install order). Stable: two overdue apps keep their relative
 * order, so the list does not shuffle between polls.
 */
export function sortAppsOverdueFirst<T extends Pick<App, 'backup'>>(apps: readonly T[]): T[] {
  const overdue = apps.filter((a) => a.backup?.state === 'overdue');
  const rest = apps.filter((a) => a.backup?.state !== 'overdue');
  return [...overdue, ...rest];
}
