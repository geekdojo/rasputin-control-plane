// Display helpers for the backup-target picker.
//
// Everything here answers one §4.8 requirement: the destructive confirmation
// "shows model, size and current contents". A disk the operator cannot tell
// apart from the one next to it is the failure mode the whole feature guards
// against, so these functions bias towards saying MORE — a nameless disk still
// gets its device path, an empty partition table still gets a sentence.

import type { BackupCandidate, StoragePartition, StorageTransport } from '../../lib/types';

/**
 * Disk vendors sell in decimal gigabytes and the label on the drive says
 * "2 TB", so the picker uses decimal too. Matching the sticker is the whole
 * job: an operator comparing the screen to the object in their hand should not
 * have to know about the GB/GiB split to be sure they picked the right one.
 */
export function formatDiskSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return 'unknown size';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let v = bytes;
  let u = 0;
  while (v >= 1000 && u < units.length - 1) {
    v /= 1000;
    u += 1;
  }
  return `${u === 0 ? v : v.toFixed(v >= 100 ? 0 : 1)} ${units[u]}`;
}

const TRANSPORT_LABEL: Record<StorageTransport, string> = {
  usb: 'USB',
  nvme: 'NVMe',
  sata: 'SATA',
  mmc: 'eMMC/SD',
  virtual: 'virtual',
  unknown: 'unknown bus',
};

export function transportLabel(t: StorageTransport): string {
  return TRANSPORT_LABEL[t] ?? TRANSPORT_LABEL.unknown;
}

/** A one-line name for a disk. Never empty — falls back through to the path. */
export function diskName(c: BackupCandidate): string {
  return c.model?.trim() || c.wwn?.trim() || c.devicePath;
}

/**
 * The string the operator must type to unlock a wipe.
 *
 * The disk's own serial when it has one, so the confirmation is specific to
 * THIS disk rather than a word muscle memory can produce. Falls back to the
 * model and then the device path — a disk with no stable identity is exactly
 * the one whose fingerprint is weak, and typing something is still better than
 * clicking.
 */
export function wipePhrase(c: BackupCandidate): string {
  return c.serial?.trim() || c.model?.trim() || c.devicePath;
}

/**
 * §4.8's "current contents", in prose. A partition table the operator can read
 * is the difference between a blank disk and someone's photo archive.
 */
export function partitionSummary(parts: StoragePartition[] | undefined): string {
  if (!parts || parts.length === 0) return 'no partition table — the disk reads as blank';
  return `${parts.length} partition${parts.length === 1 ? '' : 's'}`;
}

/** One partition, rendered the way an operator recognises their own data. */
export function partitionLine(p: StoragePartition): string {
  const bits = [p.devicePath, formatDiskSize(p.sizeBytes)];
  if (p.fsType) bits.push(p.fsType);
  if (p.label) bits.push(`“${p.label}”`);
  if (p.mountpoint) bits.push(`mounted at ${p.mountpoint}`);
  return bits.join(' · ');
}

/**
 * What claiming this disk would DO — the three cases §4.8 defines, plus the one
 * dead end it defines an exit for.
 *
 *  - `protected`  the boot medium. Not claimable at all, and shown saying so.
 *  - `format`     blank (to Rasputin's eye): format and claim.
 *  - `adopt`      carries a Rasputin backup set: take it over as it stands.
 *  - `unreadable` announces a set whose marker could not be parsed. It can be
 *                 neither adopted (no partition UUID to adopt it by) nor
 *                 claimed as blank (the backup-set refusal stands in the way).
 *                 Wipe is the only exit, which is why the api mints a token for
 *                 it like any other.
 */
export type CandidateDisposition = 'protected' | 'format' | 'adopt' | 'unreadable';

export function disposition(c: BackupCandidate): CandidateDisposition {
  if (c.protected) return 'protected';
  if (!c.hasBackupSet) return 'format';
  return c.backupSet ? 'adopt' : 'unreadable';
}
