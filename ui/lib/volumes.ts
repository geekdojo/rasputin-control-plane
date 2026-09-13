// The uninstall prompt's reasoning — geekdojo/geekdojo-brain#399.
//
// "Delete volumes?" defaults to keep, and the answer is informed: each volume
// is shown with its backup class and when it was last captured, and ticking
// delete over a `critical` or `state` volume that has never been backed up is
// said in plain words before the operator confirms (design/storage.md §4.4:
// an operator must never be allowed to believe a backup exists when it does
// not). Pure functions, so the rule is testable without rendering.

import { timeAgo } from './time';

/**
 * What the uninstall prompt says about a custom app's volumes, in place of the
 * api's note (geekdojo/geekdojo-brain#424). A custom app has no tile, so its
 * volumes are not classified and cannot be listed; what the prompt CAN say is
 * what "delete volumes" covers. The api's note named only the compose
 * project's rasp_<id>_* volumes, but since #413 (rasputin-control-plane#274)
 * a delete with data also removes the anonymous volumes the node's agent
 * recorded for the app — which have docker's 64-hex names, not rasp_<id>_*,
 * and which a keep-data delete leaves under Orphaned volumes by service and
 * path. The project name is the api's proto.AppProjectName: "rasp_" plus the
 * lower-cased id.
 */
export function customAppVolumesNote(appId: string, targetNode: string): string {
  const project = `rasp_${appId.toLowerCase()}`;
  const where = targetNode ? ` on ${targetNode}` : '';
  return (
    'A custom app: its compose was not installed from a catalog tile, so its volumes are not classified and cannot be ' +
    `listed here. Its data is the named volumes of its compose project (${project}_*)${where}, plus the anonymous ` +
    'volumes the node recorded for it: unnamed mounts, and paths its images declare as VOLUME. Deleting volumes ' +
    'removes both kinds.'
  );
}

// The checkbox's initial state. Destroying data is never the path of least
// resistance: delete requires a deliberate act.
export const DELETE_VOLUMES_DEFAULT = false;

// The shape both the uninstall prompt (an installed app's tile volumes) and
// the reclaim prompt (orphans) hand to these functions.
export interface PromptVolume {
  name: string;
  // The §4.2 class: 'critical' | 'state' | 'cache' | 'bulk'. '' when unknown
  // — an orphan no manifest ever recorded.
  backup: string;
  // null means never captured into a retained backup generation.
  lastCaptured: { generationId: string; at: string } | null;
}

// isProtectedClass: the classes §4.2 makes mandatory in every backup, and so
// the ones whose loss without a backup is the thing to warn about. An unknown
// class ('') is treated as protected — not knowing is not a reason to be
// quiet.
export function isProtectedClass(backup: string): boolean {
  return backup === 'critical' || backup === 'state' || backup === '';
}

// describeCapture renders a volume's backup state for the prompt: "never", or
// the generation and its age.
export function describeCapture(v: PromptVolume, now: number = Date.now()): string {
  if (!v.lastCaptured) return 'never';
  const at = new Date(v.lastCaptured.at).getTime();
  const age = Number.isFinite(at) ? timeAgoFrom(at, now) : '';
  return age ? `${v.lastCaptured.generationId}, ${age}` : v.lastCaptured.generationId;
}

// unbackedProtected: the volumes a delete would destroy the only copy of.
export function unbackedProtected(volumes: PromptVolume[]): PromptVolume[] {
  return volumes.filter((v) => isProtectedClass(v.backup) && !v.lastCaptured);
}

// deleteWarning is the sentence shown, in red, when the operator has ticked
// delete over data that has never been backed up. null when there is nothing
// to say: the box is unticked, or every protected volume has a retained
// capture, or only cache/bulk volumes are unbacked.
export function deleteWarning(volumes: PromptVolume[], deleteVolumes: boolean): string | null {
  if (!deleteVolumes) return null;
  const hit = unbackedProtected(volumes);
  if (hit.length === 0) return null;
  const names = hit.map((v) => `${v.name} (${v.backup || 'unclassified'})`).join(', ');
  if (hit.length === 1) {
    return `${names} has never been backed up. Deleting it destroys the only copy of that data.`;
  }
  return `${names} have never been backed up. Deleting them destroys the only copy of that data.`;
}

// timeAgoFrom is timeAgo with an injectable "now", so a test can pin the age.
function timeAgoFrom(t: number, now: number): string {
  const d = Math.max(0, now - t);
  const s = Math.floor(d / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// formatBytes renders a volume size the way an operator reads one.
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

// Re-exported so callers that already import from here need only one import.
export { timeAgo };
