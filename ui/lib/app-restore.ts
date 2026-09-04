// Restoring one app's data from a backup generation (design/storage.md
// §4.5 phase 2, geekdojo-brain#291) — the browser half.
//
// The second and last module that puts a §4.6 private key on the wire, and
// it does so the same way lib/restore.ts does: through
// lendArchiveKeyForRestore, for the duration of one startAppRestore call,
// zeroed in that function's `finally`. Nothing here stores it, logs it, or
// returns it. unlockArchiveKey still never returns key material.
//
// The confirmation's rules live here as pure functions so they are testable
// without rendering: the box that says "replace the current data" starts
// UNTICKED, and nothing can be submitted until it is ticked, a generation is
// chosen that can actually be restored, the app is installed on a node that
// is online, and a custody secret is ready.

import { startAppRestore } from './api';
import { lendArchiveKeyForRestore, type ArchiveKeyBlobs, type CustodySecret } from './archive-key';
import type { Bytes } from './passphrase-kdf';
import type {
  App,
  AppRestoreGeneration,
  AppRestoreRequest,
  AppRestoreResponse,
  AppRestoreSources,
  AppRestoreVolumeView,
} from './types';

/** The confirmation checkbox's initial state. Replacing data is never the path of least resistance. */
export const RESTORE_CONFIRM_DEFAULT = false;

/** The three identifiers a restore names, without the key. */
export interface AppRestoreSelection {
  partUuid: string;
  generationId: string;
  keyId: string;
  volumes?: string[];
}

function b64url(bytes: Bytes): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * appRestoreRequestBody is the exact body POST /api/apps/{id}/restore
 * receives: the identifiers, the key base64url, and optionally the volumes.
 * Nothing else — the api decodes with DisallowUnknownFields, and there is no
 * field for a passphrase or a recovery code because neither leaves this
 * browser.
 */
export function appRestoreRequestBody(sel: AppRestoreSelection, privateKey: Bytes): AppRestoreRequest {
  if (privateKey.length !== 32) throw new Error('an archive private key is 32 bytes');
  const body: AppRestoreRequest = {
    partUuid: sel.partUuid,
    generationId: sel.generationId,
    keyId: sel.keyId,
    privateKey: b64url(privateKey),
  };
  if (sel.volumes && sel.volumes.length > 0) body.volumes = [...sel.volumes];
  return body;
}

/**
 * blobsForSources reads the wrapped key off the target's marker in the shape
 * the unwrap wants. Refuses a marker this build cannot open — the api already
 * said so in `problem`, and this is the same check on this side of the wire.
 */
export function blobsForSources(src: AppRestoreSources): ArchiveKeyBlobs {
  const m = src.marker;
  if (!m || !m.keyId || !m.publicKey || !m.wrappedByPassphrase || !m.wrappedByRecoveryCode) {
    throw new Error(src.problem || 'the backup disk carries no archive key this build can open');
  }
  return {
    keyId: m.keyId,
    alg: m.keyAlg ?? '',
    publicKey: m.publicKey,
    wrappedByPassphrase: m.wrappedByPassphrase,
    wrappedByRecoveryCode: m.wrappedByRecoveryCode,
  };
}

/**
 * restoreBlocker says, in words, why a restore cannot be started yet — or
 * null when it can. The order is the operator's: the app first, then the
 * disk, then the generation.
 */
export function restoreBlocker(src: AppRestoreSources | null, generation: AppRestoreGeneration | null): string | null {
  if (!src) return 'Reading the backup target…';
  if (!src.installed) {
    return `${src.appName} is not deployed to any node. A restore puts data into an existing install and never creates one — deploy it first.`;
  }
  if (!src.nodeOnline) {
    return `Node ${src.nodeId} hosts ${src.appName} and is offline. The restore is refused, not queued — bring the node back first.`;
  }
  if (src.problem && src.generations.length === 0) return src.problem;
  if (!generation) return 'Choose the backup to restore from.';
  if (!generation.restorable) return generation.problem || 'That backup cannot be restored to this app.';
  return null;
}

/** restorableVolumes is the subset of a generation's volumes the plan will put back. */
export function restorableVolumes(g: AppRestoreGeneration): AppRestoreVolumeView[] {
  return g.volumes.filter((v) => v.restorable);
}

/** generationLine is one line for the picker: when, how old, whether the run was complete, what it holds for this app. */
export function generationLine(g: AppRestoreGeneration): string {
  const when = g.createdAt ? new Date(g.createdAt).toLocaleString() : 'unknown date';
  const complete = g.complete ? 'complete' : 'INCOMPLETE';
  const n = restorableVolumes(g).length;
  const vols = `${n} volume${n === 1 ? '' : 's'}`;
  return `${when} · ${g.ageHuman} · ${complete} · ${vols}`;
}

/**
 * confirmationCopy is what the operator is agreeing to, in the words the
 * checkbox and the paragraph beside it carry: which volumes, from when, that
 * the current data is REPLACED, and that the app is stopped for the swap.
 */
export function confirmationCopy(app: App, src: AppRestoreSources, g: AppRestoreGeneration): { checkbox: string; detail: string; reinstalled: string | null } {
  const vols = restorableVolumes(g);
  const names = vols.map((v) => `${v.volume} (${v.class})`).join(', ');
  const node = src.nodeId || app.targetNode;
  return {
    checkbox: `Replace the current data of ${app.name} with the backup from ${g.ageHuman}`,
    detail:
      `${vols.length} volume${vols.length === 1 ? '' : 's'} on ${node} will be REPLACED from generation ${g.id}: ${names}. ` +
      `Whatever ${app.name} holds right now is moved aside beside each volume on ${node} and not deleted. ` +
      `${app.name} is stopped while each volume is swapped and started again afterwards; the download happens while it runs.`,
    reinstalled:
      g.matchedBy === 'tile+name'
        ? `This backup was taken of an earlier install of ${app.name} (a different app id); it is matched by tile and name.`
        : null,
  };
}

/**
 * canSubmitRestore is the whole gate for the RESTORE button: informed
 * consent ticked, a restorable generation chosen, nothing blocking, a secret
 * ready, and no request in flight.
 */
export function canSubmitRestore(state: {
  confirmed: boolean;
  src: AppRestoreSources | null;
  generation: AppRestoreGeneration | null;
  secretReady: boolean;
  busy: boolean;
}): boolean {
  if (!state.confirmed || state.busy || !state.secretReady) return false;
  return restoreBlocker(state.src, state.generation) === null;
}

/**
 * restoreAppData unwraps the disk's key with the operator's custody secret,
 * checks it against the disk, sends it once inside the restore request, and
 * zeroes it. The secret is consumed. Resolves to the api's 202 — the job —
 * or rejects with an ArchiveKeyError (wrong secret, unreadable blob, key
 * mismatch: the key never left the browser) or the api's refusal.
 */
export function restoreAppData(
  app: App,
  src: AppRestoreSources,
  generation: AppRestoreGeneration,
  secret: CustodySecret,
  volumes?: string[],
): Promise<AppRestoreResponse> {
  const blobs = blobsForSources(src);
  const partUuid = src.target?.partUuid ?? src.marker?.partUuid ?? '';
  if (!partUuid) throw new Error('the backup target names no partition UUID');
  const sel: AppRestoreSelection = { partUuid, generationId: generation.id, keyId: blobs.keyId, volumes };
  return lendArchiveKeyForRestore(blobs, secret, (privateKey) => startAppRestore(app.id, appRestoreRequestBody(sel, privateKey)));
}
