// Restore-before-first-boot (design/storage.md §4.5, #291) — the browser half.
//
// The only module that puts a §4.6 private key on the wire, and it does so
// through lendArchiveKeyForRestore: the key exists for the duration of one
// startRestore call and is zeroed in that function's `finally`. Nothing here
// stores it, logs it, or returns it. What comes back is the api's response —
// the restore report and the fact that the api is restarting.

import { startRestore } from './api';
import {
  lendArchiveKeyForRestore,
  type ArchiveKeyBlobs,
  type CustodySecret,
} from './archive-key';
import type { Bytes } from './passphrase-kdf';
import type {
  RestoreCandidate,
  RestoreGeneration,
  RestoreStartRequest,
  RestoreStartResponse,
} from './types';

/** The three identifiers a restore names, without the key. */
export interface RestoreSelection {
  partUuid: string;
  generationId: string;
  keyId: string;
}

function b64url(bytes: Bytes): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * restoreRequestBody is the exact body POST /api/restore receives: the three
 * identifiers and the key, base64url. Nothing else — the api decodes with
 * DisallowUnknownFields, and there is no field for a passphrase or a
 * recovery code because neither ever leaves this browser.
 */
export function restoreRequestBody(sel: RestoreSelection, privateKey: Bytes): RestoreStartRequest {
  if (privateKey.length !== 32) throw new Error('an archive private key is 32 bytes');
  return {
    partUuid: sel.partUuid,
    generationId: sel.generationId,
    keyId: sel.keyId,
    privateKey: b64url(privateKey),
  };
}

/**
 * blobsFor reads the wrapped key off a candidate's marker in the shape the
 * unwrap wants. Refuses a candidate whose marker cannot be restored from —
 * the api already said so in `problem`, and this is the same check on the
 * client side of the wire.
 */
export function blobsFor(candidate: RestoreCandidate): ArchiveKeyBlobs {
  const m = candidate.marker;
  if (!m || !m.keyId || !m.publicKey || !m.wrappedByPassphrase || !m.wrappedByRecoveryCode) {
    throw new Error(candidate.problem || 'this disk carries no archive key this build can open');
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
 * restoreFromGeneration unwraps the disk's key with the operator's custody
 * secret, checks it against the disk, sends it once, and zeroes it.
 *
 * The secret is consumed (a passphrase's bytes are zeroed by the unwrap).
 * The returned promise resolves to the api's 202 — the report — or rejects
 * with an ArchiveKeyError (wrong secret, unreadable blob, key mismatch: the
 * key never left the browser) or the api's refusal.
 */
export function restoreFromGeneration(
  candidate: RestoreCandidate,
  generation: RestoreGeneration,
  secret: CustodySecret,
): Promise<RestoreStartResponse> {
  const blobs = blobsFor(candidate);
  const sel: RestoreSelection = {
    partUuid: candidate.marker?.partUuid ?? '',
    generationId: generation.id,
    keyId: blobs.keyId,
  };
  if (!sel.partUuid) throw new Error('this disk names no partition UUID');
  return lendArchiveKeyForRestore(blobs, secret, (privateKey) =>
    startRestore(restoreRequestBody(sel, privateKey)),
  );
}

/**
 * clusterIdMismatch says, in words, when an archive was written by a cluster
 * of a different name than the one this box was flashed with — or null when
 * they agree or either is unknown.
 *
 * It matters because the name is load-bearing well beyond the label: the
 * WebAuthn RP ID passkeys bind to is `<cluster-id>.local`, and the NATS URL
 * every node dials is derived from it. The archive restores the credentials
 * and the tokens; it cannot restore the hostname, which lives in the OS's
 * node.env. A restore across names comes up with passkeys no browser will
 * present and nodes dialling a name that no longer answers.
 */
export function clusterIdMismatch(archiveClusterId: string | undefined, thisClusterId: string): string | null {
  const a = (archiveClusterId ?? '').trim();
  const b = thisClusterId.trim();
  if (!a || !b || a === b) return null;
  return (
    `This backup was written by cluster "${a}" and this controlplane was flashed as "${b}". ` +
    `Passkeys bind to ${a}.local and nodes dial it; restoring here would bring back credentials for a name this box does not answer to. ` +
    `Re-flash with cluster id "${a}" before restoring.`
  );
}

/** generationHeadline is one line for the picker: when, what it reached, whether it was complete. */
export function generationHeadline(g: RestoreGeneration): string {
  const when = g.createdAt ? new Date(g.createdAt).toLocaleString() : 'unknown date';
  const reach = g.scope ? `scope ${g.scope}` : 'scope unknown';
  const complete = g.complete ? 'complete' : 'INCOMPLETE';
  return `${when} · ${reach} · ${complete}`;
}

/**
 * appVolumeGap is the sentence the wizard shows under a chosen generation:
 * every app volume it holds that this phase will NOT put back, by name.
 * Empty when the generation holds none.
 */
export function appVolumeGap(g: RestoreGeneration): string {
  if (g.appVolumesPresent.length === 0) return '';
  const names = g.appVolumesPresent.map((v) => v.name).join(', ');
  return (
    `This restore puts back the control-plane identity only. ${g.appVolumesPresent.length} app volume(s) in this generation ` +
    `will NOT be restored and stay sealed on the disk: ${names}.`
  );
}
