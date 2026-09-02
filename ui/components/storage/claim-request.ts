// Building the POST /api/backup/targets body.
//
// Pulled out of ClaimTargetDrawer as a pure function for one reason: this is
// the exact boundary the §4.6 rule is about. "The private key and the
// passphrase never leave the browser" is a claim about what is in this object,
// and a claim about an object is testable in a way that a claim about a React
// component's closure is not. archive-key.test.ts serialises what this returns
// and asserts nothing secret is in it. The PUBLIC key is in it, deliberately —
// that is §4.6's 2026-09-02 amendment, and it is what leaves the controlplane
// holding no secret at all.
//
// It also keeps the drawer honest about the ADOPT path. Adopting does not mint
// a key and does not re-wrap one — it carries the disk's own sealed key across
// verbatim, having proved in the browser that it opens. The api refuses an
// adopt whose blobs disagree with the marker (checkAdoptedKeyCustody), so a
// builder that "helpfully" reconstructed them would fail there rather than
// quietly succeed, which is the right way round.

import type { ArchiveKeyPayload } from '../../lib/archive-key';
import type { BackupCandidate, ClaimBackupTargetRequest } from '../../lib/types';

/** The three answers §4.8 allows for a chosen disk. */
export type ClaimAction = 'format' | 'adopt' | 'wipe';

export interface ClaimRequestInput {
  candidate: BackupCandidate;
  nodeId: string;
  action: ClaimAction;
  label: string;
  /** True only when the cluster has a claimed target AND the operator ticked it. */
  replace: boolean;
  /**
   * The §4.6 material to record. On format and wipe it is freshly minted; on
   * adopt it is the disk's own, read back out of the marker. Absent means the
   * target is claimed without encryption configured — which, on the adopt path,
   * is only legitimate for a disk whose marker carries no wrappings at all.
   */
  archiveKey?: ArchiveKeyPayload;
}

/**
 * What a candidate's marker says about its §4.6 key — the four cases the adopt
 * path has to tell apart, and it does have to tell them apart, because three of
 * them look identical in a listing and lead to different places.
 *
 *   `none` — no key at all. Nothing to unlock; adopt straight through.
 *   `named-only` — a key-id and no wrappings. Every disk claimed before the
 *     marker learned to carry custody material. Nothing on the disk can produce
 *     that key, so demanding a secret would only strand it: adopt, and the api
 *     says so on the live stream.
 *   `legacy-symmetric` — both wrappings, no public key. A target from before
 *     the 2026-09-02 amendment, sealed under a symmetric data key this build no
 *     longer mints. It CANNOT be adopted, by this build or the api's, and the
 *     operator needs to be told that in words rather than meet a crypto error.
 *   `sealed` — a public key and both wrappings. The current shape, and the one
 *     the unlock prompt exists for.
 */
export type MarkerKeyState = 'none' | 'named-only' | 'legacy-symmetric' | 'sealed';

export function markerKeyState(c: BackupCandidate): MarkerKeyState {
  const set = c.backupSet;
  if (!set?.keyId) return 'none';
  // Both or neither: one wrapping on a disk is not custody, it is a target one
  // forgotten passphrase from unreadable, and §4.6 refuses to create that state
  // anywhere else either. A half-written marker reads as `named-only` and
  // adopts with the api's warning rather than pretending to be openable.
  if (!set.wrappedByPassphrase || !set.wrappedByRecoveryCode) return 'named-only';
  return set.publicKey ? 'sealed' : 'legacy-symmetric';
}

/**
 * archiveKeyFromMarker reads the §4.6 key off a candidate's marker: the public
 * key in clear plus both sealed copies of the private key.
 *
 * Returns undefined unless the key-id, the public key AND both wrappings are
 * there. Both wrappings or neither is the rule the api's ArchiveKey.validate
 * enforces and the one mintArchiveKey enforces before a request is even built.
 * The public key joins them for a different reason: without it there is nothing
 * to check a recovered private key against, so an unlock could only prove the
 * secret and not the target.
 */
export function archiveKeyFromMarker(c: BackupCandidate): ArchiveKeyPayload | undefined {
  const set = c.backupSet;
  if (markerKeyState(c) !== 'sealed' || !set?.keyId || !set.publicKey) return undefined;
  return {
    keyId: set.keyId,
    alg: set.keyAlg ?? '',
    publicKey: set.publicKey,
    wrappedByPassphrase: set.wrappedByPassphrase!,
    wrappedByRecoveryCode: set.wrappedByRecoveryCode!,
  };
}

/**
 * needsUnlock reports whether adopting this disk must prompt for a custody
 * secret first.
 *
 * True exactly when the disk carries a sealed key with a public key to check it
 * against. Under the symmetric design the argument for prompting was
 * capability — a controlplane that had not been handed an openable key could
 * not write a generation. Asymmetric removes that argument: writing needs only
 * the public key, which is on the disk in clear. The prompt stays because it is
 * now the only thing that proves the custody secrets actually open THIS disk;
 * without it an operator adopts a target whose private key nobody can unwrap
 * and the schedule seals four generations no one will ever read. See
 * lib/archive-key.ts's unwrap header for the full argument.
 *
 * False for a disk whose marker names no key, names one but carries no
 * wrappings, or carries symmetric-era wrappings — nothing this build can unlock
 * lives on any of those, and prompting would only produce a refusal.
 */
export function needsUnlock(c: BackupCandidate): boolean {
  return markerKeyState(c) === 'sealed';
}

export function buildClaimRequest(input: ClaimRequestInput): ClaimBackupTargetRequest {
  const { candidate, nodeId, action, label, replace, archiveKey } = input;
  return {
    nodeId,
    devicePath: candidate.devicePath,
    fingerprint: candidate.fingerprint,
    ...(label.trim() ? { label: label.trim() } : {}),
    ...(replace ? { replace: true } : {}),
    ...(action === 'adopt' ? { adopt: true } : {}),
    // The token is echoed back verbatim from the picker. Its absence is a
    // refusal, never a default — and a candidate with no token has no wipe
    // control to reach this branch from.
    ...(action === 'wipe' && candidate.wipeToken ? { wipe: { token: candidate.wipeToken } } : {}),
    ...(archiveKey ? { archiveKey } : {}),
  };
}
