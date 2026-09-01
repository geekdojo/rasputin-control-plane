// Building the POST /api/backup/targets body.
//
// Pulled out of ClaimTargetDrawer as a pure function for one reason: this is
// the exact boundary the §4.6 rule is about. "The plaintext data key and the
// passphrase never leave the browser" is a claim about what is in this object,
// and a claim about an object is testable in a way that a claim about a React
// component's closure is not. archive-key.test.ts serialises what this returns
// and asserts nothing secret is in it.
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
 * archiveKeyFromMarker reads the sealed §4.6 key off a candidate's marker.
 *
 * Returns undefined unless BOTH wrappings and the key-id are there. Both or
 * neither, the same rule the api's ArchiveKey.validate enforces and the same
 * one mintArchiveKey enforces before a request is even built: a target holding
 * one wrapping is one forgotten passphrase away from an archive nobody can
 * read, and the operator would not find out until the day they needed it.
 */
export function archiveKeyFromMarker(c: BackupCandidate): ArchiveKeyPayload | undefined {
  const set = c.backupSet;
  if (!set?.keyId || !set.wrappedByPassphrase || !set.wrappedByRecoveryCode) return undefined;
  return {
    keyId: set.keyId,
    alg: set.keyAlg ?? '',
    wrappedByPassphrase: set.wrappedByPassphrase,
    wrappedByRecoveryCode: set.wrappedByRecoveryCode,
  };
}

/**
 * needsUnlock reports whether adopting this disk must prompt for a custody
 * secret first.
 *
 * True exactly when the disk carries a sealed key. That is the case this whole
 * change exists for: adopting such a disk without opening the key records a
 * target that lists as configured, cannot have a generation written to it, and
 * announces neither fact. The api refuses it too — the prompt is here so the
 * operator meets a passphrase field rather than a refusal.
 *
 * False for a disk whose marker names no key, or names one but carries no
 * wrappings (every disk claimed before the marker learned to carry them). There
 * is nothing on such a disk to unlock, so demanding a secret would only strand
 * it.
 */
export function needsUnlock(c: BackupCandidate): boolean {
  return archiveKeyFromMarker(c) !== undefined;
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
