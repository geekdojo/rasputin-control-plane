import type { MeshDeviceTrust } from './types';

// How a node's reported trust fingerprint reads on Mesh → Devices.
//
// The agent reports the fingerprint of the trust bundle it holds (the
// controlplane CA, plus the operator's CA on an external Headscale), "none"
// when it holds no bundle, or "reload-pending" when it installed a new bundle
// but tailscaled has not reloaded it. "reload-pending" is a state, not a
// fingerprint: truncating it would read as a short hash.

/** The fingerprint as the stale badge's hover names it. */
export function trustFingerprintLabel(fingerprint?: string): string {
  switch (fingerprint) {
    case 'none':
      return 'NONE';
    case 'reload-pending':
      return 'reload pending';
    case undefined:
    case '':
      return '?';
    default:
      return fingerprint.slice(0, 12);
  }
}

/** The stale badge's hover text. */
export function staleTrustTitle(trust: Pick<MeshDeviceTrust, 'fingerprint'>): string {
  if (trust.fingerprint === 'reload-pending') {
    return 'this node installed the current controlplane CA but tailscaled has not reloaded it (reload pending) — the next trust convergence retries the reload';
  }
  return `this node trusts controlplane CA ${trustFingerprintLabel(trust.fingerprint)}, not the current one — the next trust convergence re-delivers it`;
}
