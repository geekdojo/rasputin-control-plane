import type { Node } from './types';

// accessUrl builds the LAN URL to reach an app running on a node.
//
// Each Rasputin node answers `<hostname>.local` via systemd-resolved mDNS —
// the controlplane is `rasputin`, every other node is its node id (see
// rasputin-hostname.sh) — the same mechanism that makes `rasputin.local` work.
// Docker publishes the app on the node's 0.0.0.0:<port>, so the app is reachable
// at http://<hostname>.local:<port>.
//
// This is the honest interim; the eventual form is the reverse-proxy hostname
// from app-access.md (https://<app>.<cluster-domain>, no port). Returns null
// when the app declares no published port.
export function accessUrl(node: Node | undefined, targetNodeId: string, port?: number): string | null {
  if (!port) return null;
  const host = node?.hostname || targetNodeId;
  return `http://${host}.local:${port}`;
}
