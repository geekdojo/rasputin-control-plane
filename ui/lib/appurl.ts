import type { App } from './types';

// appAccess builds the HTTPS URL(s) to reach an installed app (ADR-0004 §9).
//
// With E3 App Access shipped, each node runs a local Caddy that terminates TLS
// with the app's Mesh-CA leaf and fronts the container; the controlplane
// nameserver + Headscale MagicDNS resolve the app's name to its target node. So
// an app is reached at its real HTTPS name, no host/port — not the old
// <node>.local:<published-port> direct-to-container URL:
//
//   tailnet (always): https://<app>.<cluster-id>.internal
//   LAN (exposeLan):  https://<app>.lan.<cluster-id>.internal
//
// These mirror the SANs the api mints (api/internal/mesh/appleaf.go:AppLeafDNSNames)
// and the records the nameserver serves — keep the shapes in lockstep or TLS/DNS
// break. An empty cluster id (dev box / unnamed cluster) falls back to
// "rasputin", matching the api's baseDomainFor. Returns null when the app
// declares no published port — Caddy only fronts the primary port, so there's
// no web UI to hand off.
export interface AppAccess {
  // The tailnet name — the default hand-off URL, reachable from anywhere on the
  // tailnet. Present whenever the app has a published port.
  tailnet: string;
  // The .lan name — present only when the app is LAN-exposed (exposeLan). LAN is
  // always an explicit opt-in; tailnet-only apps have no LAN name.
  lan?: string;
}

// clusterBaseDomain mirrors the api's baseDomainFor: "<cluster-id>.internal", or
// "rasputin.internal" on a dev box / unnamed cluster (empty id).
function clusterBaseDomain(clusterId: string): string {
  return `${clusterId.trim() || 'rasputin'}.internal`;
}

export function appAccess(
  app: Pick<App, 'name' | 'publishedPort' | 'exposeLan'>,
  clusterId: string,
): AppAccess | null {
  if (!app.publishedPort) return null;
  const base = clusterBaseDomain(clusterId);
  const access: AppAccess = { tailnet: `https://${app.name}.${base}` };
  if (app.exposeLan) access.lan = `https://${app.name}.lan.${base}`;
  return access;
}
