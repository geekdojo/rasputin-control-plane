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

// isPrivateIPv4 — RFC 1918 ranges only. Deliberately excludes 100.64/10 (the
// tailnet CGNAT range): reaching the CP over a tailnet IP is a tailnet context,
// not a LAN one.
function isPrivateIPv4(host: string): boolean {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

// isLanContext — is the operator reaching the control plane over a LAN name?
// The bare <cluster-id>.internal tailnet name resolves only on the tailnet
// (MagicDNS); on the LAN the CP nameserver NXDOMAINs it and answers only the
// .lan. names (ADR-0004 §9). So the LAN signals are: the mDNS cluster-login name
// (<cluster>.local, ADR-0003), a .lan.<cluster>.internal host, or a raw RFC1918
// IP. A bare .internal name, localhost, or anything else → tailnet.
function isLanContext(host: string): boolean {
  const h = host.toLowerCase();
  if (!h) return false;
  return h.endsWith('.local') || h.includes('.lan.') || isPrivateIPv4(h);
}

// preferredAppUrl picks which of an app's URLs to hand off as the single "open"
// target (the Apps OPEN button, the dashboard deployed-app row) so it matches
// the network the operator is currently on: a LAN-exposed app opened from a LAN
// view uses its .lan name (the tailnet name would NXDOMAIN there); otherwise the
// tailnet name, which every app has. Surfaces that show every URL (the detail
// drawer, the install hand-off) stay exhaustive and don't use this.
//
// host defaults to the current page's hostname; pass it explicitly in tests or
// where window isn't available (SSR → tailnet, the safe universal default).
export function preferredAppUrl(access: AppAccess | null, host?: string): string | null {
  if (!access) return null;
  if (!access.lan) return access.tailnet; // tailnet-only app → only one name exists
  const h = host ?? (typeof window !== 'undefined' ? window.location.hostname : '');
  return isLanContext(h) ? access.lan : access.tailnet;
}
