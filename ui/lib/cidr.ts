// Advertise-route validation for the mesh enroll form — the client-side half
// of api/internal/mesh/advertise.go, with the SAME wording, so the operator
// reads one message whether the form or the api caught it.
//
// `tailscale up --advertise-routes` accepts only a NETWORK prefix:
// "192.168.1.149/24 has non-address bits set; expected 192.168.1.0/24"
// (e3bench-compute1, 2026-09-04). A route with host bits set is refused here
// before submit, naming the value and the network it sits in. It is NOT
// rewritten: the operator typed it, so the operator corrects it.
//
// IPv4 only, deliberately — Rasputin is IPv4-only (LOCKED decision #9).

const IPV4_CIDR = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;

// canonicalCIDR parses an IPv4 CIDR and returns its network form
// (192.168.1.149/24 → 192.168.1.0/24), or an error naming what is wrong.
// Exactly one of `network` / `error` is set.
export function canonicalCIDR(route: string): { network?: string; error?: string } {
  if (route.includes(':')) {
    return { error: `advertise route "${route}" is IPv6; Rasputin is IPv4-only` };
  }
  const m = IPV4_CIDR.exec(route);
  const notCIDR = { error: `advertise route "${route}" is not an IPv4 CIDR (expected e.g. 192.168.1.0/24)` };
  if (!m) return notCIDR;
  const octets = m.slice(1, 5).map((o) => parseInt(o, 10));
  const prefix = parseInt(m[5], 10);
  if (octets.some((o) => o > 255) || prefix > 32) return notCIDR;
  // Mask in 32-bit unsigned arithmetic: `>>> 0` keeps the sign bit from
  // turning 192.x.x.x negative. A /0 mask is 0, not (0xffffffff << 32).
  const addr = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const net = (addr & mask) >>> 0;
  return {
    network: `${net >>> 24}.${(net >>> 16) & 255}.${(net >>> 8) & 255}.${net & 255}/${prefix}`,
  };
}

// validateAdvertiseRoute is the refusing check: null when `route` is a
// canonical IPv4 network, else the message to show. Mirrors
// mesh.ValidateAdvertiseRoutes on the api.
export function validateAdvertiseRoute(route: string): string | null {
  const { network, error } = canonicalCIDR(route);
  if (error) return error;
  if (network !== route) {
    return `advertise route "${route}" is a host address, not a network — advertise ${network}`;
  }
  return null;
}

// parseAdvertiseRoutes turns the form's comma-separated input into the list
// the api receives, validating each entry. Whitespace around entries and
// empty entries (a trailing comma) are ignored; `error` is the first refusal,
// with `routes` still populated so a caller can show what would be sent.
export function parseAdvertiseRoutes(input: string): { routes: string[]; error: string | null } {
  const routes = input
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  for (const r of routes) {
    const err = validateAdvertiseRoute(r);
    if (err) return { routes, error: err };
  }
  return { routes, error: null };
}
