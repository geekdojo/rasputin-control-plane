// Shared time formatting helpers.

// timeAgo renders an ISO timestamp as a compact "Ns/Nm/Nh/Nd ago" string.
// Returns '' for an unparseable input. Clamped at 0 so a slightly-future
// timestamp (clock skew) reads as "0s ago" rather than a negative value.
export function timeAgo(iso: string): string {
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return '';
  const d = Math.max(0, Date.now() - t);
  const s = Math.floor(d / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const dd = Math.floor(h / 24);
  return `${dd}d ago`;
}
