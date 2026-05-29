// Single source for the Rasputin brand accent used by the ported Figma
// components. The source design used a blue (#4a9eff); per the locked brand
// aesthetic this is remapped to Pantone 172 C. Keep all accent references
// going through here so future CMF tweaks are one-line changes.

export const ACCENT = '#fa3c04'; // Pantone 172 C primary signal orange — canonical in design/industrial-design-brief
export const ACCENT_RGB = '250, 60, 4';

/** Translucent accent, e.g. accentA(0.12) → 'rgba(250, 60, 4, 0.12)'. */
export const accentA = (alpha: number) => `rgba(${ACCENT_RGB}, ${alpha})`;

export type NodeViewStatus = 'online' | 'offline' | 'warning' | 'updating';

export const STATUS_COLOR: Record<NodeViewStatus, string> = {
  online: '#4ade80',
  offline: 'rgba(148, 163, 184, 0.35)',
  warning: '#facc15',
  updating: ACCENT,
};

export const MONO = 'JetBrains Mono, monospace';
