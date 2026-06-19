// Single source for the Rasputin brand accent used by the ported Figma
// components. The source design used a blue (#4a9eff); per the locked brand
// aesthetic this is remapped to Pantone 172 C. Keep all accent references
// going through here so future CMF tweaks are one-line changes.
//
// These resolve through the --rasp-* CSS variables (see app/globals.css) so
// the runtime theme (default | cyberdeck — see lib/theme.tsx) flows through
// every inline style and lucide `color` prop without per-component wiring.
// They're CSS-value strings, valid anywhere a color is expected in inline
// styles and in SVG presentation attributes — NOT in <canvas> (see THEME_HUD).

export const ACCENT = 'var(--rasp-accent)'; // resolves to the active theme's accent
export const ACCENT_RGB = 'var(--rasp-accent-rgb)';

/** Translucent accent, e.g. accentA(0.12) → 'rgba(var(--rasp-accent-rgb), 0.12)'. */
export const accentA = (alpha: number) => `rgba(var(--rasp-accent-rgb), ${alpha})`;

export type NodeViewStatus = 'online' | 'offline' | 'warning' | 'updating';

export const STATUS_COLOR: Record<NodeViewStatus, string> = {
  online: '#4ade80',
  offline: 'rgba(148, 163, 184, 0.35)',
  warning: '#facc15',
  updating: ACCENT,
};

export const MONO = 'JetBrains Mono, monospace';

// Canvas can't resolve CSS variables, so the animated HUD background carries
// its own per-theme palette here (the rest of the chrome themes via --rasp-*).
// Default keeps the source "ambient cool" cyans; cyberdeck swaps to amber so
// the grid/particles read as warm CRT phosphor instead of clashing blue.
export type ThemeName = 'default' | 'cyberdeck';

export interface HudPalette {
  primary: string; // grid, scan lines, corner brackets (rgb triplet)
  mid: string; // diagonals, radial orbs
  particle: string; // drifting particles
}

export const THEME_HUD: Record<ThemeName, HudPalette> = {
  default: { primary: '0, 200, 255', mid: '0, 180, 255', particle: '0, 210, 255' },
  cyberdeck: { primary: '255, 160, 0', mid: '255, 138, 0', particle: '255, 176, 0' },
};
