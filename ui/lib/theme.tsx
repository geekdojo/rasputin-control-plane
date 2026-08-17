'use client';

// Runtime theme selection. A theme is just a set of --rasp-* CSS variables
// (see app/globals.css); switching one flips `data-theme` on <html> and every
// inline-styled screen re-renders through the new tokens. The choice is
// persisted per-browser in localStorage and applied before first paint by the
// inline bootstrap script in app/layout.tsx (no flash of the wrong theme).

import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useMemo,
  useSyncExternalStore,
} from 'react';
import type { ThemeName } from '../components/ui-theme';

export const STORAGE_KEY = 'rasputin.theme';
export const DEFAULT_THEME: ThemeName = 'default';

export interface ThemeMeta {
  id: ThemeName;
  label: string;
  description: string;
  /** Representative swatch colors for the Settings picker preview. */
  swatch: { bg: string; panel: string; fg: string; accent: string };
}

// Order here is the order shown in Settings. Keep `default` first.
export const THEMES: ThemeMeta[] = [
  {
    id: 'default',
    label: 'Mission Control',
    description:
      'The standard Rasputin look — deep navy panels, Pantone 172 C orange, animated HUD.',
    swatch: { bg: '#07101f', panel: '#0d1829', fg: '#e4e6ea', accent: '#fa3c04' },
  },
  {
    id: 'cyberdeck',
    label: 'Cyberdeck',
    description:
      'Retro amber CRT terminal — pure black, warm amber, sharp corners. Same layout, different glow.',
    swatch: { bg: '#060606', panel: '#0e0d0b', fg: '#ece3d0', accent: '#ffa000' },
  },
];

function isThemeName(v: string | null): v is ThemeName {
  return v === 'default' || v === 'cyberdeck';
}

/** Read the theme the bootstrap script already applied to <html>. */
function currentTheme(): ThemeName {
  if (typeof document === 'undefined') return DEFAULT_THEME;
  const attr = document.documentElement.getAttribute('data-theme');
  return isThemeName(attr) ? attr : DEFAULT_THEME;
}

interface ThemeContextValue {
  theme: ThemeName;
  setTheme: (t: ThemeName) => void;
}

const ThemeContext = createContext<ThemeContextValue>({
  theme: DEFAULT_THEME,
  setTheme: () => {},
});

// The data-theme attribute on <html> is the real source of truth: THEME_BOOTSTRAP
// below sets it in <head> before first paint, so the page is already correct
// visually before React runs. Mirroring it into useState meant a second copy
// that had to be re-synced from an effect — a synchronous setState on effect
// entry (react-hooks/set-state-in-effect), and a duplicate that could disagree.
//
// useSyncExternalStore reads the attribute directly with an explicit server
// snapshot, so there is one source of truth and no sync effect at all.
const themeListeners = new Set<() => void>();

function subscribeTheme(onChange: () => void): () => void {
  themeListeners.add(onChange);
  return () => {
    themeListeners.delete(onChange);
  };
}

function getThemeServerSnapshot(): ThemeName {
  return DEFAULT_THEME;
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const theme = useSyncExternalStore(subscribeTheme, currentTheme, getThemeServerSnapshot);

  const setTheme = useCallback((t: ThemeName) => {
    document.documentElement.setAttribute('data-theme', t);
    try {
      localStorage.setItem(STORAGE_KEY, t);
    } catch {
      // Private-mode / disabled storage — theme still applies for the session.
    }
    // Tell every subscriber to re-read the attribute.
    themeListeners.forEach((l) => l());
  }, []);

  // Memoised so consumers don't re-render on every provider render.
  const value = useMemo(() => ({ theme, setTheme }), [theme, setTheme]);

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  return useContext(ThemeContext);
}

// Inline script body executed in <head> before paint to apply the saved theme
// and avoid a flash of the default theme. Stringified into a <script> tag.
export const THEME_BOOTSTRAP = `(function(){try{var t=localStorage.getItem('${STORAGE_KEY}');if(t==='cyberdeck'||t==='default'){document.documentElement.setAttribute('data-theme',t);}}catch(e){}})();`;
