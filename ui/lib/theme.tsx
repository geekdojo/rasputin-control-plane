'use client';

// Runtime theme selection. A theme is just a set of --rasp-* CSS variables
// (see app/globals.css); switching one flips `data-theme` on <html> and every
// inline-styled screen re-renders through the new tokens. The choice is
// persisted per-browser in localStorage and applied before first paint by the
// inline bootstrap script in app/layout.tsx (no flash of the wrong theme).

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
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

export function ThemeProvider({ children }: { children: ReactNode }) {
  // Start from DEFAULT_THEME so server and first client render agree; the
  // effect below re-syncs to whatever the bootstrap script applied. The
  // visuals are already correct pre-hydration (the script set data-theme),
  // so this only corrects React state used by the Settings picker + HUD.
  const [theme, setThemeState] = useState<ThemeName>(DEFAULT_THEME);

  useEffect(() => {
    setThemeState(currentTheme());
  }, []);

  const setTheme = useCallback((t: ThemeName) => {
    setThemeState(t);
    document.documentElement.setAttribute('data-theme', t);
    try {
      localStorage.setItem(STORAGE_KEY, t);
    } catch {
      // Private-mode / disabled storage — theme still applies for the session.
    }
  }, []);

  return <ThemeContext.Provider value={{ theme, setTheme }}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  return useContext(ThemeContext);
}

// Inline script body executed in <head> before paint to apply the saved theme
// and avoid a flash of the default theme. Stringified into a <script> tag.
export const THEME_BOOTSTRAP = `(function(){try{var t=localStorage.getItem('${STORAGE_KEY}');if(t==='cyberdeck'||t==='default'){document.documentElement.setAttribute('data-theme',t);}}catch(e){}})();`;
