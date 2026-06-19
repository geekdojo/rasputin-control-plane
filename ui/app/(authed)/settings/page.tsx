'use client';

// /settings — operator preferences for this control plane. First section is
// Appearance (theme picker); more settings land here as they ship. The Settings
// icon in the sidebar routes here.

import { Check, Settings as SettingsIcon } from 'lucide-react';
import { useState } from 'react';
import { PageShell, PageHeader, PageBody, SectionLabel, Hint, DIM, FG, HAIR } from '../../../components/kit';
import { accentA, ACCENT, MONO } from '../../../components/ui-theme';
import { THEMES, useTheme, type ThemeMeta } from '../../../lib/theme';

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();

  return (
    <PageShell>
      <PageHeader icon={SettingsIcon} title="SETTINGS" />
      <PageBody>
        <SectionLabel>APPEARANCE / THEME</SectionLabel>
        <Hint style={{ marginBottom: 16 }}>
          Choose how the control plane looks. Applies instantly and is remembered on this device.
        </Hint>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
            gap: 12,
            maxWidth: 880,
          }}
        >
          {THEMES.map((t) => (
            <ThemeCard key={t.id} meta={t} selected={theme === t.id} onSelect={() => setTheme(t.id)} />
          ))}
        </div>
      </PageBody>
    </PageShell>
  );
}

function ThemeCard({
  meta,
  selected,
  onSelect,
}: {
  meta: ThemeMeta;
  selected: boolean;
  onSelect: () => void;
}) {
  const [hover, setHover] = useState(false);
  const { bg, panel, fg, accent } = meta.swatch;

  return (
    <button
      type="button"
      onClick={onSelect}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      aria-pressed={selected}
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
        padding: 12,
        textAlign: 'left',
        cursor: 'pointer',
        fontFamily: MONO,
        background: selected ? accentA(0.08) : hover ? 'rgba(var(--rasp-fg-rgb),0.04)' : 'transparent',
        border: `1px solid ${selected ? ACCENT : HAIR}`,
        transition: 'background 0.15s, border-color 0.15s',
      }}
    >
      {/* Live mini-preview rendered from the theme's own swatch colors so it
          reads correctly regardless of which theme is currently active. */}
      <div
        style={{
          position: 'relative',
          height: 92,
          background: bg,
          border: `1px solid ${HAIR}`,
          overflow: 'hidden',
          padding: 10,
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: accent, flexShrink: 0 }} />
          <span style={{ width: 54, height: 6, background: fg, opacity: 0.85 }} />
          <span style={{ marginLeft: 'auto', width: 26, height: 6, background: accent }} />
        </div>
        <div style={{ flex: 1, background: panel, border: `1px solid ${accent}`, padding: 6 }}>
          <span style={{ display: 'block', width: '40%', height: 5, background: accent, marginBottom: 5 }} />
          <span style={{ display: 'block', width: '70%', height: 4, background: fg, opacity: 0.4 }} />
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ color: selected ? ACCENT : FG, fontSize: 12, letterSpacing: '0.08em' }}>
          {meta.label.toUpperCase()}
        </span>
        {selected && (
          <span
            style={{
              marginLeft: 'auto',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4,
              color: ACCENT,
              fontSize: 9,
              letterSpacing: '0.1em',
            }}
          >
            <Check size={11} /> ACTIVE
          </span>
        )}
      </div>
      <span style={{ color: DIM, fontSize: 10, lineHeight: 1.55 }}>{meta.description}</span>
    </button>
  );
}
