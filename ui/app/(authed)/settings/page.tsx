'use client';

// /settings — operator preferences for this control plane. Sections:
//   • Appearance (theme picker)
//   • Deployment mode (post-setup change of setup.mode — the only surface for
//     this once the first-run wizard has completed; the wizard redirects away
//     when setup is done, so without this an operator who picked the wrong mode
//     was stuck. Backend: POST /api/setup/mode, same endpoint the wizard uses.)
// The Settings icon in the sidebar routes here.

import { Check, Settings as SettingsIcon } from 'lucide-react';
import { useEffect, useState } from 'react';
import { PageShell, PageHeader, PageBody, SectionLabel, Hint, DIM, FG, HAIR } from '../../../components/kit';
import { accentA, ACCENT, MONO } from '../../../components/ui-theme';
import { THEMES, useTheme, type ThemeMeta } from '../../../lib/theme';
import { DeploymentModePicker, MODES } from '../../../components/DeploymentModePicker';
import { ConfirmModal } from '../../../components/ConfirmModal';
import { getSetupState, setDeploymentMode } from '../../../lib/api';
import type { DeploymentMode, SetupState } from '../../../lib/types';

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

        <div style={{ height: 32 }} />
        <DeploymentModeSection />
      </PageBody>
    </PageShell>
  );
}

// --- Deployment mode ------------------------------------------------------

// consequenceOf returns the confirm-dialog copy for switching TO `target`.
// The sharp edge is LAN-peer: it idles a live firewall (DHCP + threat detection
// off), which can drop devices offline if Rasputin is the one running the
// network. Copy stays plain-language / vendor-neutral (no "DHCP"/OpenWrt).
function consequenceOf(target: Exclude<DeploymentMode, ''>, firewallCapable: boolean): {
  message: string;
  danger: boolean;
} {
  if (target === 'lan_peer') {
    if (firewallCapable) {
      return {
        danger: true,
        message:
          'Switching to “Join my existing network” turns your firewall node off — it stops handing out addresses and stops watching for threats. If Rasputin is currently running your network, connected devices — including the one you’re using right now — may drop offline when their address lease renews. Only switch if another router on the network hands out addresses.',
      };
    }
    return {
      danger: false,
      message:
        'Rasputin will run as a device on your existing network. Your current router keeps doing the firewalling — nothing else changes.',
    };
  }
  if (target === 'router') {
    return {
      danger: false,
      message:
        'Rasputin becomes your router — it starts handing out addresses, running the firewall, and watching for threats on its network port.',
    };
  }
  return {
    danger: false,
    message:
      'Rasputin runs its own protected network — it starts handing out addresses, running the firewall, and watching for threats on that network.',
  };
}

function DeploymentModeSection() {
  const [state, setState] = useState<SetupState | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [pending, setPending] = useState<Exclude<DeploymentMode, ''> | null>(null);

  useEffect(() => {
    getSetupState()
      .then(setState)
      .catch((e) => setErr(String(e)));
  }, []);

  async function apply(mode: Exclude<DeploymentMode, ''>) {
    setBusy(true);
    setErr(null);
    try {
      setState(await setDeploymentMode(mode));
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
      setPending(null);
    }
  }

  const currentLabel = state ? MODES.find((m) => m.id === state.mode)?.label : null;
  const consequence = pending ? consequenceOf(pending, state?.firewallCapable ?? false) : null;

  return (
    <>
      <SectionLabel>DEPLOYMENT MODE</SectionLabel>
      <Hint style={{ marginBottom: 16 }}>
        How Rasputin sits on your network. Changing this reconfigures the firewall node — it takes
        effect within a minute or two.{' '}
        {currentLabel && (
          <>
            Currently: <span style={{ color: FG }}>{currentLabel}</span>.
          </>
        )}
      </Hint>

      {state === null && !err && <Hint>Loading…</Hint>}
      {err && <Hint warn>{err}</Hint>}

      {state && (
        <div style={{ maxWidth: 560 }}>
          <DeploymentModePicker
            mode={state.mode}
            firewallCapable={state.firewallCapable}
            busy={busy}
            onSelect={(m) => setPending(m)}
          />
        </div>
      )}

      {pending && consequence && (
        <ConfirmModal
          title="Change deployment mode?"
          message={consequence.message}
          confirmLabel={busy ? 'SWITCHING…' : 'SWITCH MODE'}
          danger={consequence.danger}
          onConfirm={() => apply(pending)}
          onCancel={() => setPending(null)}
        />
      )}
    </>
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
