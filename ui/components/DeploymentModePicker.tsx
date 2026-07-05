'use client';

// Shared deployment-mode picker — the three-way topology chooser used by BOTH
// the first-run wizard (app/(authed)/setup) and the post-setup Settings surface
// (app/(authed)/settings). Presentational: it renders the mode cards + the
// "which is right for me?" help toggle + the firewall-node hint, and calls
// onSelect when the operator picks a *different* mode. The parent owns what
// happens next (the wizard applies immediately; Settings confirms first,
// because a post-setup change to LAN-peer idles a live firewall).

import { Check, Circle } from 'lucide-react';
import { useState } from 'react';
import type { DeploymentMode } from '../lib/types';
import { Badge, DIM, FG, HAIR } from './kit';
import { ACCENT, accentA, MONO } from './ui-theme';

// The three deployment topologies. `summary` is the always-visible one-liner;
// `detail` is the fuller "which is right for me?" explanation. Copy is
// deliberately vendor-neutral — no "firewall image"/OpenWrt/router brands.
export const MODES: {
  id: Exclude<DeploymentMode, ''>;
  label: string;
  summary: string;
  detail: string;
  needsFirewall: boolean;
  recommended?: boolean;
}[] = [
  {
    id: 'router',
    label: 'Rasputin runs my internet connection',
    summary: 'Plug your internet straight into Rasputin — it becomes your router and firewall.',
    detail:
      'Plug the cable from your modem straight into Rasputin. It becomes your home’s router — handing out addresses, running the firewall, and watching traffic for threats. The most control, and the biggest change to your network. Choose this if you’re ready to replace your current router.',
    needsFirewall: true,
  },
  {
    id: 'lan_peer',
    label: 'Join my existing network',
    summary: 'Keep your current router. Rasputin plugs in as just another device.',
    detail:
      'Keep your current router. Plug Rasputin into a spare network port like any other device. Your existing router keeps doing the firewalling; Rasputin runs your apps, storage, and remote access. The simplest, lowest-risk way to start — nothing about your home network changes.',
    needsFirewall: false,
  },
  {
    id: 'sub_segment',
    label: 'Give Rasputin its own protected network to learn on',
    summary: 'Keep your current router, but branch off a walled-off network you can experiment with safely.',
    detail:
      'Keep your current router, but give Rasputin its own walled-off network branching off it. You get to set up and experiment with the firewall, threat detection, and network rules on a real network — without any risk to the family’s Wi-Fi. The recommended way to learn how everything works. (Your traffic passes through two routers, which is fine for almost everything.)',
    needsFirewall: true,
    recommended: true,
  },
];

function Mono({ children }: { children: React.ReactNode }) {
  return <span style={{ color: FG }}>{children}</span>;
}

export function DeploymentModePicker({
  mode,
  firewallCapable,
  busy,
  onSelect,
  showFirewallHint = true,
}: {
  mode: DeploymentMode;
  firewallCapable: boolean;
  busy: boolean;
  // Fired only when the operator picks a mode other than the current one.
  onSelect: (m: Exclude<DeploymentMode, ''>) => void;
  showFirewallHint?: boolean;
}) {
  const [showHelp, setShowHelp] = useState(false);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <button
        type="button"
        onClick={() => setShowHelp((v) => !v)}
        style={{
          alignSelf: 'flex-start',
          background: 'transparent',
          border: 'none',
          padding: 0,
          color: ACCENT,
          fontSize: 10,
          fontFamily: MONO,
          cursor: 'pointer',
          letterSpacing: '0.04em',
        }}
      >
        {showHelp ? '– ' : '+ '}Which mode is right for me?
      </button>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {MODES.map((m) => {
          const selected = mode === m.id;
          const locked = m.needsFirewall && !firewallCapable;
          // The current mode is shown selected but isn't a click target — a
          // change means picking a *different* card.
          const disabled = busy || locked || selected;
          return (
            <button
              key={m.id}
              type="button"
              disabled={disabled}
              onClick={() => !selected && onSelect(m.id)}
              title={locked ? 'Needs a firewall node — see below' : undefined}
              style={{
                textAlign: 'left',
                background: selected ? accentA(0.1) : 'transparent',
                border: `1px solid ${selected ? ACCENT : HAIR}`,
                padding: '10px 12px',
                cursor: disabled ? (locked ? 'not-allowed' : 'default') : 'pointer',
                opacity: locked ? 0.4 : 1,
                display: 'flex',
                flexDirection: 'column',
                gap: 4,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                {selected ? <Check size={12} color={ACCENT} /> : <Circle size={12} color={DIM} />}
                <span style={{ color: FG, fontSize: 11, fontFamily: MONO, letterSpacing: '0.03em' }}>{m.label}</span>
                {m.recommended && <Badge color={ACCENT}>RECOMMENDED FOR LEARNING</Badge>}
                {selected && <Badge color={ACCENT}>CURRENT</Badge>}
              </div>
              <p style={{ color: DIM, fontSize: 10, fontFamily: MONO, lineHeight: 1.6, margin: 0, paddingLeft: 20 }}>
                {showHelp ? m.detail : m.summary}
              </p>
            </button>
          );
        })}
      </div>

      {showFirewallHint && !firewallCapable && (
        <p style={{ color: DIM, fontSize: 10, fontFamily: MONO, lineHeight: 1.6, margin: 0 }}>
          Running Rasputin as your router or a learning network needs a firewall node — a small
          dedicated box with two network ports. We recommend a{' '}
          <Mono>CWWK x86-P5 (Intel N100, dual 2.5GbE)</Mono> or equivalent. Have one that’s still
          starting up? Refresh once it’s online. Without one, you can still join your existing
          network above.
        </p>
      )}
    </div>
  );
}
