'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { listFirewallState, listIntents } from '../../../lib/api';
import type { FirewallIntent, FirewallNodeState } from '../../../lib/types';
import {
  DIM,
  FG,
  HAIR,
  Hint,
  PANEL,
  SectionLabel,
  Tok,
} from '../../../components/kit';
import { ACCENT, MONO } from '../../../components/ui-theme';

export default function FirewallOverview() {
  const [intents, setIntents] = useState<FirewallIntent[]>([]);
  const [states, setStates] = useState<FirewallNodeState[]>([]);

  useEffect(() => {
    listIntents().then(setIntents).catch(() => {});
    listFirewallState().then(setStates).catch(() => {});
  }, []);

  if (states.length === 0) {
    return (
      <Hint>
        No firewall-role agent is registered. Start one with <Tok>RASPUTIN_NODE_ROLE=firewall</Tok>.
      </Hint>
    );
  }

  const counts = countByKind(intents);

  return (
    <>
      <SectionLabel>WHAT&apos;S MANAGED</SectionLabel>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginBottom: 24 }}>
        <CountTile label="PORT FORWARDS" count={counts.port_forward} href="/firewall/port-forwards" />
        <CountTile label="RULES" count={counts.firewall_rule} href="/firewall/rules" />
        <CountTile label="WAN CONFIGS" count={counts.wan_config} href="/firewall/wan" />
        <CountTile label="WIREGUARD PEERS" count={0} href="/firewall/wireguard" comingSoon />
      </div>

      <SectionLabel>NEXT</SectionLabel>
      <Hint>
        Port forwards, zone-based rules, and WAN configs are live. WireGuard peers land once the
        Headscale mesh has settled (see F-5). The firewall&apos;s native admin UI is the escape
        hatch for anything Rasputin doesn&apos;t expose — see{' '}
        <Link href="/firewall/advanced" style={{ color: ACCENT, textDecoration: 'none' }}>
          ADVANCED
        </Link>
        .
      </Hint>
    </>
  );
}

function countByKind(intents: FirewallIntent[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const i of intents) {
    out[i.kind] = (out[i.kind] ?? 0) + 1;
  }
  return { port_forward: 0, firewall_rule: 0, wan_config: 0, ...out };
}

function CountTile({
  label,
  count,
  href,
  comingSoon = false,
}: {
  label: string;
  count: number;
  href: string;
  comingSoon?: boolean;
}) {
  return (
    <Link
      href={href}
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 6,
        padding: '12px 16px',
        minWidth: 140,
        background: PANEL,
        border: `1px solid ${HAIR}`,
        textDecoration: 'none',
        opacity: comingSoon ? 0.6 : 1,
      }}
    >
      <span style={{ color: DIM, fontSize: 9, fontFamily: MONO, letterSpacing: '0.12em' }}>{label}</span>
      <span style={{ color: comingSoon ? DIM : FG, fontSize: 22, fontFamily: MONO }}>
        {comingSoon ? '—' : count}
      </span>
      {comingSoon && (
        <span style={{ color: DIM, fontSize: 8, fontFamily: MONO, letterSpacing: '0.08em' }}>SOON</span>
      )}
    </Link>
  );
}
