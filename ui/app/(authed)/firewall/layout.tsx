'use client';

import { ShieldAlert } from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  applyFirewall,
  listFirewallState,
  openFirewallWS,
  reconcileFirewall,
} from '../../../lib/api';
import type { FirewallNodeState } from '../../../lib/types';
import {
  Badge,
  Btn,
  DIM,
  HAIR,
  PageHeader,
  PageShell,
  PageTabs,
  type PageTab,
} from '../../../components/kit';
import { MONO } from '../../../components/ui-theme';

const TABS: PageTab[] = [
  { label: 'OVERVIEW', href: '/firewall' },
  { label: 'PORT FORWARDS', href: '/firewall/port-forwards' },
  { label: 'RULES', href: '/firewall/rules' },
  { label: 'WAN', href: '/firewall/wan' },
  { label: 'WIREGUARD', href: '/firewall/wireguard' },
  { label: 'ADVANCED', href: '/firewall/advanced' },
];

export default function FirewallLayout({ children }: { children: React.ReactNode }) {
  const [states, setStates] = useState<FirewallNodeState[]>([]);
  const [busy, setBusy] = useState<'apply' | 'reconcile' | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    refresh();
    const close = openFirewallWS(refresh);
    return close;
  }, []);

  function refresh() {
    listFirewallState().then(setStates).catch(() => {});
  }

  async function act(which: 'apply' | 'reconcile') {
    setBusy(which);
    setErr(null);
    try {
      await (which === 'apply' ? applyFirewall() : reconcileFirewall());
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  // v0 explicitly supports exactly one firewall node (firewall-integration.md
  // §9). Picking states[0] for the header chip; if a future v2 HA pair lands,
  // we'll switch to a multi-chip treatment.
  const primary = states[0];

  return (
    <PageShell>
      <PageHeader
        icon={ShieldAlert}
        title="FIREWALL"
        right={
          primary ? (
            <>
              <FirewallStateChip state={primary} />
              <Btn variant="primary" small disabled={busy !== null} onClick={() => act('apply')}>
                {busy === 'apply' ? 'APPLYING…' : 'APPLY'}
              </Btn>
              <Btn small disabled={busy !== null} onClick={() => act('reconcile')}>
                {busy === 'reconcile' ? 'RECONCILING…' : 'RECONCILE'}
              </Btn>
            </>
          ) : undefined
        }
      />
      {err && (
        <div
          style={{
            padding: '8px 20px',
            borderBottom: `1px solid ${HAIR}`,
            color: '#f87171',
            fontSize: 10,
            fontFamily: MONO,
            flexShrink: 0,
          }}
        >
          {err}
        </div>
      )}
      <PageTabs tabs={TABS} />
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>{children}</div>
    </PageShell>
  );
}

function FirewallStateChip({ state }: { state: FirewallNodeState }) {
  const status: 'in-sync' | 'drift' | 'unknown' = state.drift
    ? 'drift'
    : state.lastApplied
    ? 'in-sync'
    : 'unknown';
  const color = status === 'in-sync' ? '#4ade80' : status === 'drift' ? '#facc15' : DIM;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <Badge color={color}>{status === 'in-sync' ? 'IN SYNC' : status.toUpperCase()}</Badge>
      <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>
        {state.lastApplied
          ? `applied ${new Date(state.lastApplied).toLocaleTimeString()}`
          : 'never applied'}
      </span>
    </div>
  );
}
