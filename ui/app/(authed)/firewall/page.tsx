'use client';

import { ShieldAlert, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { useEffect } from 'react';
import {
  applyFirewall,
  createIntent,
  deleteIntent,
  listFirewallState,
  listIntents,
  openFirewallWS,
  reconcileFirewall,
} from '../../../lib/api';
import type { FirewallIntent, FirewallNodeState, PortForwardProto } from '../../../lib/types';
import {
  Badge,
  Btn,
  DIM,
  FG,
  HAIR,
  Hint,
  Input,
  PageBody,
  PageHeader,
  PageShell,
  PANEL,
  Select,
  SectionLabel,
  Tok,
  tdStyle,
  thStyle,
} from '../../../components/kit';
import { MONO } from '../../../components/ui-theme';

export default function FirewallPage() {
  const [intents, setIntents] = useState<FirewallIntent[]>([]);
  const [states, setStates] = useState<FirewallNodeState[]>([]);
  const [busy, setBusy] = useState<'apply' | 'reconcile' | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    refresh();
    const close = openFirewallWS(() => listFirewallState().then(setStates).catch(() => {}));
    return close;
  }, []);

  function refresh() {
    listIntents().then(setIntents).catch((e) => setErr(String(e)));
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

  async function handleDelete(id: string) {
    if (!confirm('Delete this intent? It will remain on the firewall until you Apply again.')) return;
    try {
      await deleteIntent(id);
      setIntents((prev) => prev.filter((p) => p.id !== id));
    } catch (e) {
      setErr(String(e));
    }
  }

  return (
    <PageShell>
      <PageHeader
        icon={ShieldAlert}
        title="FIREWALL"
        right={
          states.length > 0 ? (
            <>
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
      <PageBody>
        {states.length === 0 ? (
          <Hint style={{ marginBottom: 16 }}>
            No firewall-role agent is registered. Start one with <Tok>RASPUTIN_NODE_ROLE=firewall</Tok>.
          </Hint>
        ) : (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginBottom: 20 }}>
            {states.map((s) => (
              <FirewallStateChip key={s.nodeId} state={s} />
            ))}
          </div>
        )}

        {err && <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}>{err}</div>}

        <SectionLabel>PORT FORWARDS</SectionLabel>
        {intents.length === 0 ? (
          <Hint style={{ marginBottom: 24 }}>no intents yet</Hint>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 24 }}>
            <thead>
              <tr>
                {['NAME', 'WAN PORT', 'LAN TARGET', 'PROTO', ''].map((c, i) => (
                  <th key={c || i} style={thStyle}>
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {intents.map((i) => (
                <tr key={i.id}>
                  <td style={{ ...tdStyle, color: FG }}>
                    {i.name}
                    {!i.enabled && <span style={{ color: DIM, marginLeft: 8, fontSize: 9 }}>(disabled)</span>}
                  </td>
                  <td style={{ ...tdStyle, color: DIM }}>{i.spec.wanPort}</td>
                  <td style={{ ...tdStyle, color: DIM }}>
                    {i.spec.lanHost}:{i.spec.lanPort}
                  </td>
                  <td style={{ ...tdStyle, color: DIM }}>{i.spec.protocol}</td>
                  <td style={{ ...tdStyle, paddingRight: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                      <Btn variant="danger" small onClick={() => handleDelete(i.id)}>
                        <Trash2 size={10} /> DELETE
                      </Btn>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <SectionLabel>ADD PORT FORWARD</SectionLabel>
        <AddPortForwardForm onCreated={(i) => setIntents((p) => [...p, i])} />
      </PageBody>
    </PageShell>
  );
}

function FirewallStateChip({ state }: { state: FirewallNodeState }) {
  const status: 'in-sync' | 'drift' | 'unknown' = state.drift ? 'drift' : state.lastApplied ? 'in-sync' : 'unknown';
  const color = status === 'in-sync' ? '#4ade80' : status === 'drift' ? '#facc15' : DIM;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', background: PANEL, border: `1px solid ${HAIR}` }}>
      <span style={{ color: FG, fontSize: 10, fontFamily: MONO }}>{state.nodeId}</span>
      <Badge color={color}>{status === 'in-sync' ? 'IN SYNC' : status.toUpperCase()}</Badge>
      <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>
        {state.lastApplied ? `applied ${new Date(state.lastApplied).toLocaleTimeString()}` : 'never applied'}
      </span>
    </div>
  );
}

function AddPortForwardForm({ onCreated }: { onCreated: (i: FirewallIntent) => void }) {
  const [name, setName] = useState('');
  const [wanPort, setWanPort] = useState('');
  const [lanHost, setLanHost] = useState('');
  const [lanPort, setLanPort] = useState('');
  const [protocol, setProtocol] = useState<PortForwardProto>('tcp');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const created = await createIntent({
        kind: 'port_forward',
        name,
        enabled: true,
        spec: { wanPort: Number(wanPort), lanHost, lanPort: Number(lanPort), protocol },
      });
      onCreated(created);
      setName('');
      setWanPort('');
      setLanHost('');
      setLanPort('');
      setProtocol('tcp');
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 10, maxWidth: 720 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <Input placeholder="name (e.g. minecraft)" value={name} onChange={(e) => setName(e.target.value)} required style={{ flex: '1 1 160px' }} />
        <Input placeholder="WAN port" value={wanPort} onChange={(e) => setWanPort(e.target.value)} inputMode="numeric" required style={{ width: 100 }} />
        <span style={{ color: DIM }}>→</span>
        <Input placeholder="LAN host (10.0.0.50)" value={lanHost} onChange={(e) => setLanHost(e.target.value)} required style={{ flex: '1 1 160px' }} />
        <Input placeholder="LAN port" value={lanPort} onChange={(e) => setLanPort(e.target.value)} inputMode="numeric" required style={{ width: 100 }} />
        <Select value={protocol} onChange={(e) => setProtocol(e.target.value as PortForwardProto)}>
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
          <option value="tcpudp">tcp+udp</option>
        </Select>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <Btn type="submit" variant="primary" disabled={busy || !name || !wanPort || !lanHost || !lanPort}>
          {busy ? 'ADDING…' : 'ADD FORWARD'}
        </Btn>
        {err && <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{err}</span>}
      </div>
    </form>
  );
}
