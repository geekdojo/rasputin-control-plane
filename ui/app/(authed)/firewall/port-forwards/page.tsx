'use client';

import { Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  createIntent,
  deleteIntent,
  listIntents,
} from '../../../../lib/api';
import type { FirewallIntent, PortForwardProto } from '../../../../lib/types';
import {
  Btn,
  DIM,
  FG,
  Hint,
  Input,
  Select,
  SectionLabel,
  tdStyle,
  thStyle,
} from '../../../../components/kit';
import { MONO } from '../../../../components/ui-theme';

export default function PortForwardsPage() {
  const [intents, setIntents] = useState<FirewallIntent[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    refresh();
  }, []);

  function refresh() {
    listIntents().then(setIntents).catch((e) => setErr(String(e)));
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

  // Until other intent kinds ship, the list is port-forwards only. The api
  // returns every kind; we filter here so the column headers stay accurate
  // when wg_peer / firewall_rule land.
  const portForwards = intents.filter((i) => i.kind === 'port_forward');

  return (
    <>
      {err && (
        <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}>{err}</div>
      )}

      <SectionLabel>PORT FORWARDS</SectionLabel>
      {portForwards.length === 0 ? (
        <Hint style={{ marginBottom: 24 }}>no port forwards yet</Hint>
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
            {portForwards.map((i) => (
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
    </>
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
