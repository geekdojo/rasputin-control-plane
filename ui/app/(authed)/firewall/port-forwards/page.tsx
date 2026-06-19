'use client';

import { Pencil, Trash2 } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import {
  createIntent,
  deleteIntent,
  listIntents,
  updateIntent,
} from '../../../../lib/api';
import { useFirewallStateRefresh } from '../../../../lib/firewall-state-context';
import type { FirewallIntent, PortForwardProto, PortForwardSpec } from '../../../../lib/types';
import {
  Btn,
  DIM,
  EnabledToggle,
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
  const [editing, setEditing] = useState<FirewallIntent | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const formRef = useRef<HTMLDivElement>(null);
  const refreshFirewallState = useFirewallStateRefresh();

  useEffect(() => {
    refresh();
  }, []);

  useEffect(() => {
    if (editing) formRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [editing]);

  function refresh() {
    listIntents().then(setIntents).catch((e) => setErr(String(e)));
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this intent? It will remain on the firewall until you Apply again.')) return;
    try {
      await deleteIntent(id);
      setIntents((prev) => prev.filter((p) => p.id !== id));
      if (editing?.id === id) setEditing(null);
      refreshFirewallState();
    } catch (e) {
      setErr(String(e));
    }
  }

  async function handleToggle(intent: FirewallIntent) {
    try {
      const updated = await updateIntent(intent.id, { enabled: !intent.enabled });
      setIntents((prev) => prev.map((p) => (p.id === updated.id ? updated : p)));
      refreshFirewallState();
    } catch (e) {
      setErr(String(e));
    }
  }

  // Until other intent kinds ship on this tab, the list is port-forwards only.
  // The api returns every kind; we filter so the column headers stay accurate.
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
            {portForwards.map((i) => {
              const spec = i.spec as PortForwardSpec;
              const nameColor = i.enabled ? FG : DIM;
              const cellColor = i.enabled ? DIM : 'rgba(138, 155, 181, 0.55)';
              const isEditing = editing?.id === i.id;
              return (
                <tr
                  key={i.id}
                  style={isEditing ? { background: 'rgba(var(--rasp-fg-rgb),0.04)' } : undefined}
                >
                  <td style={{ ...tdStyle, color: nameColor }}>{i.name}</td>
                  <td style={{ ...tdStyle, color: cellColor }}>{spec.wanPort}</td>
                  <td style={{ ...tdStyle, color: cellColor }}>
                    {spec.lanHost}:{spec.lanPort}
                  </td>
                  <td style={{ ...tdStyle, color: cellColor }}>{spec.protocol}</td>
                  <td style={{ ...tdStyle, paddingRight: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6 }}>
                      <EnabledToggle enabled={i.enabled} onToggle={() => handleToggle(i)} />
                      <Btn small onClick={() => setEditing(i)} title="Edit this port forward">
                        <Pencil size={10} /> EDIT
                      </Btn>
                      <Btn variant="danger" small onClick={() => handleDelete(i.id)}>
                        <Trash2 size={10} /> DELETE
                      </Btn>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      <div ref={formRef} style={{ scrollMarginTop: 16 }}>
        <SectionLabel>
          {editing ? `EDIT PORT FORWARD — ${editing.name}` : 'ADD PORT FORWARD'}
        </SectionLabel>
        <PortForwardForm
          editing={editing}
          onCreated={(i) => {
            setIntents((p) => [...p, i]);
            refreshFirewallState();
          }}
          onUpdated={(i) => {
            setIntents((prev) => prev.map((p) => (p.id === i.id ? i : p)));
            setEditing(null);
            refreshFirewallState();
          }}
          onCancelEdit={() => setEditing(null)}
        />
      </div>
    </>
  );
}

function PortForwardForm({
  editing,
  onCreated,
  onUpdated,
  onCancelEdit,
}: {
  editing: FirewallIntent | null;
  onCreated: (i: FirewallIntent) => void;
  onUpdated: (i: FirewallIntent) => void;
  onCancelEdit: () => void;
}) {
  const [name, setName] = useState('');
  const [wanPort, setWanPort] = useState('');
  const [lanHost, setLanHost] = useState('');
  const [lanPort, setLanPort] = useState('');
  const [protocol, setProtocol] = useState<PortForwardProto>('tcp');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function resetFields() {
    setName('');
    setWanPort('');
    setLanHost('');
    setLanPort('');
    setProtocol('tcp');
    setErr(null);
  }

  useEffect(() => {
    if (!editing) return;
    const s = editing.spec as PortForwardSpec;
    setName(editing.name);
    setWanPort(String(s.wanPort));
    setLanHost(s.lanHost);
    setLanPort(String(s.lanPort));
    setProtocol(s.protocol);
    setErr(null);
    requestAnimationFrame(() => document.getElementById('pf-name')?.focus());
  }, [editing]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const spec: PortForwardSpec = {
        wanPort: Number(wanPort),
        lanHost,
        lanPort: Number(lanPort),
        protocol,
      };
      if (editing) {
        const updated = await updateIntent(editing.id, { name, spec });
        onUpdated(updated);
        resetFields();
      } else {
        const created = await createIntent({
          kind: 'port_forward',
          name,
          enabled: true,
          spec,
        });
        onCreated(created);
        resetFields();
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  function cancel() {
    resetFields();
    onCancelEdit();
  }

  return (
    <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 10, maxWidth: 720 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <Input
          id="pf-name"
          placeholder="name (e.g. minecraft)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          style={{ flex: '1 1 160px' }}
        />
        <Input
          placeholder="WAN port"
          value={wanPort}
          onChange={(e) => setWanPort(e.target.value)}
          inputMode="numeric"
          required
          style={{ width: 100 }}
        />
        <span style={{ color: DIM }}>→</span>
        <Input
          placeholder="LAN host (10.0.0.50)"
          value={lanHost}
          onChange={(e) => setLanHost(e.target.value)}
          required
          style={{ flex: '1 1 160px' }}
        />
        <Input
          placeholder="LAN port"
          value={lanPort}
          onChange={(e) => setLanPort(e.target.value)}
          inputMode="numeric"
          required
          style={{ width: 100 }}
        />
        <Select value={protocol} onChange={(e) => setProtocol(e.target.value as PortForwardProto)}>
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
          <option value="tcpudp">tcp+udp</option>
        </Select>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <Btn type="submit" variant="primary" disabled={busy || !name || !wanPort || !lanHost || !lanPort}>
          {busy
            ? editing
              ? 'UPDATING…'
              : 'ADDING…'
            : editing
            ? 'UPDATE FORWARD'
            : 'ADD FORWARD'}
        </Btn>
        {editing && (
          <Btn onClick={cancel} disabled={busy}>
            CANCEL
          </Btn>
        )}
        {err && <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{err}</span>}
      </div>
    </form>
  );
}
