'use client';

import { Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { createIntent, deleteIntent, listIntents } from '../../../../lib/api';
import type {
  FirewallIntent,
  FirewallRuleProto,
  FirewallRuleSpec,
  FirewallRuleTarget,
} from '../../../../lib/types';
import {
  Btn,
  DIM,
  FG,
  Hint,
  Input,
  Select,
  SectionLabel,
  Tok,
  tdStyle,
  thStyle,
} from '../../../../components/kit';
import { ACCENT, MONO } from '../../../../components/ui-theme';

export default function RulesPage() {
  const [intents, setIntents] = useState<FirewallIntent[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    refresh();
  }, []);

  function refresh() {
    listIntents().then(setIntents).catch((e) => setErr(String(e)));
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this rule? It will remain on the firewall until you Apply again.')) return;
    try {
      await deleteIntent(id);
      setIntents((prev) => prev.filter((p) => p.id !== id));
    } catch (e) {
      setErr(String(e));
    }
  }

  const rules = intents.filter((i) => i.kind === 'firewall_rule');

  return (
    <>
      <Hint style={{ marginBottom: 14 }}>
        Zone-based accept/reject/drop rules. <Tok>SRC</Tok> is the originating zone (wan, lan, iot,
        …); leave <Tok>DEST</Tok> blank to target the firewall itself (e.g. allow SSH from LAN to
        the router). Changes don&apos;t take effect until you click <Tok>APPLY</Tok>.
      </Hint>

      {err && (
        <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}>{err}</div>
      )}

      <SectionLabel>RULES</SectionLabel>
      {rules.length === 0 ? (
        <Hint style={{ marginBottom: 24 }}>no rules yet</Hint>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 24 }}>
          <thead>
            <tr>
              {['NAME', 'SRC', 'DEST', 'SRC IP', 'DEST IP', 'PORT', 'PROTO', 'TARGET', ''].map((c, i) => (
                <th key={c || i} style={thStyle}>
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rules.map((i) => {
              const spec = i.spec as FirewallRuleSpec;
              return (
                <tr key={i.id}>
                  <td style={{ ...tdStyle, color: FG }}>
                    {i.name}
                    {!i.enabled && <span style={{ color: DIM, marginLeft: 8, fontSize: 9 }}>(disabled)</span>}
                  </td>
                  <td style={{ ...tdStyle, color: DIM }}>{spec.src}</td>
                  <td style={{ ...tdStyle, color: DIM }}>{spec.dest || '(input)'}</td>
                  <td style={{ ...tdStyle, color: DIM }}>{spec.srcIp || '—'}</td>
                  <td style={{ ...tdStyle, color: DIM }}>{spec.destIp || '—'}</td>
                  <td style={{ ...tdStyle, color: DIM }}>
                    {fmtPorts(spec.srcPort, spec.destPort)}
                  </td>
                  <td style={{ ...tdStyle, color: DIM }}>{spec.proto || 'any'}</td>
                  <td style={tdStyle}>
                    <span style={{ color: targetColor(spec.target), fontSize: 10, fontFamily: MONO }}>
                      {spec.target.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ ...tdStyle, paddingRight: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
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

      <SectionLabel>ADD RULE</SectionLabel>
      <AddRuleForm onCreated={(i) => setIntents((p) => [...p, i])} />
    </>
  );
}

function fmtPorts(src?: string, dest?: string): string {
  if (src && dest) return `${src} → ${dest}`;
  if (dest) return `→ ${dest}`;
  if (src) return `${src} →`;
  return '—';
}

function targetColor(t: FirewallRuleTarget): string {
  switch (t) {
    case 'accept':
      return '#4ade80';
    case 'reject':
      return '#facc15';
    case 'drop':
      return '#f87171';
    default:
      return ACCENT;
  }
}

function AddRuleForm({ onCreated }: { onCreated: (i: FirewallIntent) => void }) {
  const [name, setName] = useState('');
  const [src, setSrc] = useState('lan');
  const [dest, setDest] = useState('');
  const [srcIp, setSrcIp] = useState('');
  const [srcPort, setSrcPort] = useState('');
  const [destIp, setDestIp] = useState('');
  const [destPort, setDestPort] = useState('');
  const [protocol, setProtocol] = useState<FirewallRuleProto>('any');
  const [target, setTarget] = useState<FirewallRuleTarget>('accept');
  const [log, setLog] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const spec: FirewallRuleSpec = {
        src,
        target,
        ...(dest && { dest }),
        ...(srcIp && { srcIp }),
        ...(srcPort && { srcPort }),
        ...(destIp && { destIp }),
        ...(destPort && { destPort }),
        ...(protocol !== 'any' && { proto: protocol }),
        ...(log && { log: true }),
      };
      const created = await createIntent({
        kind: 'firewall_rule',
        name,
        enabled: true,
        spec,
      });
      onCreated(created);
      setName('');
      setDest('');
      setSrcIp('');
      setSrcPort('');
      setDestIp('');
      setDestPort('');
      setProtocol('any');
      setTarget('accept');
      setLog(false);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 12, maxWidth: 780 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <Input
          placeholder="name (e.g. block-iot-egress)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          style={{ flex: '1 1 220px' }}
        />
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <FieldLabel>FROM</FieldLabel>
        <Input
          placeholder="src zone (lan, iot, wan)"
          value={src}
          onChange={(e) => setSrc(e.target.value)}
          required
          style={{ width: 140 }}
        />
        <Input
          placeholder="src IP/CIDR (optional)"
          value={srcIp}
          onChange={(e) => setSrcIp(e.target.value)}
          style={{ flex: '1 1 180px' }}
        />
        <Input
          placeholder="src port (optional)"
          value={srcPort}
          onChange={(e) => setSrcPort(e.target.value)}
          style={{ width: 140 }}
        />
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <FieldLabel>TO</FieldLabel>
        <Input
          placeholder="dest zone (blank → firewall itself)"
          value={dest}
          onChange={(e) => setDest(e.target.value)}
          style={{ width: 220 }}
        />
        <Input
          placeholder="dest IP/CIDR (optional)"
          value={destIp}
          onChange={(e) => setDestIp(e.target.value)}
          style={{ flex: '1 1 180px' }}
        />
        <Input
          placeholder="dest port (optional)"
          value={destPort}
          onChange={(e) => setDestPort(e.target.value)}
          style={{ width: 140 }}
        />
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <FieldLabel>WHEN</FieldLabel>
        <Select value={protocol} onChange={(e) => setProtocol(e.target.value as FirewallRuleProto)}>
          <option value="any">any proto</option>
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
          <option value="tcpudp">tcp+udp</option>
          <option value="icmp">icmp</option>
        </Select>
        <FieldLabel>THEN</FieldLabel>
        <Select value={target} onChange={(e) => setTarget(e.target.value as FirewallRuleTarget)}>
          <option value="accept">accept</option>
          <option value="reject">reject</option>
          <option value="drop">drop</option>
        </Select>
        <label
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            color: DIM,
            fontSize: 10,
            fontFamily: MONO,
            cursor: 'pointer',
          }}
        >
          <input
            type="checkbox"
            checked={log}
            onChange={(e) => setLog(e.target.checked)}
            style={{ accentColor: ACCENT }}
          />
          log matches
        </label>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <Btn type="submit" variant="primary" disabled={busy || !name || !src}>
          {busy ? 'ADDING…' : 'ADD RULE'}
        </Btn>
        {err && <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{err}</span>}
      </div>
    </form>
  );
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <span style={{ color: DIM, fontSize: 9, fontFamily: MONO, letterSpacing: '0.12em', minWidth: 40 }}>
      {children}
    </span>
  );
}
