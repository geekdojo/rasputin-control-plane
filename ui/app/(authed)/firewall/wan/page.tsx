'use client';

import { Pencil, Trash2 } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { createIntent, deleteIntent, listIntents, updateIntent } from '../../../../lib/api';
import { useFirewallStateRefresh } from '../../../../lib/firewall-state-context';
import type { FirewallIntent, WANConfigSpec, WANProto } from '../../../../lib/types';
import {
  Btn,
  DIM,
  EnabledToggle,
  FG,
  Hint,
  Input,
  SectionLabel,
  Select,
  Tok,
  tdStyle,
  thStyle,
} from '../../../../components/kit';
import { MONO } from '../../../../components/ui-theme';

export default function WANPage() {
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
    if (!confirm('Delete this WAN config? It will remain on the firewall until you Apply again.')) return;
    try {
      await deleteIntent(id);
      setIntents((prev) => prev.filter((p) => p.id !== id));
      if (editing?.id === id) setEditing(null);
      refreshFirewallState();
    } catch (e) {
      setErr(String(e));
    }
  }

  // Toggling ON implicitly disables sibling wan_configs on the api side. Refetch
  // the full list rather than patching the single row — sibling rows may have
  // flipped to OFF and we want the table to reflect that immediately.
  async function handleToggle(intent: FirewallIntent) {
    try {
      await updateIntent(intent.id, { enabled: !intent.enabled });
      refresh();
      refreshFirewallState();
    } catch (e) {
      setErr(String(e));
    }
  }

  const wanConfigs = intents.filter((i) => i.kind === 'wan_config');
  const noneEnabled = wanConfigs.length > 0 && !wanConfigs.some((w) => w.enabled);

  return (
    <>
      <Hint style={{ marginBottom: 14 }}>
        WAN configs for the firewall&apos;s upstream interface. Keep multiple profiles around
        (<Tok>isp-primary</Tok>, <Tok>isp-backup</Tok>); turning one ON automatically turns the
        others OFF. With <strong>zero</strong> rows, Rasputin doesn&apos;t manage WAN — whatever
        the firewall&apos;s stock config does is in effect. Once you add a row, Rasputin owns the
        section.
      </Hint>

      {noneEnabled && (
        <Hint warn style={{ marginBottom: 14 }}>
          ⚠ No WAN config is enabled. On the next APPLY the firewall&apos;s WAN interface will be
          administratively brought down — outbound traffic blocked. Enable a row to restore
          connectivity.
        </Hint>
      )}

      {err && (
        <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}>{err}</div>
      )}

      <SectionLabel>WAN CONFIGS</SectionLabel>
      {wanConfigs.length === 0 ? (
        <Hint style={{ marginBottom: 24 }}>
          no WAN configs — the firewall&apos;s stock config is in effect. Add one below for
          Rasputin to take over.
        </Hint>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 24 }}>
          <thead>
            <tr>
              {['NAME', 'PROTO', 'DETAILS', ''].map((c, i) => (
                <th key={c || i} style={thStyle}>
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {wanConfigs.map((i) => {
              const spec = i.spec as WANConfigSpec;
              const nameColor = i.enabled ? FG : DIM;
              const cellColor = i.enabled ? DIM : 'rgba(138, 155, 181, 0.55)';
              const isEditing = editing?.id === i.id;
              return (
                <tr
                  key={i.id}
                  style={isEditing ? { background: 'rgba(228,230,234,0.04)' } : undefined}
                >
                  <td style={{ ...tdStyle, color: nameColor }}>{i.name}</td>
                  <td style={{ ...tdStyle, color: cellColor }}>{spec.proto}</td>
                  <td style={{ ...tdStyle, color: cellColor }}>{specSummary(spec)}</td>
                  <td style={{ ...tdStyle, paddingRight: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6 }}>
                      <EnabledToggle enabled={i.enabled} onToggle={() => handleToggle(i)} />
                      <Btn small onClick={() => setEditing(i)} title="Edit this WAN config">
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
          {editing ? `EDIT WAN — ${editing.name}` : 'ADD WAN CONFIG'}
        </SectionLabel>
        <WANForm
          editing={editing}
          onCreated={(i) => {
            setIntents((p) => [...p, i]);
            refreshFirewallState();
            refresh();
          }}
          onUpdated={(i) => {
            setIntents((prev) => prev.map((p) => (p.id === i.id ? i : p)));
            setEditing(null);
            refreshFirewallState();
            refresh();
          }}
          onCancelEdit={() => setEditing(null)}
        />
      </div>
    </>
  );
}

function specSummary(spec: WANConfigSpec): string {
  switch (spec.proto) {
    case 'dhcp':
      return spec.hostname ? `hostname=${spec.hostname}` : 'auto';
    case 'static':
      return `${spec.ip ?? '?'} via ${spec.gateway ?? '?'}${spec.dns?.length ? ` · dns ${spec.dns.join(', ')}` : ''}`;
    case 'pppoe':
      return `${spec.username ?? '?'}${spec.service ? ` · ${spec.service}` : ''}`;
    default:
      return '';
  }
}

function WANForm({
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
  const [proto, setProto] = useState<WANProto>('dhcp');
  const [enabled, setEnabled] = useState(true);
  // DHCP
  const [hostname, setHostname] = useState('');
  // Static
  const [ip, setIp] = useState('');
  const [gateway, setGateway] = useState('');
  const [dns, setDns] = useState(''); // comma-separated for the input
  // PPPoE
  const [username, setUsername] = useState('');
  const [secret, setSecret] = useState('');
  const [service, setService] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function resetFields() {
    setName('');
    setProto('dhcp');
    setEnabled(true);
    setHostname('');
    setIp('');
    setGateway('');
    setDns('');
    setUsername('');
    setSecret('');
    setService('');
    setErr(null);
  }

  useEffect(() => {
    if (!editing) return;
    const s = editing.spec as WANConfigSpec;
    setName(editing.name);
    setEnabled(editing.enabled);
    setProto(s.proto);
    setHostname(s.hostname ?? '');
    setIp(s.ip ?? '');
    setGateway(s.gateway ?? '');
    setDns((s.dns ?? []).join(', '));
    setUsername(s.username ?? '');
    setSecret(s.secret ?? '');
    setService(s.service ?? '');
    setErr(null);
    requestAnimationFrame(() => document.getElementById('wan-name')?.focus());
  }, [editing]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const spec = buildSpec(proto, { hostname, ip, gateway, dns, username, secret, service });
      if (editing) {
        const updated = await updateIntent(editing.id, { name, enabled, spec });
        onUpdated(updated);
        resetFields();
      } else {
        const created = await createIntent({
          kind: 'wan_config',
          name,
          enabled,
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
    <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 12, maxWidth: 720 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <Input
          id="wan-name"
          placeholder="name (e.g. isp-primary, isp-backup)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          style={{ flex: '1 1 220px' }}
        />
        <Select value={proto} onChange={(e) => setProto(e.target.value as WANProto)}>
          <option value="dhcp">DHCP</option>
          <option value="static">Static</option>
          <option value="pppoe">PPPoE</option>
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
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            style={{ accentColor: '#fa3c04' }}
          />
          active
        </label>
      </div>

      {proto === 'dhcp' && (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <Input
            placeholder="hostname (optional, client-id sent to DHCP server)"
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            style={{ flex: '1 1 320px' }}
          />
        </div>
      )}

      {proto === 'static' && (
        <>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
            <Input
              placeholder="IP / CIDR (e.g. 203.0.113.5/24)"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              required
              style={{ flex: '1 1 200px' }}
            />
            <Input
              placeholder="gateway (e.g. 203.0.113.1)"
              value={gateway}
              onChange={(e) => setGateway(e.target.value)}
              required
              style={{ flex: '1 1 180px' }}
            />
          </div>
          <Input
            placeholder="DNS servers (comma-separated, optional)"
            value={dns}
            onChange={(e) => setDns(e.target.value)}
            style={{ flex: '1 1 300px' }}
          />
        </>
      )}

      {proto === 'pppoe' && (
        <>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
            <Input
              placeholder="PPPoE username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              style={{ flex: '1 1 220px' }}
            />
            <Input
              placeholder="PPPoE secret"
              type="password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              required
              style={{ flex: '1 1 220px' }}
            />
          </div>
          <Input
            placeholder="service name (optional, ISP-specific)"
            value={service}
            onChange={(e) => setService(e.target.value)}
            style={{ flex: '1 1 220px' }}
          />
        </>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <Btn type="submit" variant="primary" disabled={busy || !name}>
          {busy
            ? editing
              ? 'UPDATING…'
              : 'ADDING…'
            : editing
            ? 'UPDATE WAN'
            : 'ADD WAN'}
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

function buildSpec(
  proto: WANProto,
  fields: {
    hostname: string;
    ip: string;
    gateway: string;
    dns: string;
    username: string;
    secret: string;
    service: string;
  },
): WANConfigSpec {
  switch (proto) {
    case 'dhcp':
      return { proto, ...(fields.hostname && { hostname: fields.hostname }) };
    case 'static':
      return {
        proto,
        ip: fields.ip,
        gateway: fields.gateway,
        ...(fields.dns && {
          dns: fields.dns
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean),
        }),
      };
    case 'pppoe':
      return {
        proto,
        username: fields.username,
        secret: fields.secret,
        ...(fields.service && { service: fields.service }),
      };
  }
}
