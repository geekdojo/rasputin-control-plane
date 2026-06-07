'use client';

import { Pencil, Trash2 } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { createIntent, deleteIntent, listIntents, updateIntent } from '../../../../lib/api';
import type {
  FirewallIntent,
  FirewallRuleProto,
  FirewallRuleSpec,
  FirewallRuleTarget,
} from '../../../../lib/types';
import {
  Btn,
  DIM,
  EnabledToggle,
  FG,
  HAIR,
  Hint,
  Input,
  PANEL,
  Select,
  SectionLabel,
  Tok,
  tdStyle,
  thStyle,
} from '../../../../components/kit';
import { ACCENT, accentA, MONO } from '../../../../components/ui-theme';

// Templates pre-fill the add-rule form for the most-common patterns r/homelab
// asks about. Picking a template snapshots the entire form; the user then
// fills in the field listed in `needs` (when relevant), tweaks anything, and
// clicks ADD. Each template is intentionally self-contained — no hidden
// assumption that a complementary rule already exists.
type RulePreset = Partial<Omit<FirewallRuleSpec, 'target' | 'src'>> & {
  src: string;
  target: FirewallRuleTarget;
  name: string;
  log?: boolean;
};

type RuleTemplate = {
  id: string;
  title: string;
  description: string;
  preset: RulePreset;
  needs?: 'srcIp' | 'destIp' | 'destPort' | 'srcPort';
};

const TEMPLATES: RuleTemplate[] = [
  {
    id: 'block-internet',
    title: 'Block device from internet',
    description: 'Stop a specific LAN host (Roku, IoT cam, ad-supported smart TV) from reaching the WAN.',
    preset: {
      name: 'block-internet',
      src: 'lan',
      dest: 'wan',
      target: 'reject',
      proto: 'any',
    },
    needs: 'srcIp',
  },
  {
    id: 'tailnet-only',
    title: 'Open port from tailnet only',
    description: 'A service reachable over the tailnet but invisible from the LAN.',
    preset: {
      name: 'tailnet-only',
      src: 'ts',
      dest: '',
      target: 'accept',
      proto: 'tcp',
    },
    needs: 'destPort',
  },
  {
    id: 'isolate-iot',
    title: 'Isolate IoT from LAN',
    description: "IoT zone can't reach LAN. Internet still works (separate default rule).",
    preset: {
      name: 'isolate-iot',
      src: 'iot',
      dest: 'lan',
      target: 'reject',
      proto: 'any',
    },
  },
  {
    id: 'allow-ping',
    title: 'Allow ping to firewall',
    description: 'ICMP echo to the firewall itself — handy for connectivity checks.',
    preset: {
      name: 'allow-ping',
      src: 'lan',
      dest: '',
      target: 'accept',
      proto: 'icmp',
    },
  },
];

export default function RulesPage() {
  const [intents, setIntents] = useState<FirewallIntent[]>([]);
  const [err, setErr] = useState<string | null>(null);
  // Each template-click constructs a NEW preset object; AddRuleForm watches
  // by reference so re-picking the same template still resets fields.
  const [preset, setPreset] = useState<{ value: RulePreset; needs?: RuleTemplate['needs'] } | null>(
    null,
  );
  // `editing` is mutually exclusive with `preset` — picking a template clears
  // any in-progress edit, and clicking Edit clears any pending template.
  const [editing, setEditing] = useState<FirewallIntent | null>(null);
  const formRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    refresh();
  }, []);

  // Both template-pick and edit-start should bring the form back into view —
  // templates and the rules table both sit far from the form.
  useEffect(() => {
    if (preset || editing) formRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [preset, editing]);

  function refresh() {
    listIntents().then(setIntents).catch((e) => setErr(String(e)));
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this rule? It will remain on the firewall until you Apply again.')) return;
    try {
      await deleteIntent(id);
      setIntents((prev) => prev.filter((p) => p.id !== id));
      // Cancel any in-progress edit pointing at the now-gone row.
      if (editing?.id === id) setEditing(null);
    } catch (e) {
      setErr(String(e));
    }
  }

  async function handleToggle(intent: FirewallIntent) {
    try {
      const updated = await updateIntent(intent.id, { enabled: !intent.enabled });
      setIntents((prev) => prev.map((p) => (p.id === updated.id ? updated : p)));
    } catch (e) {
      setErr(String(e));
    }
  }

  function startEdit(intent: FirewallIntent) {
    setPreset(null);
    setEditing(intent);
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
              const nameColor = i.enabled ? FG : DIM;
              const cellColor = i.enabled ? DIM : 'rgba(138, 155, 181, 0.55)';
              const isEditing = editing?.id === i.id;
              return (
                <tr
                  key={i.id}
                  style={isEditing ? { background: 'rgba(228,230,234,0.04)' } : undefined}
                >
                  <td style={{ ...tdStyle, color: nameColor }}>{i.name}</td>
                  <td style={{ ...tdStyle, color: cellColor }}>{spec.src}</td>
                  <td style={{ ...tdStyle, color: cellColor }}>{spec.dest || '(input)'}</td>
                  <td style={{ ...tdStyle, color: cellColor }}>{spec.srcIp || '—'}</td>
                  <td style={{ ...tdStyle, color: cellColor }}>{spec.destIp || '—'}</td>
                  <td style={{ ...tdStyle, color: cellColor }}>{fmtPorts(spec.srcPort, spec.destPort)}</td>
                  <td style={{ ...tdStyle, color: cellColor }}>{spec.proto || 'any'}</td>
                  <td style={tdStyle}>
                    <span
                      style={{
                        color: i.enabled ? targetColor(spec.target) : DIM,
                        fontSize: 10,
                        fontFamily: MONO,
                      }}
                    >
                      {spec.target.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ ...tdStyle, paddingRight: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6 }}>
                      <EnabledToggle enabled={i.enabled} onToggle={() => handleToggle(i)} />
                      <Btn small onClick={() => startEdit(i)} title="Edit this rule">
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
          {editing ? `EDIT RULE — ${editing.name}` : 'ADD RULE'}
        </SectionLabel>
        <AddRuleForm
          preset={preset}
          editing={editing}
          onCreated={(i) => {
            setIntents((p) => [...p, i]);
            setPreset(null);
          }}
          onUpdated={(i) => {
            setIntents((prev) => prev.map((p) => (p.id === i.id ? i : p)));
            setEditing(null);
          }}
          onCancelEdit={() => setEditing(null)}
        />
      </div>

      {!editing && (
        <div style={{ marginTop: 28 }}>
          <SectionLabel>TEMPLATES</SectionLabel>
          <Hint style={{ marginBottom: 12 }}>
            Quick-fill the form above. Pick one, the form scrolls back into view; type any extra
            fields (highlighted in orange when a template needs them), then click ADD.
          </Hint>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
            {TEMPLATES.map((t) => (
              <TemplateCard
                key={t.id}
                template={t}
                onPick={() => setPreset({ value: { ...t.preset }, needs: t.needs })}
              />
            ))}
          </div>
        </div>
      )}
    </>
  );
}

function TemplateCard({ template, onPick }: { template: RuleTemplate; onPick: () => void }) {
  const [hover, setHover] = useState(false);
  return (
    <button
      type="button"
      onClick={onPick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'flex-start',
        gap: 6,
        padding: '10px 12px',
        width: 220,
        textAlign: 'left',
        background: hover ? accentA(0.08) : PANEL,
        border: `1px solid ${hover ? accentA(0.45) : HAIR}`,
        cursor: 'pointer',
        transition: 'background 0.15s, border-color 0.15s',
        fontFamily: MONO,
      }}
    >
      <span style={{ color: hover ? ACCENT : FG, fontSize: 11, letterSpacing: '0.04em' }}>
        {template.title}
      </span>
      <span style={{ color: DIM, fontSize: 9, lineHeight: 1.5 }}>{template.description}</span>
      {template.needs && (
        <span
          style={{
            color: ACCENT,
            fontSize: 8,
            letterSpacing: '0.12em',
            marginTop: 2,
          }}
        >
          NEEDS: {template.needs.toUpperCase()}
        </span>
      )}
    </button>
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

function AddRuleForm({
  preset,
  editing,
  onCreated,
  onUpdated,
  onCancelEdit,
}: {
  preset: { value: RulePreset; needs?: RuleTemplate['needs'] } | null;
  editing: FirewallIntent | null;
  onCreated: (i: FirewallIntent) => void;
  onUpdated: (i: FirewallIntent) => void;
  onCancelEdit: () => void;
}) {
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

  function resetFields() {
    setName('');
    setSrc('lan');
    setDest('');
    setSrcIp('');
    setSrcPort('');
    setDestIp('');
    setDestPort('');
    setProtocol('any');
    setTarget('accept');
    setLog(false);
    setErr(null);
  }

  // Apply an editing rule when one is set. Takes precedence over preset since
  // edit mode is the explicit, in-progress action.
  useEffect(() => {
    if (!editing) return;
    const s = editing.spec as FirewallRuleSpec;
    setName(editing.name);
    setSrc(s.src);
    setDest(s.dest ?? '');
    setSrcIp(s.srcIp ?? '');
    setSrcPort(s.srcPort ?? '');
    setDestIp(s.destIp ?? '');
    setDestPort(s.destPort ?? '');
    setProtocol((s.proto ?? 'any') as FirewallRuleProto);
    setTarget(s.target);
    setLog(s.log ?? false);
    setErr(null);
    requestAnimationFrame(() => document.getElementById('rule-name')?.focus());
  }, [editing]);

  // Watch by reference — RulesPage builds a fresh object on each pick, so the
  // same template clicked twice still resets the form. Skip when editing —
  // RulesPage clears `preset` when entering edit mode, but a stale ref could
  // still fire on a render race.
  useEffect(() => {
    if (!preset || editing) return;
    const p = preset.value;
    setName(p.name ?? '');
    setSrc(p.src);
    setDest(p.dest ?? '');
    setSrcIp(p.srcIp ?? '');
    setSrcPort(p.srcPort ?? '');
    setDestIp(p.destIp ?? '');
    setDestPort(p.destPort ?? '');
    setProtocol((p.proto ?? 'any') as FirewallRuleProto);
    setTarget(p.target);
    setLog(p.log ?? false);
    setErr(null);
    if (preset.needs) {
      const fieldId = 'rule-' + preset.needs;
      requestAnimationFrame(() => document.getElementById(fieldId)?.focus());
    }
  }, [preset, editing]);

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
      if (editing) {
        const updated = await updateIntent(editing.id, { name, spec });
        onUpdated(updated);
        resetFields();
      } else {
        const created = await createIntent({
          kind: 'firewall_rule',
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
    <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 12, maxWidth: 780 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <Input
          id="rule-name"
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
          id="rule-srcIp"
          placeholder="src IP/CIDR (optional)"
          value={srcIp}
          onChange={(e) => setSrcIp(e.target.value)}
          style={highlightStyle('srcIp', preset?.needs, srcIp, { flex: '1 1 180px' })}
        />
        <Input
          id="rule-srcPort"
          placeholder="src port (optional)"
          value={srcPort}
          onChange={(e) => setSrcPort(e.target.value)}
          style={highlightStyle('srcPort', preset?.needs, srcPort, { width: 140 })}
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
          id="rule-destIp"
          placeholder="dest IP/CIDR (optional)"
          value={destIp}
          onChange={(e) => setDestIp(e.target.value)}
          style={highlightStyle('destIp', preset?.needs, destIp, { flex: '1 1 180px' })}
        />
        <Input
          id="rule-destPort"
          placeholder="dest port (optional)"
          value={destPort}
          onChange={(e) => setDestPort(e.target.value)}
          style={highlightStyle('destPort', preset?.needs, destPort, { width: 140 })}
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
          {busy
            ? editing
              ? 'UPDATING…'
              : 'ADDING…'
            : editing
            ? 'UPDATE RULE'
            : 'ADD RULE'}
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

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <span style={{ color: DIM, fontSize: 9, fontFamily: MONO, letterSpacing: '0.12em', minWidth: 40 }}>
      {children}
    </span>
  );
}

// highlightStyle accents a field's border while it's the one a freshly-picked
// template still needs the user to fill in. Once they type anything, the
// highlight drops — the template's job is done.
function highlightStyle(
  field: RuleTemplate['needs'],
  needs: RuleTemplate['needs'] | undefined,
  value: string,
  base: React.CSSProperties,
): React.CSSProperties {
  if (needs && needs === field && value === '') {
    return { ...base, border: `1px solid ${accentA(0.7)}`, boxShadow: `0 0 0 1px ${accentA(0.2)}` };
  }
  return base;
}
