'use client';

import { Pencil, Trash2, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { createMeshKey, deleteMeshKey, listMeshKeys, updateMeshKey } from '../../../../lib/api';
import { useMeshStateRefresh } from '../../../../lib/mesh-state-context';
import type { MeshIntent, PreAuthKeySpec } from '../../../../lib/types';
import {
  Btn,
  CopyButton,
  DIM,
  FG,
  HAIR,
  Hint,
  Input,
  SectionLabel,
  Select,
  Tok,
  tdStyle,
  thStyle,
} from '../../../../components/kit';
import { ACCENT, accentA, MONO } from '../../../../components/ui-theme';

export default function KeysPage() {
  const [keys, setKeys] = useState<MeshIntent[]>([]);
  const [freshKey, setFreshKey] = useState<MeshIntent | null>(null);
  const [editing, setEditing] = useState<MeshIntent | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const formRef = useRef<HTMLDivElement>(null);
  const refreshMeshState = useMeshStateRefresh();

  useEffect(() => {
    refresh();
  }, []);

  useEffect(() => {
    if (editing) formRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [editing]);

  function refresh() {
    listMeshKeys().then(setKeys).catch((e) => setErr(String(e)));
  }

  async function handleDeleteKey(id: string) {
    if (!confirm("Delete this pre-auth key? Already-enrolled devices keep access; the key just can't be reused.")) return;
    try {
      await deleteMeshKey(id);
      setKeys((prev) => prev.filter((k) => k.id !== id));
      if (editing?.id === id) setEditing(null);
      refreshMeshState();
    } catch (e) {
      setErr(String(e));
    }
  }

  return (
    <>
      {err && (
        <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}>{err}</div>
      )}

      {freshKey && <FreshKeyBanner intent={freshKey} onClose={() => setFreshKey(null)} />}

      <SectionLabel>PRE-AUTH KEYS</SectionLabel>
      <Hint style={{ marginBottom: 12 }}>
        Generate a single-use key to enroll your laptop or phone. The value appears once — copy it immediately.
      </Hint>
      {keys.length === 0 ? (
        <Hint style={{ marginBottom: 14 }}>no keys yet</Hint>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 14 }}>
          <thead>
            <tr>
              {['NAME', 'USER', 'REUSABLE', 'TAGS', 'EXPIRES', ''].map((c, i) => (
                <th key={c || i} style={thStyle}>
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {keys.map((k) => {
              const spec = k.spec as PreAuthKeySpec;
              const isEditing = editing?.id === k.id;
              return (
                <tr
                  key={k.id}
                  style={isEditing ? { background: 'rgba(228,230,234,0.04)' } : undefined}
                >
                  <td style={{ ...tdStyle, color: FG }}>
                    {k.name}
                    {spec.deviceHint && (
                      <span style={{ color: DIM, fontSize: 9, marginLeft: 8 }}>· {spec.deviceHint}</span>
                    )}
                  </td>
                  <td style={{ ...tdStyle, color: DIM }}>{spec.user}</td>
                  <td style={{ ...tdStyle, color: DIM }}>{spec.reusable ? 'yes' : 'no'}</td>
                  <td style={{ ...tdStyle, color: DIM }}>{(spec.tags || []).join(', ') || '—'}</td>
                  <td style={{ ...tdStyle, color: DIM }}>{spec.expiresIn || '—'}</td>
                  <td style={{ ...tdStyle, paddingRight: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6 }}>
                      <Btn small onClick={() => setEditing(k)} title="Rename or edit device hint">
                        <Pencil size={10} /> EDIT
                      </Btn>
                      <Btn variant="danger" small onClick={() => handleDeleteKey(k.id)}>
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
          {editing ? `EDIT KEY — ${editing.name}` : 'ADD DEVICE'}
        </SectionLabel>
        <KeyForm
          editing={editing}
          onCreated={(intent) => {
            setFreshKey(intent);
            refresh();
            refreshMeshState();
          }}
          onUpdated={(intent) => {
            setKeys((prev) => prev.map((p) => (p.id === intent.id ? intent : p)));
            setEditing(null);
            // No mesh state refresh needed: rename/hint don't change the
            // compile hash (intents are compiled by their Headscale-side
            // attributes — user/tags/expiry/reusable — none of which we let
            // you edit). Skipping the round trip keeps the chip stable
            // through a pure display-field edit.
          }}
          onCancelEdit={() => setEditing(null)}
        />
      </div>
    </>
  );
}

function FreshKeyBanner({ intent, onClose }: { intent: MeshIntent; onClose: () => void }) {
  const value = intent.hsValue || '';
  const spec = intent.spec as PreAuthKeySpec;
  const command = `tailscale up --login-server=<your-rasputin-mesh-url> --auth-key=${value}`;
  return (
    <div
      style={{
        background: accentA(0.06),
        border: `1px solid ${accentA(0.4)}`,
        padding: '14px 16px',
        marginBottom: 18,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ color: ACCENT, fontSize: 11, fontFamily: MONO, letterSpacing: '0.08em' }}>
          KEY MINTED — COPY NOW, NOT SHOWN AGAIN
        </span>
        <button
          onClick={onClose}
          style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
          title="Close"
        >
          <X size={14} color={DIM} />
        </button>
      </div>
      <span style={{ color: FG, fontSize: 10, fontFamily: MONO }}>
        {intent.name}
        {spec.deviceHint && ` · ${spec.deviceHint}`}
      </span>
      <CopyBlock value={value} />
      <Hint>On the device, install Tailscale, then run:</Hint>
      <CopyBlock value={command} />
      <div>
        <Btn variant="primary" small onClick={onClose}>
          DONE — CLOSE
        </Btn>
      </div>
    </div>
  );
}

// Pre + COPY button overlay. The CopyButton floats in the top-right corner
// so the value stays readable underneath.
function CopyBlock({ value }: { value: string }) {
  return (
    <div style={{ position: 'relative' }}>
      <pre style={keyBox}>{value}</pre>
      <div style={{ position: 'absolute', top: 4, right: 4 }}>
        <CopyButton value={value} />
      </div>
    </div>
  );
}

const keyBox: React.CSSProperties = {
  margin: 0,
  padding: '8px 10px',
  background: '#060c16',
  border: `1px solid ${HAIR}`,
  color: '#cdd6e4',
  fontSize: 10,
  fontFamily: MONO,
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all',
};

function KeyForm({
  editing,
  onCreated,
  onUpdated,
  onCancelEdit,
}: {
  editing: MeshIntent | null;
  onCreated: (i: MeshIntent) => void;
  onUpdated: (i: MeshIntent) => void;
  onCancelEdit: () => void;
}) {
  const [name, setName] = useState('');
  const [hint, setHint] = useState('');
  const [reusable, setReusable] = useState(false);
  const [expiresIn, setExpiresIn] = useState('24h');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function resetFields() {
    setName('');
    setHint('');
    setReusable(false);
    setExpiresIn('24h');
    setErr(null);
  }

  useEffect(() => {
    if (!editing) return;
    const s = editing.spec as PreAuthKeySpec;
    setName(editing.name);
    setHint(s.deviceHint ?? '');
    setReusable(s.reusable);
    setExpiresIn(s.expiresIn ?? '24h');
    setErr(null);
    requestAnimationFrame(() => document.getElementById('key-name')?.focus());
  }, [editing]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      if (editing) {
        const updated = await updateMeshKey(editing.id, { name, deviceHint: hint });
        onUpdated(updated);
        resetFields();
      } else {
        const created = await createMeshKey({ name, deviceHint: hint, reusable, expiresIn });
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
    <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {editing && (
        <Hint>
          Only name and device hint are editable. <Tok>Reusable</Tok>, <Tok>expiry</Tok>, and{' '}
          <Tok>tags</Tok> are bound at mint and can&apos;t change without re-creating the key (the
          plaintext would be different).
        </Hint>
      )}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <Input
          id="key-name"
          placeholder="name (e.g. Rasputin Terminal)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          style={{ flex: '1 1 200px' }}
        />
        <Input
          placeholder="device hint (optional)"
          value={hint}
          onChange={(e) => setHint(e.target.value)}
          style={{ flex: '1 1 180px' }}
        />
        {!editing && (
          <>
            <Select value={expiresIn} onChange={(e) => setExpiresIn(e.target.value)}>
              <option value="1h">1h</option>
              <option value="24h">24h (recommended)</option>
              <option value="168h">7d</option>
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
                checked={reusable}
                onChange={(e) => setReusable(e.target.checked)}
                style={{ accentColor: ACCENT }}
              />
              reusable
            </label>
          </>
        )}
        {editing && (
          <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>
            expires <Tok>{expiresIn}</Tok> · reusable <Tok>{reusable ? 'yes' : 'no'}</Tok>
          </span>
        )}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <Btn type="submit" variant="primary" disabled={busy || !name}>
          {busy ? (editing ? 'UPDATING…' : 'MINTING…') : editing ? 'UPDATE KEY' : 'GENERATE KEY'}
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
