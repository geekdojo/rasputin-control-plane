'use client';

import { Trash2, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { createMeshKey, deleteMeshKey, listMeshKeys } from '../../../../lib/api';
import { useMeshStateRefresh } from '../../../../lib/mesh-state-context';
import type { MeshIntent, PreAuthKeySpec } from '../../../../lib/types';
import {
  Btn,
  DIM,
  FG,
  HAIR,
  Hint,
  Input,
  SectionLabel,
  Select,
  tdStyle,
  thStyle,
} from '../../../../components/kit';
import { ACCENT, accentA, MONO } from '../../../../components/ui-theme';

export default function KeysPage() {
  const [keys, setKeys] = useState<MeshIntent[]>([]);
  const [freshKey, setFreshKey] = useState<MeshIntent | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const refreshMeshState = useMeshStateRefresh();

  useEffect(() => {
    refresh();
  }, []);

  function refresh() {
    listMeshKeys().then(setKeys).catch((e) => setErr(String(e)));
  }

  async function handleDeleteKey(id: string) {
    if (!confirm("Delete this pre-auth key? Already-enrolled devices keep access; the key just can't be reused.")) return;
    try {
      await deleteMeshKey(id);
      setKeys((prev) => prev.filter((k) => k.id !== id));
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
              return (
                <tr key={k.id}>
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
                    <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
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

      <SectionLabel>ADD DEVICE</SectionLabel>
      <AddDeviceForm
        onCreated={(intent) => {
          setFreshKey(intent);
          refresh();
          refreshMeshState();
        }}
      />
    </>
  );
}

function FreshKeyBanner({ intent, onClose }: { intent: MeshIntent; onClose: () => void }) {
  const value = intent.hsValue || '';
  const spec = intent.spec as PreAuthKeySpec;
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
      <pre style={keyBox}>{value}</pre>
      <Hint>On the device, install Tailscale, then run:</Hint>
      <pre style={keyBox}>tailscale up --login-server=&lt;your-rasputin-mesh-url&gt; --auth-key={value}</pre>
      <div>
        <Btn variant="primary" small onClick={onClose}>
          I&apos;VE COPIED IT — CLOSE
        </Btn>
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

function AddDeviceForm({ onCreated }: { onCreated: (i: MeshIntent) => void }) {
  const [name, setName] = useState('');
  const [hint, setHint] = useState('');
  const [reusable, setReusable] = useState(false);
  const [expiresIn, setExpiresIn] = useState('24h');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const created = await createMeshKey({ name, deviceHint: hint, reusable, expiresIn });
      onCreated(created);
      setName('');
      setHint('');
      setReusable(false);
      setExpiresIn('24h');
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
      <Input
        placeholder="name (e.g. Bryce's MacBook)"
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
      <Btn type="submit" variant="primary" disabled={busy || !name}>
        {busy ? 'MINTING…' : 'GENERATE KEY'}
      </Btn>
      {err && <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{err}</span>}
    </form>
  );
}
