'use client';

import { GitBranch, Trash2, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  applyMesh,
  createMeshKey,
  createMeshRoute,
  deleteMeshKey,
  deleteMeshRoute,
  enrollMeshNode,
  getMeshState,
  listMeshDevices,
  listMeshKeys,
  listMeshRoutes,
  listNodes,
  openMeshWS,
  reconcileMesh,
} from '../../../lib/api';
import type { MeshDevice, MeshIntent, MeshStateEnvelope, Node, PreAuthKeySpec, SubnetRouteSpec } from '../../../lib/types';
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
import { ACCENT, accentA, MONO } from '../../../components/ui-theme';

export default function MeshPage() {
  const [env, setEnv] = useState<MeshStateEnvelope | null>(null);
  const [devices, setDevices] = useState<MeshDevice[]>([]);
  const [keys, setKeys] = useState<MeshIntent[]>([]);
  const [routes, setRoutes] = useState<MeshIntent[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [busy, setBusy] = useState<'apply' | 'reconcile' | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [freshKey, setFreshKey] = useState<MeshIntent | null>(null);

  useEffect(() => {
    refresh();
    const close = openMeshWS(() => refresh());
    return close;
  }, []);

  function refresh() {
    getMeshState().then(setEnv).catch((e) => setErr(String(e)));
    listMeshDevices().then(setDevices).catch(() => {});
    listMeshKeys().then(setKeys).catch(() => {});
    listMeshRoutes().then(setRoutes).catch(() => {});
    listNodes().then(setNodes).catch(() => {});
  }

  async function act(which: 'apply' | 'reconcile') {
    setBusy(which);
    setErr(null);
    try {
      await (which === 'apply' ? applyMesh() : reconcileMesh());
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function handleDeleteKey(id: string) {
    if (!confirm("Delete this pre-auth key? Already-enrolled devices keep access; the key just can't be reused.")) return;
    try {
      await deleteMeshKey(id);
      setKeys((prev) => prev.filter((k) => k.id !== id));
    } catch (e) {
      setErr(String(e));
    }
  }

  async function handleDeleteRoute(id: string) {
    try {
      await deleteMeshRoute(id);
      setRoutes((prev) => prev.filter((r) => r.id !== id));
    } catch (e) {
      setErr(String(e));
    }
  }

  const drift = env?.state?.drift ?? false;
  const syncColor = drift ? '#facc15' : env?.state.lastApplied ? '#4ade80' : DIM;
  const syncLabel = drift ? 'DRIFT' : env?.state.lastApplied ? 'IN SYNC' : 'UNSTARTED';

  return (
    <PageShell>
      <PageHeader
        icon={GitBranch}
        title="MESH"
        right={
          env ? (
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
        {env && env.backend === 'mock' && (
          <Hint warn style={{ marginBottom: 14 }}>
            ⚠ Headscale is in mock mode (file-backed). Real Headscale wiring lands when the controlplane node has Docker. See wiki{' '}
            <Tok>design/control-plane/mesh.md §2</Tok>.
          </Hint>
        )}

        {env && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap', marginBottom: 18 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', background: PANEL, border: `1px solid ${HAIR}` }}>
              <span style={{ color: FG, fontSize: 10, fontFamily: MONO }}>tailnet</span>
              <Badge color={syncColor}>{syncLabel}</Badge>
              <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>
                {env.state.lastApplied ? `applied ${new Date(env.state.lastApplied).toLocaleTimeString()}` : 'never applied'}
              </span>
            </div>
            <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>
              login server: <Tok>{env.loginServer}</Tok> · user: <Tok>{env.defaultUser}</Tok> · backend: <Tok>{env.backend}</Tok>
            </span>
          </div>
        )}

        {err && <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}>{err}</div>}

        {freshKey && <FreshKeyBanner intent={freshKey} onClose={() => setFreshKey(null)} />}

        <SectionLabel>DEVICES</SectionLabel>
        {devices.length === 0 ? (
          <Hint style={{ marginBottom: 18 }}>
            no devices in the tailnet yet — enroll a Rasputin node below, or add your laptop with the &quot;add device&quot; form.
          </Hint>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 18 }}>
            <thead>
              <tr>
                {['HOST', 'KIND', 'TAILNET IP', 'TAGS', 'ROUTES', 'LAST SEEN'].map((c) => (
                  <th key={c} style={thStyle}>
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.hsId}>
                  <td style={{ ...tdStyle, color: FG }}>{d.hostname || d.hsId}</td>
                  <td style={tdStyle}>
                    <Badge color={d.kind === 'rasputin' ? ACCENT : DIM}>{d.kind.toUpperCase()}</Badge>
                  </td>
                  <td style={{ ...tdStyle, color: DIM }}>{d.tailnetIp || '—'}</td>
                  <td style={{ ...tdStyle, color: DIM }}>{(d.tags || []).join(' · ') || '—'}</td>
                  <td style={{ ...tdStyle, color: DIM }}>{(d.advertisedRoutes || []).join(', ') || '—'}</td>
                  <td style={{ ...tdStyle, color: DIM }}>{new Date(d.lastSeen).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <EnrollNodeForm nodes={nodes} devices={devices} onEnrolled={refresh} />

        <div style={{ marginTop: 24 }}>
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
                        {spec.deviceHint && <span style={{ color: DIM, fontSize: 9, marginLeft: 8 }}>· {spec.deviceHint}</span>}
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
          <AddDeviceForm
            onCreated={(intent) => {
              setFreshKey(intent);
              refresh();
            }}
          />
        </div>

        <div style={{ marginTop: 24 }}>
          <SectionLabel>SUBNET ROUTES</SectionLabel>
          {routes.length === 0 ? (
            <Hint style={{ marginBottom: 14 }}>no subnet routes yet</Hint>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 14 }}>
              <thead>
                <tr>
                  {['NAME', 'NODE', 'CIDR', ''].map((c, i) => (
                    <th key={c || i} style={thStyle}>
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {routes.map((r) => {
                  const spec = r.spec as SubnetRouteSpec;
                  return (
                    <tr key={r.id}>
                      <td style={{ ...tdStyle, color: FG }}>{r.name}</td>
                      <td style={{ ...tdStyle, color: DIM }}>{spec.nodeId}</td>
                      <td style={{ ...tdStyle, color: DIM }}>{spec.cidr}</td>
                      <td style={{ ...tdStyle, paddingRight: 0 }}>
                        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                          <Btn variant="danger" small onClick={() => handleDeleteRoute(r.id)}>
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
          <AddRouteForm nodes={nodes} onCreated={refresh} />
        </div>
      </PageBody>
    </PageShell>
  );
}

function FreshKeyBanner({ intent, onClose }: { intent: MeshIntent; onClose: () => void }) {
  const value = intent.hsValue || '';
  const spec = intent.spec as PreAuthKeySpec;
  return (
    <div style={{ background: accentA(0.06), border: `1px solid ${accentA(0.4)}`, padding: '14px 16px', marginBottom: 18, display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ color: ACCENT, fontSize: 11, fontFamily: MONO, letterSpacing: '0.08em' }}>KEY MINTED — COPY NOW, NOT SHOWN AGAIN</span>
        <button onClick={onClose} style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }} title="Close">
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

function EnrollNodeForm({ nodes, devices, onEnrolled }: { nodes: Node[]; devices: MeshDevice[]; onEnrolled: () => void }) {
  const enrolled = new Set(devices.filter((d) => d.kind === 'rasputin').map((d) => d.rasputinNodeId || d.hostname));
  const candidates = nodes.filter((n) => n.status === 'online' && !enrolled.has(n.id));
  const [nodeId, setNodeId] = useState('');
  const [routes, setRoutes] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!nodeId && candidates.length > 0) setNodeId(candidates[0].id);
  }, [candidates, nodeId]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!nodeId) return;
    setBusy(true);
    setErr(null);
    try {
      const cidrs = routes.split(',').map((s) => s.trim()).filter(Boolean);
      await enrollMeshNode(nodeId, cidrs);
      setRoutes('');
      onEnrolled();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (candidates.length === 0) {
    return <Hint>enroll Rasputin node — all online Rasputin nodes are already in the tailnet</Hint>;
  }

  return (
    <form onSubmit={submit} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
      <Select value={nodeId} onChange={(e) => setNodeId(e.target.value)} style={{ minWidth: 180 }}>
        {candidates.map((n) => (
          <option key={n.id} value={n.id}>
            {n.id} ({n.role})
          </option>
        ))}
      </Select>
      <Input placeholder="advertise routes (CIDRs, comma-sep; optional)" value={routes} onChange={(e) => setRoutes(e.target.value)} style={{ flex: '1 1 240px' }} />
      <Btn type="submit" variant="primary" disabled={busy || !nodeId}>
        {busy ? 'ENROLLING…' : 'ENROLL NODE'}
      </Btn>
      {err && <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{err}</span>}
    </form>
  );
}

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
      <Input placeholder="name (e.g. Bryce's MacBook)" value={name} onChange={(e) => setName(e.target.value)} required style={{ flex: '1 1 200px' }} />
      <Input placeholder="device hint (optional)" value={hint} onChange={(e) => setHint(e.target.value)} style={{ flex: '1 1 180px' }} />
      <Select value={expiresIn} onChange={(e) => setExpiresIn(e.target.value)}>
        <option value="1h">1h</option>
        <option value="24h">24h (recommended)</option>
        <option value="168h">7d</option>
      </Select>
      <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: DIM, fontSize: 10, fontFamily: MONO, cursor: 'pointer' }}>
        <input type="checkbox" checked={reusable} onChange={(e) => setReusable(e.target.checked)} style={{ accentColor: ACCENT }} />
        reusable
      </label>
      <Btn type="submit" variant="primary" disabled={busy || !name}>
        {busy ? 'MINTING…' : 'GENERATE KEY'}
      </Btn>
      {err && <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{err}</span>}
    </form>
  );
}

function AddRouteForm({ nodes, onCreated }: { nodes: Node[]; onCreated: () => void }) {
  const [name, setName] = useState('');
  const [nodeId, setNodeId] = useState('');
  const [cidr, setCidr] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!nodeId && nodes.length > 0) setNodeId(nodes[0].id);
  }, [nodes, nodeId]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await createMeshRoute({ name, nodeId, cidr });
      setName('');
      setCidr('');
      onCreated();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (nodes.length === 0) {
    return <Hint>add subnet route — no nodes registered yet</Hint>;
  }

  return (
    <form onSubmit={submit} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
      <Input placeholder="name (e.g. lan-vlan-10)" value={name} onChange={(e) => setName(e.target.value)} required style={{ flex: '1 1 180px' }} />
      <Select value={nodeId} onChange={(e) => setNodeId(e.target.value)} style={{ minWidth: 180 }}>
        {nodes.map((n) => (
          <option key={n.id} value={n.id}>
            {n.id} ({n.role})
          </option>
        ))}
      </Select>
      <Input placeholder="CIDR (e.g. 10.0.0.0/24)" value={cidr} onChange={(e) => setCidr(e.target.value)} required style={{ flex: '1 1 160px' }} />
      <Btn type="submit" variant="primary" disabled={busy || !name || !cidr}>
        {busy ? 'ADDING…' : 'ADD ROUTE'}
      </Btn>
      {err && <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{err}</span>}
    </form>
  );
}
