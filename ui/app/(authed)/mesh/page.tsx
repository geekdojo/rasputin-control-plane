'use client';

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
import type {
  MeshDevice,
  MeshIntent,
  MeshStateEnvelope,
  Node,
  PreAuthKeySpec,
  SubnetRouteSpec,
} from '../../../lib/types';

export default function MeshPage() {
  const [env, setEnv] = useState<MeshStateEnvelope | null>(null);
  const [devices, setDevices] = useState<MeshDevice[]>([]);
  const [keys, setKeys] = useState<MeshIntent[]>([]);
  const [routes, setRoutes] = useState<MeshIntent[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [busy, setBusy] = useState<'apply' | 'reconcile' | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // freshlyMintedKey is shown once, in plaintext, after createMeshKey.
  // After dismiss it's gone — server-side scrubs hsValue on subsequent reads.
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

  async function handleApply() {
    setBusy('apply');
    setErr(null);
    try {
      await applyMesh();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function handleReconcile() {
    setBusy('reconcile');
    setErr(null);
    try {
      await reconcileMesh();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  const drift = env?.state?.drift ?? false;

  return (
    <section className="mesh-section">
      <h2>Mesh</h2>

      {env && env.backend === 'mock' && (
        <p className="hint warn">
          ⚠ Headscale is in <strong>mock mode</strong> (file-backed). Real
          Headscale wiring lands when the controlplane node has Docker. See
          wiki <code>design/control-plane/mesh.md §2</code>.
        </p>
      )}

      {env && (
        <div className="firewall-state-bar">
          <div className={`fw-state fw-${drift ? 'drift' : 'in-sync'}`}>
            <span className="fw-state-label">tailnet</span>
            <span className="fw-state-pill">
              {drift ? 'drift' : env.state.lastApplied ? 'in sync' : 'unstarted'}
            </span>
            <span className="fw-state-meta">
              {env.state.lastApplied
                ? `applied ${new Date(env.state.lastApplied).toLocaleTimeString()}`
                : 'never applied'}
            </span>
          </div>
          <span className="hint">
            login server: <code>{env.loginServer}</code> · user:{' '}
            <code>{env.defaultUser}</code> · backend:{' '}
            <code>{env.backend}</code>
          </span>
          <div className="spacer" />
          <button onClick={handleApply} disabled={busy !== null}>
            {busy === 'apply' ? 'applying…' : 'Apply'}
          </button>
          <button onClick={handleReconcile} disabled={busy !== null}>
            {busy === 'reconcile' ? 'reconciling…' : 'Reconcile'}
          </button>
        </div>
      )}

      {err && <pre className="err">{err}</pre>}

      {freshKey && <FreshKeyBanner intent={freshKey} onClose={() => setFreshKey(null)} />}

      <h3>Devices</h3>
      {devices.length === 0 ? (
        <p className="hint">
          no devices in the tailnet yet — enroll a Rasputin node below, or
          add your laptop with the "Add device" form.
        </p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>Kind</th>
              <th>Tailnet IP</th>
              <th>Tags</th>
              <th>Routes</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.hsId}>
                <td>
                  <strong>{d.hostname || d.hsId}</strong>
                </td>
                <td>
                  <span className={`status status-${d.kind === 'rasputin' ? 'running' : 'queued'}`}>
                    {d.kind}
                  </span>
                </td>
                <td>
                  <code>{d.tailnetIp || '—'}</code>
                </td>
                <td>{(d.tags || []).join(' · ') || '—'}</td>
                <td>{(d.advertisedRoutes || []).join(', ') || '—'}</td>
                <td>{new Date(d.lastSeen).toLocaleTimeString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <EnrollNodeForm nodes={nodes} devices={devices} onEnrolled={() => refresh()} />

      <h3>Pre-auth keys</h3>
      <p className="hint">
        Generate a single-use key to enroll your laptop or phone. The key
        value appears <strong>once</strong> — copy it immediately.
      </p>
      {keys.length === 0 ? (
        <p className="hint">no keys yet</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>User</th>
              <th>Reusable</th>
              <th>Tags</th>
              <th>Expires</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {keys.map((k) => {
              const spec = k.spec as PreAuthKeySpec;
              return (
                <tr key={k.id}>
                  <td>
                    <strong>{k.name}</strong>
                    {spec.deviceHint && <span className="hint"> · {spec.deviceHint}</span>}
                  </td>
                  <td><code>{spec.user}</code></td>
                  <td>{spec.reusable ? 'yes' : 'no'}</td>
                  <td>{(spec.tags || []).join(', ') || '—'}</td>
                  <td>{spec.expiresIn || '—'}</td>
                  <td className="row-actions">
                    <button onClick={() => handleDeleteKey(k.id)}>delete</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      <AddDeviceForm onCreated={(intent) => { setFreshKey(intent); refresh(); }} />

      <h3>Subnet routes</h3>
      {routes.length === 0 ? (
        <p className="hint">no subnet routes yet</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Node</th>
              <th>CIDR</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {routes.map((r) => {
              const spec = r.spec as SubnetRouteSpec;
              return (
                <tr key={r.id}>
                  <td><strong>{r.name}</strong></td>
                  <td><code>{spec.nodeId}</code></td>
                  <td><code>{spec.cidr}</code></td>
                  <td className="row-actions">
                    <button onClick={() => handleDeleteRoute(r.id)}>delete</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      <AddRouteForm nodes={nodes} onCreated={() => refresh()} />
    </section>
  );

  async function handleDeleteKey(id: string) {
    if (!confirm('Delete this pre-auth key? Already-enrolled devices keep their access; the key just can\'t be used again.')) return;
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
}

// FreshKeyBanner shows the plaintext key value once with copy-paste cmd.
function FreshKeyBanner({ intent, onClose }: { intent: MeshIntent; onClose: () => void }) {
  const value = intent.hsValue || '';
  const spec = intent.spec as PreAuthKeySpec;
  return (
    <div className="fresh-key">
      <h4>Key minted — copy now, it won't be shown again</h4>
      <p>
        <strong>{intent.name}</strong>
        {spec.deviceHint && <> · {spec.deviceHint}</>}
      </p>
      <pre className="auth-key">{value}</pre>
      <p className="hint">
        On the device, install Tailscale, then run:
      </p>
      <pre className="install-cmd">
        tailscale up --login-server={'<your-rasputin-mesh-url>'} --auth-key={value}
      </pre>
      <p className="hint">
        (Replace the login-server URL with the value shown in Mesh state above.)
      </p>
      <button onClick={onClose}>I&apos;ve copied it — close</button>
    </div>
  );
}

// EnrollNodeForm dispatches mesh.enroll_node for a Rasputin inventory node
// that isn't yet in the tailnet.
function EnrollNodeForm({
  nodes,
  devices,
  onEnrolled,
}: {
  nodes: Node[];
  devices: MeshDevice[];
  onEnrolled: () => void;
}) {
  const enrolled = new Set(
    devices.filter((d) => d.kind === 'rasputin').map((d) => d.rasputinNodeId || d.hostname),
  );
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
      const cidrs = routes
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
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
    return (
      <div className="add-intent">
        <h4>Enroll Rasputin node</h4>
        <p className="hint">
          all online Rasputin nodes are already in the tailnet
        </p>
      </div>
    );
  }

  return (
    <form className="add-intent" onSubmit={submit}>
      <h4>Enroll Rasputin node</h4>
      <div className="row">
        <select value={nodeId} onChange={(e) => setNodeId(e.target.value)}>
          {candidates.map((n) => (
            <option key={n.id} value={n.id}>
              {n.id} ({n.role})
            </option>
          ))}
        </select>
        <input
          placeholder="advertise routes (CIDRs, comma-separated; optional)"
          value={routes}
          onChange={(e) => setRoutes(e.target.value)}
        />
        <button type="submit" disabled={busy || !nodeId}>
          {busy ? 'enrolling…' : 'enroll'}
        </button>
      </div>
      {err && <pre className="err">{err}</pre>}
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
      const created = await createMeshKey({
        name,
        deviceHint: hint,
        reusable,
        expiresIn,
      });
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
    <form className="add-intent" onSubmit={submit}>
      <h4>Add device</h4>
      <div className="row">
        <input
          placeholder="name (e.g. Bryce's MacBook)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
        <input
          placeholder="device hint (e.g. MacBook Pro 14)"
          value={hint}
          onChange={(e) => setHint(e.target.value)}
        />
        <select value={expiresIn} onChange={(e) => setExpiresIn(e.target.value)}>
          <option value="1h">1h</option>
          <option value="24h">24h (recommended)</option>
          <option value="168h">7d</option>
        </select>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={reusable}
            onChange={(e) => setReusable(e.target.checked)}
          />
          reusable
        </label>
        <button type="submit" disabled={busy || !name}>
          {busy ? 'minting…' : 'generate key'}
        </button>
      </div>
      {err && <pre className="err">{err}</pre>}
    </form>
  );
}

function AddRouteForm({
  nodes,
  onCreated,
}: {
  nodes: Node[];
  onCreated: () => void;
}) {
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
    return (
      <div className="add-intent">
        <h4>Add subnet route</h4>
        <p className="hint">no nodes registered yet</p>
      </div>
    );
  }

  return (
    <form className="add-intent" onSubmit={submit}>
      <h4>Add subnet route</h4>
      <div className="row">
        <input
          placeholder="name (e.g. lan-vlan-10)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
        <select value={nodeId} onChange={(e) => setNodeId(e.target.value)}>
          {nodes.map((n) => (
            <option key={n.id} value={n.id}>
              {n.id} ({n.role})
            </option>
          ))}
        </select>
        <input
          placeholder="CIDR (e.g. 10.0.0.0/24)"
          value={cidr}
          onChange={(e) => setCidr(e.target.value)}
          required
        />
        <button type="submit" disabled={busy || !name || !cidr}>
          {busy ? 'adding…' : 'add'}
        </button>
      </div>
      {err && <pre className="err">{err}</pre>}
    </form>
  );
}
