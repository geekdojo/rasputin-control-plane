'use client';

import { useEffect, useState } from 'react';
import {
  applyFirewall,
  createIntent,
  deleteIntent,
  listFirewallState,
  listIntents,
  openFirewallWS,
  reconcileFirewall,
} from '../../../lib/api';
import type {
  FirewallIntent,
  FirewallNodeState,
  PortForwardProto,
} from '../../../lib/types';

export default function FirewallPage() {
  const [intents, setIntents] = useState<FirewallIntent[]>([]);
  const [states, setStates] = useState<FirewallNodeState[]>([]);
  const [busy, setBusy] = useState<'apply' | 'reconcile' | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    refresh();
    const close = openFirewallWS(() => {
      listFirewallState().then(setStates).catch(console.error);
    });
    return close;
  }, []);

  function refresh() {
    listIntents().then(setIntents).catch((e) => setErr(String(e)));
    listFirewallState().then(setStates).catch(console.error);
  }

  async function handleApply() {
    setBusy('apply');
    setErr(null);
    try {
      await applyFirewall();
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
      await reconcileFirewall();
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
    <section className="firewall-section">
      <h2>Firewall</h2>

      {states.length === 0 ? (
        <p className="hint">
          No firewall-role agent is registered. Start one with{' '}
          <code>RASPUTIN_NODE_ROLE=firewall</code>.
        </p>
      ) : (
        <div className="firewall-state-bar">
          {states.map((s) => (
            <FirewallStateBadge key={s.nodeId} state={s} />
          ))}
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

      <h3>Port forwards</h3>
      {intents.length === 0 ? (
        <p className="hint">no intents yet</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>WAN port</th>
              <th>→</th>
              <th>LAN target</th>
              <th>Proto</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {intents.map((i) => (
              <tr key={i.id}>
                <td>
                  <strong>{i.name}</strong>
                  {!i.enabled && <span className="hint"> (disabled)</span>}
                </td>
                <td><code>{i.spec.wanPort}</code></td>
                <td className="arrow">→</td>
                <td><code>{i.spec.lanHost}:{i.spec.lanPort}</code></td>
                <td><code>{i.spec.protocol}</code></td>
                <td className="row-actions">
                  <button onClick={() => handleDelete(i.id)} title="Delete">
                    delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <AddPortForwardForm onCreated={(i) => setIntents((p) => [...p, i])} />
    </section>
  );
}

function FirewallStateBadge({ state }: { state: FirewallNodeState }) {
  const status: 'in-sync' | 'drift' | 'unknown' = state.drift
    ? 'drift'
    : state.lastApplied
    ? 'in-sync'
    : 'unknown';
  return (
    <div className={`fw-state fw-${status}`}>
      <span className="fw-state-label">{state.nodeId}</span>
      <span className="fw-state-pill">{status === 'in-sync' ? 'in sync' : status}</span>
      <span className="fw-state-meta">
        {state.lastApplied
          ? `applied ${new Date(state.lastApplied).toLocaleTimeString()}`
          : 'never applied'}
      </span>
    </div>
  );
}

function AddPortForwardForm({
  onCreated,
}: {
  onCreated: (i: FirewallIntent) => void;
}) {
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
        spec: {
          wanPort: Number(wanPort),
          lanHost,
          lanPort: Number(lanPort),
          protocol,
        },
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
    <form className="add-intent" onSubmit={submit}>
      <h4>Add port forward</h4>
      <div className="row">
        <input
          placeholder="name (e.g. minecraft)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
        <input
          placeholder="WAN port"
          value={wanPort}
          onChange={(e) => setWanPort(e.target.value)}
          inputMode="numeric"
          required
        />
        <span className="arrow">→</span>
        <input
          placeholder="LAN host (10.0.0.50)"
          value={lanHost}
          onChange={(e) => setLanHost(e.target.value)}
          required
        />
        <input
          placeholder="LAN port"
          value={lanPort}
          onChange={(e) => setLanPort(e.target.value)}
          inputMode="numeric"
          required
        />
        <select
          value={protocol}
          onChange={(e) => setProtocol(e.target.value as PortForwardProto)}
        >
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
          <option value="tcpudp">tcp+udp</option>
        </select>
        <button type="submit" disabled={busy || !name || !wanPort || !lanHost || !lanPort}>
          {busy ? 'adding…' : 'add'}
        </button>
      </div>
      {err && <pre className="err">{err}</pre>}
    </form>
  );
}
