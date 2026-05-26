'use client';

import { useEffect, useState } from 'react';
import {
  createApp,
  deleteApp,
  deployApp,
  listApps,
  listNodes,
  openAppsWS,
  openInventoryWS,
  stopApp,
} from '../../../lib/api';
import type { App, Node } from '../../../lib/types';

export default function AppsPage() {
  const [apps, setApps] = useState<App[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    refresh();
    const closeApps = openAppsWS(() => {
      listApps().then(setApps).catch(console.error);
    });
    const closeInv = openInventoryWS(() => {
      listNodes().then(setNodes).catch(console.error);
    });
    return () => {
      closeApps();
      closeInv();
    };
  }, []);

  function refresh() {
    listApps().then(setApps).catch((e) => setErr(String(e)));
    listNodes().then(setNodes).catch(console.error);
  }

  async function handle(action: 'deploy' | 'stop' | 'delete', app: App) {
    setBusy(app.id);
    setErr(null);
    try {
      if (action === 'deploy') await deployApp(app.id);
      else if (action === 'stop') await stopApp(app.id);
      else {
        if (!confirm(`Delete app "${app.name}"? This removes the record; stop it first if it's running.`)) {
          return;
        }
        await deleteApp(app.id);
        setApps((prev) => prev.filter((a) => a.id !== app.id));
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  const deployTargets = nodes.filter(
    (n) => n.role === 'compute' || n.role === 'controlplane',
  );

  return (
    <section className="apps-section">
      <h2>Apps</h2>
      {err && <pre className="err">{err}</pre>}

      {apps.length === 0 ? (
        <p className="hint">no apps yet — define one below</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Target</th>
              <th>Status</th>
              <th>Last deployed</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {apps.map((a) => (
              <tr key={a.id}>
                <td><strong>{a.name}</strong></td>
                <td><code>{a.targetNode}</code></td>
                <td>
                  <span className={`status status-${appStatusClass(a.lastStatus)}`}>
                    {a.lastStatus}
                  </span>
                  {a.lastDetail && (
                    <span className="hint" title={a.lastDetail}>
                      {' '}· {a.lastDetail.length > 40 ? a.lastDetail.slice(0, 37) + '…' : a.lastDetail}
                    </span>
                  )}
                </td>
                <td>{a.lastDeployed ? new Date(a.lastDeployed).toLocaleTimeString() : '—'}</td>
                <td className="row-actions">
                  {a.lastStatus !== 'running' && (
                    <button
                      onClick={() => handle('deploy', a)}
                      disabled={busy === a.id}
                    >
                      deploy
                    </button>
                  )}
                  {(a.lastStatus === 'running' || a.lastStatus === 'deploying' || a.lastStatus === 'failed') && (
                    <button
                      onClick={() => handle('stop', a)}
                      disabled={busy === a.id}
                    >
                      stop
                    </button>
                  )}
                  <button
                    onClick={() => handle('delete', a)}
                    disabled={busy === a.id}
                  >
                    delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <AddAppForm
        deployTargets={deployTargets}
        onCreated={(a) => setApps((prev) => [...prev, a])}
      />
    </section>
  );
}

function appStatusClass(s: App['lastStatus']): string {
  switch (s) {
    case 'running': return 'succeeded';
    case 'failed': return 'failed';
    case 'deploying':
    case 'stopping': return 'running';
    case 'stopped': return 'queued';
    default: return 'pending';
  }
}

function AddAppForm({
  deployTargets,
  onCreated,
}: {
  deployTargets: Node[];
  onCreated: (a: App) => void;
}) {
  const [name, setName] = useState('');
  const [targetNode, setTargetNode] = useState('');
  const [composeYaml, setComposeYaml] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!targetNode && deployTargets.length > 0) {
      setTargetNode(deployTargets[0].id);
    }
  }, [deployTargets, targetNode]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const created = await createApp({ name, targetNode, composeYaml });
      onCreated(created);
      setName('');
      setComposeYaml('');
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (deployTargets.length === 0) {
    return (
      <div className="add-intent">
        <h4>Add app</h4>
        <p className="hint">no compute or controlplane nodes registered yet — start one to add apps</p>
      </div>
    );
  }

  return (
    <form className="add-intent add-app" onSubmit={submit}>
      <h4>Add app</h4>
      <div className="row">
        <input
          placeholder="name (e.g. nextcloud)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
        <select
          value={targetNode}
          onChange={(e) => setTargetNode(e.target.value)}
        >
          {deployTargets.map((n) => (
            <option key={n.id} value={n.id}>
              {n.id} ({n.role})
            </option>
          ))}
        </select>
      </div>
      <textarea
        placeholder={`services:\n  web:\n    image: nginx:alpine\n    ports:\n      - "8080:80"`}
        value={composeYaml}
        onChange={(e) => setComposeYaml(e.target.value)}
        required
        rows={8}
      />
      <div className="form-actions">
        <button type="submit" disabled={busy || !name || !targetNode || !composeYaml}>
          {busy ? 'adding…' : 'add'}
        </button>
        {err && <pre className="err">{err}</pre>}
      </div>
    </form>
  );
}
