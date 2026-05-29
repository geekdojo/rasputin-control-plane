'use client';

import { Package, Square, Trash2, UploadCloud } from 'lucide-react';
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
import {
  Badge,
  Btn,
  DIM,
  FG,
  Input,
  PageBody,
  PageHeader,
  PageShell,
  Select,
  SectionLabel,
  Textarea,
  tdStyle,
  thStyle,
} from '../../../components/kit';
import { accentA, MONO } from '../../../components/ui-theme';

const COLS = ['NAME', 'TARGET', 'STATUS', 'LAST DEPLOYED', ''];

function statusColor(s: App['lastStatus']): string {
  switch (s) {
    case 'running':
      return '#4ade80';
    case 'deploying':
    case 'stopping':
      return '#facc15';
    case 'failed':
      return '#f87171';
    default:
      return DIM; // stopped / unknown
  }
}

export default function AppsPage() {
  const [apps, setApps] = useState<App[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    refresh();
    const closeApps = openAppsWS(() => listApps().then(setApps).catch(() => {}));
    const closeInv = openInventoryWS(() => listNodes().then(setNodes).catch(() => {}));
    return () => {
      closeApps();
      closeInv();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function refresh() {
    listApps().then(setApps).catch((e) => setErr(String(e)));
    listNodes().then(setNodes).catch(() => {});
  }

  async function handle(action: 'deploy' | 'stop' | 'delete', app: App) {
    setBusy(app.id);
    setErr(null);
    try {
      if (action === 'deploy') await deployApp(app.id);
      else if (action === 'stop') await stopApp(app.id);
      else {
        if (!confirm(`Delete app "${app.name}"? This removes the record; stop it first if it's running.`)) return;
        await deleteApp(app.id);
        setApps((prev) => prev.filter((a) => a.id !== app.id));
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  const deployTargets = nodes.filter((n) => n.role === 'compute' || n.role === 'controlplane');

  return (
    <PageShell>
      <PageHeader icon={Package} title={`APPS — ${apps.length}`} />
      <PageBody>
        {err && <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}>{err}</div>}

        {apps.length === 0 ? (
          <p style={{ color: DIM, fontSize: 11, fontFamily: MONO }}>no apps yet — define one below</p>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 28 }}>
            <thead>
              <tr>
                {COLS.map((c, i) => (
                  <th key={c || i} style={thStyle}>
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {apps.map((a) => (
                <AppRow key={a.id} app={a} busy={busy === a.id} onAction={handle} />
              ))}
            </tbody>
          </table>
        )}

        <SectionLabel>ADD APP</SectionLabel>
        <AddAppForm deployTargets={deployTargets} onCreated={(a) => setApps((prev) => [...prev, a])} />
      </PageBody>
    </PageShell>
  );
}

function AppRow({
  app,
  busy,
  onAction,
}: {
  app: App;
  busy: boolean;
  onAction: (action: 'deploy' | 'stop' | 'delete', app: App) => void;
}) {
  const [hover, setHover] = useState(false);
  const canStop = app.lastStatus === 'running' || app.lastStatus === 'deploying' || app.lastStatus === 'failed';

  return (
    <tr
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{ background: hover ? accentA(0.05) : 'transparent', transition: 'background 0.1s' }}
    >
      <td style={{ ...tdStyle, color: FG }}>{app.name}</td>
      <td style={{ ...tdStyle, color: DIM }}>{app.targetNode}</td>
      <td style={tdStyle}>
        <Badge color={statusColor(app.lastStatus)}>{app.lastStatus.toUpperCase()}</Badge>
        {app.lastDetail && (
          <span style={{ color: DIM, fontSize: 9, marginLeft: 8 }} title={app.lastDetail}>
            {app.lastDetail.length > 36 ? app.lastDetail.slice(0, 33) + '…' : app.lastDetail}
          </span>
        )}
      </td>
      <td style={{ ...tdStyle, color: DIM }}>{app.lastDeployed ? new Date(app.lastDeployed).toLocaleTimeString() : '—'}</td>
      <td style={{ ...tdStyle, paddingRight: 0 }}>
        <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
          {app.lastStatus !== 'running' && (
            <Btn variant="primary" small disabled={busy} onClick={() => onAction('deploy', app)}>
              <UploadCloud size={10} /> DEPLOY
            </Btn>
          )}
          {canStop && (
            <Btn small disabled={busy} onClick={() => onAction('stop', app)}>
              <Square size={10} /> STOP
            </Btn>
          )}
          <Btn variant="danger" small disabled={busy} onClick={() => onAction('delete', app)}>
            <Trash2 size={10} /> DELETE
          </Btn>
        </div>
      </td>
    </tr>
  );
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
    if (!targetNode && deployTargets.length > 0) setTargetNode(deployTargets[0].id);
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
      <p style={{ color: DIM, fontSize: 11, fontFamily: MONO }}>
        no compute or controlplane nodes registered yet — start one to add apps
      </p>
    );
  }

  return (
    <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 10, maxWidth: 640 }}>
      <div style={{ display: 'flex', gap: 10 }}>
        <Input
          placeholder="name (e.g. nextcloud)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          style={{ flex: 1 }}
        />
        <Select value={targetNode} onChange={(e) => setTargetNode(e.target.value)} style={{ minWidth: 200 }}>
          {deployTargets.map((n) => (
            <option key={n.id} value={n.id}>
              {n.id} ({n.role})
            </option>
          ))}
        </Select>
      </div>
      <Textarea
        placeholder={'services:\n  web:\n    image: nginx:alpine\n    ports:\n      - "8080:80"'}
        value={composeYaml}
        onChange={(e) => setComposeYaml(e.target.value)}
        required
        rows={8}
      />
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <Btn type="submit" variant="primary" disabled={busy || !name || !targetNode || !composeYaml}>
          {busy ? 'ADDING…' : 'ADD APP'}
        </Btn>
        {err && <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{err}</span>}
      </div>
    </form>
  );
}
