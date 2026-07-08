'use client';

import { Package, Plus, Square, Trash2, UploadCloud } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import { deleteApp, deployApp, listApps, openAppsWS, stopApp } from '../../../lib/api';
import type { App } from '../../../lib/types';
import {
  Badge,
  Btn,
  DIM,
  FG,
  Hint,
  PageBody,
  PageHeader,
  PageShell,
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
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    listApps().then(setApps).catch((e) => setErr(String(e)));
    const closeApps = openAppsWS(() => listApps().then(setApps).catch(() => {}));
    return () => closeApps();
  }, []);

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

  const addButton = (
    <Link href="/app-catalog" style={{ textDecoration: 'none' }}>
      <Btn variant="primary" small>
        <Plus size={10} /> ADD APP
      </Btn>
    </Link>
  );

  return (
    <PageShell>
      <PageHeader icon={Package} title={`APPS — ${apps.length}`} right={addButton} />
      <PageBody>
        {err && <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}>{err}</div>}

        {apps.length === 0 ? (
          <Hint>
            No apps yet — add one from the{' '}
            <Link href="/app-catalog" style={{ color: 'var(--rasp-accent)', textDecoration: 'none' }}>
              App Catalog
            </Link>
            .
          </Hint>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
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
