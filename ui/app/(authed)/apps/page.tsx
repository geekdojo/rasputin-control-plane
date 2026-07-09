'use client';

import { ExternalLink, Package, Play, Plus, Square, Trash2, UploadCloud } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import {
  deleteApp,
  deployApp,
  getCatalogTile,
  listApps,
  listNodes,
  openAppsWS,
  openInventoryWS,
  stopApp,
} from '../../../lib/api';
import type { App, CatalogTile, Node } from '../../../lib/types';
import { accessUrl } from '../../../lib/appurl';
import {
  Badge,
  Btn,
  CopyButton,
  DIM,
  Drawer,
  FG,
  HAIR,
  Hint,
  PageBody,
  PageHeader,
  PageShell,
  SectionLabel,
  tdStyle,
  thStyle,
} from '../../../components/kit';
import { accentA, ACCENT, MONO } from '../../../components/ui-theme';

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
  const [detail, setDetail] = useState<App | null>(null);

  useEffect(() => {
    listApps().then(setApps).catch((e) => setErr(String(e)));
    listNodes().then(setNodes).catch(() => {});
    const closeApps = openAppsWS(() => listApps().then(setApps).catch(() => {}));
    const closeInv = openInventoryWS(() => listNodes().then(setNodes).catch(() => {}));
    return () => {
      closeApps();
      closeInv();
    };
  }, []);

  const nodesById = new Map(nodes.map((n) => [n.id, n]));

  async function handle(action: 'deploy' | 'stop' | 'delete', app: App) {
    setBusy(app.id);
    setErr(null);
    try {
      if (action === 'deploy') await deployApp(app.id);
      else if (action === 'stop') await stopApp(app.id);
      else {
        if (!confirm(`Stop and remove "${app.name}" and its containers?`)) return;
        // Async: the stop → remove saga emits a `deleted` event; the WS refresh
        // drops the row once the container is actually torn down.
        await deleteApp(app.id);
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
                <AppRow
                  key={a.id}
                  app={a}
                  url={accessUrl(nodesById.get(a.targetNode), a.targetNode, a.publishedPort)}
                  busy={busy === a.id}
                  onAction={handle}
                  onOpenDetail={() => setDetail(a)}
                />
              ))}
            </tbody>
          </table>
        )}
      </PageBody>

      {detail && <AppDetail app={detail} node={nodesById.get(detail.targetNode)} onClose={() => setDetail(null)} />}
    </PageShell>
  );
}

function AppRow({
  app,
  url,
  busy,
  onAction,
  onOpenDetail,
}: {
  app: App;
  url: string | null;
  busy: boolean;
  onAction: (action: 'deploy' | 'stop' | 'delete', app: App) => void;
  onOpenDetail: () => void;
}) {
  const [hover, setHover] = useState(false);
  const transient = app.lastStatus === 'deploying' || app.lastStatus === 'stopping';
  const canStop = app.lastStatus === 'running' || app.lastStatus === 'deploying' || app.lastStatus === 'failed';
  const canOpen = app.lastStatus === 'running' && !!url;
  // The action that runs `docker compose up` reads DEPLOY the first time and
  // START once the app has run before (stop does `compose down`, so bringing it
  // back up is a start, not a fresh deploy). Same underlying action either way.
  const started = !!app.lastDeployed;

  return (
    <tr
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{ background: hover ? accentA(0.05) : 'transparent', transition: 'background 0.1s' }}
    >
      <td style={tdStyle}>
        <button
          onClick={onOpenDetail}
          title="App details"
          style={{ background: 'transparent', border: 'none', padding: 0, color: FG, fontFamily: MONO, fontSize: 10, cursor: 'pointer', textDecoration: hover ? 'underline' : 'none' }}
        >
          {app.name}
        </button>
      </td>
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
          {canOpen && (
            <a href={url!} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
              <Btn variant="primary" small title={url!}>
                <ExternalLink size={10} /> OPEN
              </Btn>
            </a>
          )}
          {!transient && app.lastStatus !== 'running' && (
            <Btn variant="primary" small disabled={busy} onClick={() => onAction('deploy', app)}>
              {started ? (
                <>
                  <Play size={10} /> START
                </>
              ) : (
                <>
                  <UploadCloud size={10} /> DEPLOY
                </>
              )}
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

// AppDetail — the "what next" for a running app: where to open it, what it is,
// and the first-run step. Tile info (docs + first-run note) is fetched lazily
// for apps installed from the catalog; custom-compose apps show just access.
function AppDetail({ app, node, onClose }: { app: App; node?: Node; onClose: () => void }) {
  const [tile, setTile] = useState<CatalogTile | null>(null);

  useEffect(() => {
    if (app.sourceTile) getCatalogTile(app.sourceTile).then(setTile).catch(() => {});
  }, [app.sourceTile]);

  const url = accessUrl(node, app.targetNode, app.publishedPort);
  const running = app.lastStatus === 'running';

  return (
    <Drawer title={app.name.toUpperCase()} icon={tile?.icon} onClose={onClose}>
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <Badge color={statusColor(app.lastStatus)}>{app.lastStatus.toUpperCase()}</Badge>
          <span style={{ color: DIM, fontSize: 10 }}>on {app.targetNode}</span>
        </div>

        <div>
          <SectionLabel>ACCESS</SectionLabel>
          {url ? (
            <>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                <a
                  href={url}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: running ? ACCENT : DIM, fontSize: 10, textDecoration: 'none' }}
                >
                  {url} <ExternalLink size={9} style={{ verticalAlign: 'middle' }} />
                </a>
                <CopyButton value={url} label="COPY" />
              </div>
              {!running && <Hint style={{ marginTop: 6 }}>Deploy it first — the link works once it&apos;s running.</Hint>}
            </>
          ) : (
            <Hint>This app doesn&apos;t expose a web port.</Hint>
          )}
        </div>

        {tile?.postInstall && (
          <div>
            <SectionLabel>FIRST RUN</SectionLabel>
            <Hint>{tile.postInstall}</Hint>
          </div>
        )}

        {tile && (tile.description || tile.website) && (
          <div>
            <SectionLabel>ABOUT</SectionLabel>
            {tile.description && <p style={{ color: DIM, fontSize: 10, lineHeight: 1.6, margin: '0 0 8px' }}>{tile.description}</p>}
            {tile.website && (
              <a href={tile.website} target="_blank" rel="noopener noreferrer" style={{ color: ACCENT, fontSize: 10, textDecoration: 'none' }}>
                Learn more &amp; customize <ExternalLink size={9} style={{ verticalAlign: 'middle' }} />
              </a>
            )}
          </div>
        )}

        {!app.sourceTile && (
          <Hint style={{ color: DIM }}>Custom app — no catalog guide. Manage it from the table.</Hint>
        )}
      </div>

      <div style={{ borderTop: `1px solid ${HAIR}`, padding: '14px 20px' }}>
        <Link href="/app-catalog" style={{ textDecoration: 'none' }}>
          <Btn>BACK TO CATALOG</Btn>
        </Link>
      </div>
    </Drawer>
  );
}
