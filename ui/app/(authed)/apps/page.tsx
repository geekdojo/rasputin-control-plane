'use client';

import { ExternalLink, Package, Play, Plus, Square, Trash2, UploadCloud } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import {
  deleteApp,
  deployApp,
  getCatalogTile,
  getSetupState,
  listApps,
  openAppsWS,
  setAppExposure,
  stopApp,
} from '../../../lib/api';
import type { App, CatalogTile } from '../../../lib/types';
import { appAccess, preferredAppUrl, type AppAccess } from '../../../lib/appurl';
import {
  Badge,
  Btn,
  CopyButton,
  DIM,
  Drawer,
  EnabledToggle,
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

// Fixed column widths so the table doesn't reflow as per-row action buttons
// appear/disappear (the actions cell is right-aligned; buttons grow within its
// fixed width instead of shoving the other columns around).
const COLS: { label: string; width: string }[] = [
  { label: 'NAME', width: '22%' },
  { label: 'TARGET', width: '16%' },
  { label: 'STATUS', width: '22%' },
  { label: 'LAST DEPLOYED', width: '14%' },
  { label: '', width: '26%' },
];

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

// Display label for the status badge. A restart reuses the deploy saga, so the
// raw status is 'deploying' — but if the app has run before we call it STARTING
// to match the START button the user just clicked.
function statusLabel(app: App): string {
  if (app.lastStatus === 'deploying' && app.lastDeployed) return 'STARTING';
  return app.lastStatus.toUpperCase();
}

export default function AppsPage() {
  const [apps, setApps] = useState<App[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [detail, setDetail] = useState<App | null>(null);
  // Cluster id seeds the app-access hostname (<app>.<cluster-id>.internal). ''
  // until the fetch lands and '' on a dev box — appAccess falls back to
  // "rasputin" then, matching the api's baseDomainFor.
  const [clusterId, setClusterId] = useState('');

  useEffect(() => {
    const refreshApps = () => listApps().then(setApps).catch((e) => setErr(String(e)));
    refreshApps();
    getSetupState().then((s) => setClusterId(s.clusterId ?? '')).catch(() => {});
    // WS drives instant updates; the onOpen callback re-syncs on every
    // (re)connect so a dropped socket can't leave the list stale.
    const closeApps = openAppsWS(refreshApps, refreshApps);
    // Catch a socket that died silently (laptop sleep, proxy idle-timeout —
    // no close event fires, so onOpen never re-runs): refresh when the tab
    // becomes visible again, plus a slow backstop poll.
    const onVisible = () => {
      if (document.visibilityState === 'visible') refreshApps();
    };
    document.addEventListener('visibilitychange', onVisible);
    const poll = setInterval(refreshApps, 20_000);
    return () => {
      closeApps();
      document.removeEventListener('visibilitychange', onVisible);
      clearInterval(poll);
    };
  }, []);

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
          <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
            <colgroup>
              {COLS.map((c, i) => (
                <col key={i} style={{ width: c.width }} />
              ))}
            </colgroup>
            <thead>
              <tr>
                {COLS.map((c, i) => (
                  <th key={c.label || i} style={thStyle}>
                    {c.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {apps.map((a) => (
                <AppRow
                  key={a.id}
                  app={a}
                  access={appAccess(a, clusterId)}
                  busy={busy === a.id}
                  onAction={handle}
                  onOpenDetail={() => setDetail(a)}
                />
              ))}
            </tbody>
          </table>
        )}
      </PageBody>

      {detail && <AppDetail app={detail} clusterId={clusterId} onClose={() => setDetail(null)} />}
    </PageShell>
  );
}

function AppRow({
  app,
  access,
  busy,
  onAction,
  onOpenDetail,
}: {
  app: App;
  access: AppAccess | null;
  busy: boolean;
  onAction: (action: 'deploy' | 'stop' | 'delete', app: App) => void;
  onOpenDetail: () => void;
}) {
  const [hover, setHover] = useState(false);
  const transient = app.lastStatus === 'deploying' || app.lastStatus === 'stopping';
  const canStop = app.lastStatus === 'running' || app.lastStatus === 'deploying' || app.lastStatus === 'failed';
  // Hand off the URL matching the operator's current network: a LAN-exposed app
  // opened from a LAN view uses its .lan name (the tailnet name NXDOMAINs on the
  // LAN); otherwise the tailnet name. Both are always in the detail drawer.
  const openUrl = preferredAppUrl(access);
  const canOpen = app.lastStatus === 'running' && !!openUrl;
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
      <td style={{ ...tdStyle, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        <Badge color={statusColor(app.lastStatus)}>{statusLabel(app)}</Badge>
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
            <a href={openUrl!} target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
              <Btn variant="primary" small title={openUrl!}>
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
function AppDetail({ app, clusterId, onClose }: { app: App; clusterId: string; onClose: () => void }) {
  const [tile, setTile] = useState<CatalogTile | null>(null);
  // Exposure is edited HERE, on a live app, which is the whole of #197: it used
  // to be settable only in the install drawer, so the only way back was delete.
  // Held locally and seeded from the record so the toggle responds immediately
  // and reverts visibly if the patch fails.
  const [exposeLan, setExposeLan] = useState(app.exposeLan ?? false);
  const [exposureBusy, setExposureBusy] = useState(false);
  const [exposureNote, setExposureNote] = useState<string | null>(null);

  useEffect(() => {
    if (app.sourceTile) getCatalogTile(app.sourceTile).then(setTile).catch(() => {});
  }, [app.sourceTile]);

  const access = appAccess(app, clusterId);
  const running = app.lastStatus === 'running';

  async function toggleExposure() {
    const want = !exposeLan;
    setExposureBusy(true);
    setExposureNote(null);
    setExposeLan(want);
    try {
      const updated = await setAppExposure(app.id, want);
      setExposeLan(updated.exposeLan ?? want);
      if (updated.leafWarning) {
        setExposureNote(
          `Saved, but the proxy certificate could not be re-issued yet (${updated.leafWarning}). The name stops resolving now; the proxy catches up on the next rotation.`
        );
      }
    } catch (e) {
      setExposeLan(!want); // revert — never leave the toggle claiming a change that failed
      setExposureNote(String(e));
    } finally {
      setExposureBusy(false);
    }
  }

  return (
    <Drawer title={app.name.toUpperCase()} icon={tile?.icon} onClose={onClose}>
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <Badge color={statusColor(app.lastStatus)}>{statusLabel(app)}</Badge>
          <span style={{ color: DIM, fontSize: 10 }}>on {app.targetNode}</span>
        </div>

        <div>
          <SectionLabel>ACCESS</SectionLabel>
          {access ? (
            <>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                <a
                  href={access.tailnet}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: running ? ACCENT : DIM, fontSize: 10, textDecoration: 'none' }}
                >
                  {access.tailnet} <ExternalLink size={9} style={{ verticalAlign: 'middle' }} />
                </a>
                <CopyButton value={access.tailnet} label="COPY" />
              </div>
              {access.lan && (
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginTop: 6 }}>
                  <span style={{ color: DIM, fontSize: 9 }}>LAN</span>
                  <a
                    href={access.lan}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ color: running ? ACCENT : DIM, fontSize: 10, textDecoration: 'none' }}
                  >
                    {access.lan} <ExternalLink size={9} style={{ verticalAlign: 'middle' }} />
                  </a>
                  <CopyButton value={access.lan} label="COPY" />
                </div>
              )}
              {!running && <Hint style={{ marginTop: 6 }}>Deploy it first — the link works once it&apos;s running.</Hint>}
            </>
          ) : (
            <Hint>This app doesn&apos;t expose a web port.</Hint>
          )}
        </div>

        {access && (
          <div>
            <SectionLabel>LAN ACCESS</SectionLabel>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <EnabledToggle
                enabled={exposeLan}
                onToggle={() => {
                  if (!exposureBusy) void toggleExposure();
                }}
                title={exposeLan ? 'Reachable on your LAN — click for tailnet-only' : 'Tailnet only — click to allow LAN access'}
              />
              <span style={{ color: FG, fontSize: 10 }}>
                {exposureBusy ? 'saving…' : exposeLan ? 'Reachable on your LAN' : 'Tailnet only'}
              </span>
            </div>
            <Hint warn={!!exposureNote} style={{ marginTop: 6 }}>
              {exposureNote ??
                (exposeLan
                  ? 'Devices on your local network can reach it at its .lan name. Turn this off to withdraw it — the app and its data stay put.'
                  : 'Reachable only over your tailnet. Turning this on adds the .lan name and a LAN bind.')}
            </Hint>
          </div>
        )}

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
