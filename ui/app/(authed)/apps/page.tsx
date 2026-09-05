'use client';

import { ClipboardList, Database, ExternalLink, HardDrive, Package, Play, Plus, RotateCcw, Square, Trash2, UploadCloud } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import {
  deleteApp,
  deployApp,
  getAppVolumes,
  getCatalogTile,
  getSetupState,
  listApps,
  listOrphanVolumes,
  openAppsWS,
  reclaimOrphanVolumes,
  setAppExposure,
  stopApp,
} from '../../../lib/api';
import type { App, AppVolumesResponse, CatalogTile, OrphanVolume, OrphanVolumesResponse } from '../../../lib/types';
import { formatBytes, timeAgo } from '../../../lib/volumes';
import { appAccess, preferredAppUrl, type AppAccess } from '../../../lib/appurl';
import { backupBadge, backupSummary, sortAppsOverdueFirst } from '../../../lib/backup-state';
import {
  Badge,
  Btn,
  CopyButton,
  DIM,
  Drawer,
  EnabledToggle,
  FG,
  HAIR,
  HAIR_SOFT,
  Hint,
  LinkBtn,
  PageBody,
  PageHeader,
  PageShell,
  SectionLabel,
  srOnly,
  tdStyle,
  thStyle,
} from '../../../components/kit';
import { UninstallAppModal, type UninstallVolumeRow } from '../../../components/UninstallAppModal';
import { RestoreAppDataModal } from '../../../components/RestoreAppDataModal';
import { ACCENT, MONO } from '../../../components/ui-theme';

// Fixed column widths so the table doesn't reflow as per-row action buttons
// appear/disappear (the actions cell is right-aligned; buttons grow within its
// fixed width instead of shoving the other columns around).
const COLS: { label: string; width: string; hideLabel?: boolean }[] = [
  { label: 'NAME', width: '22%' },
  { label: 'TARGET', width: '16%' },
  { label: 'STATUS', width: '22%' },
  { label: 'LAST DEPLOYED', width: '14%' },
  // Obvious from the buttons underneath if you can see them, and to nobody
  // else — so the header is hidden rather than empty.
  { label: 'ACTIONS', width: '26%', hideLabel: true },
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
  // Delete asks in-page rather than through window.confirm(). A native dialog
  // is browser chrome: never in the a11y tree, so an agent driving by ref has
  // nothing to click, and automation that auto-dismisses it aborts the delete
  // without a trace.
  const [pendingDelete, setPendingDelete] = useState<App | null>(null);
  // The uninstall prompt's facts (#399): the app's volumes by class and when
  // each was last backed up. null while loading; the prompt's confirm waits.
  const [deleteInfo, setDeleteInfo] = useState<AppVolumesResponse | null>(null);
  // Volumes earlier uninstalls left behind, and the one group the operator is
  // reclaiming right now.
  const [orphans, setOrphans] = useState<OrphanVolumesResponse | null>(null);
  const [pendingReclaim, setPendingReclaim] = useState<OrphanGroup | null>(null);
  const [reclaimNote, setReclaimNote] = useState<string | null>(null);
  // Cluster id seeds the app-access hostname (<app>.<cluster-id>.internal). ''
  // until the fetch lands and '' on a dev box — appAccess falls back to
  // "rasputin" then, matching the api's baseDomainFor.
  const [clusterId, setClusterId] = useState('');

  useEffect(() => {
    const refreshApps = () => listApps().then(setApps).catch((e) => setErr(String(e)));
    refreshApps();
    // Orphans are a slower question (the agent sizes each volume), asked once
    // per page load and after every reclaim — not on the 20s poll.
    listOrphanVolumes().then(setOrphans).catch(() => setOrphans(null));
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
    if (action === 'delete') {
      setDeleteInfo(null);
      setPendingDelete(app);
      getAppVolumes(app.id)
        .then(setDeleteInfo)
        .catch((e) =>
          // The prompt still opens, with the reason the facts are missing —
          // never a silent "no volumes".
          setDeleteInfo({ appId: app.id, appName: app.name, classified: false, note: `Could not read this app's volumes: ${String(e)}`, volumes: [] })
        );
      return;
    }
    setBusy(app.id);
    setErr(null);
    try {
      if (action === 'deploy') await deployApp(app.id);
      else await stopApp(app.id);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function confirmDelete(app: App, deleteVolumes: boolean) {
    setBusy(app.id);
    setErr(null);
    try {
      // Async: the stop → remove saga emits a `deleted` event; the WS refresh
      // drops the row once the container is actually torn down.
      await deleteApp(app.id, { deleteVolumes });
      // A keep-volumes uninstall creates orphans; show them once the row goes.
      if (!deleteVolumes) setTimeout(() => listOrphanVolumes().then(setOrphans).catch(() => {}), 5_000);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function confirmReclaim(group: OrphanGroup) {
    setBusy(group.key);
    setReclaimNote(null);
    try {
      const res = await reclaimOrphanVolumes(group.nodeId, group.volumes.map((v) => v.name));
      const parts: string[] = [];
      if (res.removed.length) parts.push(`Removed ${res.removed.length} volume(s) on ${res.nodeId}.`);
      for (const r of res.refused) parts.push(`${r.name}: ${r.reason}`);
      if (res.detail) parts.push(res.detail);
      setReclaimNote(parts.join(' '));
    } catch (e) {
      setReclaimNote(String(e));
    } finally {
      setBusy(null);
      listOrphanVolumes().then(setOrphans).catch(() => {});
    }
  }

  const addButton = (
    <LinkBtn href="/app-catalog" variant="primary" small>
      <Plus size={10} /> ADD APP
    </LinkBtn>
  );

  // §4.4's top billing: an app whose backup did not happen is listed first,
  // not found by scanning. The rest keep install order.
  const shown = sortAppsOverdueFirst(apps);

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
          <table aria-label="Apps" style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
            <colgroup>
              {COLS.map((c, i) => (
                <col key={i} style={{ width: c.width }} />
              ))}
            </colgroup>
            <thead>
              <tr>
                {COLS.map((c) => (
                  <th key={c.label} scope="col" style={thStyle}>
                    {c.hideLabel ? <span style={srOnly}>{c.label}</span> : c.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {shown.map((a) => (
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

        {/* Inside PageBody with the apps table, not beside it: PageBody is
            what supplies the page's padding and its scroll region, so a
            sibling rendered flush against the content edge with RECLAIM
            clipped by the shell's overflow (e3bench, 2026-09-04). */}
        {orphans && (orphans.volumes.length > 0 || orphans.unreachable.length > 0) && (
          <OrphanedVolumes
            orphans={orphans}
            busy={busy}
            note={reclaimNote}
            onReclaim={(g) => setPendingReclaim(g)}
          />
        )}
      </PageBody>

      {detail && <AppDetail app={detail} clusterId={clusterId} onClose={() => setDetail(null)} />}

      {pendingDelete && (
        <UninstallAppModal
          mode="uninstall"
          subject={pendingDelete.name}
          nodeId={pendingDelete.targetNode}
          volumes={deleteInfo ? deleteInfo.volumes : null}
          note={deleteInfo?.note}
          backupNote={deleteInfo?.backupNote}
          onConfirm={(deleteVolumes) => void confirmDelete(pendingDelete, deleteVolumes)}
          onCancel={() => setPendingDelete(null)}
        />
      )}

      {pendingReclaim && (
        <UninstallAppModal
          mode="reclaim"
          subject={pendingReclaim.label}
          nodeId={pendingReclaim.nodeId}
          volumes={pendingReclaim.volumes.map(
            (v): UninstallVolumeRow => ({
              name: v.volume,
              dockerName: v.name,
              backup: v.backup ?? '',
              lastCaptured: v.lastCaptured,
              sizeBytes: v.sizeBytes,
            })
          )}
          backupNote={orphans?.backupNote}
          onConfirm={() => void confirmReclaim(pendingReclaim)}
          onCancel={() => setPendingReclaim(null)}
        />
      )}
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

  // The OVERDUE badge (design/storage.md §4.4, #298), beside the name — the
  // first thing in the row, in red, with the elapsed time since the last
  // success. It links to the storage page, whose runs table names which app
  // failed and why; the reason is also on hover. Only `overdue` earns it:
  // a fresh install inside its grace, an unconfigured cluster (#299's nag)
  // and an app with nothing to back up show nothing here.
  const overdue = backupBadge(app.backup);

  // No row-level hover affordance: the row has no onClick, and highlighting
  // the whole row told the operator (and the bench agents) that the row was
  // the target when only the controls inside it are. The name button carries
  // its own hover instead.
  return (
    <tr>
      <td style={{ ...tdStyle, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        <NameButton name={app.name} onClick={onOpenDetail} />
        {overdue && (
          <Link
            href={overdue.href}
            title={overdue.title}
            aria-label={`Backup of ${app.name} is overdue — open backups`}
            style={{ textDecoration: 'none', marginLeft: 8 }}
          >
            <Badge color="#f87171">{overdue.label}</Badge>
          </Link>
        )}
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
          {/* Every action here repeats once per row, so each needs the app's
              name in its accessible name — otherwise a table of five apps
              offers five controls all called "DELETE". */}
          {canOpen && (
            <LinkBtn external href={openUrl!} variant="primary" small title={openUrl!} aria-label={`Open ${app.name}`}>
              <ExternalLink size={10} /> OPEN
            </LinkBtn>
          )}
          {!transient && app.lastStatus !== 'running' && (
            <Btn
              variant="primary"
              small
              disabled={busy}
              aria-label={`${started ? 'Start' : 'Deploy'} ${app.name}`}
              onClick={() => onAction('deploy', app)}
            >
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
            <Btn small disabled={busy} aria-label={`Stop ${app.name}`} onClick={() => onAction('stop', app)}>
              <Square size={10} /> STOP
            </Btn>
          )}
          <Btn variant="danger" small disabled={busy} aria-label={`Delete ${app.name}`} onClick={() => onAction('delete', app)}>
            <Trash2 size={10} /> DELETE
          </Btn>
        </div>
      </td>
    </tr>
  );
}

// The app name doubles as the detail trigger. Its own hover underline — the
// row used to carry it, which made the whole row look clickable.
function NameButton({ name, onClick }: { name: string; onClick: () => void }) {
  const [hover, setHover] = useState(false);
  return (
    <button
      type="button"
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      aria-label={`Details for ${name}`}
      style={{
        background: 'transparent',
        border: 'none',
        padding: 0,
        color: FG,
        fontFamily: MONO,
        fontSize: 10,
        cursor: 'pointer',
        textDecoration: hover ? 'underline' : 'none',
      }}
    >
      {name}
    </button>
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
  // "Restore data from a backup…" (geekdojo/geekdojo-brain#291 phase 2):
  // explicit, per app, never automatic. Offered only for an app installed
  // from a tile, because only a tile classifies the volumes a backup holds.
  const [restoreOpen, setRestoreOpen] = useState(false);

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

        {/* The status cell clips this to ~36 characters, which is nowhere near
            enough for a compose error — and until now the full text existed
            only on /tasks with nothing pointing at it. Unabridged here, plus
            the way through to the run that produced it. */}
        {app.lastDetail && (
          <div>
            <SectionLabel>{app.lastStatus === 'failed' ? 'FAILURE' : 'LAST DETAIL'}</SectionLabel>
            <pre
              style={{
                color: app.lastStatus === 'failed' ? '#f87171' : DIM,
                fontSize: 9,
                fontFamily: MONO,
                margin: 0,
                padding: '6px 8px',
                background: 'rgba(var(--rasp-fg-rgb),0.03)',
                border: `1px solid ${HAIR_SOFT}`,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
              }}
            >
              {app.lastDetail}
            </pre>
            <div style={{ marginTop: 8 }}>
              <LinkBtn href={`/tasks?app=${encodeURIComponent(app.id)}`} small aria-label={`Tasks for ${app.name}`}>
                <ClipboardList size={10} /> VIEW TASKS
              </LinkBtn>
            </div>
          </div>
        )}

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
                <CopyButton value={access.tailnet} label="COPY" ariaLabel="Copy tailnet address" />
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
                  <CopyButton value={access.lan} label="COPY" ariaLabel="Copy LAN address" />
                </div>
              )}
              {!running && <Hint style={{ marginTop: 6 }}>Deploy it first — the link works once it&apos;s running.</Hint>}
            </>
          ) : (
            <Hint>This app doesn&apos;t expose a web port.</Hint>
          )}
        </div>

        {/*
          Offered for EVERY app, not only the ones with a web page. An app's
          .lan name is a DNS record projected from its exposure and its target
          node — it does not consult ports or TLS — so a page-less app (a
          database, a game server) is reachable at that name on its own port
          just as a web app is reachable there over HTTPS. Gating this on
          `access` meant a page-less app could never be given its .lan name at
          all, which for a database is the whole point of LAN access.
        */}
        <div>
          <SectionLabel>LAN ACCESS</SectionLabel>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <EnabledToggle
              enabled={exposeLan}
              onToggle={() => {
                if (!exposureBusy) void toggleExposure();
              }}
              aria-label={`LAN access for ${app.name}`}
              title={exposeLan ? 'Reachable on your LAN — click for tailnet-only' : 'Tailnet only — click to allow LAN access'}
            />
            <span style={{ color: FG, fontSize: 10 }}>
              {exposureBusy ? 'saving…' : exposeLan ? 'Reachable on your LAN' : 'Tailnet only'}
            </span>
          </div>
          <Hint warn={!!exposureNote} style={{ marginTop: 6 }}>
            {exposureNote ??
              (exposeLan
                ? access
                  ? 'Devices on your local network can reach it at its .lan name. Turn this off to withdraw it — the app and its data stay put.'
                  : 'Devices on your local network can resolve its .lan name and connect to it there on its own port. Turn this off to withdraw the name — the app and its data stay put.'
                : 'Reachable only over your tailnet. Turning this on adds the .lan name' + (access ? ' and a LAN bind.' : '.'))}
          </Hint>
        </div>

        {/* Every app, every state: the drawer is where "is this backed up?"
            gets a sentence. OVERDUE is red and carries the api's own reason —
            the fan-out's off-node / refused / did-not-land sentence — and the
            way through to the runs table. */}
        <div>
          <SectionLabel>BACKUP</SectionLabel>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            {app.backup?.state === 'overdue' && <Badge color="#f87171">OVERDUE</Badge>}
            <span style={{ color: app.backup?.state === 'overdue' ? '#f87171' : FG, fontSize: 10 }}>{backupSummary(app.backup)}</span>
          </div>
          {app.backup?.reason && (
            <Hint warn={app.backup.state === 'overdue'} style={{ marginTop: 6 }}>
              {app.backup.reason}
            </Hint>
          )}
          {app.backup && app.backup.state !== 'none' && (
            <div style={{ marginTop: 8 }}>
              <LinkBtn href="/storage" small aria-label={`Backups for ${app.name}`}>
                <HardDrive size={10} /> VIEW BACKUPS
              </LinkBtn>
            </div>
          )}
        </div>

        {app.sourceTile && (
          <div>
            <SectionLabel>DATA</SectionLabel>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <Btn small aria-label={`Restore data of ${app.name} from a backup`} onClick={() => setRestoreOpen(true)}>
                <RotateCcw size={10} /> RESTORE DATA FROM A BACKUP…
              </Btn>
            </div>
            <Hint style={{ marginTop: 6 }}>
              Puts this app&apos;s volumes back from a backup generation you choose, replacing what it holds now. Nothing is
              restored automatically, and you confirm what is replaced before anything is stopped.
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
        <LinkBtn href="/app-catalog">BACK TO CATALOG</LinkBtn>
      </div>
      {restoreOpen && <RestoreAppDataModal app={app} onClose={() => setRestoreOpen(false)} />}
    </Drawer>
  );
}

// --- Orphaned volumes (geekdojo/geekdojo-brain#399) -------------------------

// OrphanGroup is one former app's volumes on one node — the unit the operator
// reclaims, so the prompt can list "everything immich left behind" together.
interface OrphanGroup {
  key: string;
  nodeId: string;
  appId: string;
  label: string;
  volumes: OrphanVolume[];
  sizeBytes: number;
  createdAt: string;
}

function groupOrphans(vols: OrphanVolume[]): OrphanGroup[] {
  const groups = new Map<string, OrphanGroup>();
  for (const v of vols) {
    const key = `${v.nodeId}/${v.appId}`;
    let g = groups.get(key);
    if (!g) {
      g = {
        key,
        nodeId: v.nodeId,
        appId: v.appId,
        label: v.appName ? `${v.appName} (${v.appId.slice(-6).toLowerCase()})` : v.appId.toLowerCase(),
        volumes: [],
        sizeBytes: 0,
        createdAt: v.createdAt,
      };
      groups.set(key, g);
    }
    g.volumes.push(v);
    g.sizeBytes += v.sizeBytes;
    if (v.createdAt < g.createdAt) g.createdAt = v.createdAt;
  }
  return [...groups.values()];
}

// Volumes named rasp_<appId>_* on a node whose appId no longer has an app row:
// data an earlier uninstall left behind. Every uninstall before #399 did, so
// this is where those go to be seen, and reclaimed with the same informed
// confirmation an uninstall now gets.
function OrphanedVolumes({
  orphans,
  busy,
  note,
  onReclaim,
}: {
  orphans: OrphanVolumesResponse;
  busy: string | null;
  note: string | null;
  onReclaim: (g: OrphanGroup) => void;
}) {
  const groups = groupOrphans(orphans.volumes);
  return (
    <div style={{ marginTop: 28 }}>
      <SectionLabel>
        <Database size={10} style={{ verticalAlign: 'middle', marginRight: 6 }} />
        ORPHANED VOLUMES — {orphans.volumes.length}
      </SectionLabel>
      <Hint style={{ marginBottom: 10 }}>
        Data left on a node by apps that are no longer installed. Nothing owns it and nothing backs it up; it counts against the
        node&apos;s disk until reclaimed.
      </Hint>
      {orphans.unreachable.length > 0 && (
        <Hint warn style={{ marginBottom: 10 }}>
          Not checked: {orphans.unreachable.map((u) => `${u.nodeId} (${u.reason})`).join(', ')}. Reclaim on an offline node is
          refused, not queued.
        </Hint>
      )}
      {note && <Hint style={{ marginBottom: 10 }}>{note}</Hint>}
      {groups.length > 0 && (
        <table aria-label="Orphaned volumes" style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
          <colgroup>
            <col style={{ width: '22%' }} />
            <col style={{ width: '14%' }} />
            <col style={{ width: '36%' }} />
            <col style={{ width: '14%' }} />
            <col style={{ width: '14%' }} />
          </colgroup>
          <thead>
            <tr>
              {['FORMER APP', 'NODE', 'VOLUMES', 'CREATED', 'ACTIONS'].map((h) => (
                <th key={h} scope="col" style={thStyle}>
                  {h === 'ACTIONS' ? <span style={srOnly}>{h}</span> : h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {groups.map((g) => (
              <tr key={g.key}>
                <td style={tdStyle} title={g.appId}>
                  {g.label}
                </td>
                <td style={{ ...tdStyle, color: DIM }}>{g.nodeId}</td>
                <td style={{ ...tdStyle, color: DIM, whiteSpace: 'normal' }}>
                  {g.volumes.map((v) => (
                    <div key={v.name} title={v.name}>
                      {v.volume}{' '}
                      <span style={{ color: DIM }}>
                        {formatBytes(v.sizeBytes)}
                        {v.backup ? ` · ${v.backup}` : ''}
                        {' · backup: '}
                        {v.lastCaptured ? `${v.lastCaptured.generationId}, ${timeAgo(v.lastCaptured.at)}` : 'never'}
                        {v.inUse ? ' · in use' : ''}
                      </span>
                    </div>
                  ))}
                </td>
                <td style={{ ...tdStyle, color: DIM }} title={g.createdAt}>
                  {timeAgo(g.createdAt)}
                </td>
                <td style={{ ...tdStyle, paddingRight: 0 }}>
                  <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <Btn variant="danger" small disabled={busy === g.key} aria-label={`Reclaim volumes of ${g.label}`} onClick={() => onReclaim(g)}>
                      <Trash2 size={10} /> RECLAIM
                    </Btn>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
