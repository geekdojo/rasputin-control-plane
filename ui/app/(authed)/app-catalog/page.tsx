'use client';

import { ExternalLink, FilePlus2, Search, Store, UploadCloud } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import {
  createApp,
  deployApp,
  getCatalogTile,
  getSetupState,
  installCatalogApp,
  listCatalog,
  listNodes,
  openInventoryWS,
} from '../../../lib/api';
import type { App, CatalogCollection, CatalogTile, Node } from '../../../lib/types';
import { appAccess } from '../../../lib/appurl';
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
  Input,
  PageBody,
  PageHeader,
  PageShell,
  PANEL,
  SectionLabel,
  Select,
  Textarea,
  fieldStyle,
} from '../../../components/kit';
import { accentA, ACCENT, MONO } from '../../../components/ui-theme';

const COLLECTIONS: { key: CatalogCollection; label: string; blurb: string }[] = [
  { key: 'essentials', label: 'ESSENTIALS', blurb: 'The credibility floor — every cluster should run these.' },
  { key: 'show-off', label: 'SHOW-OFF', blurb: 'Instant "look what my homelab does" — no extra hardware.' },
  { key: 'everyday', label: 'EVERYDAY FAVORITES', blurb: 'The workhorses this crowd votes for.' },
  { key: 'dongle', label: '$30 DONGLE TIER', blurb: 'Real-world signals on a map — needs a cheap SDR.' },
];

function ramLabel(mb: number): string {
  return mb >= 1024 ? `${mb % 1024 === 0 ? mb / 1024 : (mb / 1024).toFixed(1)}G RAM` : `${mb}M RAM`;
}

// A node can host an app only if it has an app-running role AND is reachable.
// Offline nodes are excluded — deploying to one just times out and fails.
function targetable(n: Node): boolean {
  return (n.role === 'compute' || n.role === 'controlplane') && n.status !== 'offline';
}

// archOK mirrors the api's install gate: a non-"both" tile needs a matching
// node arch, but an unreported arch ("") is allowed through.
function archOK(tile: CatalogTile, node: Node): boolean {
  if (tile.arch === 'both') return true;
  if (!node.architecture) return true;
  return node.architecture === tile.arch;
}

function nodeOptionLabel(n: Node): string {
  return `${n.id} (${n.role}${n.architecture ? `, ${n.architecture}` : ''}, ${n.status})`;
}

function isPreview(t: CatalogTile): boolean {
  return t.status === 'preview';
}

// Client-side substring search over the already-loaded manifest — no backend.
function matchesQuery(t: CatalogTile, q: string): boolean {
  return (
    t.name.toLowerCase().includes(q) ||
    t.tagline.toLowerCase().includes(q) ||
    (t.description ?? '').toLowerCase().includes(q) ||
    (t.category ?? '').toLowerCase().includes(q)
  );
}

export default function AppCatalogPage() {
  const [tiles, setTiles] = useState<CatalogTile[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [selected, setSelected] = useState<CatalogTile | null>(null);
  const [customOpen, setCustomOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [activeCat, setActiveCat] = useState('all');
  // Cluster id seeds the app-access hostname (<app>.<cluster-id>.internal). ''
  // until the fetch lands and '' on a dev box — appAccess falls back to
  // "rasputin" then, matching the api's baseDomainFor.
  const [clusterId, setClusterId] = useState('');

  useEffect(() => {
    listCatalog().then(setTiles).catch((e) => setErr(String(e)));
    listNodes().then(setNodes).catch(() => {});
    getSetupState().then((s) => setClusterId(s.clusterId ?? '')).catch(() => {});
    const closeInv = openInventoryWS(() => listNodes().then(setNodes).catch(() => {}));
    return () => closeInv();
  }, []);

  const deployTargets = nodes.filter(targetable);
  const canInstall = (t: CatalogTile) => !isPreview(t) && deployTargets.some((n) => archOK(t, n));

  const categories = Array.from(new Set(tiles.map((t) => t.category).filter(Boolean))).sort() as string[];
  const q = query.trim().toLowerCase();
  const filtering = activeCat !== 'all' || q !== '';
  const filtered = tiles.filter(
    (t) => (activeCat === 'all' || t.category === activeCat) && (q === '' || matchesQuery(t, q))
  );

  const card = (t: CatalogTile) => (
    <CatalogCard key={t.id} tile={t} installable={canInstall(t)} preview={isPreview(t)} onOpen={() => setSelected(t)} />
  );

  return (
    <PageShell>
      <PageHeader icon={Store} title={`APP CATALOG — ${tiles.length}`} />
      <PageBody>
        {err && <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}>{err}</div>}

        {tiles.length === 0 && !err && (
          <p style={{ color: DIM, fontSize: 11, fontFamily: MONO }}>loading catalog…</p>
        )}

        {/* Search + category filter chips — all client-side over the manifest. */}
        {tiles.length > 0 && (
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', marginBottom: 18 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, ...fieldStyle, padding: '0 9px' }}>
              <Search size={12} color={DIM} />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search apps…"
                style={{ background: 'transparent', border: 'none', outline: 'none', color: FG, fontFamily: MONO, fontSize: 11, padding: '7px 0', width: 180 }}
              />
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {['all', ...categories].map((cat) => (
                <Btn key={cat} small variant={activeCat === cat ? 'primary' : 'default'} onClick={() => setActiveCat(cat)}>
                  {cat === 'all' ? 'ALL' : cat.toUpperCase()}
                </Btn>
              ))}
            </div>
          </div>
        )}

        {filtering ? (
          <div style={{ marginBottom: 28 }}>
            <SectionLabel>
              {filtered.length} {filtered.length === 1 ? 'RESULT' : 'RESULTS'}
            </SectionLabel>
            {filtered.length === 0 ? (
              <Hint>No apps match — try a different search or category.</Hint>
            ) : (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>{filtered.map(card)}</div>
            )}
          </div>
        ) : (
          <>
            {COLLECTIONS.map(({ key, label, blurb }) => {
              const group = tiles.filter((t) => t.collection === key);
              if (group.length === 0) return null;
              return (
                <div key={key} style={{ marginBottom: 28 }}>
                  <SectionLabel>{label}</SectionLabel>
                  <Hint style={{ marginTop: -4, marginBottom: 12 }}>{blurb}</Hint>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>{group.map(card)}</div>
                </div>
              );
            })}

            {/* Custom — bring-your-own-compose. Consolidates the old Apps-page
                "Add App" form so all app-adding lives in one place. */}
            <div style={{ marginBottom: 28 }}>
              <SectionLabel>CUSTOM</SectionLabel>
              <Hint style={{ marginTop: -4, marginBottom: 12 }}>Bring your own Docker Compose stack.</Hint>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
                <CustomCard onOpen={() => setCustomOpen(true)} />
              </div>
            </div>
          </>
        )}
      </PageBody>

      {selected && (
        <InstallDrawer
          tile={selected}
          deployTargets={deployTargets.filter((n) => archOK(selected, n))}
          clusterId={clusterId}
          onClose={() => setSelected(null)}
        />
      )}
      {customOpen && (
        <CustomDrawer deployTargets={deployTargets} clusterId={clusterId} onClose={() => setCustomOpen(false)} />
      )}
    </PageShell>
  );
}

function CatalogCard({
  tile,
  installable,
  preview,
  onOpen,
}: {
  tile: CatalogTile;
  installable: boolean;
  preview: boolean;
  onOpen: () => void;
}) {
  const [hover, setHover] = useState(false);
  return (
    <div
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        flex: '1 1 280px',
        maxWidth: 340,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        padding: 14,
        opacity: preview ? 0.72 : 1,
        background: hover ? accentA(0.04) : PANEL,
        border: `1px ${preview ? 'dashed' : 'solid'} ${hover ? accentA(0.35) : HAIR}`,
        transition: 'background 0.15s, border-color 0.15s',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {tile.icon && <span style={{ fontSize: 18, lineHeight: 1 }}>{tile.icon}</span>}
        <span style={{ color: FG, fontSize: 12, fontFamily: MONO, letterSpacing: '0.04em' }}>{tile.name}</span>
        {preview && (
          <span style={{ marginLeft: 'auto' }}>
            <Badge color="#facc15">SOON</Badge>
          </span>
        )}
      </div>
      <p style={{ color: DIM, fontSize: 10, fontFamily: MONO, lineHeight: 1.5, margin: 0, minHeight: 30 }}>
        {tile.tagline}
      </p>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
        <Badge>{ramLabel(tile.ramFloorMB)}</Badge>
        {tile.arch !== 'both' && <Badge color="#facc15">{tile.arch.toUpperCase()} ONLY</Badge>}
        {tile.placementHint === 'prefer-x86' && <Badge>PREFERS X86</Badge>}
        {tile.needsHardware && <Badge color="#facc15">NEEDS {tile.needsHardware.toUpperCase()}</Badge>}
        {tile.needsFeedKey && tile.needsFeedKey.length > 0 && <Badge color="#facc15">NEEDS KEYS</Badge>}
      </div>
      <div style={{ display: 'flex', gap: 6, marginTop: 2 }}>
        <Btn variant="primary" small onClick={onOpen}>
          <UploadCloud size={10} /> {preview ? 'DETAILS' : installable ? 'INSTALL' : 'DETAILS'}
        </Btn>
        {tile.website && (
          <Btn variant="ghost" small onClick={() => window.open(tile.website, '_blank', 'noopener')}>
            SOURCE
          </Btn>
        )}
      </div>
    </div>
  );
}

function CustomCard({ onOpen }: { onOpen: () => void }) {
  const [hover, setHover] = useState(false);
  return (
    <div
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        flex: '1 1 280px',
        maxWidth: 340,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        padding: 14,
        background: hover ? accentA(0.04) : PANEL,
        border: `1px dashed ${hover ? accentA(0.35) : HAIR}`,
        transition: 'background 0.15s, border-color 0.15s',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <FilePlus2 size={16} color={ACCENT} />
        <span style={{ color: FG, fontSize: 12, fontFamily: MONO, letterSpacing: '0.04em' }}>Custom app</span>
      </div>
      <p style={{ color: DIM, fontSize: 10, fontFamily: MONO, lineHeight: 1.5, margin: 0, minHeight: 30 }}>
        Paste any Docker Compose stack and deploy it to a node.
      </p>
      <div style={{ marginTop: 2 }}>
        <Btn variant="primary" small onClick={onOpen}>
          <FilePlus2 size={10} /> NEW CUSTOM APP
        </Btn>
      </div>
    </div>
  );
}

// ExposureField — the per-app LAN opt-in (ADR-0004 §9). Off (default) = the app
// is tailnet-only; on adds the <app>.lan.<cluster-id>.internal name and a LAN
// bind so other devices on the local network can reach it. It's a real bind, not
// just a DNS record — tailnet-only apps aren't reachable from the LAN at all.
function ExposureField({ exposeLan, onChange }: { exposeLan: boolean; onChange: (v: boolean) => void }) {
  return (
    <div>
      <SectionLabel>LAN ACCESS</SectionLabel>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <EnabledToggle
          enabled={exposeLan}
          onToggle={() => onChange(!exposeLan)}
          title={exposeLan ? 'LAN access on — click for tailnet-only' : 'Tailnet-only — click to allow LAN access'}
        />
        <span style={{ color: FG, fontSize: 10 }}>{exposeLan ? 'Reachable on your LAN' : 'Tailnet only'}</span>
      </div>
      <Hint style={{ marginTop: 6 }}>
        {exposeLan
          ? 'Devices on your local network can reach it at its .lan name. It stays reachable over your tailnet too.'
          : 'Reachable only over your tailnet — the safe default. Turn on to also let devices on your LAN reach it.'}
      </Hint>
    </div>
  );
}

// Footer shown after an app is declared (install or custom) — offers deploy,
// then the "what next": where to open it + the tile's first-run note.
function InstalledFooter({ app, clusterId, postInstall }: { app: App; clusterId: string; postInstall?: string }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [deployed, setDeployed] = useState(false);

  const access = appAccess(app, clusterId);

  async function deployNow() {
    setBusy(true);
    setErr(null);
    try {
      await deployApp(app.id);
      setDeployed(true);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Hint>
        Installed as <span style={{ color: FG }}>{app.name}</span> on <span style={{ color: FG }}>{app.targetNode}</span>.
        {deployed ? ' Deploying now…' : " It isn't running yet."}
      </Hint>
      {deployed ? (
        <>
          {access && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span style={{ color: DIM, fontSize: 10 }}>Open it at</span>
                <a href={access.tailnet} target="_blank" rel="noopener noreferrer" style={{ color: ACCENT, fontSize: 10, textDecoration: 'none' }}>
                  {access.tailnet} <ExternalLink size={9} style={{ verticalAlign: 'middle' }} />
                </a>
                <CopyButton value={access.tailnet} label="COPY" />
              </div>
              {access.lan && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <span style={{ color: DIM, fontSize: 10 }}>On your LAN</span>
                  <a href={access.lan} target="_blank" rel="noopener noreferrer" style={{ color: ACCENT, fontSize: 10, textDecoration: 'none' }}>
                    {access.lan} <ExternalLink size={9} style={{ verticalAlign: 'middle' }} />
                  </a>
                  <CopyButton value={access.lan} label="COPY" />
                </div>
              )}
            </div>
          )}
          {postInstall && <Hint>{postInstall}</Hint>}
          <Hint style={{ color: DIM }}>It may take a moment to come up — watch its status on the Apps page.</Hint>
          <Link href="/apps" style={{ textDecoration: 'none' }}>
            <Btn variant="primary">GO TO APPS</Btn>
          </Link>
        </>
      ) : (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <Btn variant="primary" disabled={busy} onClick={deployNow}>
            <UploadCloud size={11} /> {busy ? 'DEPLOYING…' : 'DEPLOY NOW'}
          </Btn>
          <Link href="/apps" style={{ textDecoration: 'none' }}>
            <Btn>VIEW IN APPS</Btn>
          </Link>
        </div>
      )}
      {err && <span style={{ color: '#f87171', fontSize: 10 }}>{err}</span>}
    </>
  );
}

function InstallDrawer({
  tile,
  deployTargets,
  clusterId,
  onClose,
}: {
  tile: CatalogTile;
  deployTargets: Node[];
  clusterId: string;
  onClose: () => void;
}) {
  const [name, setName] = useState(tile.id);
  const [targetNode, setTargetNode] = useState('');
  const [compose, setCompose] = useState<string | null>(tile.composeYaml ?? null);
  // LAN exposure opt-in. Default off (tailnet-only) — the safe default per
  // ADR-0004 §9; not pre-filled from tile.exposureDefault (see PR note).
  const [exposeLan, setExposeLan] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [installed, setInstalled] = useState<App | null>(null);
  const preview = tile.status === 'preview';
  // Only a fronted (primary) port is reachable, so LAN access is meaningful only
  // for apps that publish one — hide the toggle for port-less tiles.
  const hasWebPort = tile.ports.some((p) => p.primary);

  useEffect(() => {
    if (!preview && compose === null) {
      getCatalogTile(tile.id)
        .then((full) => setCompose(full.composeYaml ?? ''))
        .catch(() => setCompose(''));
    }
    if (!targetNode && deployTargets.length > 0) setTargetNode(deployTargets[0].id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function install() {
    setBusy(true);
    setErr(null);
    try {
      setInstalled(await installCatalogApp(tile.id, { targetNode, name, exposeLan }));
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  const noTargets = deployTargets.length === 0;

  return (
    <Drawer title={tile.name.toUpperCase()} icon={tile.icon} onClose={onClose}>
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
        <p style={{ color: FG, fontSize: 11, lineHeight: 1.6, margin: 0 }}>{tile.tagline}</p>
        {tile.description && <p style={{ color: DIM, fontSize: 10, lineHeight: 1.6, margin: 0 }}>{tile.description}</p>}

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
          <Badge>{ramLabel(tile.ramFloorMB)}</Badge>
          <Badge>{tile.arch === 'both' ? 'ARM64 + X86' : `${tile.arch.toUpperCase()} ONLY`}</Badge>
          {tile.placementHint === 'prefer-x86' && <Badge color="#facc15">PREFERS X86</Badge>}
          <Badge>{tile.exposureDefault.toUpperCase()}</Badge>
          {tile.needsHardware && <Badge color="#facc15">NEEDS {tile.needsHardware.toUpperCase()}</Badge>}
        </div>

        {tile.needsFeedKey && tile.needsFeedKey.length > 0 && (
          <Hint warn>Needs external API key(s): {tile.needsFeedKey.join(', ')}. Add them after install.</Hint>
        )}

        {tile.ports.length > 0 && (
          <div>
            <SectionLabel>PORTS</SectionLabel>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {tile.ports.map((p) => (
                <Badge key={`${p.name}-${p.published}`} color={p.primary ? ACCENT : DIM}>
                  {p.name} {p.published}
                  {p.protocol && p.protocol !== 'tcp' ? `/${p.protocol}` : ''}
                  {p.primary ? ' ★' : ''}
                </Badge>
              ))}
            </div>
            <Hint style={{ marginTop: 6 }}>★ = the port the built-in reverse proxy will front.</Hint>
          </div>
        )}

        {!preview && (
          <div>
            <SectionLabel>STACK</SectionLabel>
            {compose === null ? (
              <p style={{ color: DIM, fontSize: 10 }}>loading…</p>
            ) : (
              <>
                <pre style={{ ...fieldStyle, fontSize: 10, lineHeight: 1.5, maxHeight: 200, overflow: 'auto', margin: 0, whiteSpace: 'pre' }}>
                  {compose}
                </pre>
                <div style={{ marginTop: 6 }}>
                  <CopyButton value={compose} label="COPY COMPOSE" />
                </div>
              </>
            )}
          </div>
        )}

        {tile.website && (
          <a href={tile.website} target="_blank" rel="noopener noreferrer" style={{ color: ACCENT, fontSize: 10, textDecoration: 'none' }}>
            Learn more &amp; customize <ExternalLink size={9} style={{ verticalAlign: 'middle' }} />
          </a>
        )}
      </div>

      <div style={{ borderTop: `1px solid ${HAIR}`, padding: '14px 20px', display: 'flex', flexDirection: 'column', gap: 10 }}>
        {preview ? (
          <Hint warn>Coming soon — this app is on the roadmap but isn&apos;t available to install yet.</Hint>
        ) : installed ? (
          <InstalledFooter app={installed} clusterId={clusterId} postInstall={tile.postInstall} />
        ) : noTargets ? (
          <Hint warn>
            No online {tile.arch === 'both' ? 'compute or controlplane' : tile.arch} node is available. Bring a matching node
            online first.
          </Hint>
        ) : (
          <>
            <div style={{ display: 'flex', gap: 8 }}>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="app name" style={{ flex: 1 }} title="Instance name — must be unique" />
              <Select value={targetNode} onChange={(e) => setTargetNode(e.target.value)} style={{ minWidth: 200 }}>
                {deployTargets.map((n) => (
                  <option key={n.id} value={n.id}>
                    {nodeOptionLabel(n)}
                  </option>
                ))}
              </Select>
            </div>
            {hasWebPort && <ExposureField exposeLan={exposeLan} onChange={setExposeLan} />}
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <Btn variant="primary" disabled={busy || !name || !targetNode} onClick={install}>
                <UploadCloud size={11} /> {busy ? 'INSTALLING…' : 'INSTALL'}
              </Btn>
              {err && <span style={{ color: '#f87171', fontSize: 10 }}>{err}</span>}
            </div>
            <Hint>Install declares the app; deploy is a separate step so you can review it first.</Hint>
          </>
        )}
      </div>
    </Drawer>
  );
}

function CustomDrawer({ deployTargets, clusterId, onClose }: { deployTargets: Node[]; clusterId: string; onClose: () => void }) {
  const [name, setName] = useState('');
  const [targetNode, setTargetNode] = useState('');
  const [composeYaml, setComposeYaml] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [installed, setInstalled] = useState<App | null>(null);

  useEffect(() => {
    if (!targetNode && deployTargets.length > 0) setTargetNode(deployTargets[0].id);
  }, [deployTargets, targetNode]);

  async function create() {
    setBusy(true);
    setErr(null);
    try {
      setInstalled(await createApp({ name, targetNode, composeYaml }));
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  const noTargets = deployTargets.length === 0;

  return (
    <Drawer title="CUSTOM APP" onClose={onClose}>
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 12 }}>
        {installed ? (
          <InstalledFooter app={installed} clusterId={clusterId} />
        ) : noTargets ? (
          <Hint warn>No online compute or controlplane node is available. Bring one online first.</Hint>
        ) : (
          <>
            <div>
              <SectionLabel>NAME + TARGET</SectionLabel>
              <div style={{ display: 'flex', gap: 8 }}>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="name (e.g. nextcloud)" style={{ flex: 1 }} />
                <Select value={targetNode} onChange={(e) => setTargetNode(e.target.value)} style={{ minWidth: 200 }}>
                  {deployTargets.map((n) => (
                    <option key={n.id} value={n.id}>
                      {nodeOptionLabel(n)}
                    </option>
                  ))}
                </Select>
              </div>
            </div>
            <div>
              <SectionLabel>COMPOSE</SectionLabel>
              <Textarea
                placeholder={'services:\n  web:\n    image: nginx:alpine\n    ports:\n      - "8080:80"'}
                value={composeYaml}
                onChange={(e) => setComposeYaml(e.target.value)}
                rows={12}
                style={{ width: '100%' }}
              />
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <Btn variant="primary" disabled={busy || !name || !targetNode || !composeYaml} onClick={create}>
                <UploadCloud size={11} /> {busy ? 'ADDING…' : 'ADD APP'}
              </Btn>
              {err && <span style={{ color: '#f87171', fontSize: 10 }}>{err}</span>}
            </div>
            <Hint>Adds the app; deploy is a separate step so you can review it first.</Hint>
          </>
        )}
      </div>
    </Drawer>
  );
}
