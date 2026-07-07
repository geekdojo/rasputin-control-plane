'use client';

import { Store, UploadCloud, X } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import {
  deployApp,
  getCatalogTile,
  installCatalogApp,
  listCatalog,
  listNodes,
  openInventoryWS,
} from '../../../lib/api';
import type { App, CatalogCollection, CatalogTile, Node } from '../../../lib/types';
import {
  Badge,
  Btn,
  CopyButton,
  DIM,
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

// archOK mirrors the api's install gate: a non-"both" tile needs a matching
// node arch, but an unreported arch ("") is allowed through.
function archOK(tile: CatalogTile, node: Node): boolean {
  if (tile.arch === 'both') return true;
  if (!node.architecture) return true;
  return node.architecture === tile.arch;
}

export default function AppCatalogPage() {
  const [tiles, setTiles] = useState<CatalogTile[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [selected, setSelected] = useState<CatalogTile | null>(null);

  useEffect(() => {
    listCatalog().then(setTiles).catch((e) => setErr(String(e)));
    listNodes().then(setNodes).catch(() => {});
    const closeInv = openInventoryWS(() => listNodes().then(setNodes).catch(() => {}));
    return () => closeInv();
  }, []);

  const deployTargets = nodes.filter((n) => n.role === 'compute' || n.role === 'controlplane');

  return (
    <PageShell>
      <PageHeader icon={Store} title={`APP CATALOG — ${tiles.length}`} />
      <PageBody>
        {err && <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}>{err}</div>}

        {tiles.length === 0 && !err && (
          <p style={{ color: DIM, fontSize: 11, fontFamily: MONO }}>loading catalog…</p>
        )}

        {COLLECTIONS.map(({ key, label, blurb }) => {
          const group = tiles.filter((t) => t.collection === key);
          if (group.length === 0) return null;
          return (
            <div key={key} style={{ marginBottom: 28 }}>
              <SectionLabel>{label}</SectionLabel>
              <Hint style={{ marginTop: -4, marginBottom: 12 }}>{blurb}</Hint>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
                {group.map((t) => (
                  <CatalogCard
                    key={t.id}
                    tile={t}
                    installable={deployTargets.some((n) => archOK(t, n))}
                    onOpen={() => setSelected(t)}
                  />
                ))}
              </div>
            </div>
          );
        })}
      </PageBody>

      {selected && (
        <InstallDrawer
          tile={selected}
          deployTargets={deployTargets.filter((n) => archOK(selected, n))}
          onClose={() => setSelected(null)}
        />
      )}
    </PageShell>
  );
}

function CatalogCard({
  tile,
  installable,
  onOpen,
}: {
  tile: CatalogTile;
  installable: boolean;
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
        background: hover ? accentA(0.04) : PANEL,
        border: `1px solid ${hover ? accentA(0.35) : HAIR}`,
        transition: 'background 0.15s, border-color 0.15s',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {tile.icon && <span style={{ fontSize: 18, lineHeight: 1 }}>{tile.icon}</span>}
        <span style={{ color: FG, fontSize: 12, fontFamily: MONO, letterSpacing: '0.04em' }}>{tile.name}</span>
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
          <UploadCloud size={10} /> {installable ? 'INSTALL' : 'DETAILS'}
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

function InstallDrawer({
  tile,
  deployTargets,
  onClose,
}: {
  tile: CatalogTile;
  deployTargets: Node[];
  onClose: () => void;
}) {
  const [name, setName] = useState(tile.id);
  const [targetNode, setTargetNode] = useState('');
  const [compose, setCompose] = useState<string | null>(tile.composeYaml ?? null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [installed, setInstalled] = useState<App | null>(null);
  const [deployMsg, setDeployMsg] = useState<string | null>(null);

  useEffect(() => {
    if (compose === null) {
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
      const app = await installCatalogApp(tile.id, { targetNode, name });
      setInstalled(app);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function deployNow() {
    if (!installed) return;
    setBusy(true);
    setErr(null);
    try {
      await deployApp(installed.id);
      setDeployMsg('Deploy started — track it on the Apps page.');
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  const noTargets = deployTargets.length === 0;

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.5)',
        display: 'flex',
        justifyContent: 'flex-end',
        zIndex: 50,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 'min(560px, 92vw)',
          height: '100%',
          background: 'var(--rasp-bg)',
          borderLeft: `1px solid ${HAIR}`,
          display: 'flex',
          flexDirection: 'column',
          fontFamily: MONO,
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            padding: '14px 20px',
            borderBottom: `1px solid ${HAIR}`,
          }}
        >
          {tile.icon && <span style={{ fontSize: 18 }}>{tile.icon}</span>}
          <span style={{ color: FG, fontSize: 12, letterSpacing: '0.06em' }}>{tile.name.toUpperCase()}</span>
          <button
            onClick={onClose}
            title="Close"
            style={{ marginLeft: 'auto', background: 'transparent', border: 'none', cursor: 'pointer', color: DIM, display: 'flex' }}
          >
            <X size={16} />
          </button>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
          <p style={{ color: FG, fontSize: 11, lineHeight: 1.6, margin: 0 }}>{tile.tagline}</p>
          {tile.description && (
            <p style={{ color: DIM, fontSize: 10, lineHeight: 1.6, margin: 0 }}>{tile.description}</p>
          )}

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

          <div>
            <SectionLabel>STACK</SectionLabel>
            {compose === null ? (
              <p style={{ color: DIM, fontSize: 10 }}>loading…</p>
            ) : (
              <>
                <pre
                  style={{
                    ...fieldStyle,
                    fontSize: 10,
                    lineHeight: 1.5,
                    maxHeight: 200,
                    overflow: 'auto',
                    margin: 0,
                    whiteSpace: 'pre',
                  }}
                >
                  {compose}
                </pre>
                <div style={{ marginTop: 6 }}>
                  <CopyButton value={compose} label="COPY COMPOSE" />
                </div>
              </>
            )}
          </div>
        </div>

        {/* Install footer */}
        <div style={{ borderTop: `1px solid ${HAIR}`, padding: '14px 20px', display: 'flex', flexDirection: 'column', gap: 10 }}>
          {installed ? (
            <>
              <Hint>
                Installed as <span style={{ color: FG }}>{installed.name}</span> on{' '}
                <span style={{ color: FG }}>{installed.targetNode}</span>. It isn&apos;t running yet.
              </Hint>
              {deployMsg ? (
                <Hint>{deployMsg}</Hint>
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
              {deployMsg && (
                <Link href="/apps" style={{ textDecoration: 'none' }}>
                  <Btn variant="primary">GO TO APPS</Btn>
                </Link>
              )}
              {err && <span style={{ color: '#f87171', fontSize: 10 }}>{err}</span>}
            </>
          ) : noTargets ? (
            <Hint warn>
              No {tile.arch === 'both' ? 'compute or controlplane' : `${tile.arch}`} node is available to install onto.
              Register a matching node first.
            </Hint>
          ) : (
            <>
              <div style={{ display: 'flex', gap: 8 }}>
                <Input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="app name"
                  style={{ flex: 1 }}
                  title="Instance name — must be unique"
                />
                <Select value={targetNode} onChange={(e) => setTargetNode(e.target.value)} style={{ minWidth: 180 }}>
                  {deployTargets.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.id} ({n.role}
                      {n.architecture ? `, ${n.architecture}` : ''})
                    </option>
                  ))}
                </Select>
              </div>
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
      </div>
    </div>
  );
}
