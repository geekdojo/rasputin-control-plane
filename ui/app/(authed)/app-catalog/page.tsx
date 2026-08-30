'use client';

import { ExternalLink, FilePlus2, RefreshCw, Search, ShieldAlert, Store, UploadCloud } from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  createApp,
  deployApp,
  getCatalogStatus,
  getCatalogTile,
  getSetupState,
  installCatalogApp,
  listCatalog,
  listNodes,
  openInventoryWS,
  refreshCatalog,
} from '../../../lib/api';
import type { App, CatalogCollection, CatalogStatus, CatalogTile, Node } from '../../../lib/types';
import { grantLabel, isRoutine, TIER_COPY, tierOf } from '../../../lib/privilege';
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
  LinkBtn,
  PageBody,
  PageHeader,
  PageShell,
  PANEL,
  SectionLabel,
  Select,
  Textarea,
  fieldStyle,
} from '../../../components/kit';
import { ACCENT, MONO } from '../../../components/ui-theme';

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
//
// COMPUTE ONLY. The controlplane node is excluded to match the api's install
// gate: rasputin-api owns :443 there, so the node-local Caddy that fronts apps
// can never bind it and the app ends up running and unreachable behind the
// control plane's own cert and 404. Offering it here would only produce a
// choice that always 400s.
function targetable(n: Node): boolean {
  return n.role === 'compute' && n.status !== 'offline';
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

        <CatalogFreshness onAdopted={() => listCatalog().then(setTiles).catch(() => {})} />

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
                aria-label="Search apps"
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
  // No hover affordance on the card itself: it has no onClick, no role and no
  // tabIndex, so lighting up its background AND border on hover advertised a
  // click it never handled. Only the buttons below are targets — and the card
  // can't become one, because it contains the SOURCE link.
  return (
    <div
      style={{
        flex: '1 1 280px',
        maxWidth: 340,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        padding: 14,
        opacity: preview ? 0.72 : 1,
        background: PANEL,
        border: `1px ${preview ? 'dashed' : 'solid'} ${HAIR}`,
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
        <PrivilegeBadges tile={tile} />
      </div>
      <div style={{ display: 'flex', gap: 6, marginTop: 2 }}>
        <Btn
          variant="primary"
          small
          aria-label={`${!preview && installable ? 'Install' : 'Details for'} ${tile.name}`}
          onClick={onOpen}
        >
          <UploadCloud size={10} /> {preview ? 'DETAILS' : installable ? 'INSTALL' : 'DETAILS'}
        </Btn>
        {/* A real link, not window.open(): Chrome's popup blocker wants
            transient user activation, which a synthetic click has none of, so
            the old onClick was silently dropped for every browser agent. */}
        {tile.website && (
          <LinkBtn external href={tile.website} variant="ghost" small aria-label={`${tile.name} source website`}>
            SOURCE
          </LinkBtn>
        )}
      </div>
    </div>
  );
}

function CustomCard({ onOpen }: { onOpen: () => void }) {
  // Same as CatalogCard: no wrapper hover, the button is the target.
  return (
    <div
      style={{
        flex: '1 1 280px',
        maxWidth: 340,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        padding: 14,
        background: PANEL,
        border: `1px dashed ${HAIR}`,
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

// relativeTime renders an ISO timestamp as "4m ago". Deliberately coarse: the
// question this panel answers is "has it looked recently", not "when exactly".
function relativeTime(iso: string): string {
  const secs = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (secs < 90) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 90) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 36) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

// How long to keep re-reading _status after a manual refresh. The refresh is
// fire-and-forget (the api answers 202 and the poll runs in the background), so
// the panel watches for lastChecked to advance. Bounded deliberately: an
// unbounded poll would spin forever against a cluster whose fetch is wedged and
// report nothing, which is the exact opposite of what this panel is for.
const REFRESH_POLL_MS = 1500;
const REFRESH_DEADLINE_MS = 30_000;

// CatalogFreshness — where the catalog in effect came from, and a way to check
// now (#163).
//
// Without this, "apps show up on their own" is indistinguishable from "the
// catalog is broken". The distinction that matters most is NEVER CHECKED vs
// CHECKED AND UP TO DATE: lastChecked is null until a poll completes, and a
// cluster that has never reached the internet must not render the same as one
// that is current. That was #149's failure mode in the updates panel — reading
// "nothing available" when it had simply never looked — and the api carries the
// null specifically so this cannot repeat it.
function CatalogFreshness({ onAdopted }: { onAdopted: () => void }) {
  const [status, setStatus] = useState<CatalogStatus | null>(null);
  const [checking, setChecking] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  useEffect(() => {
    getCatalogStatus().then(setStatus).catch(() => {});
  }, []);

  async function checkNow() {
    if (!status) return;
    const before = status.lastChecked;
    const startedVersion = status.version;
    setChecking(true);
    setNote(null);
    try {
      await refreshCatalog();
    } catch (e) {
      setChecking(false);
      setNote(String(e));
      return;
    }

    const deadline = Date.now() + REFRESH_DEADLINE_MS;
    for (;;) {
      await new Promise((r) => setTimeout(r, REFRESH_POLL_MS));
      let next: CatalogStatus;
      try {
        next = await getCatalogStatus();
      } catch {
        continue; // transient; the deadline below still bounds this
      }
      if (next.lastChecked && next.lastChecked !== before) {
        setStatus(next);
        setChecking(false);
        if (next.version !== startedVersion) onAdopted();
        return;
      }
      if (Date.now() >= deadline) {
        setStatus(next);
        setChecking(false);
        // Said plainly rather than left spinning. "Still running" is a real
        // answer; a spinner that never resolves is not.
        setNote('Still checking after 30s — the fetch is taking longer than expected. Reload to see the result.');
        return;
      }
    }
  }

  if (!status) return null;

  const neverChecked = !status.lastChecked;
  const embedded = status.source === 'embedded';
  const warn = neverChecked || !!status.lastError || (status.rejectedTiles?.length ?? 0) > 0;

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: 12,
        flexWrap: 'wrap',
        padding: '10px 12px',
        marginBottom: 16,
        border: `1px ${warn ? 'solid' : 'dashed'} ${warn ? '#facc1555' : HAIR}`,
        background: warn ? '#facc150d' : 'transparent',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', flex: 1, minWidth: 260 }}>
        <Badge color={embedded ? '#facc15' : ACCENT}>CATALOG v{status.version}</Badge>
        <Badge>{status.tiles} TILES</Badge>
        {embedded && (
          <Badge color="#facc15" title="Nothing has been adopted — these are the tiles baked into this image">
            BUILT IN
          </Badge>
        )}
        <span style={{ color: DIM, fontSize: 10 }}>
          {checking
            ? 'checking…'
            : neverChecked
              ? 'never checked for updates'
              : `checked ${relativeTime(status.lastChecked as string)}`}
        </span>
      </div>
      <Btn small disabled={checking} onClick={() => void checkNow()}>
        <RefreshCw size={10} /> {checking ? 'CHECKING…' : 'CHECK NOW'}
      </Btn>

      {(note || status.lastError || status.note || neverChecked || (status.rejectedTiles?.length ?? 0) > 0) && (
        <div style={{ flexBasis: '100%' }}>
          {note && <Hint warn>{note}</Hint>}
          {status.lastError && <Hint warn>Last check failed: {status.lastError}</Hint>}
          {!status.lastError && neverChecked && (
            <Hint warn>
              This cluster has not checked for a published catalog yet, so these are the tiles baked into its image.
              That is not the same as being up to date.
            </Hint>
          )}
          {status.note && !status.lastError && <Hint>{status.note}</Hint>}
          {(status.rejectedTiles?.length ?? 0) > 0 && (
            <div style={{ marginTop: 6 }}>
              <Hint warn>
                {status.rejectedTiles!.length} tile(s) in the published catalog were refused by this build — usually
                because this cluster is older than the catalog it is reading. Update it to see them.
              </Hint>
              <ul style={{ margin: '4px 0 0', paddingLeft: 16, color: DIM, fontSize: 10, lineHeight: 1.6 }}>
                {status.rejectedTiles!.map((r) => (
                  <li key={r.id}>
                    <span style={{ color: FG }}>{r.id}</span> — {r.reason}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// PrivilegeBadges — the tier, in the same yellow-badge idiom the catalog
// already uses for NEEDS <hardware>. Routine tiles carry no badge at all:
// almost every tile is routine, so badging them would make the badge mean
// "this is an app" rather than "look at this".
//
// The container runtime socket gets its OWN badge rather than being folded
// into the tier (ADR-0006 Decision 12b). It is not merely root-equivalent — it
// is the ability to escape any constraint added later, and it is the specific
// footgun of this hobby. A tier that hides it teaches the owner nothing.
function PrivilegeBadges({ tile }: { tile: CatalogTile }) {
  if (isRoutine(tile.privilege)) return null;
  const copy = TIER_COPY[tierOf(tile.privilege)];
  return (
    <>
      <Badge color={copy.color} title={copy.summary}>
        {copy.label}
      </Badge>
      {tile.privilege?.dockerSocket && (
        <Badge color={TIER_COPY['host-trusting'].color} title="Can control the container runtime">
          RUNTIME SOCKET
        </Badge>
      )}
    </>
  );
}

// PrivilegePanel — what the app can do, why it says it needs to, and a "what
// does this mean" that teaches rather than warns (ADR-0006 Decision 12c).
//
// The grant list is DERIVED from the app's own compose by the publisher and
// covered by the catalog signature, so it is not a promise — it is the same
// list the control plane checked before it would load the tile at all.
function PrivilegePanel({ tile }: { tile: CatalogTile }) {
  const [open, setOpen] = useState(false);
  if (isRoutine(tile.privilege)) return null;
  const tier = tierOf(tile.privilege);
  const copy = TIER_COPY[tier];
  const grants = tile.privilege?.grants ?? [];

  return (
    <div style={{ border: `1px solid ${copy.color}55`, background: `${copy.color}0d`, padding: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <ShieldAlert size={12} color={copy.color} />
        <span style={{ color: copy.color, fontSize: 10, fontFamily: MONO, letterSpacing: '0.06em' }}>
          {copy.label}
        </span>
        <span style={{ color: DIM, fontSize: 10 }}>{copy.summary}</span>
      </div>

      {tile.privilege?.why && (
        <p style={{ color: FG, fontSize: 10, lineHeight: 1.6, margin: '0 0 8px' }}>{tile.privilege.why}</p>
      )}

      {grants.length > 0 && (
        <>
          <SectionLabel>THIS APP CAN</SectionLabel>
          <ul style={{ margin: '4px 0 0', paddingLeft: 16, color: FG, fontSize: 10, lineHeight: 1.7 }}>
            {grants.map((g) => (
              <li key={g} title={g}>
                {grantLabel(g)}
              </li>
            ))}
          </ul>
        </>
      )}

      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        style={{
          marginTop: 10,
          padding: 0,
          border: 'none',
          background: 'none',
          color: ACCENT,
          fontSize: 10,
          fontFamily: MONO,
          cursor: 'pointer',
        }}
      >
        {open ? '\u2212' : '+'} what does this mean?
      </button>
      {open && (
        <p style={{ color: DIM, fontSize: 10, lineHeight: 1.7, margin: '8px 0 0' }}>
          {copy.explainer}{' '}
          {tier !== 'routine' && (
            <>
              Everything listed above was read out of the app&apos;s own compose file by the catalog publisher and
              signed with it, and this cluster refused to load the tile until the two matched — so the list is what
              the app takes, not what it claims.
            </>
          )}
        </p>
      )}
    </div>
  );
}

// ConsentGate — consent PROPORTIONAL to the tier (ADR-0006 Decision 12c).
// Routine asks nothing; elevated is an acknowledgement; host-trusting is a
// deliberate act, so it asks for the app's name to be typed.
//
// This is a gate on the owner, not on an attacker: the install API is
// authenticated to the same person, and Decision 12 is explicit that nothing
// here is enforced beyond what Docker enforces from the compose. Its job is to
// make sure nobody grants root by clicking the same button they click for a
// note-taking app.
function ConsentGate({
  tile,
  consented,
  onConsent,
  typed,
  onType,
}: {
  tile: CatalogTile;
  consented: boolean;
  onConsent: (v: boolean) => void;
  typed: string;
  onType: (v: string) => void;
}) {
  const tier = tierOf(tile.privilege);
  if (tier === 'routine') return null;
  const copy = TIER_COPY[tier];

  return (
    <div>
      <SectionLabel>CONSENT</SectionLabel>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <EnabledToggle
          enabled={consented}
          onToggle={() => onConsent(!consented)}
          aria-label={`Consent to what ${tile.name} can do`}
          title={consented ? 'Consent given — click to withdraw' : 'Click to consent'}
        />
        <span style={{ color: FG, fontSize: 10 }}>
          {tier === 'host-trusting'
            ? `Give ${tile.name} root-equivalent access to this node`
            : `Let ${tile.name} reach beyond its own container`}
        </span>
      </div>
      {consented && tier === 'host-trusting' && (
        <div style={{ marginTop: 8 }}>
          <Input
            value={typed}
            onChange={(e) => onType(e.target.value)}
            placeholder={tile.id}
            aria-label={`Type ${tile.id} to confirm`}
            title="Type the app id to confirm"
            style={{ width: '100%' }}
          />
          <Hint warn style={{ marginTop: 6 }}>
            Type <strong>{tile.id}</strong> to confirm. {copy.summary} You can change your mind later, but you cannot
            un-run it.
          </Hint>
        </div>
      )}
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
          aria-label="LAN access"
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
                <CopyButton value={access.tailnet} label="COPY" ariaLabel="Copy tailnet address" />
              </div>
              {access.lan && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <span style={{ color: DIM, fontSize: 10 }}>On your LAN</span>
                  <a href={access.lan} target="_blank" rel="noopener noreferrer" style={{ color: ACCENT, fontSize: 10, textDecoration: 'none' }}>
                    {access.lan} <ExternalLink size={9} style={{ verticalAlign: 'middle' }} />
                  </a>
                  <CopyButton value={access.lan} label="COPY" ariaLabel="Copy LAN address" />
                </div>
              )}
            </div>
          )}
          {postInstall && <Hint>{postInstall}</Hint>}
          <Hint style={{ color: DIM }}>It may take a moment to come up — watch its status on the Apps page.</Hint>
          <LinkBtn href="/apps" variant="primary">GO TO APPS</LinkBtn>
        </>
      ) : (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <Btn variant="primary" disabled={busy} onClick={deployNow}>
            <UploadCloud size={11} /> {busy ? 'DEPLOYING…' : 'DEPLOY NOW'}
          </Btn>
          <LinkBtn href="/apps">VIEW IN APPS</LinkBtn>
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
  // Default selection DERIVED rather than written from an effect — "nothing
  // chosen yet" falls back to the first deploy target. Writing it was a
  // synchronous setState on effect entry (set-state-in-effect).
  const selectedTarget = targetNode || (deployTargets[0]?.id ?? '');
  const [compose, setCompose] = useState<string | null>(tile.composeYaml ?? null);
  // LAN exposure opt-in. Default off (tailnet-only) — the safe default per
  // ADR-0004 §9; not pre-filled from tile.exposureDefault (see PR note).
  const [exposeLan, setExposeLan] = useState(false);
  // Consent state (ADR-0006 Decision 12c). Both start false on every open, so
  // reopening the drawer never carries a previous decision forward.
  const [consented, setConsented] = useState(false);
  const [typedConfirm, setTypedConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [installed, setInstalled] = useState<App | null>(null);
  const preview = tile.status === 'preview';
  // Only a fronted port is reachable by name over HTTPS, so LAN access is
  // meaningful only for apps that declare one — hide the toggle for page-less
  // tiles.
  const hasWebPort = tile.ports.some((p) => p.web);
  // A routine tile is asked nothing; elevated needs the acknowledgement;
  // host-trusting needs the acknowledgement AND the app's id typed back.
  const tier = tierOf(tile.privilege);
  const consentSatisfied =
    tier === 'routine' || (consented && (tier !== 'host-trusting' || typedConfirm.trim() === tile.id));

  useEffect(() => {
    if (!preview && compose === null) {
      getCatalogTile(tile.id)
        .then((full) => setCompose(full.composeYaml ?? ''))
        .catch(() => setCompose(''));
    }
  }, []);

  async function install() {
    setBusy(true);
    setErr(null);
    try {
      setInstalled(await installCatalogApp(tile.id, { targetNode: selectedTarget, name, exposeLan }));
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
          <PrivilegeBadges tile={tile} />
        </div>

        <PrivilegePanel tile={tile} />

        {tile.needsFeedKey && tile.needsFeedKey.length > 0 && (
          <Hint warn>Needs external API key(s): {tile.needsFeedKey.join(', ')}. Add them after install.</Hint>
        )}

        {tile.ports.length > 0 && (
          <div>
            <SectionLabel>PORTS</SectionLabel>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {tile.ports.map((p) => (
                <Badge key={`${p.name}-${p.published}`} color={p.web ? ACCENT : DIM}>
                  {p.name} {p.published}
                  {p.protocol && p.protocol !== 'tcp' ? `/${p.protocol}` : ''}
                  {p.web ? ' ★' : ''}
                </Badge>
              ))}
            </div>
            <Hint style={{ marginTop: 6 }}>
              {hasWebPort
                ? '★ = the port the built-in reverse proxy will front.'
                : 'This app has no web page — connect to it directly on the port above.'}
            </Hint>
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
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="app name"
                aria-label="Instance name"
                title="Instance name — must be unique"
                style={{ flex: 1 }}
              />
              <Select
                value={selectedTarget}
                onChange={(e) => setTargetNode(e.target.value)}
                aria-label="Target node"
                style={{ minWidth: 200 }}
              >
                {deployTargets.map((n) => (
                  <option key={n.id} value={n.id}>
                    {nodeOptionLabel(n)}
                  </option>
                ))}
              </Select>
            </div>
            {hasWebPort && <ExposureField exposeLan={exposeLan} onChange={setExposeLan} />}
            <ConsentGate
              tile={tile}
              consented={consented}
              onConsent={setConsented}
              typed={typedConfirm}
              onType={setTypedConfirm}
            />
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <Btn
                variant="primary"
                disabled={busy || !name || !selectedTarget || !consentSatisfied}
                aria-label={`Install ${tile.name}`}
                title={consentSatisfied ? undefined : 'Consent to what this app can do before installing'}
                onClick={install}
              >
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

  // Default selection DERIVED rather than written from an effect — "nothing
  // chosen yet" falls back to the first deploy target. Writing it was a
  // synchronous setState on effect entry (set-state-in-effect).
  const selectedTarget = targetNode || (deployTargets[0]?.id ?? '');

  async function create() {
    setBusy(true);
    setErr(null);
    try {
      setInstalled(await createApp({ name, targetNode: selectedTarget, composeYaml }));
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
                <Input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="name (e.g. nextcloud)"
                  aria-label="App name"
                  style={{ flex: 1 }}
                />
                <Select
                  value={selectedTarget}
                  onChange={(e) => setTargetNode(e.target.value)}
                  aria-label="Target node"
                  style={{ minWidth: 200 }}
                >
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
                aria-label="Docker Compose YAML"
                rows={12}
                style={{ width: '100%' }}
              />
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <Btn variant="primary" disabled={busy || !name || !selectedTarget || !composeYaml} onClick={create}>
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
