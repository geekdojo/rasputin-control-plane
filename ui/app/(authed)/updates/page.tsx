'use client';

import { ChevronDown, ChevronRight, DownloadCloud, RefreshCw, Trash2, UploadCloud, Zap } from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  checkForUpdates,
  createSystemUpdate,
  createUpdate,
  deleteBundle,
  listBundles,
  listChildJobs,
  listSteps,
  listJobs,
  listNodes,
  listUpdates,
  openSystemUpdatesWS,
  previewSystemUpdatePlan,
  openUpdatesWS,
  pullUpdate,
  uploadBundle,
} from '../../../lib/api';
import type {
  Bundle,
  ComponentUpdate,
  Job,
  JobStatus,
  JobStep,
  Node,
  NodeOutcome,
  NodeRole,
  NodeResult,
  NodeUpdate,
  NodeUpdateStatus,
  PlanTarget,
  SkippedNode,
  SkipReason,
  SystemUpdatePlan,
  UpdateChangeEvent,
  UpdateCheckResult,
} from '../../../lib/types';
import {
  Badge,
  Btn,
  CopyButton,
  Drawer,
  Input,
  DIM,
  FG,
  HAIR,
  Hint,
  PageBody,
  PageHeader,
  PageShell,
  PANEL,
  Select,
  SectionLabel,
  Tok,
  fieldStyle,
  tdStyle,
  thStyle,
} from '../../../components/kit';
import { ACCENT, accentA, MONO } from '../../../components/ui-theme';

function nodeUpdateColor(s: NodeUpdateStatus): string {
  switch (s) {
    case 'committed':
      return '#4ade80';
    case 'rolled_back':
      return '#facc15';
    case 'failed':
      return '#f87171';
    default:
      return ACCENT; // in_progress
  }
}

function jobColor(s: JobStatus): string {
  switch (s) {
    case 'succeeded':
      return '#4ade80';
    case 'failed':
      return '#f87171';
    case 'running':
      return ACCENT;
    default:
      return DIM;
  }
}

function changeColor(change: string): string {
  if (change === 'committed') return '#4ade80';
  if (change === 'rolled_back') return '#facc15';
  if (change === 'failed') return '#f87171';
  if (change === 'started') return ACCENT;
  return DIM;
}

export default function UpdatesPage() {
  const [bundles, setBundles] = useState<Bundle[]>([]);
  const [trustConfigured, setTrustConfigured] = useState(true);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [history, setHistory] = useState<NodeUpdate[]>([]);
  const [systemJobs, setSystemJobs] = useState<Job[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [recent, setRecent] = useState<UpdateChangeEvent[]>([]);
  const [check, setCheck] = useState<UpdateCheckResult | null>(null);
  const [checking, setChecking] = useState(false);
  const [checkErr, setCheckErr] = useState<string | null>(null);

  async function runCheck() {
    setChecking(true);
    setCheckErr(null);
    try {
      setCheck(await checkForUpdates());
    } catch (e) {
      setCheckErr(String(e));
    } finally {
      setChecking(false);
    }
  }

  useEffect(() => {
    refresh();
    const closePerNode = openUpdatesWS((ev) => {
      setRecent((prev) => [ev, ...prev].slice(0, 20));
      listUpdates().then(setHistory).catch(() => {});
    });
    const closeSystem = openSystemUpdatesWS(() => refreshSystemJobs());
    return () => {
      closePerNode();
      closeSystem();
    };
  }, []);

  function refresh() {
    listBundles()
      .then((b) => {
        setBundles(b.bundles);
        setTrustConfigured(b.trustConfigured);
      })
      .catch((e) => setErr(String(e)));
    listNodes().then(setNodes).catch(() => {});
    listUpdates().then(setHistory).catch(() => {});
    refreshSystemJobs();
  }

  function refreshSystemJobs() {
    listJobs(50)
      .then((all) => setSystemJobs(all.filter((j) => j.kind === 'system.update')))
      .catch(() => {});
  }

  async function handleDeleteBundle(sha: string) {
    if (!confirm('Delete this bundle? Any node currently mid-update will fail.')) return;
    try {
      await deleteBundle(sha);
      setBundles((prev) => prev.filter((b) => b.sha256 !== sha));
    } catch (e) {
      setErr(String(e));
    }
  }

  return (
    <PageShell>
      <PageHeader icon={Zap} title="UPDATES" />
      <PageBody>
        {!trustConfigured && (
          <Hint warn style={{ marginBottom: 14 }}>
            ⚠ No root CA configured at <Tok>data/trust/root-ca.pem</Tok>. Bundle signatures will not be verified — run{' '}
            <Tok>./scripts/pki-init.sh</Tok> and copy <Tok>root-ca.pem</Tok> into the trust dir.
          </Hint>
        )}
        {err && <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}>{err}</div>}

        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10 }}>
          <SectionLabel style={{ marginBottom: 0, borderBottom: 'none', flex: 1 }}>
            AVAILABLE UPDATES{check ? ` · ${check.channel.toUpperCase()} CHANNEL` : ''}
          </SectionLabel>
          <Btn variant="primary" small disabled={checking} onClick={runCheck}>
            <RefreshCw size={10} /> {checking ? 'CHECKING…' : 'CHECK FOR UPDATES'}
          </Btn>
        </div>
        {checkErr && (
          <Hint warn style={{ marginBottom: 14 }}>
            Couldn&apos;t reach the release server: {checkErr}
          </Hint>
        )}
        {!check && !checkErr && (
          <Hint style={{ marginBottom: 18 }}>
            check the release channel for newer OS and firewall versions — nothing is downloaded until you stage it
          </Hint>
        )}
        {check && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 22 }}>
            {check.components.map((c) => (
              <ComponentUpdateRow
                key={c.component}
                cu={c}
                onStaged={() => {
                  refresh();
                  runCheck();
                }}
              />
            ))}
          </div>
        )}

        {bundles.length > 0 && (
          <>
            <SectionLabel>STAGED RELEASES</SectionLabel>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 18 }}>
              {groupBundlesByRelease(bundles).map((rel) => (
                <ReleaseRow key={`${rel.component}:${rel.version}`} release={rel} nodes={nodes} />
              ))}
            </div>
          </>
        )}

        <SectionLabel>BUNDLES</SectionLabel>
        {bundles.length === 0 ? (
          <Hint style={{ marginBottom: 18 }}>
            nothing staged — updates you stage from the channel above land here, ready to deploy
          </Hint>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 18 }}>
            <thead>
              <tr>
                {['VERSION', 'ARCH', 'COMPAT', 'SIZE', 'SIGNED BY', 'UPLOADED', ''].map((c, i) => (
                  <th key={c || i} style={thStyle}>
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {bundles.map((b) => (
                <tr key={b.sha256}>
                  <td style={{ ...tdStyle, color: FG }}>
                    {b.version}
                    {b.description && <span style={{ color: DIM, fontSize: 9, marginLeft: 8 }}>· {b.description}</span>}
                  </td>
                  <td style={{ ...tdStyle, color: DIM }}>{b.architecture}</td>
                  <td style={{ ...tdStyle, color: DIM }}>{b.compatible}</td>
                  <td style={{ ...tdStyle, color: DIM }}>{formatBytes(b.sizeBytes)}</td>
                  <td style={tdStyle}>
                    {b.signedBy === '<unverified>' ? (
                      <Badge color="#facc15">UNVERIFIED</Badge>
                    ) : (
                      <span style={{ color: DIM }}>{b.signedBy || '—'}</span>
                    )}
                  </td>
                  <td style={{ ...tdStyle, color: DIM }} title={b.sha256}>
                    {new Date(b.uploadedAt).toLocaleString()}
                  </td>
                  <td style={{ ...tdStyle, paddingRight: 0 }}>
                    <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                      <DeployBundleButton bundle={b} nodes={nodes} />
                      <SystemUpdateButton bundle={b} />
                      <Btn variant="danger" small onClick={() => handleDeleteBundle(b.sha256)}>
                        <Trash2 size={10} /> DELETE
                      </Btn>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <AdvancedUpload onUploaded={(b) => setBundles((prev) => [b, ...prev])} />

        {systemJobs.length > 0 && (
          <div style={{ marginTop: 24 }}>
            <SectionLabel>SYSTEM UPDATES</SectionLabel>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {systemJobs.map((j) => (
                <SystemUpdateRow key={j.id} job={j} />
              ))}
            </div>
          </div>
        )}

        <div style={{ marginTop: 24 }}>
          <SectionLabel>HISTORY</SectionLabel>
          {history.length === 0 ? (
            <Hint>no update history yet</Hint>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  {['NODE', 'VERSION', 'SLOT', 'STATUS', 'STARTED', 'FINISHED', 'NOTES'].map((c) => (
                    <th key={c} style={thStyle}>
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.jobId}>
                    <td style={{ ...tdStyle, color: FG }}>{h.nodeId}</td>
                    <td style={{ ...tdStyle, color: DIM }}>
                      {h.fromVersion ? `${h.fromVersion} → ${h.toVersion}` : h.toVersion}
                    </td>
                    <td style={{ ...tdStyle, color: DIM }}>{h.fromSlot !== 'unknown' ? `${h.fromSlot} → ${h.toSlot}` : '—'}</td>
                    <td style={tdStyle}>
                      <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                        <Badge color={nodeUpdateColor(h.status)}>{prettyStatus(h.status)}</Badge>
                        {/* A committed row that could not evaluate every conjunct is
                            still a success — it just rests on less evidence than the
                            row above it, and saying so is the whole point. */}
                        {(h.unverifiedBoot || h.unverifiedVersion) && (
                          <Badge color="#facc15" title={unverifiedTitle(h)}>
                            DEGRADED
                          </Badge>
                        )}
                      </span>
                    </td>
                    <td style={{ ...tdStyle, color: DIM }}>{new Date(h.startedAt).toLocaleTimeString()}</td>
                    <td style={{ ...tdStyle, color: DIM }}>{h.finishedAt ? new Date(h.finishedAt).toLocaleTimeString() : '—'}</td>
                    <td style={{ ...tdStyle, color: DIM, paddingRight: 0 }}>{h.error || ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {recent.length > 0 && (
          <div style={{ marginTop: 24 }}>
            <SectionLabel>LIVE EVENTS</SectionLabel>
            <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
              {recent.map((ev, i) => (
                <li key={i} style={{ display: 'flex', gap: 8, alignItems: 'baseline', fontSize: 10, fontFamily: MONO }}>
                  <span style={{ color: FG }}>{ev.nodeId}</span>
                  <Badge color={changeColor(ev.change)}>{ev.change}</Badge>
                  {ev.version && <span style={{ color: DIM }}>{ev.version}</span>}
                  {ev.reason && <span style={{ color: DIM }}>— {ev.reason}</span>}
                  <span style={{ color: DIM, marginLeft: 'auto' }}>{new Date(ev.ts).toLocaleTimeString()}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </PageBody>
    </PageShell>
  );
}

function DeployBundleButton({ bundle, nodes }: { bundle: Bundle; nodes: Node[] }) {
  const [open, setOpen] = useState(false);
  const [nodeId, setNodeId] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // Eligibility = the bundle's SKU must match what the node runs (mirrors the
  // api's compatible-match guard). The firewall runs its OWN image
  // (rasputin-fw-n100) and now updates through the SAME node.update saga as the
  // OS nodes (openwrt-ab backend), so it IS deployable — to the firewall bundle,
  // and only that. OS nodes take OS bundles matching their arch; an amd64 bundle
  // can't install on an arm64 node. Nodes with no reported arch (pre-arch agents)
  // stay eligible for OS bundles — the api re-checks and the on-node compatible
  // check is the backstop.
  const FIREWALL_COMPATIBLE = 'rasputin-fw-n100';
  const targets = nodes.filter((n) => {
    if (n.status !== 'online') return false;
    if (n.role === 'firewall') {
      // Firewall accepts only its own image.
      return bundle.compatible === FIREWALL_COMPATIBLE;
    }
    // OS node: never the firewall image; arch must match.
    if (bundle.compatible === FIREWALL_COMPATIBLE) return false;
    return !n.architecture || n.architecture === bundle.architecture;
  });

  async function start() {
    if (!nodeId) {
      setErr('pick a node');
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await createUpdate({ nodeId, bundleSha256: bundle.sha256 });
      setOpen(false);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return (
      <Btn variant="primary" small disabled={targets.length === 0} title={targets.length === 0 ? 'no online nodes' : 'apply bundle to node'} onClick={() => setOpen(true)}>
        <UploadCloud size={10} /> DEPLOY
      </Btn>
    );
  }

  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      {/* eslint-disable-next-line jsx-a11y/no-autofocus -- this picker only
          exists after the operator clicks DEPLOY; moving focus to the control
          their click just produced is focus management, not a hijack. */}
      <Select value={nodeId} onChange={(e) => setNodeId(e.target.value)} autoFocus style={{ fontSize: 10, padding: '4px 6px' }}>
        <option value="">— pick node —</option>
        {targets.map((n) => (
          <option key={n.id} value={n.id}>
            {n.id} ({n.role})
          </option>
        ))}
      </Select>
      <Btn variant="primary" small disabled={busy || !nodeId} onClick={start}>
        {busy ? '…' : 'GO'}
      </Btn>
      <Btn small onClick={() => setOpen(false)}>
        CANCEL
      </Btn>
      {err && <span style={{ color: '#f87171', fontSize: 9 }}>{err}</span>}
    </span>
  );
}

// AdvancedUpload tucks the manual bundle upload behind a collapsed disclosure.
// The normal path is staging from the channel (the control plane fetches the
// bundle itself); manual upload is only for air-gapped installs or a locally
// built bundle, so it shouldn't read as the primary action.
function AdvancedUpload({ onUploaded }: { onUploaded: (b: Bundle) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ marginTop: 6 }}>
      <button
        onClick={() => setOpen((v) => !v)}
        style={{
          background: 'none',
          border: 'none',
          padding: 0,
          cursor: 'pointer',
          color: DIM,
          fontSize: 10,
          fontFamily: MONO,
          letterSpacing: '0.06em',
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
        }}
      >
        {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
        ADVANCED — MANUAL / AIR-GAPPED UPLOAD
      </button>
      {open && (
        <div style={{ marginTop: 10 }}>
          <UploadBundleForm onUploaded={onUploaded} />
        </div>
      )}
    </div>
  );
}

function UploadBundleForm({ onUploaded }: { onUploaded: (b: Bundle) => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function handle(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true);
    setErr(null);
    try {
      onUploaded(await uploadBundle(file));
    } catch (e2) {
      setErr(String(e2));
    } finally {
      setBusy(false);
      e.target.value = '';
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <Hint>
        only needed for air-gapped installs or a locally built bundle — produce a <Tok>.raspbundle</Tok> with{' '}
        <Tok>scripts/build-bundle.sh</Tok>, then upload it
      </Hint>
      <label
        style={{
          ...fieldStyle,
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          width: 'fit-content',
          color: ACCENT,
          border: `1px solid ${accentA(0.35)}`,
          background: accentA(0.08),
          fontSize: 10,
          letterSpacing: '0.08em',
          cursor: busy ? 'not-allowed' : 'pointer',
          opacity: busy ? 0.5 : 1,
        }}
      >
        <UploadCloud size={11} />
        {busy ? 'UPLOADING…' : 'UPLOAD BUNDLE'}
        <input type="file" onChange={handle} disabled={busy} aria-label="Upload bundle" style={{ display: 'none' }} />
      </label>
      {err && <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{err}</span>}
    </div>
  );
}

const FIREWALL_COMPATIBLE = 'rasputin-fw-n100';

/** A release is one artifact per architecture, and UPDATE ALL acts on the
 *  release — not on one of its artifacts. Grouping the staged bundles back into
 *  releases is what lets the button mean "all nodes" instead of "all nodes of
 *  whichever arch I happened to click". */
interface StagedRelease {
  version: string;
  component: 'os' | 'fw';
  bundles: Bundle[];
}

function groupBundlesByRelease(bundles: Bundle[]): StagedRelease[] {
  const byKey = new Map<string, StagedRelease>();
  for (const b of bundles) {
    const component = b.compatible === FIREWALL_COMPATIBLE ? 'fw' : 'os';
    const key = `${component}:${b.version}`;
    const rel = byKey.get(key) ?? { version: b.version, component, bundles: [] };
    rel.bundles.push(b);
    byKey.set(key, rel);
  }
  return [...byKey.values()];
}

/** Which OS SKU a node needs. Mirrors releases.ArchCompatible — a node that
 *  never reported its arch resolves to nothing, deliberately, rather than
 *  being guessed into amd64. */
function nodeCompatible(n: Node): string | null {
  if (n.role === 'firewall') return FIREWALL_COMPATIBLE;
  if (n.architecture === 'amd64') return 'rasputin-n100';
  if (n.architecture === 'arm64') return 'rasputin-rpi-arm64';
  return null;
}

// ----- Fleet-update pre-flight drawer (#95) --------------------------------

// The rollout knobs are per-run, not persistent cluster config, so they live at
// the UPDATE ALL action rather than in Settings. We remember the last-used
// width/budget/soak client-side (localStorage) so the boxes come back
// pre-filled, seeded from the ADR defaults on a fresh cluster. The canary
// override is deliberately NOT remembered — it defaults to the plan's computed
// pick each run, because a specific node id does not survive a changing fleet.
const KNOBS_LS_KEY = 'rasputin.fleetUpdate.knobs';
const DEFAULT_KNOBS = { maxInFlight: '4', maxFailures: '15%', canarySoakSeconds: 0 };
type Knobs = typeof DEFAULT_KNOBS;

function loadKnobs(): Knobs {
  try {
    const raw = localStorage.getItem(KNOBS_LS_KEY);
    if (raw) return { ...DEFAULT_KNOBS, ...JSON.parse(raw) };
  } catch {
    /* ignore corrupt/absent localStorage — fall back to defaults */
  }
  return { ...DEFAULT_KNOBS };
}

// An IntOrString knob is valid as a bare count (`4`) or a percentage (`20%`).
const KNOB_RE = /^\d+%?$/;
const groupKey = (tier: string, arch: string) => `${tier}/${arch}`;

function FleetUpdateDrawer({
  release,
  onClose,
  onDeployed,
}: {
  release: StagedRelease;
  onClose: () => void;
  onDeployed: () => void;
}) {
  const [plan, setPlan] = useState<SystemUpdatePlan | null>(null);
  const [planErr, setPlanErr] = useState<string | null>(null);
  const [knobs, setKnobs] = useState<Knobs>(loadKnobs);
  // groupKey -> chosen canary nodeId. Empty until the operator overrides one.
  const [canaryOverride, setCanaryOverride] = useState<Record<string, string>>({});
  const [advanced, setAdvanced] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // (Re)resolve the plan on open and whenever a canary override changes, so the
  // preview always reflects the pick that will actually run.
  useEffect(() => {
    let active = true;
    const canaryNodes = Object.values(canaryOverride).filter(Boolean);
    previewSystemUpdatePlan({ version: release.version, component: release.component, canaryNodes })
      .then((p) => active && (setPlan(p), setPlanErr(null)))
      .catch((e) => active && setPlanErr(String(e)));
    return () => {
      active = false;
    };
  }, [release.version, release.component, canaryOverride]);

  // Group targets by (tier, arch) so each canary-bearing group offers an
  // override select. Order preserved from the plan (planned order).
  const groups = new Map<string, { tier: NodeRole; arch: string; nodes: PlanTarget[]; canary?: string }>();
  for (const t of plan?.targets ?? []) {
    const k = groupKey(t.tier, t.compatible);
    if (!groups.has(k)) groups.set(k, { tier: t.tier, arch: t.compatible, nodes: [] });
    const g = groups.get(k)!;
    g.nodes.push(t);
    if (t.canary) g.canary = t.nodeId;
  }
  const canaryGroups = [...groups.values()].filter((g) => g.canary);

  const knobsValid = KNOB_RE.test(knobs.maxInFlight.trim()) && KNOB_RE.test(knobs.maxFailures.trim());

  async function deploy() {
    if (!knobsValid) {
      setErr('Max in flight and max failures must be a number (4) or a percentage (20%).');
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const canaryNodes = Object.values(canaryOverride).filter(Boolean);
      await createSystemUpdate({
        version: release.version,
        component: release.component,
        maxInFlight: knobs.maxInFlight.trim(),
        maxFailures: knobs.maxFailures.trim(),
        canarySoakSeconds: knobs.canarySoakSeconds || undefined,
        canaryNodes: canaryNodes.length ? canaryNodes : undefined,
      });
      try {
        localStorage.setItem(KNOBS_LS_KEY, JSON.stringify(knobs));
      } catch {
        /* non-fatal: the update still dispatched */
      }
      onDeployed();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  const skips = plan?.skipped ?? [];
  const stranded = skips.filter((s) => s.reason === 'no-artifact-for-arch');

  return (
    <Drawer title={`REVIEW ROLLOUT · ${release.version}`} icon="🚀" onClose={onClose}>
      <div style={{ padding: '16px 20px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 18 }}>
        {planErr && (
          <Hint warn>
            The plan can&apos;t run as staged: {planErr}
          </Hint>
        )}

        {/* Plan — ordered targets, canaries flagged */}
        <div>
          <SectionLabel>PLAN{plan ? ` · ${plan.targets.length} NODE${plan.targets.length === 1 ? '' : 'S'}` : ''}</SectionLabel>
          {!plan && !planErr && <span style={{ color: DIM, fontSize: 10 }}>resolving…</span>}
          {plan && plan.targets.length === 0 && !planErr && (
            <span style={{ color: DIM, fontSize: 10 }}>no online nodes match this release</span>
          )}
          {plan && plan.targets.length > 0 && (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <tbody>
                {plan.targets.map((t) => (
                  <tr key={t.nodeId}>
                    <td style={{ ...tdStyle, color: FG }}>
                      {t.nodeId}
                      {t.canary && (
                        <span style={{ color: ACCENT, fontSize: 8, marginLeft: 6, letterSpacing: 0.5 }}>CANARY</span>
                      )}
                    </td>
                    <td style={{ ...tdStyle, color: DIM }}>{t.tier}</td>
                    <td style={{ ...tdStyle, color: DIM, paddingRight: 0 }}>{t.compatible}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {/* The one consequence a list of node ids cannot show: the last node
              in the plan is the one serving this page (#56). Not a choice —
              UPDATE ALL means all — but an operator should not have the UI go
              dark on them unannounced. */}
          {plan?.selfNodeId && (
            <Hint style={{ marginTop: 8 }}>
              this run updates <strong>{plan.selfNodeId}</strong>, the node running the control plane. It goes{' '}
              <strong>last</strong>, after every other node has reported. This page will drop while it reboots and come
              back on its own — the run finishes and reports itself either way.
            </Hint>
          )}
        </div>

        {/* Canary override — one select per (tier, arch) group */}
        {canaryGroups.length > 0 && (
          <div>
            <SectionLabel>CANARY</SectionLabel>
            <Hint style={{ marginBottom: 8 }}>
              one node per tier and architecture proves the image before fan-out. Override the pick if you have a node
              you can afford to lose first.
            </Hint>
            {canaryGroups.map((g) => {
              const k = groupKey(g.tier, g.arch);
              return (
                <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                  <span style={{ color: DIM, fontSize: 10, minWidth: 190 }}>
                    {g.tier} / {g.arch}
                  </span>
                  <Select
                    value={canaryOverride[k] ?? g.canary ?? ''}
                    onChange={(e) => setCanaryOverride((prev) => ({ ...prev, [k]: e.target.value }))}
                    style={{ flex: 1 }}
                  >
                    {g.nodes.map((n) => (
                      <option key={n.nodeId} value={n.nodeId}>
                        {n.nodeId}
                        {n.nodeId === g.canary ? ' (plan default)' : ''}
                      </option>
                    ))}
                  </Select>
                </div>
              );
            })}
          </div>
        )}

        {/* Knobs */}
        <div>
          <SectionLabel>ROLLOUT</SectionLabel>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
            <label htmlFor="rollout-max-in-flight" style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <span style={{ color: DIM, fontSize: 10 }}>MAX IN FLIGHT</span>
              <Input
                id="rollout-max-in-flight"
                value={knobs.maxInFlight}
                onChange={(e) => setKnobs((k) => ({ ...k, maxInFlight: e.target.value }))}
                style={{ width: 90 }}
                placeholder="4 or 20%"
              />
            </label>
            <label htmlFor="rollout-max-failures" style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <span style={{ color: DIM, fontSize: 10 }}>MAX FAILURES</span>
              <Input
                id="rollout-max-failures"
                value={knobs.maxFailures}
                onChange={(e) => setKnobs((k) => ({ ...k, maxFailures: e.target.value }))}
                style={{ width: 90 }}
                placeholder="15% · 0=∞"
              />
            </label>
          </div>
          <button
            onClick={() => setAdvanced((v) => !v)}
            style={{ background: 'transparent', border: 'none', color: DIM, cursor: 'pointer', fontSize: 10, marginTop: 10, padding: 0, fontFamily: MONO }}
          >
            {advanced ? '▾' : '▸'} advanced
          </button>
          {advanced && (
            <label htmlFor="rollout-canary-soak" style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 8 }}>
              <span style={{ color: DIM, fontSize: 10 }}>CANARY SOAK (SECONDS)</span>
              <Input
                id="rollout-canary-soak"
                type="number"
                min={0}
                max={3600}
                value={knobs.canarySoakSeconds}
                onChange={(e) => setKnobs((k) => ({ ...k, canarySoakSeconds: Math.max(0, Number(e.target.value) || 0) }))}
                style={{ width: 120 }}
              />
              <span style={{ color: DIM, fontSize: 9 }}>hold fan-out this long after canaries pass. 0 = no soak (default).</span>
            </label>
          )}
        </div>

        {/* Skips */}
        {skips.length > 0 && (
          <div>
            <SectionLabel>NOT TARGETED · {skips.length}</SectionLabel>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <tbody>
                {skips.map((s) => (
                  <tr key={s.nodeId}>
                    <td style={{ ...tdStyle, color: DIM }}>{s.nodeId}</td>
                    <td style={tdStyle}>
                      <Badge color={skipColor(s.reason)}>{s.reason === 'no-artifact-for-arch' ? 'STRANDED' : 'SKIPPED'}</Badge>
                    </td>
                    <td style={{ ...tdStyle, color: DIM, paddingRight: 0 }}>{s.detail || s.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {stranded.length > 0 && (
              <Hint warn style={{ marginTop: 8 }}>
                {stranded.length} node{stranded.length === 1 ? '' : 's'} would be stranded — no artifact for their
                architecture. The run will fail even if every other node succeeds. Stage the missing arch first.
              </Hint>
            )}
          </div>
        )}
      </div>

      {/* Footer */}
      <div style={{ marginTop: 'auto', borderTop: `1px solid ${HAIR}`, padding: '14px 20px', display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ color: '#f87171', fontSize: 9, flex: 1 }}>{err ?? ''}</span>
        <Btn small onClick={onClose}>
          CANCEL
        </Btn>
        <Btn
          small
          variant="primary"
          disabled={busy || !!planErr || !plan || plan.targets.length === 0 || !knobsValid}
          onClick={deploy}
          title={planErr ? 'Fix the plan first' : 'Cascade this release with the settings above'}
        >
          {busy ? '…' : 'DEPLOY'}
        </Btn>
      </div>
    </Drawer>
  );
}

function ReleaseRow({ release, nodes }: { release: StagedRelease; nodes: Node[] }) {
  const [drawer, setDrawer] = useState(false);

  const staged = new Set(release.bundles.map((b) => b.compatible));
  const inScope = nodes.filter((n) =>
    release.component === 'fw' ? n.role === 'firewall' : n.role !== 'firewall',
  );
  // SKUs the fleet needs that this release has no staged artifact for. The
  // plan step refuses to run in exactly this state, so say so before the click
  // rather than after.
  const missing = [
    ...new Set(
      inScope
        .map(nodeCompatible)
        .filter((c): c is string => c !== null)
        .filter((c) => !staged.has(c)),
    ),
  ];
  const covered = inScope.filter((n) => {
    const c = nodeCompatible(n);
    return c !== null && staged.has(c);
  }).length;

  return (
    <div style={{ background: PANEL, border: `1px solid ${HAIR}`, padding: '10px 14px', display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
      <span style={{ color: FG, fontSize: 11, fontFamily: MONO, letterSpacing: '0.06em' }}>
        {release.component === 'fw' ? 'FIREWALL' : 'OS'} {release.version}
      </span>
      {[...staged].sort().map((c) => (
        <Badge key={c} color="#4ade80">
          {release.bundles.find((b) => b.compatible === c)?.architecture || c}
        </Badge>
      ))}
      {missing.map((c) => (
        <Badge key={c} color="#fbbf24">
          {c} NOT STAGED
        </Badge>
      ))}
      <span style={{ color: DIM, fontSize: 10, fontFamily: MONO }}>
        {covered}/{inScope.length} node{inScope.length === 1 ? '' : 's'} covered
      </span>
      <div style={{ marginLeft: 'auto' }}>
        <Btn
          small
          variant="primary"
          disabled={missing.length > 0 || covered === 0}
          title={
            missing.length > 0
              ? `Stage ${missing.join(', ')} first — the plan refuses to run a fleet update that would leave nodes behind`
              : 'Review the plan and roll this release out across every online node'
          }
          onClick={() => setDrawer(true)}
        >
          UPDATE ALL
        </Btn>
      </div>
      {drawer && (
        <FleetUpdateDrawer
          release={release}
          onClose={() => setDrawer(false)}
          onDeployed={() => setDrawer(false)}
        />
      )}
    </div>
  );
}

/** The targeted form: cascade ONE artifact to whatever matches it. Kept for
 *  deploying a specific bundle, and named so it cannot be mistaken for the
 *  fleet action — that one lives on the release row above. */
function SystemUpdateButton({ bundle }: { bundle: Bundle }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function go() {
    if (
      !confirm(
        `Cascade this ${bundle.compatible} bundle (${bundle.version}) to every online node that takes it? ` +
          `Nodes on any OTHER architecture are NOT updated by this — use UPDATE ALL on the release above for that. ` +
          `The controlplane is not included. The cascade halts on the first failure.`,
      )
    )
      return;
    setBusy(true);
    setErr(null);
    try {
      await createSystemUpdate({ bundleSha256: bundle.sha256 });
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Btn small disabled={busy} title={`Cascade only this ${bundle.compatible} artifact`} onClick={go}>
        {busy ? '…' : 'UPDATE MATCHING'}
      </Btn>
      {err && <span style={{ color: '#f87171', fontSize: 9 }}>{err}</span>}
    </>
  );
}

// outcomeColor / outcomeLabel keep `not-attempted` visually distinct from
// `failed`. They are the same shade of "did not update" and completely
// different operator problems: a failure is a machine to go and look at, a
// not-attempted node is one the canary gate protected and is still on its old
// slot, untouched.
// GridOutcome is a row's terminal NodeOutcome plus 'running', the one state the
// final report never carries. It exists only for the live fallback below: while
// a run is in flight there is no cascade grid yet, so rows come from the child
// jobs, and an in-flight child MUST render distinctly from 'not-attempted'.
// Conflating them (the bug this fixes, #96) makes a node that is actively
// updating read as one the run never touched — the opposite fact — on the exact
// screen an operator watches during a rollout.
// 'pending' is the second live-only state: a planned target the cascade has
// not reached yet. It is NOT 'not-attempted', which is a verdict — the run
// stopped short of this node and it is staying on its old slot. On a run still
// in flight that verdict is not in yet, and rendering it would tell an operator
// a rollout had given up on nodes it is about to reach.
type GridOutcome = NodeOutcome | 'running' | 'pending';

function outcomeColor(o: GridOutcome): string {
  switch (o) {
    case 'succeeded':
      return '#4ade80';
    case 'failed':
      return '#f87171';
    case 'running':
      return ACCENT; // in flight right now
    default:
      return DIM; // not-attempted / pending — nothing has happened to this node
  }
}

function outcomeLabel(o: GridOutcome): string {
  switch (o) {
    case 'running':
      return 'UPDATING';
    case 'not-attempted':
      return 'NOT STARTED';
    case 'pending':
      return 'WAITING';
    default:
      return o.toUpperCase();
  }
}

type GridRow = Omit<NodeResult, 'outcome'> & { outcome: GridOutcome };

// liveGrid is the report a run can show BEFORE the cascade step returns.
//
// The real grid is stashed in that step's result, so it does not exist until
// the run is over — half an hour on a real fleet, which is exactly the window
// an operator is watching. Falling back to the child jobs alone (what this
// replaced) loses every dimension the report is for: child jobs carry a node
// and a status and nothing else, so TIER and ARCH rendered blank for the whole
// run, rows arrived in completion order, and a target with no child yet was
// simply absent from a grid whose job is to account for the entire plan.
//
// The plan step's result is durable from the first second and carries all of
// it. Joining the two gives the same shape the final grid has, which is also
// what makes the transition to the real grid invisible when it lands.
function liveGrid(targets: PlanTarget[], children: Job[], jobStatus: JobStatus): GridRow[] {
  const rowFor = (c: Job): GridOutcome =>
    c.status === 'succeeded' ? 'succeeded' : c.status === 'running' || c.status === 'queued' ? 'running' : 'failed';

  // No plan targets: a job recorded before the plan step stashed them. Keep
  // the old child-only shape rather than showing an empty report.
  if (targets.length === 0) {
    return children.map((c) => ({
      nodeId: extractNodeId(c.spec),
      outcome: rowFor(c),
      childJobId: c.id,
      detail: c.error,
    }));
  }

  const byNode = new Map(children.map((c) => [extractNodeId(c.spec), c]));
  const settled = jobStatus !== 'running' && jobStatus !== 'queued';
  return targets.map((t) => {
    const c = byNode.get(t.nodeId);
    return {
      nodeId: t.nodeId,
      tier: t.tier,
      compatible: t.compatible,
      canary: t.canary,
      // A target with no child on a run that has ENDED is a target the run
      // never reached — the same verdict rebuildReport records. On a run still
      // going it is simply next.
      outcome: c ? rowFor(c) : settled ? 'not-attempted' : 'pending',
      childJobId: c?.id,
      detail: c?.error,
    };
  });
}

// skipColor separates the designed skips from the stranding. `firewall-sku`,
// `excluded` and `offline` are the plan working; `no-artifact-for-arch` is a
// node nobody asked to leave behind, and it must never render like the others
// (ADR-0005 Decision 11).
function skipColor(r: SkipReason): string {
  return r === 'no-artifact-for-arch' ? '#f87171' : DIM;
}

// stepResult digs one step's stashed result out of the parent job's steps.
// The grid lives there rather than being rebuilt from the live event stream so
// that it survives a page reload — a fleet update runs for half an hour and
// the report is the thing you come back to.
function stepResult<T>(steps: JobStep[], name: string): T | undefined {
  const s = steps.find((x) => x.name === name);
  return s?.result as T | undefined;
}

function SystemUpdateRow({ job }: { job: Job }) {
  const [children, setChildren] = useState<Job[]>([]);
  const [steps, setSteps] = useState<JobStep[]>([]);

  useEffect(() => {
    let active = true;
    const fetch = () => {
      listChildJobs(job.id).then((kids) => active && setChildren(kids)).catch(() => {});
      listSteps(job.id).then((s) => active && setSteps(s)).catch(() => {});
    };
    fetch();
    const t = job.status === 'running' || job.status === 'queued' ? setInterval(fetch, 3000) : null;
    return () => {
      active = false;
      if (t) clearInterval(t);
    };
  }, [job.id, job.status]);

  const cascade = stepResult<{ results?: NodeResult[] }>(steps, 'cascade');
  const plan = stepResult<{ targets?: PlanTarget[]; skipped?: SkippedNode[] }>(steps, 'plan');
  const skipped = plan?.skipped ?? [];

  // The grid is the cascade's when it has one. Until then — the whole time a
  // run is in flight — it is rebuilt from the plan and the child jobs, which
  // is the same pair the api's own post-reboot resume rebuilds from.
  const results: GridRow[] = cascade?.results ?? liveGrid(plan?.targets ?? [], children, job.status);

  const byChildId = new Map(children.map((c) => [c.id, c]));
  const count = (o: GridOutcome) => results.filter((r) => r.outcome === o).length;
  const running = count('running');
  const notAttempted = count('not-attempted');
  const stranded = skipped.filter((s) => s.reason === 'no-artifact-for-arch').length;
  const hasRows = results.length > 0 || skipped.length > 0;

  return (
    <div style={{ background: PANEL, border: `1px solid ${HAIR}`, padding: '12px 14px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: hasRows ? 10 : 0, flexWrap: 'wrap' }}>
        <Badge color={jobColor(job.status)}>{job.status.toUpperCase()}</Badge>
        <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>
          {job.id.slice(0, 12)} · {new Date(job.createdAt).toLocaleString()}
        </span>
        <span style={{ color: DIM, fontSize: 9, fontFamily: MONO, marginLeft: 'auto' }}>
          {count('succeeded')} succeeded · {count('failed')} failed
          {running > 0 && <span style={{ color: ACCENT }}> · {running} updating</span>}
          {notAttempted > 0 && <span style={{ color: '#facc15' }}> · {notAttempted} never started</span>}
          {stranded > 0 && <span style={{ color: '#f87171' }}> · {stranded} stranded</span>}
          {' · '}
          {results.length} planned
        </span>
      </div>
      {job.error && <pre style={{ color: '#f87171', fontSize: 9, fontFamily: MONO, margin: '0 0 8px', whiteSpace: 'pre-wrap' }}>{job.error}</pre>}
      {hasRows && (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {['NODE', 'TIER', 'ARCH', 'OUTCOME', 'STARTED', 'FINISHED', 'NOTES'].map((c) => (
                <th key={c} style={thStyle}>
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {results.map((r) => {
              const child = r.childJobId ? byChildId.get(r.childJobId) : undefined;
              return (
                <tr key={r.nodeId}>
                  <td style={{ ...tdStyle, color: FG }}>
                    {r.nodeId}
                    {r.canary && (
                      <span
                        title="Canary — this node's outcome gated fan-out for its tier and architecture."
                        style={{ color: ACCENT, fontSize: 8, marginLeft: 6, letterSpacing: 0.5 }}
                      >
                        CANARY
                      </span>
                    )}
                  </td>
                  <td style={{ ...tdStyle, color: DIM }}>{r.tier ?? '—'}</td>
                  <td style={{ ...tdStyle, color: DIM }}>{r.compatible ?? '—'}</td>
                  <td style={tdStyle}>
                    <Badge color={outcomeColor(r.outcome)}>{outcomeLabel(r.outcome)}</Badge>
                  </td>
                  <td style={{ ...tdStyle, color: DIM }}>{child?.startedAt ? new Date(child.startedAt).toLocaleTimeString() : '—'}</td>
                  <td style={{ ...tdStyle, color: DIM }}>{child?.finishedAt ? new Date(child.finishedAt).toLocaleTimeString() : '—'}</td>
                  <td style={{ ...tdStyle, color: DIM, paddingRight: 0 }}>{r.detail || child?.error || ''}</td>
                </tr>
              );
            })}
            {/* Skipped nodes belong in the same report — a node left out is
                part of what happened to the fleet — but they were never
                targets, so they get no outcome and no timings. Their tier and
                arch ARE known (the api carries them since #152); on a stranded
                row the arch is the entire point of the row. */}
            {skipped.map((s) => (
              <tr key={`skip-${s.nodeId}`}>
                <td style={{ ...tdStyle, color: DIM }}>{s.nodeId}</td>
                <td style={{ ...tdStyle, color: DIM }}>{s.tier ?? '—'}</td>
                <td style={{ ...tdStyle, color: DIM }}>{s.compatible ?? '—'}</td>
                <td style={tdStyle}>
                  <Badge color={skipColor(s.reason)}>{s.reason === 'no-artifact-for-arch' ? 'STRANDED' : 'SKIPPED'}</Badge>
                </td>
                <td style={{ ...tdStyle, color: DIM }}>—</td>
                <td style={{ ...tdStyle, color: DIM }}>—</td>
                <td style={{ ...tdStyle, color: DIM, paddingRight: 0 }}>{s.detail || s.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// unverifiedTitle names which conjuncts were skipped. An unverified BOOT is
// usually a pre-bootId agent and fixes itself on the next rollout; an
// unverified VERSION means the node could not say what it is running, which
// does not self-heal — so they are worth distinguishing rather than merging
// into one "degraded" with no cause.
function unverifiedTitle(h: NodeUpdate): string {
  const gaps: string[] = [];
  if (h.unverifiedBoot) gaps.push('boot identity not reported (agent predates it)');
  if (h.unverifiedVersion) gaps.push('running version not reported');
  return `Verified on fewer checks than usual: ${gaps.join('; ')}. The update succeeded on the checks that could run.`;
}

function updateStatusColor(s: ComponentUpdate['status']): string {
  switch (s) {
    case 'update_available':
      return ACCENT;
    case 'up_to_date':
      return '#4ade80';
    // Amber, not green: the comparison passed but its inputs are suspect.
    case 'needs_attention':
      return '#facc15';
    case 'unknown':
      return '#facc15';
    default:
      return DIM; // no_release
  }
}

function updateStatusLabel(s: ComponentUpdate['status']): string {
  switch (s) {
    case 'update_available':
      return 'UPDATE AVAILABLE';
    case 'up_to_date':
      return 'UP TO DATE';
    case 'needs_attention':
      return 'NEEDS ATTENTION';
    case 'no_release':
      return 'NO RELEASE';
    default:
      return 'UNKNOWN';
  }
}

function ComponentUpdateRow({ cu, onStaged }: { cu: ComponentUpdate; onStaged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function stage() {
    setBusy(true);
    setErr(null);
    try {
      const res = await pullUpdate(cu.component, cu.channel);
      // A partial pull resolves (HTTP 207) rather than throwing — some arches
      // are in the store and some are not. Saying nothing here is what made a
      // half-staged release invisible in the first place.
      if (res.failed?.length) {
        setErr(
          `Staged ${res.staged.map((a) => a.architecture).join(', ') || 'nothing'}. ` +
            res.failed.map((a) => `${a.architecture} failed: ${a.error}`).join('; '),
        );
      }
      onStaged();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  // Only the arches this cluster actually runs. An all-N100 fleet is not
  // half-staged for lacking the Pi bundle it will never deploy.
  const needed = (cu.artifacts ?? []).filter((a) => a.neededBy > 0);
  const missing = needed.filter((a) => !a.staged);
  const canStage = cu.status === 'update_available' && cu.deployable && !cu.staged;
  const showManual = cu.status === 'update_available' && !cu.deployable && Boolean(cu.manualInstructions);

  return (
    <div style={{ background: PANEL, border: `1px solid ${HAIR}`, padding: '10px 14px', display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <span style={{ color: FG, fontSize: 11, fontFamily: MONO, letterSpacing: '0.06em', minWidth: 160 }}>
          {cu.label.toUpperCase()}
        </span>
        <Badge color={updateStatusColor(cu.status)}>{updateStatusLabel(cu.status)}</Badge>
        <span style={{ color: DIM, fontSize: 10, fontFamily: MONO }}>
          {cu.installed || '—'}
          {cu.latest ? ` → ${cu.latest}` : ''}
        </span>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
          {cu.staged && <Badge color="#4ade80">STAGED</Badge>}
          {!cu.staged && needed.length > 1 && missing.length > 0 && missing.length < needed.length && (
            <Badge color="#fbbf24">
              PARTIAL — {missing.map((a) => a.architecture).join(', ')} MISSING
            </Badge>
          )}
          {canStage && (
            <Btn variant="primary" small disabled={busy} onClick={stage} title="download into the bundle catalog">
              <DownloadCloud size={10} /> {busy ? 'STAGING…' : 'DOWNLOAD & STAGE'}
            </Btn>
          )}
        </div>
      </div>
      {cu.bundled?.map((b) => (
        <span key={b.label} style={{ color: DIM, fontSize: 9, fontFamily: MONO, letterSpacing: '0.04em' }}>
          {b.label.toLowerCase()} {b.version} · ships in this image
        </span>
      ))}
      {cu.staged && cu.deployable && (
        <Hint>staged in the bundle catalog below — use DEPLOY or UPDATE ALL to roll it out</Hint>
      )}
      {showManual && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <Hint warn>{cu.manualInstructions}</Hint>
          {cu.assetName && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: DIM, fontSize: 10, fontFamily: MONO }}>{cu.assetName}</span>
              <CopyButton value={cu.assetName} label="COPY IMAGE NAME" />
            </div>
          )}
        </div>
      )}
      {cu.note && <Hint>{cu.note}</Hint>}
      {cu.error && <Hint warn>{cu.error}</Hint>}
      {err && <span style={{ color: '#f87171', fontSize: 9, fontFamily: MONO }}>{err}</span>}
    </div>
  );
}

function extractNodeId(spec: unknown): string {
  if (spec && typeof spec === 'object' && 'nodeId' in (spec as Record<string, unknown>) && typeof (spec as Record<string, unknown>).nodeId === 'string') {
    return (spec as Record<string, string>).nodeId;
  }
  return '';
}

function prettyStatus(s: NodeUpdateStatus): string {
  if (s === 'in_progress') return 'IN PROGRESS';
  if (s === 'rolled_back') return 'ROLLED BACK';
  return s.toUpperCase();
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
