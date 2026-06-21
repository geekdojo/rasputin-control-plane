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
  listJobs,
  listNodes,
  listUpdates,
  openSystemUpdatesWS,
  openUpdatesWS,
  pullUpdate,
  uploadBundle,
} from '../../../lib/api';
import type {
  Bundle,
  ComponentUpdate,
  Job,
  JobStatus,
  Node,
  NodeUpdate,
  NodeUpdateStatus,
  UpdateChangeEvent,
  UpdateCheckResult,
} from '../../../lib/types';
import {
  Badge,
  Btn,
  CopyButton,
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
                      <Badge color={nodeUpdateColor(h.status)}>{prettyStatus(h.status)}</Badge>
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
  const targets = nodes.filter((n) => n.status === 'online');

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
        <input type="file" onChange={handle} disabled={busy} style={{ display: 'none' }} />
      </label>
      {err && <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{err}</span>}
    </div>
  );
}

function SystemUpdateButton({ bundle }: { bundle: Bundle }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function go() {
    if (
      !confirm(
        `Update every online node to ${bundle.version}? Nodes update one at a time in role-safe order (compute → storage → controlplane → firewall). The cascade halts on the first failure.`,
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
      <Btn small disabled={busy} title="Cascade this bundle across every online node" onClick={go}>
        {busy ? '…' : 'UPDATE ALL'}
      </Btn>
      {err && <span style={{ color: '#f87171', fontSize: 9 }}>{err}</span>}
    </>
  );
}

function SystemUpdateRow({ job }: { job: Job }) {
  const [children, setChildren] = useState<Job[]>([]);

  useEffect(() => {
    let active = true;
    const fetch = () => listChildJobs(job.id).then((kids) => active && setChildren(kids)).catch(() => {});
    fetch();
    const t = job.status === 'running' || job.status === 'queued' ? setInterval(fetch, 3000) : null;
    return () => {
      active = false;
      if (t) clearInterval(t);
    };
  }, [job.id, job.status]);

  const succeeded = children.filter((c) => c.status === 'succeeded').length;
  const failed = children.filter((c) => c.status === 'failed' || c.status === 'cancelled').length;

  return (
    <div style={{ background: PANEL, border: `1px solid ${HAIR}`, padding: '12px 14px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: children.length > 0 ? 10 : 0, flexWrap: 'wrap' }}>
        <Badge color={jobColor(job.status)}>{job.status.toUpperCase()}</Badge>
        <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>
          {job.id.slice(0, 12)} · {new Date(job.createdAt).toLocaleString()}
        </span>
        <span style={{ color: DIM, fontSize: 9, fontFamily: MONO, marginLeft: 'auto' }}>
          {succeeded} succeeded · {failed} failed · {children.length} total
        </span>
      </div>
      {job.error && <pre style={{ color: '#f87171', fontSize: 9, fontFamily: MONO, margin: '0 0 8px', whiteSpace: 'pre-wrap' }}>{job.error}</pre>}
      {children.length > 0 && (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {['NODE', 'STATUS', 'STARTED', 'FINISHED', 'NOTES'].map((c) => (
                <th key={c} style={thStyle}>
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {children.map((c) => (
              <tr key={c.id}>
                <td style={{ ...tdStyle, color: FG }}>{extractNodeId(c.spec)}</td>
                <td style={tdStyle}>
                  <Badge color={jobColor(c.status)}>{c.status.toUpperCase()}</Badge>
                </td>
                <td style={{ ...tdStyle, color: DIM }}>{c.startedAt ? new Date(c.startedAt).toLocaleTimeString() : '—'}</td>
                <td style={{ ...tdStyle, color: DIM }}>{c.finishedAt ? new Date(c.finishedAt).toLocaleTimeString() : '—'}</td>
                <td style={{ ...tdStyle, color: DIM, paddingRight: 0 }}>{c.error || ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function updateStatusColor(s: ComponentUpdate['status']): string {
  switch (s) {
    case 'update_available':
      return ACCENT;
    case 'up_to_date':
      return '#4ade80';
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
      await pullUpdate(cu.component, cu.channel);
      onStaged();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

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
