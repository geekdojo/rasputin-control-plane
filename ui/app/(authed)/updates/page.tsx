'use client';

import { useEffect, useState } from 'react';
import {
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
  uploadBundle,
} from '../../../lib/api';
import type {
  Bundle,
  Job,
  Node,
  NodeUpdate,
  UpdateChangeEvent,
} from '../../../lib/types';

export default function UpdatesPage() {
  const [bundles, setBundles] = useState<Bundle[]>([]);
  const [trustConfigured, setTrustConfigured] = useState(true);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [history, setHistory] = useState<NodeUpdate[]>([]);
  const [systemJobs, setSystemJobs] = useState<Job[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [recent, setRecent] = useState<UpdateChangeEvent[]>([]);

  useEffect(() => {
    refresh();
    const closePerNode = openUpdatesWS((ev) => {
      setRecent((prev) => [ev, ...prev].slice(0, 20));
      // Any lifecycle event might change history — refetch.
      listUpdates().then(setHistory).catch(() => {});
    });
    const closeSystem = openSystemUpdatesWS(() => {
      // Refetch parent-job list on each system-update lifecycle event so
      // the rollup view stays current.
      refreshSystemJobs();
    });
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
    // List the most-recent jobs and filter for system.update kind. v0 has
    // no kind filter on the api yet; the slice is small.
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
    <section className="updates-section">
      <h2>Updates</h2>

      {!trustConfigured && (
        <p className="hint warn">
          ⚠ No root CA is configured at <code>data/trust/root-ca.pem</code>.
          Bundle signatures will not be verified. Run{' '}
          <code>./scripts/pki-init.sh</code> and copy <code>root-ca.pem</code>{' '}
          into the trust dir.
        </p>
      )}

      {err && <pre className="err">{err}</pre>}

      <h3>Bundles</h3>
      {bundles.length === 0 ? (
        <p className="hint">
          no bundles uploaded yet — build one with{' '}
          <code>scripts/build-bundle.sh</code> and upload below
        </p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Version</th>
              <th>Arch</th>
              <th>Compat</th>
              <th>Size</th>
              <th>Signed by</th>
              <th>Uploaded</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {bundles.map((b) => (
              <tr key={b.sha256}>
                <td>
                  <strong>{b.version}</strong>
                  {b.description && (
                    <span className="hint"> · {b.description}</span>
                  )}
                </td>
                <td>
                  <code>{b.architecture}</code>
                </td>
                <td>
                  <code>{b.compatible}</code>
                </td>
                <td>{formatBytes(b.sizeBytes)}</td>
                <td>
                  {b.signedBy === '<unverified>' ? (
                    <span className="hint warn">unverified</span>
                  ) : (
                    <code>{b.signedBy || '—'}</code>
                  )}
                </td>
                <td title={b.sha256}>
                  {new Date(b.uploadedAt).toLocaleString()}
                </td>
                <td className="row-actions">
                  <DeployBundleButton bundle={b} nodes={nodes} />
                  <SystemUpdateButton bundle={b} />
                  <button onClick={() => handleDeleteBundle(b.sha256)}>
                    delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <UploadBundleForm
        onUploaded={(b) => setBundles((prev) => [b, ...prev])}
      />

      {systemJobs.length > 0 && (
        <>
          <h3>System updates</h3>
          {systemJobs.map((j) => (
            <SystemUpdateRow key={j.id} job={j} />
          ))}
        </>
      )}

      <h3>History</h3>
      {history.length === 0 ? (
        <p className="hint">no update history yet</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Node</th>
              <th>Version</th>
              <th>Slot</th>
              <th>Status</th>
              <th>Started</th>
              <th>Finished</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody>
            {history.map((h) => (
              <tr key={h.jobId} className={`update-row update-${h.status}`}>
                <td>
                  <code>{h.nodeId}</code>
                </td>
                <td>
                  {h.fromVersion ? (
                    <>
                      <code>{h.fromVersion}</code> →{' '}
                      <code>{h.toVersion}</code>
                    </>
                  ) : (
                    <code>{h.toVersion}</code>
                  )}
                </td>
                <td>
                  {h.fromSlot !== 'unknown' && (
                    <>
                      <code>{h.fromSlot}</code> → <code>{h.toSlot}</code>
                    </>
                  )}
                </td>
                <td>
                  <span className={`status update-status-${h.status}`}>
                    {prettyStatus(h.status)}
                  </span>
                </td>
                <td>{new Date(h.startedAt).toLocaleTimeString()}</td>
                <td>
                  {h.finishedAt
                    ? new Date(h.finishedAt).toLocaleTimeString()
                    : '—'}
                </td>
                <td className="hint">{h.error || ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {recent.length > 0 && (
        <>
          <h3>Live events</h3>
          <ul className="event-feed">
            {recent.map((ev, i) => (
              <li key={i}>
                <code>{ev.nodeId}</code>{' '}
                <span className={`status update-status-${ev.change}`}>
                  {ev.change}
                </span>
                {ev.version && (
                  <>
                    {' '}· <code>{ev.version}</code>
                  </>
                )}
                {ev.reason && <span className="hint"> — {ev.reason}</span>}
                <span className="hint">
                  {' '}
                  · {new Date(ev.ts).toLocaleTimeString()}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function DeployBundleButton({
  bundle,
  nodes,
}: {
  bundle: Bundle;
  nodes: Node[];
}) {
  const [open, setOpen] = useState(false);
  const [nodeId, setNodeId] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Targets: anything online matching the bundle's arch. v0 doesn't
  // record per-node arch yet, so we show all online nodes and let the
  // operator pick.
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
      <button
        onClick={() => setOpen(true)}
        disabled={targets.length === 0}
        title={
          targets.length === 0 ? 'no online nodes' : 'apply bundle to node'
        }
      >
        deploy
      </button>
    );
  }

  return (
    <span className="inline-form">
      <select
        value={nodeId}
        onChange={(e) => setNodeId(e.target.value)}
        autoFocus
      >
        <option value="">— pick node —</option>
        {targets.map((n) => (
          <option key={n.id} value={n.id}>
            {n.id} ({n.role})
          </option>
        ))}
      </select>
      <button onClick={start} disabled={busy || !nodeId}>
        {busy ? 'starting…' : 'go'}
      </button>
      <button onClick={() => setOpen(false)}>cancel</button>
      {err && <span className="err">{err}</span>}
    </span>
  );
}

function UploadBundleForm({
  onUploaded,
}: {
  onUploaded: (b: Bundle) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function handle(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true);
    setErr(null);
    try {
      const b = await uploadBundle(file);
      onUploaded(b);
    } catch (e2) {
      setErr(String(e2));
    } finally {
      setBusy(false);
      e.target.value = '';
    }
  }

  return (
    <div className="add-intent">
      <h4>Upload bundle</h4>
      <p className="hint">
        produce a <code>.raspbundle</code> with{' '}
        <code>scripts/build-bundle.sh</code>, then upload it here
      </p>
      <input type="file" onChange={handle} disabled={busy} />
      {busy && <span className="hint"> uploading…</span>}
      {err && <pre className="err">{err}</pre>}
    </div>
  );
}

// SystemUpdateButton kicks off a system.update saga that cascades across
// every online node in role-safe order (firewall last). The api's own
// self-node is implicitly excluded server-side.
function SystemUpdateButton({ bundle }: { bundle: Bundle }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function go() {
    if (
      !confirm(
        `Update every online node to ${bundle.version}? Nodes are updated one at a time in role-safe order (compute → storage → controlplane → firewall). The cascade halts on the first failure.`,
      )
    ) {
      return;
    }
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
      <button onClick={go} disabled={busy} title="Cascade this bundle across every online node">
        {busy ? 'starting…' : 'update all'}
      </button>
      {err && <span className="err">{err}</span>}
    </>
  );
}

// SystemUpdateRow renders one parent system.update job with its per-node
// child jobs expanded inline. Refetches children whenever the parent's
// status changes (driven by the openSystemUpdatesWS refresh on the page).
function SystemUpdateRow({ job }: { job: Job }) {
  const [children, setChildren] = useState<Job[]>([]);

  useEffect(() => {
    let active = true;
    const fetch = () => {
      listChildJobs(job.id)
        .then((kids) => {
          if (active) setChildren(kids);
        })
        .catch(() => {});
    };
    fetch();
    // While the parent is still running, poll every 3s so the rollup
    // reflects child progress without relying solely on WS refreshes.
    const t =
      job.status === 'running' || job.status === 'queued'
        ? setInterval(fetch, 3000)
        : null;
    return () => {
      active = false;
      if (t) clearInterval(t);
    };
  }, [job.id, job.status]);

  const succeeded = children.filter((c) => c.status === 'succeeded').length;
  const failed = children.filter(
    (c) => c.status === 'failed' || c.status === 'cancelled',
  ).length;

  return (
    <article className={`system-update system-update-${job.status}`}>
      <header>
        <span className={`status status-${job.status}`}>{job.status}</span>
        <span className="hint">
          <code>{job.id.slice(0, 12)}</code> ·{' '}
          {new Date(job.createdAt).toLocaleString()}
        </span>
        <span className="hint">
          {succeeded} succeeded · {failed} failed · {children.length} total
        </span>
      </header>
      {job.error && <pre className="err">{job.error}</pre>}
      {children.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Node</th>
              <th>Status</th>
              <th>Started</th>
              <th>Finished</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody>
            {children.map((c) => (
              <tr key={c.id}>
                <td>
                  <code>{extractNodeId(c.spec)}</code>
                </td>
                <td>
                  <span className={`status status-${c.status}`}>{c.status}</span>
                </td>
                <td>
                  {c.startedAt
                    ? new Date(c.startedAt).toLocaleTimeString()
                    : '—'}
                </td>
                <td>
                  {c.finishedAt
                    ? new Date(c.finishedAt).toLocaleTimeString()
                    : '—'}
                </td>
                <td className="hint">{c.error || ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </article>
  );
}

// extractNodeId pulls nodeId off a job's spec when present (node.update
// children have it). Returns empty string for jobs without a nodeId.
function extractNodeId(spec: unknown): string {
  if (
    spec &&
    typeof spec === 'object' &&
    'nodeId' in (spec as Record<string, unknown>) &&
    typeof (spec as Record<string, unknown>).nodeId === 'string'
  ) {
    return (spec as Record<string, string>).nodeId;
  }
  return '';
}

function prettyStatus(s: NodeUpdate['status']): string {
  switch (s) {
    case 'in_progress':
      return 'in progress';
    case 'rolled_back':
      return 'rolled back';
    default:
      return s;
  }
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
