'use client';

import { useEffect, useState } from 'react';
import {
  createUpdate,
  deleteBundle,
  listBundles,
  listNodes,
  listUpdates,
  openUpdatesWS,
  uploadBundle,
} from '../../../lib/api';
import type {
  Bundle,
  Node,
  NodeUpdate,
  UpdateChangeEvent,
} from '../../../lib/types';

export default function UpdatesPage() {
  const [bundles, setBundles] = useState<Bundle[]>([]);
  const [trustConfigured, setTrustConfigured] = useState(true);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [history, setHistory] = useState<NodeUpdate[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [recent, setRecent] = useState<UpdateChangeEvent[]>([]);

  useEffect(() => {
    refresh();
    const close = openUpdatesWS((ev) => {
      setRecent((prev) => [ev, ...prev].slice(0, 20));
      // Any lifecycle event might change history — refetch.
      listUpdates().then(setHistory).catch(() => {});
    });
    return close;
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
