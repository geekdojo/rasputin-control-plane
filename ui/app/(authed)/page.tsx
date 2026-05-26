'use client';

import { useEffect, useState } from 'react';
import {
  createJob,
  getMetrics,
  listNodes,
  openInventoryWS,
} from '../../lib/api';
import type {
  InventoryChangeEvent,
  MetricSeries,
  Node,
} from '../../lib/types';

export default function NodesPage() {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    listNodes().then(setNodes).catch(console.error);
    const close = openInventoryWS((ev) => {
      setNodes((prev) => applyInventoryEvent(prev, ev));
    });
    // The inventory WS only fires on status transitions (online↔stale↔offline),
    // not on every heartbeat. Without a backstop, a steadily-online node never
    // sees its lastSeen update and the relative time grows forever. Poll the
    // list every 15s — cheap for 1–8 nodes — and the WS keeps transitions instant.
    const refresh = setInterval(() => {
      listNodes().then(setNodes).catch(() => {});
    }, 15_000);
    return () => {
      close();
      clearInterval(refresh);
    };
  }, []);

  // Tick the "last seen" relative timestamps every second.
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <section className="nodes-section">
      <h2>Nodes</h2>
      {nodes.length === 0 ? (
        <p className="hint">
          no nodes registered yet — start <code>rasputin-agent</code> and one
          should appear here within a second
        </p>
      ) : (
        <div className="nodes-grid">
          {nodes.map((n) => (
            <NodeCard key={n.id} node={n} now={now} />
          ))}
        </div>
      )}
    </section>
  );
}

function NodeCard({ node, now }: { node: Node; now: number }) {
  const lastSeenMs = now - new Date(node.lastSeen).getTime();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [metrics, setMetrics] = useState<MetricSeries | null>(null);

  // Poll metrics every 30s. The current api forwards live metric events on
  // the bus but no /ws/metrics endpoint exists yet, so polling drives the
  // sparkline window for now.
  useEffect(() => {
    let active = true;
    const fetch = () => {
      getMetrics(node.id, '15m', [
        'cpu_percent',
        'mem_used_bytes',
        'mem_total_bytes',
      ])
        .then((m) => {
          if (active) setMetrics(m);
        })
        .catch(() => {
          /* sparkline stays empty on failure */
        });
    };
    fetch();
    const t = setInterval(fetch, 30_000);
    return () => {
      active = false;
      clearInterval(t);
    };
  }, [node.id]);

  async function handleReboot() {
    setBusy(true);
    setErr(null);
    try {
      await createJob('node.reboot', { nodeId: node.id });
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  const cpuPoints = metrics?.series?.cpu_percent ?? [];
  const memUsedPoints = metrics?.series?.mem_used_bytes ?? [];
  const memTotalPoints = metrics?.series?.mem_total_bytes ?? [];
  const memPctValues = memUsedPoints.map((p, i) => {
    const total = memTotalPoints[i]?.value ?? 0;
    return total > 0 ? (p.value / total) * 100 : 0;
  });
  const cpuValues = cpuPoints.map((p) => p.value);
  const latestCpu = cpuValues.length ? cpuValues[cpuValues.length - 1] : null;
  const latestMem = memPctValues.length ? memPctValues[memPctValues.length - 1] : null;

  return (
    <article className={`node-card status-${node.status}`}>
      <header>
        <span className={`status status-${node.status}`}>{node.status}</span>
        <span className="role">{node.role}</span>
      </header>
      <h3>{node.id}</h3>
      <dl>
        <dt>host</dt>
        <dd>{node.hostname || <em>unknown</em>}</dd>
        <dt>last seen</dt>
        <dd>{relativeTime(lastSeenMs)}</dd>
        <dt>agent</dt>
        <dd>
          <code>{node.agentVersion}</code>
        </dd>
      </dl>
      <div className="card-metrics">
        <MetricRow label="cpu" data={cpuValues} latest={latestCpu} color="var(--warn)" />
        <MetricRow label="mem" data={memPctValues} latest={latestMem} color="var(--accent)" />
      </div>
      <div className="card-actions">
        <button
          onClick={handleReboot}
          disabled={busy || node.status !== 'online'}
          title={node.status !== 'online' ? 'Node is not online' : 'Reboot this node'}
        >
          {busy ? 'sending…' : 'Reboot'}
        </button>
        {err && <span className="err">{err}</span>}
      </div>
    </article>
  );
}

function MetricRow({
  label,
  data,
  latest,
  color,
}: {
  label: string;
  data: number[];
  latest: number | null;
  color: string;
}) {
  return (
    <div className="metric-row">
      <span className="metric-label">{label}</span>
      <Sparkline data={data} max={100} color={color} />
      <span className="metric-value">
        {latest != null ? `${latest.toFixed(0)}%` : '—'}
      </span>
    </div>
  );
}

function Sparkline({
  data,
  max,
  color,
}: {
  data: number[];
  max: number;
  color: string;
}) {
  const w = 80;
  const h = 18;
  if (data.length < 2) {
    return <svg width={w} height={h} className="sparkline" aria-hidden />;
  }
  const safeMax = max > 0 ? max : 1;
  const xStep = w / (data.length - 1);
  const points = data
    .map((v, i) => {
      const x = (i * xStep).toFixed(1);
      const y = (h - (Math.min(Math.max(v, 0), safeMax) / safeMax) * h).toFixed(1);
      return `${x},${y}`;
    })
    .join(' ');
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="sparkline" aria-hidden>
      <polyline fill="none" stroke={color} strokeWidth={1.5} points={points} />
    </svg>
  );
}

function applyInventoryEvent(prev: Node[], ev: InventoryChangeEvent): Node[] {
  const exists = prev.find((n) => n.id === ev.node.id);
  if (!exists) return [...prev, ev.node];
  return prev.map((n) => (n.id === ev.node.id ? ev.node : n));
}

function relativeTime(ms: number): string {
  if (ms < 1000) return 'just now';
  if (ms < 60_000) return `${Math.floor(ms / 1000)}s ago`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  return `${Math.floor(ms / 3_600_000)}h ago`;
}
