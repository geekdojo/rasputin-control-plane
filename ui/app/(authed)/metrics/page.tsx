'use client';

// /metrics — fleet-level observability dashboard. Cards-grid surface:
// one card per node with CPU/mem sparklines pulled from VM via
// /api/obs/series, click-to-drill into a per-node detail drawer
// (drawer wired in Slice 3 of the revamp; Slice 2 lands the grid).
//
// We replaced the previous Grafana iframe — embedding Grafana's chrome
// inside our shell looked off and the operator couldn't see all nodes
// at once. The "↗ OPEN IN GRAFANA" button in the header is the escape
// hatch for power-user PromQL / dashboard editing.

import { useEffect, useMemo, useState } from 'react';
import { BarChart2, ExternalLink, RefreshCw } from 'lucide-react';
import {
  getObsSeries,
  getObsStatus,
  listNodes,
  openInventoryWS,
} from '../../../lib/api';
import type { Node, ObsSeries, ObsStatus } from '../../../lib/types';
import {
  Btn,
  DIM,
  FG,
  HAIR,
  Hint,
  PageBody,
  PageHeader,
  PageShell,
  PANEL,
  SectionLabel,
  Select,
  Tok,
} from '../../../components/kit';
import { MONO } from '../../../components/ui-theme';
import { NodeCard } from '../../../components/obs/NodeCard';
import { NodeDetailDrawer } from '../../../components/obs/NodeDetailDrawer';

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? '';

// Sticking to a single-digit count of well-supported ranges. PromQL
// happily ranges further but the homelab use-case is "what just
// happened" / "where did the night go" — 24h is the practical ceiling.
const RANGES = [
  { value: '15m', label: 'LAST 15M' },
  { value: '30m', label: 'LAST 30M' },
  { value: '1h', label: 'LAST 1H' },
  { value: '6h', label: 'LAST 6H' },
  { value: '24h', label: 'LAST 24H' },
] as const;
type RangeKey = (typeof RANGES)[number]['value'];

// Per-node series bundle. We cache cpu+mem per node so card re-renders
// from inventory WS events don't blow away the sparklines.
type NodeSeries = { cpu: ObsSeries | null; mem: ObsSeries | null };

// Role display priority for the cards grid. Firewall first because
// it's the network ingress/egress — operators glance there first when
// something feels off. Controlplane next (the brain). Compute and
// storage are interchangeable from the operator's perspective and
// fall through to alphabetic. `default` covers future roles cleanly.
const ROLE_PRIORITY: Record<string, number> = {
  firewall: 0,
  controlplane: 1,
  compute: 2,
  storage: 3,
  default: 99,
};

export default function MetricsPage() {
  const [status, setStatus] = useState<ObsStatus | null>(null);
  const [statusErr, setStatusErr] = useState<string | null>(null);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [range, setRange] = useState<RangeKey>('30m');
  const [seriesByNode, setSeriesByNode] = useState<Record<string, NodeSeries>>({});
  const [drawerNodeId, setDrawerNodeId] = useState<string | null>(null);

  // --- bootstrap: nodes + obs status -----------------------------------
  useEffect(() => {
    let cancelled = false;
    Promise.all([listNodes(), getObsStatus()])
      .then(([ns, st]) => {
        if (cancelled) return;
        setNodes(ns);
        setStatus(st);
        setStatusErr(null);
      })
      .catch((e: Error) => {
        if (!cancelled) setStatusErr(e.message);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // --- live inventory: keep card grid in sync with adds/removes --------
  useEffect(() => {
    const close = openInventoryWS((ev) => {
      if (ev.change === 'removed') {
        setNodes((curr) => curr.filter((n) => n.id !== ev.node.id));
        setSeriesByNode((curr) => {
          const next = { ...curr };
          delete next[ev.node.id];
          return next;
        });
        return;
      }
      // For added/online/stale/offline/updated, upsert by id with the
      // payload (carries the fresh status/lastSeen).
      setNodes((curr) => {
        const i = curr.findIndex((n) => n.id === ev.node.id);
        if (i < 0) return [...curr, ev.node];
        const next = [...curr];
        next[i] = ev.node;
        return next;
      });
    });
    return close;
  }, []);

  // --- obs status backstop poll: catches RASPUTIN_OBS_ENABLED flips
  // (operator restarts the api with obs on after seeing the disabled
  // panel). 30s is fine — once enabled, this page's value comes from
  // the per-node series polling, not status. -----------------------------
  useEffect(() => {
    const id = window.setInterval(() => {
      getObsStatus()
        .then((s) => setStatus(s))
        .catch(() => {});
    }, 30_000);
    return () => window.clearInterval(id);
  }, []);

  // --- card ordering: deterministic, role-prioritized so the grid
  // doesn't shuffle as the inventory WS fires. Firewall first (it's
  // the network entry/exit — operators look there first when
  // something goes wrong); then controlplane; then compute / storage
  // / anything else alphabetically by id. Same id used in the card's
  // primary label, so the visual order matches the sort key. -----------
  const sortedNodes = useMemo(() => {
    return [...nodes].sort((a, b) => {
      const pa = ROLE_PRIORITY[a.role] ?? ROLE_PRIORITY.default;
      const pb = ROLE_PRIORITY[b.role] ?? ROLE_PRIORITY.default;
      if (pa !== pb) return pa - pb;
      return a.id.localeCompare(b.id);
    });
  }, [nodes]);

  // --- series fetching: refetch on (range change | node set change |
  // obs enabled). We don't poll on a timer — VM samples at 10s and the
  // refresh is one click on the RangeSelector or the explicit refresh
  // button. Auto-polling at 30s gave noisy network with little benefit
  // for a watch-style dashboard. -----------------------------------------
  const nodeIds = useMemo(() => nodes.map((n) => n.id).sort().join(','), [nodes]);

  useEffect(() => {
    if (!status?.enabled) return;
    if (nodes.length === 0) return;
    let cancelled = false;
    const ids = nodes.map((n) => n.id);

    Promise.all(
      ids.map(async (id) => {
        const [cpu, mem] = await Promise.all([
          getObsSeries(id, 'cpu', range).catch(() => null),
          getObsSeries(id, 'mem', range).catch(() => null),
        ]);
        return [id, { cpu, mem }] as const;
      }),
    ).then((entries) => {
      if (cancelled) return;
      setSeriesByNode(Object.fromEntries(entries));
    });

    return () => {
      cancelled = true;
    };
  }, [nodeIds, range, status?.enabled]); // eslint-disable-line react-hooks/exhaustive-deps

  const refresh = () => {
    // Manual re-fetch for the impatient operator. The effect above
    // already runs on range / nodeIds change, so this is only useful
    // when nothing else has changed but VM has new samples (10s tick).
    if (!status?.enabled || nodes.length === 0) return;
    Promise.all(
      nodes.map(async (n) => {
        const [cpu, mem] = await Promise.all([
          getObsSeries(n.id, 'cpu', range).catch(() => null),
          getObsSeries(n.id, 'mem', range).catch(() => null),
        ]);
        return [n.id, { cpu, mem }] as const;
      }),
    ).then((entries) => setSeriesByNode(Object.fromEntries(entries)));
  };

  // --- render ----------------------------------------------------------
  return (
    <PageShell>
      <PageHeader
        icon={BarChart2}
        title="METRICS"
        right={
          <>
            <RangeSelector value={range} onChange={setRange} />
            <Btn variant="ghost" small onClick={refresh} title="Refetch series">
              <RefreshCw size={11} />
              REFRESH
            </Btn>
            {status?.enabled && status.grafanaUrl && (
              <a
                href={`${API_BASE}/observability/d/rasputin-cluster-overview?orgId=1`}
                target="_blank"
                rel="noreferrer"
                style={{ textDecoration: 'none' }}
              >
                <Btn variant="ghost" small>
                  <ExternalLink size={11} />
                  OPEN IN GRAFANA
                </Btn>
              </a>
            )}
          </>
        }
      />
      <PageBody>
        {statusErr && !status && (
          <Hint warn style={{ marginBottom: 16 }}>
            Couldn&apos;t reach /api/obs/status: {statusErr}
          </Hint>
        )}

        <ClusterStrip nodes={nodes} status={status} />

        {status && !status.enabled && <DisabledPanel />}

        {nodes.length === 0 && (
          <div style={{ marginTop: 20 }}>
            <Hint>
              No nodes registered yet. Start <Tok>rasputin-agent</Tok> on a host and it&apos;ll
              appear here within a second.
            </Hint>
          </div>
        )}

        {sortedNodes.length > 0 && (
          <div
            style={{
              marginTop: 20,
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
              gap: 12,
            }}
          >
            {sortedNodes.map((n) => {
              const s = seriesByNode[n.id];
              return (
                <NodeCard
                  key={n.id}
                  node={n}
                  cpuSeries={s?.cpu ?? null}
                  memSeries={s?.mem ?? null}
                  obsEnabled={Boolean(status?.enabled && status?.healthy)}
                  onClick={() => setDrawerNodeId(n.id)}
                />
              );
            })}
          </div>
        )}
      </PageBody>
      <NodeDetailDrawer
        node={nodes.find((n) => n.id === drawerNodeId) ?? null}
        open={drawerNodeId !== null}
        onClose={() => setDrawerNodeId(null)}
        range={range}
        obsEnabled={Boolean(status?.enabled && status?.healthy)}
        grafanaHref={
          status?.enabled && status?.grafanaUrl && drawerNodeId
            ? `${API_BASE}/observability/d/rasputin-cluster-overview?orgId=1&var-nodeId=${encodeURIComponent(drawerNodeId)}`
            : undefined
        }
      />
    </PageShell>
  );
}

// ClusterStrip — one-line cluster summary above the grid. Pulls counts
// from inventory; uses obs.status for the "last write" timestamp.
function ClusterStrip({ nodes, status }: { nodes: Node[]; status: ObsStatus | null }) {
  const counts = nodes.reduce(
    (acc, n) => {
      acc[n.status] = (acc[n.status] ?? 0) + 1;
      return acc;
    },
    { online: 0, stale: 0, offline: 0 } as Record<Node['status'], number>,
  );
  const lastWrite = status?.lastWriteOk ? new Date(status.lastWriteOk) : null;
  const lastWriteAgo = lastWrite ? Math.max(0, Math.floor((Date.now() - lastWrite.getTime()) / 1000)) : null;

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 20,
        padding: '10px 14px',
        background: PANEL,
        border: `1px solid ${HAIR}`,
        fontFamily: MONO,
        fontSize: 10,
        color: DIM,
        letterSpacing: '0.06em',
      }}
    >
      <Stat label="NODES" value={String(nodes.length)} color={FG} />
      <Stat label="ONLINE" value={String(counts.online)} color={counts.online > 0 ? '#4ade80' : DIM} />
      {counts.stale > 0 && <Stat label="STALE" value={String(counts.stale)} color="#facc15" />}
      {counts.offline > 0 && <Stat label="OFFLINE" value={String(counts.offline)} color="#f87171" />}
      <div style={{ marginLeft: 'auto' }}>
        {status?.enabled === false ? (
          <span style={{ color: '#facc15' }}>OBS OFF — set RASPUTIN_OBS_ENABLED=1</span>
        ) : status?.enabled && !status?.healthy ? (
          <span style={{ color: '#facc15' }}>OBS STARTING — health probe pending</span>
        ) : lastWriteAgo != null ? (
          <span>LAST WRITE · {lastWriteAgo}s ago</span>
        ) : status?.enabled ? (
          <span>WAITING FOR FIRST WRITE</span>
        ) : null}
      </div>
    </div>
  );
}

function Stat({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <span>
      <span style={{ color: DIM, marginRight: 6 }}>{label}</span>
      <span style={{ color, fontSize: 11 }}>{value}</span>
    </span>
  );
}

function RangeSelector({ value, onChange }: { value: RangeKey; onChange: (r: RangeKey) => void }) {
  return (
    <Select
      value={value}
      onChange={(e) => onChange(e.target.value as RangeKey)}
      style={{ padding: '4px 8px', fontSize: 9, letterSpacing: '0.08em' }}
    >
      {RANGES.map((r) => (
        <option key={r.value} value={r.value}>
          {r.label}
        </option>
      ))}
    </Select>
  );
}

function DisabledPanel() {
  return (
    <div style={{ marginTop: 20, padding: '16px 18px', border: `1px solid ${HAIR}`, background: PANEL }}>
      <SectionLabel>OBSERVABILITY IS OFF</SectionLabel>
      <Hint style={{ marginBottom: 10 }}>
        Tier 2 observability (VictoriaMetrics + Alloy + Loki + Grafana + vmalert) isn&apos;t enabled on
        this control-plane. The cards above show inventory-derived status only — sparklines stay empty
        until the obs stack is running.
      </Hint>
      <Hint style={{ marginBottom: 10 }}>To turn it on, set the env var and restart the api:</Hint>
      <pre
        style={{
          background: '#0a1322',
          border: `1px solid rgba(228,230,234,0.18)`,
          padding: 10,
          margin: 0,
          color: FG,
          fontFamily: MONO,
          fontSize: 10,
          lineHeight: 1.6,
        }}
      >
{`RASPUTIN_OBS_ENABLED=1 \\
  ./rasputin-api`}
      </pre>
      <Hint style={{ marginTop: 10 }}>
        On first start the stack pulls ~500 MB of images (VM, Alloy, Loki, Grafana, vmalert). Subsequent
        starts are fast. Optional toggles: <Tok>RASPUTIN_OBS_LOKI=0</Tok> /{' '}
        <Tok>RASPUTIN_OBS_GRAFANA=0</Tok> / <Tok>RASPUTIN_OBS_VMALERT=0</Tok>.
      </Hint>
    </div>
  );
}
