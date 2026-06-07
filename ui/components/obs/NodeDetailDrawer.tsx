'use client';

// NodeDetailDrawer — per-node drill-in shown when a NodeCard on
// /metrics is clicked. Tabbed surface: Metrics | Containers | Logs |
// Alerts. This commit lands the drawer + Metrics tab (full-size CPU,
// MEM, DISK charts from /api/obs/series). Other tabs render
// placeholders that future revamp slices replace:
//
//   - Containers tab → Slice 5 (needs /api/obs/containers shim)
//   - Logs tab       → Slice 4 (needs LogsClient filter params)
//   - Alerts tab     → Slice 6 (filters /api/alerts by relatedId)
//
// Series fetching: lifted into the drawer so it polls only when open.
// We re-fetch on tab change to Metrics + range change. No live polling
// loop — VM samples on 10s anyway and a wath-style dashboard doesn't
// need sub-30s freshness; the operator can re-open the drawer.

import { useEffect, useState } from 'react';
import { ExternalLink } from 'lucide-react';
import type { Node, ObsSeries, ObsSeriesMetric } from '../../lib/types';
import { getObsSeries } from '../../lib/api';
import { Btn, DIM, FG, HAIR, Hint } from '../kit';
import { accentA, MONO } from '../ui-theme';
import { AlertsTab } from './AlertsTab';
import { Chart } from './Chart';
import { ContainersTab } from './ContainersTab';
import { Drawer } from './Drawer';
import { LogsTab } from './LogsTab';

export type TabKey = 'metrics' | 'containers' | 'logs' | 'alerts';

interface NodeDetailDrawerProps {
  node: Node | null;
  open: boolean;
  onClose: () => void;
  range: string; // shared with the page header range selector
  obsEnabled: boolean;
  // grafanaHref — when present, the "↗ open in Grafana" header link
  // jumps to the cluster dashboard. Omitted when obs is off.
  grafanaHref?: string;
}

const TABS: { key: TabKey; label: string }[] = [
  { key: 'metrics', label: 'METRICS' },
  { key: 'containers', label: 'CONTAINERS' },
  { key: 'logs', label: 'LOGS' },
  { key: 'alerts', label: 'ALERTS' },
];

const METRICS_TO_CHART: { key: ObsSeriesMetric; title: string; unit: 'percent' | 'bytes' | 'load'; domainMax?: number }[] = [
  { key: 'cpu', title: 'CPU %', unit: 'percent', domainMax: 100 },
  { key: 'mem', title: 'MEMORY %', unit: 'percent', domainMax: 100 },
  { key: 'disk', title: 'DISK %', unit: 'percent', domainMax: 100 },
  { key: 'mem_bytes', title: 'MEMORY (BYTES)', unit: 'bytes' },
];

export function NodeDetailDrawer({
  node,
  open,
  onClose,
  range,
  obsEnabled,
  grafanaHref,
}: NodeDetailDrawerProps) {
  const [tab, setTab] = useState<TabKey>('metrics');

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={node ? node.hostname || node.id : 'NODE'}
      subtitle={node ? `${node.role.toUpperCase()} · ${node.id}` : undefined}
      headerExtras={
        grafanaHref ? (
          <a href={grafanaHref} target="_blank" rel="noreferrer" style={{ textDecoration: 'none' }}>
            <Btn variant="ghost" small>
              <ExternalLink size={11} />
              IN GRAFANA
            </Btn>
          </a>
        ) : undefined
      }
    >
      <Tabs current={tab} onChange={setTab} />
      <div style={{ flex: 1, padding: '16px 18px', display: 'flex', flexDirection: 'column' }}>
        {tab === 'metrics' && node && (
          <MetricsTab node={node} range={range} obsEnabled={obsEnabled} />
        )}
        {tab === 'containers' && node && <ContainersTab node={node} obsEnabled={obsEnabled} />}
        {tab === 'logs' && node && (
          <LogsTab node={node} range={range} obsEnabled={obsEnabled} grafanaHref={grafanaHref} />
        )}
        {tab === 'alerts' && node && <AlertsTab node={node} />}
      </div>
    </Drawer>
  );
}

function Tabs({ current, onChange }: { current: TabKey; onChange: (k: TabKey) => void }) {
  return (
    <nav
      role="tablist"
      style={{
        display: 'flex',
        gap: 4,
        padding: '0 18px',
        borderBottom: `1px solid ${HAIR}`,
      }}
    >
      {TABS.map((t) => {
        const active = t.key === current;
        return (
          <button
            key={t.key}
            role="tab"
            aria-selected={active}
            onClick={() => onChange(t.key)}
            style={{
              background: 'transparent',
              border: 'none',
              borderBottom: `2px solid ${active ? accentA(0.95) : 'transparent'}`,
              padding: '10px 12px',
              color: active ? FG : DIM,
              fontFamily: MONO,
              fontSize: 9,
              letterSpacing: '0.12em',
              cursor: 'pointer',
              transition: 'color 0.15s, border-color 0.15s',
            }}
          >
            {t.label}
          </button>
        );
      })}
    </nav>
  );
}

function MetricsTab({
  node,
  range,
  obsEnabled,
}: {
  node: Node;
  range: string;
  obsEnabled: boolean;
}) {
  const [series, setSeries] = useState<Record<ObsSeriesMetric, ObsSeries | null>>({
    cpu: null,
    mem: null,
    mem_bytes: null,
    disk: null,
    load1: null,
  });
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!obsEnabled) return;
    let cancelled = false;
    setLoading(true);
    setErr(null);
    Promise.all(
      METRICS_TO_CHART.map(async (m) => {
        try {
          const s = await getObsSeries(node.id, m.key, range);
          return [m.key, s] as const;
        } catch (e) {
          if (!cancelled) setErr((e as Error).message);
          return [m.key, null] as const;
        }
      }),
    ).then((entries) => {
      if (cancelled) return;
      setSeries((curr) => ({ ...curr, ...Object.fromEntries(entries) }));
      setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, [node.id, range, obsEnabled]);

  if (!obsEnabled) {
    return (
      <Hint>
        Observability is off. Per-node charts populate once <code>RASPUTIN_OBS_ENABLED=1</code> is
        set and VictoriaMetrics is running.
      </Hint>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 22 }}>
      {err && <Hint warn>Couldn&apos;t reach /api/obs/series: {err}</Hint>}
      {METRICS_TO_CHART.map((m) => {
        const s = series[m.key];
        return (
          <Chart
            key={m.key}
            title={m.title}
            unit={m.unit}
            points={s?.points ?? []}
            domainMax={m.domainMax}
          />
        );
      })}
      <Hint style={{ marginTop: 4, color: DIM }}>
        {loading ? 'Loading…' : `Range ${range} · ~120 points per chart · re-opens or range changes refetch.`}
      </Hint>
    </div>
  );
}

