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
import { IDSAlertsTab } from './IDSAlertsTab';
import { LogsTab } from './LogsTab';

export type TabKey = 'metrics' | 'containers' | 'logs' | 'alerts' | 'ids';

interface NodeDetailDrawerProps {
  node: Node | null;
  open: boolean;
  onClose: () => void;
  range: string; // shared with the page header range selector
  obsEnabled: boolean;
  // grafanaHref — when present, the "↗ open in Grafana" header link
  // jumps to the cluster dashboard. Omitted when obs is off.
  grafanaHref?: string;
  // initialTab — when set, the drawer opens on this tab instead of Metrics.
  // Used for deep links (the dashboard "VIEW LOGS" action opens straight to
  // Logs). The page clears it on close so a later manual open keeps the tab.
  initialTab?: TabKey;
}

// All tabs in fixed order. The IDS tab only makes sense for firewall
// nodes (snort doesn't run elsewhere), so the rendered list is filtered
// per-node — see tabsForNode below.
const ALL_TABS: { key: TabKey; label: string }[] = [
  { key: 'metrics', label: 'METRICS' },
  { key: 'containers', label: 'CONTAINERS' },
  { key: 'logs', label: 'LOGS' },
  { key: 'ids', label: 'IDS' },
  { key: 'alerts', label: 'ALERTS' },
];

function tabsForNode(node: Node | null): { key: TabKey; label: string }[] {
  if (!node || node.role !== 'firewall') {
    return ALL_TABS.filter((t) => t.key !== 'ids');
  }
  return ALL_TABS;
}

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
  initialTab,
}: NodeDetailDrawerProps) {
  const [tab, setTab] = useState<TabKey>('metrics');

  // Apply a deep-linked tab when the drawer opens. Guarded on `initialTab` so a
  // normal open (no deep link) leaves the operator's current tab untouched.
  //
  // Adjusted DURING RENDER rather than from an effect. React documents this for
  // "a prop changed and state must follow it": the component re-renders
  // immediately, before children render or the browser paints, so there is no
  // flash of the wrong tab — whereas an effect sets state after paint and is a
  // synchronous setState on effect entry (react-hooks/set-state-in-effect).
  // `honored` records which deep link has already been applied so the operator
  // can still switch tabs afterwards without being yanked back.
  const [honored, setHonored] = useState<{ open: boolean; tab?: TabKey }>({ open: false });
  if (honored.open !== open || honored.tab !== initialTab) {
    setHonored({ open, tab: initialTab });
    if (open && initialTab) setTab(initialTab);
  }

  return (
    <Drawer
      open={open}
      onClose={onClose}
      // Node id is the primary identifier (matches the Nodes-page
      // hex label convention); hostname drops to the subtitle next
      // to the role. Drawer header has room for the full id — no
      // truncation needed here.
      title={node ? node.id : 'NODE'}
      subtitle={
        node
          ? `${node.role.toUpperCase()}${node.hostname ? ` · ${node.hostname}` : ''}`
          : undefined
      }
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
      <Tabs current={tab} onChange={setTab} tabs={tabsForNode(node)} />
      <div style={{ flex: 1, padding: '16px 18px', display: 'flex', flexDirection: 'column' }}>
        {tab === 'metrics' && node && (
          <MetricsTab node={node} range={range} obsEnabled={obsEnabled} />
        )}
        {tab === 'containers' && node && <ContainersTab node={node} obsEnabled={obsEnabled} />}
        {tab === 'logs' && node && (
          <LogsTab node={node} range={range} obsEnabled={obsEnabled} grafanaHref={grafanaHref} />
        )}
        {tab === 'ids' && node && node.role === 'firewall' && (
          <IDSAlertsTab node={node} range={range} obsEnabled={obsEnabled} />
        )}
        {tab === 'alerts' && node && <AlertsTab node={node} />}
      </div>
    </Drawer>
  );
}

function Tabs({
  current,
  onChange,
  tabs,
}: {
  current: TabKey;
  onChange: (k: TabKey) => void;
  tabs: { key: TabKey; label: string }[];
}) {
  // <div>, not <nav>: role="tablist" on a landmark element is two conflicting
  // semantics on one node, and this is a tab strip inside a dialog, not site
  // navigation.
  return (
    <div
      role="tablist"
      aria-label="Node detail sections"
      style={{
        display: 'flex',
        gap: 4,
        padding: '0 18px',
        borderBottom: `1px solid ${HAIR}`,
      }}
    >
      {tabs.map((t) => {
        const active = t.key === current;
        return (
          <button
            key={t.key}
            type="button"
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
    </div>
  );
}

const EMPTY_SERIES: Record<ObsSeriesMetric, ObsSeries | null> = {
  cpu: null,
  mem: null,
  mem_bytes: null,
  disk: null,
  load1: null,
};

function MetricsTab({
  node,
  range,
  obsEnabled,
}: {
  node: Node;
  range: string;
  obsEnabled: boolean;
}) {
  // One result object keyed by the request it answers, so `loading` is DERIVED
  // rather than set synchronously on effect entry (set-state-in-effect). The
  // per-metric error is collected inside the Promise.all and written once with
  // the series, instead of racing a separate setErr from each rejected chart.
  const requestKey = `${node.id}|${range}`;
  const [result, setResult] = useState<{
    key: string;
    series: Record<ObsSeriesMetric, ObsSeries | null>;
    err: string | null;
  }>({ key: '', series: EMPTY_SERIES, err: null });

  const loading = obsEnabled && result.key !== requestKey;
  const series = result.key === requestKey ? result.series : EMPTY_SERIES;
  const err = result.key === requestKey ? result.err : null;

  useEffect(() => {
    if (!obsEnabled) return;
    let cancelled = false;
    let failure: string | null = null;
    Promise.all(
      METRICS_TO_CHART.map(async (m) => {
        try {
          const s = await getObsSeries(node.id, m.key, range);
          return [m.key, s] as const;
        } catch (e) {
          failure = (e as Error).message;
          return [m.key, null] as const;
        }
      }),
    ).then((entries) => {
      if (cancelled) return;
      setResult({
        key: requestKey,
        series: { ...EMPTY_SERIES, ...Object.fromEntries(entries) },
        err: failure,
      });
    });
    return () => {
      cancelled = true;
    };
  }, [node.id, range, obsEnabled, requestKey]);

  if (!obsEnabled) {
    return (
      <Hint>
        Metrics &amp; logs are off, so there&apos;s no recorded history to chart. Turn them on in
        Settings to start recording this node.
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

