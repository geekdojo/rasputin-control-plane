'use client';

// NodeCard — one card per node on /metrics. Shows hostname/role/status,
// CPU + Memory sparklines (30m), last-seen pill. Click → opens the
// NodeDetailDrawer (wired by the parent).
//
// Data model: the parent passes the Node from inventory plus the two
// ObsSeries we've fetched. The card is a pure render — fetching and
// polling live in the parent so the grid can batch requests and
// throttle properly.

import { useState } from 'react';
import type { Node } from '../../lib/types';
import type { ObsSeries } from '../../lib/types';
import { DIM, FG, HAIR, PANEL } from '../kit';
import { accentA, MONO } from '../ui-theme';
import { Sparkline } from './Sparkline';

interface NodeCardProps {
  node: Node;
  cpuSeries: ObsSeries | null;
  memSeries: ObsSeries | null;
  // Whether the obs stack is enabled. When false, sparklines render
  // their empty state and the card explains the absence.
  obsEnabled: boolean;
  onClick: () => void;
}

const STATUS_COLOR: Record<Node['status'], string> = {
  online: '#4ade80',
  stale: '#facc15',
  offline: '#f87171',
};

const STATUS_LABEL: Record<Node['status'], string> = {
  online: 'ONLINE',
  stale: 'STALE',
  offline: 'OFFLINE',
};

function lastValue(series: ObsSeries | null): number | null {
  if (!series || series.points.length === 0) return null;
  return series.points[series.points.length - 1].value;
}

function pct(n: number | null): string {
  if (n == null) return '—';
  return `${Math.round(n)}%`;
}

export function NodeCard({ node, cpuSeries, memSeries, obsEnabled, onClick }: NodeCardProps) {
  const [hover, setHover] = useState(false);
  const statusColor = STATUS_COLOR[node.status];

  const cpuVals = (cpuSeries?.points ?? []).map((p) => p.value);
  const memVals = (memSeries?.points ?? []).map((p) => p.value);
  const cpuNow = lastValue(cpuSeries);
  const memNow = lastValue(memSeries);

  return (
    <button
      type="button"
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        background: hover ? '#111d30' : PANEL,
        border: `1px solid ${hover ? accentA(0.45) : HAIR}`,
        padding: '14px 16px',
        textAlign: 'left',
        cursor: 'pointer',
        fontFamily: MONO,
        color: FG,
        transition: 'background 0.15s, border-color 0.15s',
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
      }}
    >
      {/* Header — name + status pill */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 10 }}>
        <span style={{ fontSize: 12, letterSpacing: '0.04em', color: FG }}>
          {node.hostname || node.id}
        </span>
        <span
          style={{
            fontSize: 8.5,
            letterSpacing: '0.12em',
            color: DIM,
            textTransform: 'uppercase',
          }}
        >
          {node.role}
        </span>
        <span
          style={{
            marginLeft: 'auto',
            display: 'inline-flex',
            alignItems: 'center',
            gap: 5,
            fontSize: 8.5,
            letterSpacing: '0.12em',
            color: statusColor,
          }}
        >
          <span
            style={{
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: statusColor,
              boxShadow: node.status === 'online' ? `0 0 6px ${statusColor}` : 'none',
            }}
          />
          {STATUS_LABEL[node.status]}
        </span>
      </div>

      {/* Sparkline rows */}
      <SparkRow
        label="CPU"
        value={pct(cpuNow)}
        values={cpuVals}
        domainMax={100}
        unavailable={!obsEnabled}
      />
      <SparkRow
        label="MEM"
        value={pct(memNow)}
        values={memVals}
        domainMax={100}
        unavailable={!obsEnabled}
      />

      {/* Footer — node id (short) + agent version. Keeps the card
          information-dense without crowding the top half. */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          fontSize: 8.5,
          letterSpacing: '0.08em',
          color: DIM,
          paddingTop: 8,
          borderTop: `1px solid rgba(228,230,234,0.08)`,
        }}
      >
        <span title={node.id}>{node.id.slice(0, 12)}</span>
        <span>v{node.agentVersion}</span>
      </div>
    </button>
  );
}

// SparkRow — label · value · sparkline, sized for two-per-card density.
function SparkRow({
  label,
  value,
  values,
  domainMax,
  unavailable,
}: {
  label: string;
  value: string;
  values: number[];
  domainMax: number;
  unavailable: boolean;
}) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <span style={{ fontSize: 8.5, letterSpacing: '0.14em', color: DIM, width: 28 }}>{label}</span>
      <span
        style={{
          fontSize: 11,
          color: unavailable ? DIM : FG,
          minWidth: 40,
          textAlign: 'right',
        }}
      >
        {unavailable ? 'OFF' : value}
      </span>
      <div style={{ marginLeft: 'auto' }}>
        <Sparkline values={values} domainMax={domainMax} />
      </div>
    </div>
  );
}
