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
        background: hover ? 'var(--rasp-field-bg)' : PANEL,
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
      {/* Header — node id (primary identifier, like the Nodes page hex
          label) + status pill. Hostname drops below as secondary. */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 10 }}>
        <span
          title={node.id}
          style={{
            fontSize: 12,
            letterSpacing: '0.04em',
            color: FG,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {shortId(node.id)}
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

      {/* Secondary row — role + hostname. Pushed under the id so the
          card hierarchy matches the Nodes-page convention. */}
      <div
        style={{
          display: 'flex',
          alignItems: 'baseline',
          gap: 8,
          fontSize: 8.5,
          letterSpacing: '0.1em',
          color: DIM,
          marginTop: -6, // tuck under the header without re-introducing the row's 12px gap
        }}
      >
        <span style={{ textTransform: 'uppercase' }}>{node.role}</span>
        {node.hostname && (
          <span
            title={node.hostname}
            style={{
              letterSpacing: '0.04em',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            · {node.hostname}
          </span>
        )}
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

      {/* Footer — agent version + last-seen marker. The id moved
          to the header so the footer doesn't need to repeat it. */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          fontSize: 8.5,
          letterSpacing: '0.08em',
          color: DIM,
          paddingTop: 8,
          borderTop: `1px solid rgba(var(--rasp-fg-rgb),0.08)`,
        }}
      >
        <span>
          AGENT v{node.agentVersion}
          {node.imageVersion ? ` · IMAGE ${node.imageVersion}` : ''}
        </span>
        <span title={node.lastSeen}>{lastSeenAgo(node.lastSeen)}</span>
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

// shortId truncates with an ellipsis past 10 chars. Matches the
// /<Nodes> page's hex label so the card and the hex agree at a glance.
function shortId(id: string): string {
  return id.length > 14 ? id.slice(0, 13) + '…' : id;
}

// lastSeenAgo — coarse "Ns ago" for the card footer. Doesn't pretend
// to be real-time (the card is re-rendered when inventory WS fires or
// when series re-fetch); the operator gets a fresh value on each tick.
function lastSeenAgo(iso: string): string {
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return '—';
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}
