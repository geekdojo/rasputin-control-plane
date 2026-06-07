'use client';

import { useState } from 'react';
import { ACCENT, accentA, MONO, STATUS_COLOR, type NodeViewStatus } from './ui-theme';

export interface NodeView {
  id: string;
  name: string;
  status: NodeViewStatus;
  cpu: number | null; // null when metrics are not yet available
  role: string;
}

// Hex geometry — pointy-top, circumradius R.
const R = 52;
const HEX_W = Math.sqrt(3) * R; // center-to-center horizontal (same row)
const HEX_H = 2 * R;
const ROW_STEP = 1.5 * R; // center-to-center vertical
const PAD = 10;

interface Slot {
  cx: number;
  cy: number;
}

// The cluster is always drawn as a complete hexagon silhouette; real nodes
// fill the slots and any remainder render as dim "open bays". The silhouette
// snaps up to the smallest hexagon that holds N. Every row-set is a symmetric
// hexagon whose adjacent rows differ by 1, so the pointy-top cells interlock
// into a true honeycomb. The ladder is tuned so no count ever shows more than
// four bays (24 is the flattened hexagon from the source design).
function rowsForCount(n: number): number[] {
  if (n <= 7) return [2, 3, 2]; // 7
  if (n <= 10) return [3, 4, 3]; // 10
  if (n <= 14) return [2, 3, 4, 3, 2]; // 14
  if (n <= 19) return [3, 4, 5, 4, 3]; // 19
  if (n <= 24) return [4, 5, 6, 5, 4]; // 24 — the design's silhouette
  return [4, 5, 6, 7, 6, 5, 4]; // 37 — safety net above the 24-node max
}

function buildSilhouette(n: number): { slots: Slot[]; width: number; height: number } {
  const rows = rowsForCount(Math.max(n, 1));
  const maxCols = Math.max(...rows);
  const width = 2 * PAD + maxCols * HEX_W;
  const height = 2 * PAD + (rows.length - 1) * ROW_STEP + HEX_H;

  const raw: Slot[] = [];
  rows.forEach((count, r) => {
    const cy = PAD + R + r * ROW_STEP;
    const startCx = PAD + HEX_W / 2 + ((maxCols - count) * HEX_W) / 2;
    for (let i = 0; i < count; i++) {
      raw.push({ cx: startCx + i * HEX_W, cy });
    }
  });

  // Order center-outward so nodes populate the core and bays sit on the rim.
  const cxAvg = raw.reduce((s, p) => s + p.cx, 0) / raw.length;
  const cyAvg = raw.reduce((s, p) => s + p.cy, 0) / raw.length;
  const slots = raw
    .map((p) => ({
      p,
      d: Math.hypot(p.cx - cxAvg, p.cy - cyAvg),
      a: Math.atan2(p.cy - cyAvg, p.cx - cxAvg),
    }))
    .sort((x, y) => x.d - y.d || x.a - y.a)
    .map((s) => s.p);

  return { slots, width, height };
}

function hexPoints(cx: number, cy: number, r: number): string {
  return Array.from({ length: 6 }, (_, i) => {
    const a = Math.PI / 6 + i * (Math.PI / 3);
    return `${(cx + r * Math.cos(a)).toFixed(2)},${(cy + r * Math.sin(a)).toFixed(2)}`;
  }).join(' ');
}

interface NodeGridProps {
  nodes: NodeView[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

// Empty chassis position — drawn dim and dashed, not interactive, visually
// distinct from an offline node (which is a solid hex with a status dot).
function BayCell({ cx, cy }: Slot) {
  return (
    <g style={{ pointerEvents: 'none' }}>
      <polygon
        points={hexPoints(cx, cy, R)}
        fill="rgba(14,26,44,0.35)"
        stroke="rgba(228,230,234,0.1)"
        strokeWidth={0.75}
        strokeDasharray="3 4"
      />
      <circle cx={cx} cy={cy} r={2} fill="rgba(228,230,234,0.1)" />
    </g>
  );
}

function HexCell({
  node,
  cx,
  cy,
  selected,
  onClick,
}: {
  node: NodeView;
  cx: number;
  cy: number;
  selected: boolean;
  onClick: () => void;
}) {
  const [hovered, setHovered] = useState(false);
  const statusColor = STATUS_COLOR[node.status];
  const outerPts = hexPoints(cx, cy, R);

  const fillColor = selected
    ? accentA(0.13)
    : hovered
      ? 'rgba(228,230,234,0.05)'
      : 'rgba(14,26,44,0.6)';
  const strokeColor = selected ? ACCENT : 'rgba(228,230,234,0.18)';
  const strokeW = selected ? 1.5 : 0.75;

  const cpuLabel =
    node.status === 'offline' ? 'OFFL' : node.cpu == null ? '—' : `${Math.round(node.cpu)}%`;

  return (
    <g
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{ cursor: 'pointer' }}
    >
      {selected && (
        <>
          <g style={{ transformOrigin: `${cx}px ${cy}px`, animation: 'hex-pulse 2s ease-out infinite' }}>
            <polygon points={outerPts} fill="none" stroke={ACCENT} strokeWidth={1.5} />
          </g>
          <g style={{ transformOrigin: `${cx}px ${cy}px`, animation: 'hex-pulse 2s ease-out 0.9s infinite' }}>
            <polygon points={outerPts} fill="none" stroke={ACCENT} strokeWidth={1.5} />
          </g>
        </>
      )}

      <polygon
        points={outerPts}
        fill={fillColor}
        stroke={strokeColor}
        strokeWidth={strokeW}
        style={{ transition: 'fill 0.15s, stroke 0.15s' }}
      />

      {selected && (
        <polygon points={hexPoints(cx, cy, R - 5)} fill="none" stroke={ACCENT} strokeWidth={0.75} opacity={0.4} />
      )}

      <circle
        cx={cx}
        cy={cy - 22}
        r={4}
        fill={selected ? statusColor : 'rgba(228,230,234,0.18)'}
        style={{ transition: 'fill 0.15s' }}
      />
      {selected && node.status !== 'offline' && (
        <circle cx={cx} cy={cy - 22} r={7} fill={statusColor} opacity={0.2} />
      )}

      <text
        x={cx}
        y={cy - 6}
        textAnchor="middle"
        fill={selected ? '#e4e6ea' : 'rgba(228,230,234,0.4)'}
        fontSize={12}
        fontFamily={MONO}
        letterSpacing="0.06em"
        style={{ transition: 'fill 0.15s', userSelect: 'none' }}
      >
        {node.name}
      </text>

      <text
        x={cx}
        y={cy + 9}
        textAnchor="middle"
        fill={selected ? '#8a9bb5' : 'rgba(138,155,181,0.3)'}
        fontSize={10}
        fontFamily={MONO}
        letterSpacing="0.04em"
        style={{ transition: 'fill 0.15s', userSelect: 'none' }}
      >
        {node.role}
      </text>

      <text
        x={cx}
        y={cy + 25}
        textAnchor="middle"
        fill={selected ? statusColor : 'rgba(228,230,234,0.18)'}
        fontSize={10}
        fontFamily={MONO}
        style={{ transition: 'fill 0.15s', userSelect: 'none' }}
      >
        {cpuLabel}
      </text>
    </g>
  );
}

// Role priority for the hex layout. Slots are sorted center-out in
// buildSilhouette, so ordered[0] gets the very center hex, ordered[1]
// the next ring, and so on. Firewall claims the center because it's
// the network ingress/egress — operators glance there first when
// something feels off. Controlplane takes the next inner slot.
// Compute / storage / anything else fall through to alphabetic by id.
//
// Keys match the SHORT role strings minted by page.tsx's ROLE_SHORT
// (controlplane→"ctrl", firewall→"fw", compute→"work", storage→"stor")
// because that's what NodeView carries on the wire.
const ROLE_PRIORITY: Record<string, number> = {
  fw: 0,
  ctrl: 1,
  work: 2,
  stor: 3,
};
const DEFAULT_ROLE_PRIORITY = 99;

export function NodeGrid({ nodes, selectedId, onSelect }: NodeGridProps) {
  const { slots, width, height } = buildSilhouette(nodes.length);

  // Stable role-prioritized order so inventory WS churn doesn't shuffle
  // the hex layout. Same priority scheme as the /metrics cards grid so
  // operators see a consistent "where is X" across views.
  const ordered = [...nodes].sort((a, b) => {
    const pa = ROLE_PRIORITY[a.role] ?? DEFAULT_ROLE_PRIORITY;
    const pb = ROLE_PRIORITY[b.role] ?? DEFAULT_ROLE_PRIORITY;
    if (pa !== pb) return pa - pb;
    return a.id.localeCompare(b.id);
  });

  return (
    <div
      style={{
        flex: '0 0 65%',
        borderRight: '1px solid rgba(228,230,234,0.18)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px 16px',
        overflow: 'auto',
      }}
    >
      {nodes.length === 0 ? (
        <p style={{ color: '#8a9bb5', fontSize: 12, fontFamily: MONO, textAlign: 'center', maxWidth: 420 }}>
          no nodes registered yet — start <span style={{ color: '#e4e6ea' }}>rasputin-agent</span> and one
          should appear here within a second
        </p>
      ) : (
        <>
          <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} style={{ overflow: 'visible' }}>
            <defs>
              <style>{`
                @keyframes hex-pulse {
                  0%   { transform: scale(1);    opacity: 0.55; }
                  100% { transform: scale(1.18); opacity: 0; }
                }
              `}</style>
            </defs>

            {/* Bays first so populated hexes (and their pulse) draw on top. */}
            {slots.map((pos, idx) =>
              idx >= ordered.length ? <BayCell key={`bay-${idx}`} cx={pos.cx} cy={pos.cy} /> : null,
            )}
            {slots.map((pos, idx) => {
              const node = ordered[idx];
              if (!node) return null;
              return (
                <HexCell
                  key={node.id}
                  node={node}
                  cx={pos.cx}
                  cy={pos.cy}
                  selected={selectedId === node.id}
                  onClick={() => onSelect(node.id)}
                />
              );
            })}
          </svg>

          <div
            style={{
              display: 'flex',
              gap: 18,
              marginTop: 20,
              borderTop: '1px solid rgba(228,230,234,0.1)',
              paddingTop: 12,
              width: '100%',
              justifyContent: 'center',
              flexWrap: 'wrap',
            }}
          >
            {[
              { label: 'ONLINE', color: STATUS_COLOR.online, dashed: false },
              { label: 'WARNING', color: STATUS_COLOR.warning, dashed: false },
              { label: 'UPDATING', color: STATUS_COLOR.updating, dashed: false },
              { label: 'OFFLINE', color: 'rgba(148,163,184,0.5)', dashed: false },
              { label: 'OPEN BAY', color: 'rgba(228,230,234,0.25)', dashed: true },
            ].map(({ label, color, dashed }) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: '50%',
                    background: dashed ? 'transparent' : color,
                    border: dashed ? `1px dashed ${color}` : 'none',
                  }}
                />
                <span style={{ color: '#8a9bb5', fontSize: 10, fontFamily: MONO, letterSpacing: '0.08em' }}>
                  {label}
                </span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
