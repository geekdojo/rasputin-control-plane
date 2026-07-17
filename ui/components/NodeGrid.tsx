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

// A pending enrollment — a node id that's been issued a join token but whose
// agent hasn't registered yet. Occupies a slot, drawn distinct from a live
// node, and clickable to cancel (revoke the token).
export interface PendingView {
  id: string;
  tokenId: string;
  role: string;
}

interface NodeGridProps {
  nodes: NodeView[];
  pending?: PendingView[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  // When set, open bays render an interactive "+" that launches the add-node
  // wizard, and the silhouette always keeps at least one open bay (up to the
  // 24-node max) so there's somewhere to click.
  onAddNode?: () => void;
  onCancelPending?: (p: PendingView) => void;
}

// Empty chassis position — drawn dim and dashed, not interactive, visually
// distinct from an offline node (which is a solid hex with a status dot).
function BayCell({ cx, cy }: Slot) {
  return (
    <g style={{ pointerEvents: 'none' }}>
      <polygon
        points={hexPoints(cx, cy, R)}
        fill="rgba(14,26,44,0.35)"
        stroke="rgba(var(--rasp-fg-rgb),0.1)"
        strokeWidth={0.75}
        strokeDasharray="3 4"
      />
      <circle cx={cx} cy={cy} r={2} fill="rgba(var(--rasp-fg-rgb),0.1)" />
    </g>
  );
}

// Interactive open bay — a dim dashed hex with a "+" that launches the
// add-node wizard. The "ADD NODE" caption shows on hover to keep a grid full
// of empty bays from reading as noise.
function AddCell({ cx, cy, onClick }: Slot & { onClick: () => void }) {
  const [hovered, setHovered] = useState(false);
  const stroke = hovered ? ACCENT : 'rgba(var(--rasp-fg-rgb),0.28)';
  return (
    <g
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{ cursor: 'pointer' }}
    >
      <polygon
        points={hexPoints(cx, cy, R)}
        fill={hovered ? accentA(0.07) : 'rgba(14,26,44,0.25)'}
        stroke={stroke}
        strokeWidth={hovered ? 1.25 : 0.75}
        strokeDasharray="3 4"
        style={{ transition: 'fill 0.15s, stroke 0.15s' }}
      />
      <line x1={cx - 11} y1={cy} x2={cx + 11} y2={cy} stroke={stroke} strokeWidth={1.75} style={{ transition: 'stroke 0.15s' }} />
      <line x1={cx} y1={cy - 11} x2={cx} y2={cy + 11} stroke={stroke} strokeWidth={1.75} style={{ transition: 'stroke 0.15s' }} />
      {hovered && (
        <text
          x={cx}
          y={cy + 30}
          textAnchor="middle"
          fill={ACCENT}
          fontSize={8}
          fontFamily={MONO}
          letterSpacing="0.1em"
          style={{ userSelect: 'none' }}
        >
          ADD NODE
        </text>
      )}
    </g>
  );
}

// Pending enrollment — a reserved node id that's been issued a token but hasn't
// come online. Dashed accent hex with a slow pulse; clicking cancels it.
function PendingCell({ cx, cy, label, onClick }: Slot & { label: string; onClick: () => void }) {
  const [hovered, setHovered] = useState(false);
  const shown = label.length > 10 ? label.slice(0, 9) + '…' : label;
  return (
    <g
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{ cursor: 'pointer' }}
    >
      <title>{`${label} — waiting to come online · click to cancel`}</title>
      <g style={{ transformOrigin: `${cx}px ${cy}px`, animation: 'hex-pulse 2.4s ease-out infinite' }}>
        <polygon points={hexPoints(cx, cy, R)} fill="none" stroke={ACCENT} strokeWidth={1} />
      </g>
      <polygon
        points={hexPoints(cx, cy, R)}
        fill={accentA(hovered ? 0.1 : 0.05)}
        stroke={accentA(hovered ? 0.6 : 0.35)}
        strokeWidth={0.75}
        strokeDasharray="3 4"
        style={{ transition: 'fill 0.15s, stroke 0.15s' }}
      />
      <text x={cx} y={cy - 6} textAnchor="middle" fill={ACCENT} fontSize={12} fontFamily={MONO} letterSpacing="0.06em" style={{ userSelect: 'none' }}>
        {shown}
      </text>
      <text x={cx} y={cy + 9} textAnchor="middle" fill={accentA(0.7)} fontSize={9} fontFamily={MONO} letterSpacing="0.1em" style={{ userSelect: 'none' }}>
        PENDING
      </text>
      <text x={cx} y={cy + 25} textAnchor="middle" fill="rgba(var(--rasp-fg-rgb),0.4)" fontSize={8} fontFamily={MONO} letterSpacing="0.06em" style={{ userSelect: 'none' }}>
        {hovered ? 'CLICK TO CANCEL' : 'waiting…'}
      </text>
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
      ? 'rgba(var(--rasp-fg-rgb),0.05)'
      : 'rgba(14,26,44,0.6)';
  const strokeColor = selected ? ACCENT : 'rgba(var(--rasp-fg-rgb),0.18)';
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
        fill={selected ? statusColor : 'rgba(var(--rasp-fg-rgb),0.18)'}
        style={{ transition: 'fill 0.15s' }}
      />
      {selected && node.status !== 'offline' && (
        <circle cx={cx} cy={cy - 22} r={7} fill={statusColor} opacity={0.2} />
      )}

      <text
        x={cx}
        y={cy - 6}
        textAnchor="middle"
        fill={selected ? 'var(--rasp-fg)' : 'rgba(var(--rasp-fg-rgb),0.4)'}
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
        fill={selected ? 'var(--rasp-dim)' : 'rgba(138,155,181,0.3)'}
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
        fill={selected ? statusColor : 'rgba(var(--rasp-fg-rgb),0.18)'}
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

// MAX_NODES is the design silhouette's capacity — the flattened 24-cell
// hexagon. At capacity the grid is "full" and shows no add affordance.
// Must stay in sync with proto.MaxClusterNodes (proto/inventory.go), which
// the api enforces at token mint and node registration.
const MAX_NODES = 24;

export function NodeGrid({ nodes, pending = [], selectedId, onSelect, onAddNode, onCancelPending }: NodeGridProps) {
  // Stable role-prioritized order so inventory WS churn doesn't shuffle
  // the hex layout. Same priority scheme as the /metrics cards grid so
  // operators see a consistent "where is X" across views.
  const ordered = [...nodes].sort((a, b) => {
    const pa = ROLE_PRIORITY[a.role] ?? DEFAULT_ROLE_PRIORITY;
    const pb = ROLE_PRIORITY[b.role] ?? DEFAULT_ROLE_PRIORITY;
    if (pa !== pb) return pa - pb;
    return a.id.localeCompare(b.id);
  });
  const pend = [...pending].sort((a, b) => a.id.localeCompare(b.id));
  const occupied = ordered.length + pend.length;

  // Size the silhouette to hold every node + pending slot, and — when adding is
  // possible — keep at least one open bay to click, capped at the 24-node max.
  const target = onAddNode ? Math.min(MAX_NODES, occupied + 1) : occupied;
  const { slots, width, height } = buildSilhouette(target);

  return (
    <div
      style={{
        flex: '0 0 65%',
        borderRight: '1px solid rgba(var(--rasp-fg-rgb),0.18)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px 16px',
        overflow: 'auto',
      }}
    >
      {occupied === 0 ? (
        <p style={{ color: 'var(--rasp-dim)', fontSize: 12, fontFamily: MONO, textAlign: 'center', maxWidth: 420 }}>
          no nodes registered yet — start <span style={{ color: 'var(--rasp-fg)' }}>rasputin-agent</span> and one
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

            {/* Open bays first so populated hexes (and their pulse) draw on top.
                With onAddNode set, every open bay is an interactive "+". */}
            {slots.map((pos, idx) => {
              if (idx < occupied) return null;
              return onAddNode ? (
                <AddCell key={`add-${idx}`} cx={pos.cx} cy={pos.cy} onClick={onAddNode} />
              ) : (
                <BayCell key={`bay-${idx}`} cx={pos.cx} cy={pos.cy} />
              );
            })}
            {/* Pending enrollments fill the slots just past the live nodes. */}
            {pend.map((p, i) => {
              const pos = slots[ordered.length + i];
              if (!pos) return null;
              return (
                <PendingCell
                  key={`pending-${p.tokenId}`}
                  cx={pos.cx}
                  cy={pos.cy}
                  label={p.id}
                  onClick={() => onCancelPending?.(p)}
                />
              );
            })}
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
              borderTop: '1px solid rgba(var(--rasp-fg-rgb),0.1)',
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
              { label: 'PENDING', color: accentA(0.8), dashed: true },
              { label: 'OPEN BAY', color: 'rgba(var(--rasp-fg-rgb),0.25)', dashed: true },
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
                <span style={{ color: 'var(--rasp-dim)', fontSize: 10, fontFamily: MONO, letterSpacing: '0.08em' }}>
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
