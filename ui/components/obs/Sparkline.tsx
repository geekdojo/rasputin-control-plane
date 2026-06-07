'use client';

// Tiny SVG sparkline for the NodeCards on /metrics. No chart library —
// each card needs to render in <1ms across an 8-node grid and any
// per-card Recharts mount adds measurable jank. The drawer's full-size
// charts will use Recharts because they need axes, tooltips, and
// brushing; cards just need a shape-of-the-curve glance.
//
// `values` is a plain number[]. If empty (cold start, no samples yet)
// renders a flat baseline so the card layout doesn't jump when data
// arrives.

import { accentA } from '../ui-theme';

interface SparklineProps {
  values: number[];
  width?: number;
  height?: number;
  color?: string;
  fill?: string;
  // domainMax overrides the y-axis upper bound. Useful for percentage
  // metrics (always 0..100) so two cards stay visually comparable —
  // without it, a node at 5% looks just as busy as one at 95%.
  domainMax?: number;
}

export function Sparkline({
  values,
  width = 96,
  height = 22,
  color,
  fill,
  domainMax,
}: SparklineProps) {
  const stroke = color ?? accentA(0.9);
  const fillC = fill ?? accentA(0.18);

  if (values.length === 0) {
    return (
      <svg width={width} height={height} aria-hidden>
        <line
          x1={0}
          y1={height - 1}
          x2={width}
          y2={height - 1}
          stroke="rgba(228,230,234,0.18)"
          strokeWidth={1}
          strokeDasharray="2 3"
        />
      </svg>
    );
  }

  const max = domainMax ?? Math.max(1, ...values);
  // Pad the bottom by 1px so the line never clips the baseline border.
  const yFor = (v: number) => {
    const norm = Math.max(0, Math.min(1, v / max));
    return height - 1 - norm * (height - 2);
  };
  const stepX = values.length > 1 ? width / (values.length - 1) : 0;

  const pts = values.map((v, i) => `${(i * stepX).toFixed(2)},${yFor(v).toFixed(2)}`);
  const linePath = `M ${pts.join(' L ')}`;
  // Close to baseline for the fill underneath.
  const areaPath = `${linePath} L ${width.toFixed(2)},${height} L 0,${height} Z`;

  return (
    <svg width={width} height={height} aria-hidden>
      <path d={areaPath} fill={fillC} stroke="none" />
      <path d={linePath} fill="none" stroke={stroke} strokeWidth={1.25} />
    </svg>
  );
}
