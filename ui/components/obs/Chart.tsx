'use client';

// Chart — full-size SVG line chart for the NodeDetailDrawer's Metrics
// tab. Same dep-free approach as Sparkline so the project doesn't pick
// up a 400 KB charting library for the drawer's four charts. Recharts
// would be appropriate if we needed tooltips with crosshairs and
// brushing — those can land in a v2 if a user asks.
//
// Provides:
//   - 4-tick Y axis with formatted labels (percent / bytes / load)
//   - 3-tick X axis (start / mid / end timestamps, HH:mm or M/D HH:mm)
//   - line + filled area in accent
//   - dashed baseline + thin grid lines
//   - "no data" caption when the series is empty
//
// Layout is responsive via the SVG viewBox — the drawer just sets a
// width/height and Chart fills it.

import type { ObsSeriesPoint } from '../../lib/types';
import { DIM } from '../kit';
import { MONO } from '../ui-theme';

// Series color is FG-white (not the accent orange — too close to red
// for a healthy chart). Accent stays reserved for hover/select/CTA
// affordances. Mirrors the Sparkline default.
const SERIES_LINE = 'rgba(228,230,234,0.95)';
const SERIES_FILL = 'rgba(228,230,234,0.1)';

interface ChartProps {
  title: string;
  unit: 'percent' | 'bytes' | 'load';
  points: ObsSeriesPoint[];
  height?: number;
  // domainMax pins the y-axis upper bound. For % metrics we always
  // want 100 so spikes vs. quiet periods look honest at a glance.
  domainMax?: number;
}

const PAD_L = 44; // y-axis label gutter
const PAD_R = 8;
const PAD_T = 18;
const PAD_B = 22; // x-axis label gutter

export function Chart({ title, unit, points, height = 200, domainMax }: ChartProps) {
  // Match the SparkRow column spacing — fixed viewBox width so SVG
  // scales by container; the chart looks identical at any column width.
  const VBW = 480;
  const innerW = VBW - PAD_L - PAD_R;
  const innerH = height - PAD_T - PAD_B;

  if (points.length === 0) {
    return (
      <ChartFrame title={title} svgViewBox={`0 0 ${VBW} ${height}`} height={height}>
        <text
          x={VBW / 2}
          y={height / 2 + 4}
          textAnchor="middle"
          fill={DIM}
          fontFamily={MONO}
          fontSize={10}
          letterSpacing="0.08em"
        >
          NO DATA YET
        </text>
      </ChartFrame>
    );
  }

  const yMax = domainMax ?? autoMax(points.map((p) => p.value));
  const yMin = 0;
  const xMin = new Date(points[0].ts).getTime();
  const xMax = new Date(points[points.length - 1].ts).getTime();
  const xRange = Math.max(1, xMax - xMin);

  const xFor = (ts: string) =>
    PAD_L + ((new Date(ts).getTime() - xMin) / xRange) * innerW;
  const yFor = (v: number) =>
    PAD_T + innerH - ((v - yMin) / (yMax - yMin || 1)) * innerH;

  const linePath =
    'M ' +
    points
      .map((p) => `${xFor(p.ts).toFixed(2)},${yFor(p.value).toFixed(2)}`)
      .join(' L ');
  const areaPath =
    linePath +
    ` L ${(PAD_L + innerW).toFixed(2)},${(PAD_T + innerH).toFixed(2)}` +
    ` L ${PAD_L.toFixed(2)},${(PAD_T + innerH).toFixed(2)} Z`;

  // Y ticks at 0%, 25%, 50%, 75%, 100% (or proportional for non-percent).
  const yTicks = [0, 0.25, 0.5, 0.75, 1.0].map((f) => yMin + f * (yMax - yMin));
  // X ticks at start, middle, end.
  const xTicks = [xMin, xMin + xRange / 2, xMax];

  return (
    <ChartFrame title={title} svgViewBox={`0 0 ${VBW} ${height}`} height={height}>
      {/* Grid lines (horizontal only — keeps it quiet) */}
      {yTicks.map((tv, i) => (
        <line
          key={i}
          x1={PAD_L}
          y1={yFor(tv)}
          x2={PAD_L + innerW}
          y2={yFor(tv)}
          stroke="rgba(228,230,234,0.06)"
          strokeWidth={1}
        />
      ))}

      {/* Area + line */}
      <path d={areaPath} fill={SERIES_FILL} stroke="none" />
      <path d={linePath} fill="none" stroke={SERIES_LINE} strokeWidth={1.4} />

      {/* Y tick labels */}
      {yTicks.map((tv, i) => (
        <text
          key={`yl-${i}`}
          x={PAD_L - 8}
          y={yFor(tv) + 3}
          textAnchor="end"
          fontSize={9}
          fontFamily={MONO}
          fill={DIM}
        >
          {formatValue(tv, unit)}
        </text>
      ))}

      {/* X tick labels */}
      {xTicks.map((tx, i) => (
        <text
          key={`xl-${i}`}
          x={i === 0 ? PAD_L : i === 1 ? PAD_L + innerW / 2 : PAD_L + innerW}
          y={height - 6}
          textAnchor={i === 0 ? 'start' : i === 1 ? 'middle' : 'end'}
          fontSize={9}
          fontFamily={MONO}
          fill={DIM}
        >
          {formatTime(tx)}
        </text>
      ))}
    </ChartFrame>
  );
}

function ChartFrame({
  title,
  svgViewBox,
  height,
  children,
}: {
  title: string;
  svgViewBox: string;
  height: number;
  children: React.ReactNode;
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div
        style={{
          color: DIM,
          fontFamily: MONO,
          fontSize: 9,
          letterSpacing: '0.12em',
          paddingBottom: 4,
        }}
      >
        {title}
      </div>
      <svg
        viewBox={svgViewBox}
        preserveAspectRatio="none"
        style={{ width: '100%', height, display: 'block' }}
      >
        {children}
      </svg>
    </div>
  );
}

// autoMax returns a sensible y-axis ceiling for a series with unknown
// scale. Picks the next round number above the data max so the chart
// has headroom without empty space hogging the top half.
function autoMax(values: number[]): number {
  const peak = Math.max(...values);
  if (peak <= 0) return 1;
  // Round up to 1 sig fig: 0.84 → 1, 12 → 20, 154 → 200, 2.4G → 3G.
  const exp = Math.floor(Math.log10(peak));
  const mag = Math.pow(10, exp);
  const m = peak / mag;
  const stepped = m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10;
  return stepped * mag;
}

function formatValue(v: number, unit: 'percent' | 'bytes' | 'load'): string {
  switch (unit) {
    case 'percent':
      return `${Math.round(v)}%`;
    case 'bytes':
      return humanBytes(v);
    case 'load':
      return v.toFixed(2);
  }
}

function humanBytes(v: number): string {
  if (v < 1024) return `${Math.round(v)}B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)}K`;
  if (v < 1024 * 1024 * 1024) return `${(v / (1024 * 1024)).toFixed(1)}M`;
  return `${(v / (1024 * 1024 * 1024)).toFixed(1)}G`;
}

function formatTime(ms: number): string {
  const d = new Date(ms);
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  // If the window spans more than a day, include M/D — operators
  // looking at 24h want to know which day the dip happened on.
  const now = Date.now();
  if (now - ms > 12 * 60 * 60 * 1000) {
    return `${d.getMonth() + 1}/${d.getDate()} ${hh}:${mm}`;
  }
  return `${hh}:${mm}`;
}

