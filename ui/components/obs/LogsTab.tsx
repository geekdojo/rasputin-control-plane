'use client';

// LogsTab — drawer Logs panel. Composed-form LogQL via /api/obs/logs:
// filters by container + grep, range from the page header. Renders
// the latest 200 entries (cap surfaced in the footer; Loki cap is
// 5000 if a power user hits the api directly).
//
// Source caveat: today Loki only receives logs from the controlplane
// host's own containers (Slice 1.2b adds per-node Alloy). We always
// pass the drawer node as ?node= so the filter starts working the
// moment 1.2b lands; until then, all nodes see the same lines (a
// Hint at the top makes that explicit).
//
// No tail/streaming yet — the operator clicks Refetch or changes a
// filter to update. WebSocket tail can land in a future iteration.

import { useEffect, useMemo, useState } from 'react';
import { ExternalLink, RefreshCw, Search } from 'lucide-react';
import type { Node } from '../../lib/types';
import type { LogEntry } from '../../lib/api';
import { getObsLogs } from '../../lib/api';
import { Btn, DIM, FG, HAIR, Hint, Input, Select } from '../kit';
import { accentA, MONO } from '../ui-theme';

interface LogsTabProps {
  node: Node;
  range: string;
  obsEnabled: boolean;
  grafanaHref?: string;
}

const DISPLAY_CAP = 200;

export function LogsTab({ node, range, obsEnabled, grafanaHref }: LogsTabProps) {
  const [container, setContainer] = useState<string>('');
  const [grep, setGrep] = useState<string>('');
  // debouncedGrep keeps us from firing a Loki query on every keystroke
  // while the operator types a regex.
  const [debouncedGrep, setDebouncedGrep] = useState<string>('');
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // 350ms grep debounce
  useEffect(() => {
    const id = window.setTimeout(() => setDebouncedGrep(grep), 350);
    return () => window.clearTimeout(id);
  }, [grep]);

  // Fetch on (node, range, container, debouncedGrep) change.
  useEffect(() => {
    if (!obsEnabled) return;
    let cancelled = false;
    setLoading(true);
    setErr(null);
    getObsLogs({
      node: node.id,
      container: container || undefined,
      grep: debouncedGrep || undefined,
      range,
      limit: 500,
    })
      .then((es) => {
        if (cancelled) return;
        setEntries(es);
        setLoading(false);
      })
      .catch((e: Error) => {
        if (cancelled) return;
        setErr(e.message);
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [node.id, range, container, debouncedGrep, obsEnabled]);

  // Derive the container dropdown options from the latest response —
  // an extra label query would be cleaner but we'd need a separate
  // /api/obs/labels handler. Self-deriving keeps the dropdown current
  // without a backend roundtrip.
  const containerOptions = useMemo(() => {
    const set = new Set<string>();
    for (const e of entries) if (e.container) set.add(e.container);
    return Array.from(set).sort();
  }, [entries]);

  const refetch = () => setDebouncedGrep((g) => g); // trigger effect

  if (!obsEnabled) {
    return (
      <Hint>
        Observability is off. Set <code>RASPUTIN_OBS_ENABLED=1</code> and restart the api to enable
        log shipping (Loki + Alloy).
      </Hint>
    );
  }

  const displayed = entries.slice(0, DISPLAY_CAP);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: '100%' }}>
      <Hint>
        Loki currently sources logs from the controlplane host only. Slice 1.2b adds per-node Alloy
        deploy — the <code>node_id</code> filter is already wired and will start narrowing results
        the moment that ships.
      </Hint>

      {/* Filter row */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          padding: '8px 0',
          borderTop: `1px solid ${HAIR}`,
          borderBottom: `1px solid ${HAIR}`,
        }}
      >
        <Select
          value={container}
          onChange={(e) => setContainer(e.target.value)}
          style={{ padding: '4px 8px', fontSize: 9, letterSpacing: '0.06em', maxWidth: 180 }}
          aria-label="Filter by container"
        >
          <option value="">ALL CONTAINERS</option>
          {containerOptions.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </Select>
        <div style={{ position: 'relative', flex: 1 }}>
          <Search
            size={11}
            color={DIM}
            style={{ position: 'absolute', left: 8, top: 8, pointerEvents: 'none' }}
          />
          <Input
            value={grep}
            onChange={(e) => setGrep(e.target.value)}
            placeholder="grep (regex, case-insensitive)"
            style={{ paddingLeft: 26, width: '100%', fontSize: 10 }}
            aria-label="grep filter"
          />
        </div>
        <Btn variant="ghost" small onClick={refetch} title="Refetch">
          <RefreshCw size={11} />
          REFETCH
        </Btn>
      </div>

      {err && <Hint warn>Couldn&apos;t reach /api/obs/logs: {err}</Hint>}

      {/* Log list */}
      <div
        style={{
          flex: 1,
          minHeight: 200,
          overflowY: 'auto',
          background: '#0a1322',
          border: `1px solid ${HAIR}`,
          fontFamily: MONO,
          fontSize: 10,
        }}
      >
        {displayed.length === 0 && !loading && (
          <div style={{ padding: '20px 12px', color: DIM, textAlign: 'center' }}>
            {entries.length === 0 ? 'NO ENTRIES IN RANGE' : 'NO ENTRIES MATCH FILTER'}
          </div>
        )}
        {loading && displayed.length === 0 && (
          <div style={{ padding: '20px 12px', color: DIM, textAlign: 'center' }}>LOADING…</div>
        )}
        {displayed.map((e, i) => (
          <LogRow key={`${e.ts}-${i}`} entry={e} />
        ))}
      </div>

      {/* Footer counts + escape hatch */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          fontSize: 9,
          letterSpacing: '0.08em',
          color: DIM,
        }}
      >
        <span>
          {entries.length === 0
            ? `0 entries · range ${range}`
            : `${displayed.length} of ${entries.length} shown · range ${range}`}
        </span>
        {grafanaHref && (
          <a
            href={`${grafanaHref}&dataSource=Loki`}
            target="_blank"
            rel="noreferrer"
            style={{ marginLeft: 'auto', color: accentA(0.9), textDecoration: 'none' }}
          >
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              <ExternalLink size={10} />
              FULL SEARCH IN GRAFANA
            </span>
          </a>
        )}
      </div>
    </div>
  );
}

function LogRow({ entry }: { entry: LogEntry }) {
  // Color-code stderr lines so eyeball-grep works without a filter.
  const isErr = entry.stream === 'stderr';
  const t = new Date(entry.ts);
  const hh = String(t.getHours()).padStart(2, '0');
  const mm = String(t.getMinutes()).padStart(2, '0');
  const ss = String(t.getSeconds()).padStart(2, '0');
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '64px 140px 1fr',
        gap: 10,
        padding: '4px 10px',
        borderBottom: '1px solid rgba(var(--rasp-fg-rgb),0.04)',
        color: isErr ? '#f87171' : FG,
      }}
    >
      <span style={{ color: DIM }}>{`${hh}:${mm}:${ss}`}</span>
      <span style={{ color: DIM, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {entry.container || '—'}
      </span>
      <span style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{entry.line}</span>
    </div>
  );
}
