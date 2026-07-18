'use client';

// LogsTab — drawer Logs panel. Composed-form LogQL via /api/obs/logs:
// filters by container + grep, range from the page header. Renders
// the latest 200 entries (cap surfaced in the footer; Loki cap is
// 5000 if a power user hits the api directly).
//
// Per-node logs (Slice 1.2c): every node's collector ships its container logs
// through the mTLS ingress tagged node_id, so ?node= narrows to that node's
// lines. The container dropdown lists the node's running containers (from
// /api/obs/containers) unioned with whatever has logged in-range, so a
// running-but-quiet container is still selectable (it just shows no entries).
//
// No tail/streaming yet — the operator clicks Refetch or changes a
// filter to update. WebSocket tail can land in a future iteration.

import { useEffect, useMemo, useState } from 'react';
import { ExternalLink, RefreshCw, Search } from 'lucide-react';
import type { Node } from '../../lib/types';
import type { LogEntry, ObsContainer } from '../../lib/api';
import { getObsContainers, getObsLogs } from '../../lib/api';
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
  // The node's running containers, so the dropdown can offer a container even
  // when it hasn't logged in the current range. Best-effort: on failure we fall
  // back to the log-derived options below.
  const [running, setRunning] = useState<string[]>([]);

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

  // Fetch the node's running containers (cAdvisor-derived) so the dropdown
  // lists them regardless of whether they've logged in-range. Independent of
  // range/grep — the running set doesn't change with the log query.
  useEffect(() => {
    if (!obsEnabled) return;
    let cancelled = false;
    getObsContainers(node.id)
      .then((cs: ObsContainer[]) => {
        if (!cancelled) setRunning(cs.map((c) => c.name).filter(Boolean));
      })
      .catch(() => {
        if (!cancelled) setRunning([]); // best-effort; log-derived options still apply
      });
    return () => {
      cancelled = true;
    };
  }, [node.id, obsEnabled]);

  // Dropdown options = the node's running containers UNION whatever has logged
  // in the current range. The union keeps a running-but-quiet container
  // selectable (it shows "no entries") and still surfaces a container that has
  // logged but already exited.
  const containerOptions = useMemo(() => {
    const set = new Set<string>(running);
    for (const e of entries) if (e.container) set.add(e.container);
    return Array.from(set).sort();
  }, [entries, running]);

  const refetch = () => setDebouncedGrep((g) => g); // trigger effect

  if (!obsEnabled) {
    return (
      <Hint>
        Metrics &amp; logs are off, so logs aren&apos;t being collected. Turn them on in Settings.
      </Hint>
    );
  }

  const displayed = entries.slice(0, DISPLAY_CAP);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: '100%' }}>
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
