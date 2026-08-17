'use client';

// ContainersTab — drawer Containers panel. Shows the cAdvisor-derived
// table from /api/obs/containers: name · image · cores · mem · started.
// Sorted by CPU descending so the noisiest container lands at the top.
//
// Source caveat (same as LogsTab): cAdvisor today only scrapes the
// controlplane host. Slice 1.2b adds per-node Alloy and the rows for
// non-controlplane nodes start populating without a UI change.

import { useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import type { Node } from '../../lib/types';
import type { ObsContainer } from '../../lib/api';
import { getObsContainers } from '../../lib/api';
import { Btn, DIM, FG, HAIR_SOFT, Hint, tdStyle, thStyle } from '../kit';
import { MONO } from '../ui-theme';

interface ContainersTabProps {
  node: Node;
  obsEnabled: boolean;
}

export function ContainersTab({ node, obsEnabled }: ContainersTabProps) {
  // refetchTick lets the manual REFETCH button retrigger the effect
  // without duplicating fetch logic into a second handler.
  const [refetchTick, setRefetchTick] = useState(0);
  const refetch = () => setRefetchTick((t) => t + 1);

  // One result object keyed by the request it answers, rather than separate
  // rows/loading/err. `loading` is then DERIVED — it is simply "the result we
  // hold is not the one the current inputs ask for" — which removes the
  // setLoading(true)/setErr(null) reset that used to run synchronously on
  // effect entry (react-hooks/set-state-in-effect). State is now only ever
  // written from a fetch continuation, which is what effects are for.
  const requestKey = `${node.id}|${refetchTick}`;
  const [result, setResult] = useState<{
    key: string;
    rows: ObsContainer[];
    err: string | null;
  }>({ key: '', rows: [], err: null });

  const loading = obsEnabled && result.key !== requestKey;
  const rows = result.key === requestKey ? result.rows : [];
  const err = result.key === requestKey ? result.err : null;

  useEffect(() => {
    if (!obsEnabled) return;
    let cancelled = false;
    getObsContainers(node.id)
      .then((rs) => {
        if (!cancelled) setResult({ key: requestKey, rows: rs, err: null });
      })
      .catch((e: Error) => {
        if (!cancelled) setResult({ key: requestKey, rows: [], err: e.message });
      });
    return () => {
      cancelled = true;
    };
  }, [node.id, obsEnabled, requestKey]);

  if (!obsEnabled) {
    return (
      <Hint>
        Metrics &amp; logs are off, so container activity isn&apos;t being collected. Turn them on in
        Settings.
      </Hint>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: '100%' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ color: DIM, fontFamily: MONO, fontSize: 9, letterSpacing: '0.08em' }}>
          {loading ? 'LOADING…' : `${rows.length} CONTAINER${rows.length === 1 ? '' : 'S'}`}
        </span>
        <Btn variant="ghost" small onClick={refetch} title="Refetch">
          <RefreshCw size={11} />
          REFETCH
        </Btn>
      </div>

      {err && <Hint warn>Couldn&apos;t reach /api/obs/containers: {err}</Hint>}

      <div style={{ overflowX: 'auto', overflowY: 'auto', flex: 1 }}>
        <table
          style={{
            width: '100%',
            borderCollapse: 'collapse',
            fontFamily: MONO,
            color: FG,
          }}
        >
          <thead>
            <tr>
              <th style={thStyle}>NAME</th>
              <th style={thStyle}>IMAGE</th>
              <th style={{ ...thStyle, textAlign: 'right' }}>CPU</th>
              <th style={{ ...thStyle, textAlign: 'right' }}>MEM</th>
              <th style={{ ...thStyle, textAlign: 'right' }}>STARTED</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && !loading && (
              <tr>
                <td colSpan={5} style={{ ...tdStyle, color: DIM, textAlign: 'center', padding: '24px 0' }}>
                  NO CONTAINERS REPORTING
                </td>
              </tr>
            )}
            {rows.map((c) => (
              <tr key={c.name} style={{ borderBottom: `1px solid ${HAIR_SOFT}` }}>
                <td style={tdStyle}>{c.name}</td>
                <td style={{ ...tdStyle, color: DIM, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {c.image}
                </td>
                <td style={{ ...tdStyle, textAlign: 'right' }}>{formatCores(c.cpuCores)}</td>
                <td style={{ ...tdStyle, textAlign: 'right' }}>{humanBytes(c.memBytes)}</td>
                <td style={{ ...tdStyle, textAlign: 'right', color: DIM }}>{startedAgo(c.restarts)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Hint style={{ color: DIM }}>
        CPU is a 1-minute average; 1.00 = one full core. STARTED is the container&apos;s last start
        time — a stand-in for a restart count, which isn&apos;t collected yet.
      </Hint>
    </div>
  );
}

function formatCores(n: number): string {
  if (n < 0.01) return '0.00';
  if (n < 1) return n.toFixed(2);
  return n.toFixed(2);
}

function humanBytes(v: number): string {
  if (v < 1024) return `${Math.round(v)} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1024 * 1024 * 1024) return `${(v / (1024 * 1024)).toFixed(1)} MB`;
  return `${(v / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function startedAgo(startEpoch: number): string {
  if (!startEpoch) return '—';
  const ms = Date.now() - startEpoch * 1000;
  if (ms < 0) return 'just now';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

