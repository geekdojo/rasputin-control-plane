'use client';

// IDSAlertsTab — drawer panel for snort3 alerts from a firewall node.
// Queries Loki via /api/obs/logs with a raw LogQL selector pinned to
// {job="rasputin-ids", node_id=<this node>}; each log line is the JSON
// the api's ids.Writer appended (see api/internal/ids/writer.go).
//
// Only rendered when the drawer's node has role="firewall" (the
// NodeDetailDrawer gates the tab visibility). On other roles snort
// doesn't run and Loki has no matching entries — there's nothing to show.

import { useEffect, useState } from 'react';
import { RefreshCw, ShieldAlert } from 'lucide-react';
import { getObsLogs } from '../../lib/api';
import type { LogEntry } from '../../lib/api';
import type { Node } from '../../lib/types';
import { Btn, DIM, FG, HAIR, HAIR_SOFT, Hint, PANEL } from '../kit';
import { accentA, MONO } from '../ui-theme';

interface IDSAlertsTabProps {
  node: Node;
  range: string;
  obsEnabled: boolean;
}

// IDSAlertRow is the JSON shape proto.IDSAlertEvt round-trips into.
// Re-declared locally instead of imported from proto-gen so this tab
// has zero coupling to the agent's wire types (a future minor wire
// change can keep the UI rendering until the new fields matter).
interface IDSAlertRow {
  ts: string;
  nodeId: string;
  gid: number;
  sid: number;
  rev: number;
  priority: number;
  protocol: string;
  srcAddr: string;
  srcPort?: number;
  dstAddr: string;
  dstPort?: number;
  classification: string;
  message: string;
  raw?: string;
}

const PAGE_CAP = 200;

// Priority → accent color. snort's priorities are 1 (highest, e.g.
// known exploit) → 4 (lowest, e.g. policy). Anything missing/0 is
// shown muted.
const PRIORITY_COLOR: Record<number, string> = {
  1: '#f87171', // crit-leaning
  2: '#fb923c',
  3: '#facc15',
  4: '#a1a1aa',
};

function priColor(p: number): string {
  return PRIORITY_COLOR[p] ?? DIM;
}

function addrPort(addr: string, port?: number): string {
  return port ? `${addr}:${port}` : addr;
}

function fmtTime(iso: string): string {
  const t = new Date(iso);
  if (!Number.isFinite(t.getTime())) return iso;
  return t.toLocaleTimeString(undefined, { hour12: false });
}

function parseRow(entry: LogEntry): IDSAlertRow | null {
  try {
    return JSON.parse(entry.line) as IDSAlertRow;
  } catch {
    return null;
  }
}

export function IDSAlertsTab({ node, range, obsEnabled }: IDSAlertsTabProps) {
  const [rows, setRows] = useState<IDSAlertRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (!obsEnabled) return;
    let cancelled = false;
    setLoading(true);
    setErr(null);
    // Raw LogQL — composed-form filters don't have a "job" param, so
    // we hand the api a literal selector. Backticks would be wrong
    // here: LogQL selectors are wrapped in double-quotes inside the
    // URL-encoded query string.
    const query = `{job="rasputin-ids",node_id="${node.id}"}`;
    getObsLogs({ query, range, limit: PAGE_CAP * 2 })
      .then((entries) => {
        if (cancelled) return;
        const parsed: IDSAlertRow[] = [];
        for (const e of entries) {
          const row = parseRow(e);
          if (row) parsed.push(row);
        }
        setRows(parsed.slice(0, PAGE_CAP));
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
  }, [node.id, range, obsEnabled, tick]);

  if (!obsEnabled) {
    return (
      <Hint style={{ color: DIM }}>
        Observability is off (RASPUTIN_OBS_ENABLED != 1). IDS alerts are written to the
        controlplane disk regardless, but the UI panel needs Loki + the api log-shim to
        surface them.
      </Hint>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minHeight: 0 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ color: DIM, fontSize: 10, letterSpacing: '0.1em', fontFamily: MONO }}>
          SNORT3 / ET OPEN · {rows.length} ALERTS
        </span>
        <span style={{ flex: 1 }} />
        <Btn variant="ghost" small onClick={() => setTick((n) => n + 1)} disabled={loading}>
          <RefreshCw size={11} />
          REFRESH
        </Btn>
      </div>

      {loading && <Hint style={{ color: DIM }}>LOADING…</Hint>}

      {!loading && err && (
        <Hint style={{ color: '#f87171' }}>
          /api/obs/logs failed: {err}. Likely Loki is not yet up (check /api/obs/status) or
          the api / Alloy hasn't finished plumbing the IDS pipe.
        </Hint>
      )}

      {!loading && !err && rows.length === 0 && (
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '40px 16px',
            gap: 10,
          }}
        >
          <ShieldAlert size={18} color={DIM} />
          <span style={{ color: DIM, fontSize: 11, letterSpacing: '0.1em' }}>
            NO ALERTS IN RANGE
          </span>
          <Hint style={{ maxWidth: 360, textAlign: 'center' }}>
            snort3 hasn't matched any ET Open signature on this firewall in the selected
            range. Generate a known-signature hit (e.g. <code>curl http://testmynids.org/uid/index.html</code>{' '}
            from a LAN client) to verify the pipeline end-to-end.
          </Hint>
        </div>
      )}

      {!loading && !err && rows.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minHeight: 0, overflowY: 'auto' }}>
          {rows.map((r, i) => (
            <div
              key={`${r.ts}-${r.sid}-${i}`}
              style={{
                display: 'grid',
                gridTemplateColumns: '74px 36px 1fr',
                gap: 10,
                alignItems: 'baseline',
                padding: '8px 10px',
                background: PANEL,
                border: `1px solid ${HAIR_SOFT}`,
                borderLeft: `2px solid ${priColor(r.priority)}`,
                fontFamily: MONO,
                color: FG,
                fontSize: 10,
              }}
            >
              <span style={{ color: DIM, fontSize: 9, letterSpacing: '0.05em' }}>
                {fmtTime(r.ts)}
              </span>
              <span
                style={{
                  color: priColor(r.priority),
                  fontSize: 9,
                  letterSpacing: '0.1em',
                  textAlign: 'center',
                  border: `1px solid ${priColor(r.priority)}`,
                  padding: '1px 0',
                }}
                title={`Priority ${r.priority} (1=highest, 4=lowest)`}
              >
                P{r.priority || '-'}
              </span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                <span
                  style={{
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                  title={r.message}
                >
                  {r.message || '(no message)'}
                </span>
                <span style={{ color: DIM, fontSize: 9 }}>
                  {r.protocol} {addrPort(r.srcAddr, r.srcPort)} → {addrPort(r.dstAddr, r.dstPort)}
                  {r.classification && (
                    <>
                      {' · '}
                      <span style={{ color: accentA(0.7) }}>{r.classification}</span>
                    </>
                  )}
                  {r.sid > 0 && (
                    <span style={{ color: DIM, marginLeft: 8 }}>
                      sid={r.gid}:{r.sid}:{r.rev}
                    </span>
                  )}
                </span>
              </div>
            </div>
          ))}
          {rows.length === PAGE_CAP && (
            <Hint style={{ marginTop: 4 }}>
              Showing the most recent {PAGE_CAP} alerts. Adjust the range selector for
              earlier windows, or query Loki directly via /api/obs/logs with a wider limit.
            </Hint>
          )}
        </div>
      )}
    </div>
  );
}
