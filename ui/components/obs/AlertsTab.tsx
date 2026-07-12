'use client';

// AlertsTab — drawer Alerts panel. Filters the GET /api/alerts snapshot
// down to entries that relate to this node (relatedKind="node" +
// relatedId=<node>) AND entries whose source is "node" carrying the
// node id in the title. Live via /ws/alerts so ack/dismiss + new fires
// land without a re-fetch.
//
// ack/dismiss only fires for source="rule" entries (vmalert-persisted).
// Aggregator-derived entries (the inventory/job/app/setup signals) carry
// their lifecycle in code — there's no concept of "acking" a stale node.

import { useEffect, useState } from 'react';
import { AlertTriangle, Bell, Box, CheckCircle2, Layers, Server, ShieldAlert, Wrench, X } from 'lucide-react';
import type { ElementType } from 'react';
import { ackAlert, dismissAlert, listAlerts, openAlertsWS } from '../../lib/api';
import type { Alert, AlertSeverity, AlertSource, Node } from '../../lib/types';
import { Btn, DIM, FG, HAIR_SOFT, Hint, PANEL } from '../kit';
import { MONO } from '../ui-theme';

interface AlertsTabProps {
  node: Node;
}

const CRIT_COLOR = '#f87171';
const WARN_COLOR = '#facc15';

const SOURCE_ICON: Record<AlertSource, ElementType> = {
  node: Server,
  job: Layers,
  app: Box,
  setup: Wrench,
  security: ShieldAlert,
  rule: Bell,
};

function severityColor(s: AlertSeverity): string {
  return s === 'crit' ? CRIT_COLOR : WARN_COLOR;
}
function severityLabel(s: AlertSeverity): string {
  return s === 'crit' ? 'CRIT' : 'WARN';
}

function isRelatedToNode(a: Alert, nodeId: string): boolean {
  // Strongest signal: relatedKind/relatedId pointing at this node.
  if (a.relatedKind === 'node' && a.relatedId === nodeId) return true;
  // Fallback for source=node entries the aggregator emits without
  // relatedKind set (legacy / inventory). Match on title containing
  // the id as a substring — bit fuzzy but covers the gap.
  if (a.source === 'node' && a.title.includes(nodeId)) return true;
  return false;
}

function timeAgo(iso: string): string {
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return '';
  const d = Math.max(0, Date.now() - t);
  const s = Math.floor(d / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export function AlertsTab({ node }: AlertsTabProps) {
  const [all, setAll] = useState<Alert[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [acting, setActing] = useState<Set<string>>(new Set());

  // Initial fetch + 15s backstop + WS push.
  useEffect(() => {
    let cancelled = false;
    const refresh = () => {
      listAlerts()
        .then((a) => {
          if (cancelled) return;
          setAll(a);
          setLoaded(true);
        })
        .catch(() => {
          if (cancelled) return;
          setLoaded(true);
        });
    };
    refresh();
    const close = openAlertsWS(() => refresh());
    const t = window.setInterval(refresh, 15_000);
    return () => {
      cancelled = true;
      close();
      window.clearInterval(t);
    };
  }, []);

  const filtered = all.filter((a) => isRelatedToNode(a, node.id));

  const mutate = async (id: string, fn: (id: string) => Promise<Alert>) => {
    setActing((s) => new Set(s).add(id));
    try {
      const updated = await fn(id);
      setAll((curr) => curr.map((a) => (a.id === id ? updated : a)));
    } catch {
      // Backend errors surface via the toast/log layer in a future
      // iteration; for now we just clear the spinner so the row is
      // actionable again.
    } finally {
      setActing((s) => {
        const next = new Set(s);
        next.delete(id);
        return next;
      });
    }
  };

  if (!loaded) {
    return (
      <Hint style={{ color: DIM }}>LOADING…</Hint>
    );
  }

  if (filtered.length === 0) {
    return (
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
        <CheckCircle2 size={18} color={DIM} />
        <span style={{ color: DIM, fontSize: 11, letterSpacing: '0.1em' }}>NO ACTIVE ALERTS</span>
        <Hint style={{ maxWidth: 360, textAlign: 'center' }}>
          Nothing in inventory, jobs, apps, or rules is currently flagging this node. Aggregator
          entries appear here when this node goes stale/offline; rule entries appear when vmalert
          fires a rule whose <code>nodeId</code> matches.
        </Hint>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {filtered.map((a) => {
        const Icon = SOURCE_ICON[a.source] ?? AlertTriangle;
        const sev = severityColor(a.severity);
        const isRule = a.source === 'rule';
        const isActing = acting.has(a.id);
        return (
          <div
            key={a.id}
            style={{
              display: 'grid',
              gridTemplateColumns: '52px 16px 1fr auto',
              gap: 12,
              alignItems: 'center',
              padding: '10px 12px',
              background: PANEL,
              border: `1px solid ${HAIR_SOFT}`,
              borderLeft: `2px solid ${sev}`,
              fontFamily: MONO,
              color: FG,
            }}
          >
            <span
              style={{
                color: sev,
                fontSize: 9,
                letterSpacing: '0.12em',
                textAlign: 'center',
                border: `1px solid ${sev}`,
                padding: '2px 0',
              }}
            >
              {severityLabel(a.severity)}
            </span>
            <Icon size={12} color={DIM} />
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
              <span
                style={{
                  fontSize: 11,
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {a.title}
                {a.acked && (
                  <span style={{ color: DIM, marginLeft: 8, fontSize: 9, letterSpacing: '0.1em' }}>
                    · ACKED
                  </span>
                )}
              </span>
              {a.detail && (
                <span
                  style={{
                    color: DIM,
                    fontSize: 10,
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {a.detail}
                </span>
              )}
            </div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                whiteSpace: 'nowrap',
              }}
            >
              <span style={{ color: DIM, fontSize: 10 }}>{timeAgo(a.since)}</span>
              {isRule && !a.acked && (
                <Btn
                  variant="ghost"
                  small
                  disabled={isActing}
                  onClick={() => mutate(a.id, ackAlert)}
                  title="Acknowledge — keeps the alert visible but quiets renotify"
                >
                  ACK
                </Btn>
              )}
              {isRule && (
                <Btn
                  variant="ghost"
                  small
                  disabled={isActing}
                  onClick={() => mutate(a.id, dismissAlert)}
                  title="Dismiss — drops the alert from the list until it re-fires"
                >
                  <X size={11} />
                </Btn>
              )}
            </div>
          </div>
        );
      })}
      <Hint style={{ marginTop: 4 }}>
        Aggregator-derived alerts (node/job/app/setup) clear automatically when the underlying
        condition goes away. Rule-derived alerts (source=rule) can be acked / dismissed.
      </Hint>
    </div>
  );
}

