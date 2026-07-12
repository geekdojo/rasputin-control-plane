'use client';

// /alerts — the destination for the TopBar ALERTS badge and the sidebar
// Bell icon. Shows the snapshot returned by GET /api/alerts: server-side
// aggregator of "current concerns" (offline/stale nodes, recently-failed
// jobs, apps in failed state, setup incomplete).
//
// Live updates use the same pattern as the TopBar count: re-fetch on
// inventory + job WS events (those are the upstream sources), with a 15 s
// backstop poll. No /ws/alerts yet — the real subsystem will add one.

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { AlertTriangle, Bell, Box, Layers, RefreshCw, Server, ShieldAlert, Wrench } from 'lucide-react';
import type { ElementType } from 'react';
import { listAlerts, openInventoryWS, openJobsWS } from '../../../lib/api';
import type { Alert, AlertSeverity, AlertSource } from '../../../lib/types';
import { PageShell, PageHeader, PageBody, Hint, DIM, FG, HAIR, HAIR_SOFT, PANEL } from '../../../components/kit';
import { accentA, MONO } from '../../../components/ui-theme';

const CRIT_COLOR = '#f87171';
const WARN_COLOR = '#facc15';

function severityColor(s: AlertSeverity): string {
  return s === 'crit' ? CRIT_COLOR : WARN_COLOR;
}

function severityLabel(s: AlertSeverity): string {
  return s === 'crit' ? 'CRIT' : 'WARN';
}

const SOURCE_ICON: Record<AlertSource, ElementType> = {
  node: Server,
  job: Layers,
  app: Box,
  setup: Wrench,
  security: ShieldAlert,
  // 'rule' = vmalert-fired (Slice 1.5). Bell distinguishes it from
  // aggregator-derived sources.
  rule: Bell,
};

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
  const dd = Math.floor(h / 24);
  return `${dd}d ago`;
}

function drillthroughPath(a: Alert): string | null {
  if (!a.relatedKind || !a.relatedId) {
    if (a.source === 'setup') return '/setup';
    return null;
  }
  switch (a.relatedKind) {
    case 'node':
      // The Nodes page reads ?select= to preselect a hex.
      return `/?select=${encodeURIComponent(a.relatedId)}`;
    case 'job':
      return `/tasks?id=${encodeURIComponent(a.relatedId)}`;
    case 'app':
      return `/apps?id=${encodeURIComponent(a.relatedId)}`;
    default:
      return null;
  }
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const refresh = () => {
      listAlerts()
        .then((a) => {
          if (cancelled) return;
          setAlerts(a);
          setLoaded(true);
        })
        .catch(() => {
          if (cancelled) return;
          setLoaded(true);
        });
    };
    refresh();
    const closeInv = openInventoryWS(() => refresh());
    const closeJobs = openJobsWS(() => refresh());
    const t = setInterval(refresh, 15_000);
    return () => {
      cancelled = true;
      closeInv();
      closeJobs();
      clearInterval(t);
    };
  }, []);

  const counts = useMemo(() => {
    let crit = 0;
    let warn = 0;
    for (const a of alerts) {
      if (a.severity === 'crit') crit++;
      else warn++;
    }
    return { crit, warn };
  }, [alerts]);

  return (
    <PageShell>
      <PageHeader
        icon={Bell}
        title="ALERTS"
        right={
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <span style={{ color: DIM, fontSize: 10, letterSpacing: '0.08em' }}>
              <span style={{ color: CRIT_COLOR }}>{counts.crit}</span> CRIT &nbsp;·&nbsp;
              <span style={{ color: WARN_COLOR }}>{counts.warn}</span> WARN
            </span>
          </div>
        }
      />
      <PageBody>
        {!loaded ? (
          <Hint>LOADING…</Hint>
        ) : alerts.length === 0 ? (
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '64px 16px',
              gap: 12,
            }}
          >
            <AlertTriangle size={18} color={DIM} />
            <span style={{ color: DIM, fontSize: 11, letterSpacing: '0.08em' }}>
              NO ACTIVE ALERTS
            </span>
            <Hint style={{ maxWidth: 360, textAlign: 'center' }}>
              Nothing in inventory, jobs, apps, or setup state is currently flagged. New concerns
              appear here as the system detects them.
            </Hint>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {alerts.map((a) => {
              const SourceIcon = SOURCE_ICON[a.source] ?? AlertTriangle;
              const sev = severityColor(a.severity);
              const path = drillthroughPath(a);
              const rowStyle = {
                display: 'grid',
                gridTemplateColumns: '60px 16px 1fr auto',
                gap: 12,
                alignItems: 'center',
                padding: '10px 14px',
                background: PANEL,
                border: `1px solid ${HAIR_SOFT}`,
                borderLeft: `2px solid ${sev}`,
                cursor: path ? 'pointer' : 'default',
                textDecoration: 'none',
                color: 'inherit',
                transition: 'background 0.15s, border-color 0.15s',
              } as const;
              const onEnter = (e: React.MouseEvent<HTMLElement>) => {
                if (path) {
                  e.currentTarget.style.background = accentA(0.04);
                  e.currentTarget.style.borderColor = HAIR;
                }
              };
              const onLeave = (e: React.MouseEvent<HTMLElement>) => {
                if (path) {
                  e.currentTarget.style.background = PANEL;
                  e.currentTarget.style.borderColor = HAIR_SOFT;
                  e.currentTarget.style.borderLeftColor = sev;
                }
              };
              const inner = (
                <>
                  {/* Severity pill */}
                  <span
                    style={{
                      color: sev,
                      fontSize: 9,
                      fontFamily: MONO,
                      letterSpacing: '0.1em',
                      textAlign: 'center',
                      border: `1px solid ${sev}`,
                      padding: '2px 0',
                    }}
                  >
                    {severityLabel(a.severity)}
                  </span>
                  <SourceIcon size={12} color={DIM} />
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                    <span
                      style={{
                        color: FG,
                        fontSize: 11,
                        fontFamily: MONO,
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                      }}
                    >
                      {a.title}
                    </span>
                    {a.detail && (
                      <span
                        style={{
                          color: DIM,
                          fontSize: 10,
                          fontFamily: MONO,
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        {a.detail}
                      </span>
                    )}
                  </div>
                  <span
                    style={{
                      color: DIM,
                      fontSize: 10,
                      fontFamily: MONO,
                      letterSpacing: '0.04em',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {timeAgo(a.since)}
                  </span>
                </>
              );
              if (path) {
                return (
                  <Link
                    key={a.id}
                    href={path}
                    style={rowStyle}
                    onMouseEnter={onEnter}
                    onMouseLeave={onLeave}
                  >
                    {inner}
                  </Link>
                );
              }
              return (
                <div key={a.id} style={rowStyle}>
                  {inner}
                </div>
              );
            })}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, paddingTop: 12, color: DIM }}>
              <RefreshCw size={10} />
              <span style={{ fontSize: 9, letterSpacing: '0.08em' }}>
                LIVE — REFRESHES ON INVENTORY + JOB EVENTS
              </span>
            </div>
          </div>
        )}
      </PageBody>
    </PageShell>
  );
}
