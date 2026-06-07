'use client';

// /metrics — operator-facing dashboard surface. The api owns the obs
// stack (VictoriaMetrics + Alloy + Loki + Grafana + vmalert) behind
// the auth-proxy at /observability/*; this page renders the embedded
// "Cluster Overview" dashboard when obs is enabled, or a setup CTA
// when RASPUTIN_OBS_ENABLED isn't set yet.
//
// We don't try to render PromQL directly here — Grafana already knows
// how to do that, and the iframe avoids re-implementing axes, time
// range pickers, etc. The trade-off is a heavier first-paint vs.
// a chart library — fine for an "open the detail view" workflow.

import { useEffect, useState } from 'react';
import { BarChart2, ExternalLink } from 'lucide-react';
import { getObsStatus } from '../../../lib/api';
import type { ObsStatus } from '../../../lib/types';
import { Btn, DIM, FG, Hint, PageBody, PageHeader, PageShell, PANEL, SectionLabel, Tok } from '../../../components/kit';
import { ACCENT, MONO } from '../../../components/ui-theme';

// The starter dashboard's UID is hard-coded in supervisor.go's
// `starterDashboardJSON` literal as "rasputin-cluster-overview". Linking
// directly to /d/<uid> opens to the dashboard view; without it, Grafana
// lands on its home page and the operator has to navigate.
const STARTER_DASHBOARD_PATH = '/observability/d/rasputin-cluster-overview?orgId=1&kiosk=tv';

// API_BASE mirrors lib/api.ts. In dev the UI runs on :3000 but the api
// (and the obs auth-proxy) is on :8080; the iframe needs the absolute
// URL there. In production both share the same origin and BASE is "".
const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? '';

export default function MetricsPage() {
  const [status, setStatus] = useState<ObsStatus | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const refresh = () => {
      getObsStatus()
        .then((s) => {
          if (!cancelled) {
            setStatus(s);
            setErr(null);
          }
        })
        .catch((e: Error) => {
          if (!cancelled) {
            setErr(e.message);
          }
        });
    };
    refresh();
    // Light backstop poll — once obs is healthy the iframe takes over
    // and the operator interacts with it directly. 30 s catches a
    // transient "enabling obs now" state without spamming the api.
    const id = window.setInterval(refresh, 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  return (
    <PageShell>
      <PageHeader
        icon={BarChart2}
        title="METRICS"
        right={
          status?.enabled && status?.grafanaUrl ? (
            <a
              href={`${API_BASE}${STARTER_DASHBOARD_PATH}`}
              target="_blank"
              rel="noreferrer"
              style={{ textDecoration: 'none' }}
            >
              <Btn variant="ghost" small>
                <ExternalLink size={11} />
                OPEN IN GRAFANA
              </Btn>
            </a>
          ) : null
        }
      />
      <PageBody style={{ padding: 0, display: 'flex', flexDirection: 'column' }}>
        {err && !status && (
          <div style={{ padding: '16px 20px' }}>
            <Hint warn>Couldn&apos;t reach /api/obs/status: {err}</Hint>
          </div>
        )}
        {status && !status.enabled && <DisabledPanel />}
        {status?.enabled && !status.healthy && <UnhealthyPanel status={status} />}
        {status?.enabled && status.healthy && status.grafanaUrl && (
          <iframe
            src={`${API_BASE}${STARTER_DASHBOARD_PATH}`}
            title="Cluster Overview"
            style={{ flex: 1, width: '100%', border: 'none', background: PANEL }}
          />
        )}
      </PageBody>
    </PageShell>
  );
}

// DisabledPanel — RASPUTIN_OBS_ENABLED wasn't set at api startup. We
// can't enable it for them from the UI (env vars are process-scoped);
// the right move is to surface the steps clearly so they don't think
// it's a UI bug.
function DisabledPanel() {
  return (
    <div style={{ padding: '20px 24px', maxWidth: 680 }}>
      <SectionLabel>OBSERVABILITY IS OFF</SectionLabel>
      <Hint style={{ marginBottom: 12 }}>
        Tier 2 observability (VictoriaMetrics + Alloy + Loki + Grafana + vmalert) isn&apos;t enabled on
        this control-plane. Tier 1 metrics — the sparklines on the Nodes page — keep working without
        it.
      </Hint>
      <Hint style={{ marginBottom: 12 }}>To turn it on, set the env var and restart the api:</Hint>
      <pre
        style={{
          background: PANEL,
          border: `1px solid rgba(228,230,234,0.2)`,
          padding: 12,
          color: FG,
          fontFamily: MONO,
          fontSize: 10,
          lineHeight: 1.6,
          margin: 0,
        }}
      >
{`RASPUTIN_OBS_ENABLED=1 \\
  ./rasputin-api`}
      </pre>
      <Hint style={{ marginTop: 12 }}>
        On first start the stack pulls ~500 MB of images (VM, Alloy, Loki, Grafana, vmalert). Subsequent
        starts are fast. Optional toggles: <Tok>RASPUTIN_OBS_LOKI=0</Tok> /{' '}
        <Tok>RASPUTIN_OBS_GRAFANA=0</Tok> / <Tok>RASPUTIN_OBS_VMALERT=0</Tok> turn off individual
        services.
      </Hint>
      <Hint style={{ marginTop: 12, color: DIM }}>
        Full design: <Tok>projects/rasputin/design/control-plane/observability-stack.md</Tok>.
      </Hint>
    </div>
  );
}

// UnhealthyPanel — obs is enabled but the supervisor's health probe
// isn't 2xx yet. Most common during first-boot when VM and Loki are
// warming up (~30-60 s); operators see this briefly then the iframe
// takes over.
function UnhealthyPanel({ status }: { status: ObsStatus }) {
  return (
    <div style={{ padding: '20px 24px', maxWidth: 680 }}>
      <SectionLabel>OBSERVABILITY STARTING UP</SectionLabel>
      <Hint style={{ marginBottom: 12 }}>
        The obs stack is enabled but Grafana isn&apos;t answering its health probe yet. On a fresh
        install this is normal for ~60 seconds while VictoriaMetrics and Loki finish their TSDB
        bootstraps. This page will switch to the dashboard automatically.
      </Hint>
      {status.lastError && (
        <Hint warn>
          Last write error: <Tok>{status.lastError}</Tok>
        </Hint>
      )}
    </div>
  );
}
