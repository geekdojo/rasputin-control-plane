'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  getSetupState,
  listAlerts,
  listJobs,
  listNodes,
  openInventoryWS,
  openJobsWS,
} from '../../lib/api';
import { getMe, logout, type CurrentUser } from '../../lib/auth';
import type { Alert, Node, SetupState } from '../../lib/types';
import { HudBackground } from '../../components/HudBackground';
import { SideNav } from '../../components/SideNav';
import { TopBar } from '../../components/TopBar';
import { ACCENT, accentA, MONO } from '../../components/ui-theme';

export default function AuthedLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname() ?? '/';
  const [user, setUser] = useState<CurrentUser | null | undefined>(undefined);
  const [setup, setSetup] = useState<SetupState | null>(null);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [tasksRunning, setTasksRunning] = useState(0);
  const [alerts, setAlerts] = useState<Alert[]>([]);

  useEffect(() => {
    getMe()
      .then((u) => {
        if (u === null) router.replace('/login');
        else setUser(u);
      })
      .catch(() => router.replace('/login'));
  }, [router]);

  // Re-fetched on every route change, not just layout mount: the App
  // Router keeps this layout alive across client-side navigations, so a
  // mount-only fetch left the "Finish setup" banner up after the operator
  // clicked Finish and was redirected to / (first Mu bench runs,
  // 2026-06-12). The state read is a tiny unauthenticated GET.
  useEffect(() => {
    getSetupState().then(setSetup).catch(() => {});
  }, [pathname]);

  // TopBar cluster summary:
  //   NODES ONLINE  — 15s poll; node status transitions are slow (heartbeat
  //                   threshold is 30s) so a faster poll wouldn't add signal.
  //   TASKS RUNNING — event-driven off /ws/jobs (most jobs finish sub-second
  //                   on the mock backend so polling alone made the badge
  //                   look dead). Incremental: +1 on 'started', -1 on
  //                   'succeeded' | 'failed'. step_* and log events ignored
  //                   to keep this O(jobs) not O(events).
  //   ALERTS        — sourced from /api/alerts so the count matches the
  //                   /alerts page exactly. Re-fetched on inventory + job
  //                   WS events (the upstream sources today). 15s backstop
  //                   poll absorbs missed events during WS reconnects.
  useEffect(() => {
    if (!user) return;

    const refreshNodes = () => {
      listNodes().then(setNodes).catch(() => {});
    };
    const refreshJobs = () => {
      listJobs(100)
        .then((jobs) => setTasksRunning(jobs.filter((j) => j.status === 'running').length))
        .catch(() => {});
    };
    const refreshAlerts = () => {
      listAlerts().then(setAlerts).catch(() => {});
    };

    refreshNodes();
    refreshJobs();
    refreshAlerts();

    const closeJobsWS = openJobsWS((ev) => {
      // 'created' is queued, not running — the matching 'started' bumps it.
      if (ev.type === 'started') setTasksRunning((n) => n + 1);
      else if (ev.type === 'succeeded' || ev.type === 'failed')
        setTasksRunning((n) => Math.max(0, n - 1));
      // Any job lifecycle event might add/clear an alert (e.g. a job-failed
      // alert appears on 'failed', not on 'started'). Re-fetch — alerts is
      // a small JSON response.
      if (ev.type === 'failed' || ev.type === 'succeeded' || ev.type === 'started') {
        refreshAlerts();
      }
    });

    const closeInvWS = openInventoryWS(() => {
      // Status transitions (online ↔ stale ↔ offline) flip node-source
      // alerts. Re-fetch both the local nodes view and the alerts count.
      refreshNodes();
      refreshAlerts();
    });

    const t = setInterval(() => {
      refreshNodes();
      refreshJobs();
      refreshAlerts();
    }, 15_000);

    return () => {
      closeJobsWS();
      closeInvWS();
      clearInterval(t);
    };
  }, [user]);

  if (user === undefined || user === null) {
    return (
      <div
        style={{
          height: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: 'var(--rasp-bg)',
          color: 'var(--rasp-dim)',
          fontFamily: MONO,
          fontSize: 12,
          letterSpacing: '0.08em',
        }}
      >
        LOADING…
      </div>
    );
  }

  async function handleLogout() {
    await logout();
    router.replace('/login');
  }

  const online = nodes.filter((n) => n.status === 'online').length;
  const alertsCrit = alerts.filter((a) => a.severity === 'crit').length;
  const alertsWarn = alerts.filter((a) => a.severity === 'warn').length;

  return (
    <div
      style={{
        height: '100vh',
        width: '100%',
        background: 'var(--rasp-bg)',
        display: 'flex',
        flexDirection: 'column',
        fontFamily: MONO,
        overflow: 'hidden',
      }}
    >
      <HudBackground />

      <div style={{ position: 'relative', zIndex: 1, flexShrink: 0 }}>
        <TopBar
          clusterName={setup?.installName ?? ''}
          nodesOnline={online}
          nodesTotal={nodes.length}
          alertsCrit={alertsCrit}
          alertsWarn={alertsWarn}
          tasksRunning={tasksRunning}
          user={user.displayName}
          onLogout={handleLogout}
        />
      </div>

      {setup && !setup.completed && pathname !== '/setup' && (
        <div
          style={{
            position: 'relative',
            zIndex: 1,
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '6px 16px',
            background: accentA(0.08),
            borderBottom: `1px solid ${accentA(0.3)}`,
            fontSize: 11,
            color: 'var(--rasp-fg)',
            flexShrink: 0,
          }}
        >
          <span>First-run setup isn&apos;t complete.</span>
          <Link href="/setup" style={{ color: ACCENT, textDecoration: 'none', letterSpacing: '0.06em' }}>
            FINISH SETUP →
          </Link>
        </div>
      )}

      <div style={{ position: 'relative', zIndex: 1, flex: 1, display: 'flex', overflow: 'hidden' }}>
        <SideNav hideFirewall={setup?.mode === 'lan_peer'} />
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {children}
        </div>
      </div>
    </div>
  );
}
