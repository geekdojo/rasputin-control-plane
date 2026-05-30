'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { getSetupState, listJobs, listNodes, openJobsWS } from '../../lib/api';
import { getMe, logout, type CurrentUser } from '../../lib/auth';
import type { Node, SetupState } from '../../lib/types';
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

  useEffect(() => {
    getMe()
      .then((u) => {
        if (u === null) router.replace('/login');
        else setUser(u);
      })
      .catch(() => router.replace('/login'));
  }, [router]);

  useEffect(() => {
    getSetupState().then(setSetup).catch(() => {});
  }, []);

  // TopBar cluster summary — NODES ONLINE polls every 15s, TASKS RUNNING is
  // event-driven off /ws/jobs.
  //
  // We were polling tasksRunning at 15s too, but most jobs (BMC ack, ping,
  // reboot dispatch) complete in under a second on the mock backend; the
  // badge sat at 0 forever because every job was already gone by the next
  // tick. Now we seed from a single listJobs call, then incrementally adjust
  // on lifecycle events (step_* and log events are ignored to keep this
  // O(jobs) not O(events)). The 15s poll stays as a drift-correction backstop
  // so a missed event during a WS reconnect doesn't leave a stale count.
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

    refreshNodes();
    refreshJobs();

    const closeWS = openJobsWS((ev) => {
      // 'created' is queued, not running — the matching 'started' bumps it.
      if (ev.type === 'started') setTasksRunning((n) => n + 1);
      else if (ev.type === 'succeeded' || ev.type === 'failed')
        setTasksRunning((n) => Math.max(0, n - 1));
    });

    const t = setInterval(() => {
      refreshNodes();
      refreshJobs();
    }, 15_000);

    return () => {
      closeWS();
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
          background: '#07101f',
          color: '#8a9bb5',
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
  const alerts = nodes.filter((n) => n.status === 'stale' || n.status === 'offline').length;

  return (
    <div
      style={{
        height: '100vh',
        width: '100%',
        background: '#07101f',
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
          alerts={alerts}
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
            color: '#e4e6ea',
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
        <SideNav />
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {children}
        </div>
      </div>
    </div>
  );
}
