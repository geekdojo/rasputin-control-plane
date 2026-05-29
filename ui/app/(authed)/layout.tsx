'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { getSetupState, listJobs, listNodes } from '../../lib/api';
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

  // Lightweight poll powering the TopBar cluster summary. The Nodes page keeps
  // its own live (WS) view; 15s is plenty for the header rollup.
  useEffect(() => {
    if (!user) return;
    const refresh = () => {
      listNodes().then(setNodes).catch(() => {});
      listJobs(100)
        .then((jobs) => setTasksRunning(jobs.filter((j) => j.status === 'running').length))
        .catch(() => {});
    };
    refresh();
    const t = setInterval(refresh, 15_000);
    return () => clearInterval(t);
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
