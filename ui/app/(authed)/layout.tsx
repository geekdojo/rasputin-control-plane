'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import Link from 'next/link';
import { getSetupState } from '../../lib/api';
import { getMe, logout, type CurrentUser } from '../../lib/auth';
import type { SetupState } from '../../lib/types';

// Tabs in display order. Adding a new section: drop a new route under
// app/(authed)/<name>/page.tsx and add an entry here.
const TABS: Array<{ href: string; label: string }> = [
  { href: '/', label: 'Nodes' },
  { href: '/apps', label: 'Apps' },
  { href: '/firewall', label: 'Firewall' },
  { href: '/mesh', label: 'Mesh' },
  { href: '/updates', label: 'Updates' },
  { href: '/tasks', label: 'Tasks' },
];

export default function AuthedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const [user, setUser] = useState<CurrentUser | null | undefined>(undefined);
  const [setup, setSetup] = useState<SetupState | null>(null);

  useEffect(() => {
    getMe()
      .then((u) => {
        if (u === null) router.replace('/login');
        else setUser(u);
      })
      .catch(() => router.replace('/login'));
  }, [router]);

  // Setup state drives the banner. Fetched alongside auth; refetched only
  // on full page loads (the wizard's own page does its own refreshes).
  useEffect(() => {
    getSetupState().then(setSetup).catch(() => {});
  }, []);

  if (user === undefined || user === null) {
    return (
      <main>
        <p className="hint">Loading…</p>
      </main>
    );
  }

  async function handleLogout() {
    await logout();
    router.replace('/login');
  }

  return (
    <main>
      <header className="with-user">
        <div>
          <h1>Rasputin</h1>
          <p className="sub">Control plane · local dev</p>
        </div>
        <div className="user-pill">
          <span>
            signed in as <strong>{user.displayName}</strong>
          </span>
          <button type="button" onClick={handleLogout}>
            sign out
          </button>
        </div>
      </header>

      <nav className="tabs" aria-label="Sections">
        {TABS.map((t) => (
          <Link
            key={t.href}
            href={t.href}
            className={pathname === t.href ? 'active' : ''}
          >
            {t.label}
          </Link>
        ))}
      </nav>

      {setup && !setup.completed && pathname !== '/setup' && (
        <div className="setup-banner">
          <span>First-run setup isn&apos;t complete.</span>
          <Link href="/setup">Finish setup →</Link>
        </div>
      )}

      {children}
    </main>
  );
}
