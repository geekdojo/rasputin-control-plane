'use client';

import {
  BarChart2,
  Bell,
  ClipboardList,
  Database,
  GitBranch,
  LayoutDashboard,
  LayoutGrid,
  Settings,
  ShieldAlert,
  Store,
  UserCog,
  Zap,
} from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import type { ElementType } from 'react';
import { ACCENT, accentA, MONO } from './ui-theme';

interface NavItem {
  icon: ElementType;
  label: string;
  href?: string; // omitted → section not built yet (rendered disabled)
}

// Primary nav. Items without an href are part of the design but not yet
// implemented — shown disabled so the shell matches the design without 404s.
const NAV: NavItem[] = [
  { icon: LayoutGrid, label: 'Nodes', href: '/' },
  { icon: LayoutDashboard, label: 'Apps', href: '/apps' },
  { icon: Store, label: 'App Catalog', href: '/app-catalog' },
  { icon: BarChart2, label: 'Metrics', href: '/metrics' },
  { icon: Database, label: 'Storage' },
  { icon: ShieldAlert, label: 'Firewall', href: '/firewall' },
  { icon: GitBranch, label: 'Mesh', href: '/mesh' },
  { icon: UserCog, label: 'IAM' },
  { icon: Zap, label: 'Updates', href: '/updates' },
  { icon: ClipboardList, label: 'Tasks', href: '/tasks' },
];

const BOTTOM: NavItem[] = [
  { icon: Bell, label: 'Alerts', href: '/alerts' },
  { icon: Settings, label: 'Settings', href: '/settings' },
];

function isActive(pathname: string, href?: string): boolean {
  if (!href) return false;
  if (href === '/') return pathname === '/';
  return pathname === href || pathname.startsWith(href + '/');
}

function NavButton({ item, active }: { item: NavItem; active: boolean }) {
  const enabled = Boolean(item.href);
  const Icon = item.icon;

  const base = {
    width: 48,
    height: 48,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: active ? accentA(0.12) : 'transparent',
    borderLeft: active ? `2px solid ${ACCENT}` : '2px solid transparent',
    borderTop: 'none',
    borderRight: 'none',
    borderBottom: 'none',
    cursor: enabled ? 'pointer' : 'not-allowed',
    opacity: enabled ? 1 : 0.35,
    transition: 'background 0.15s, border-color 0.15s',
  } as const;

  const color = active ? ACCENT : 'var(--rasp-dim)';

  const hoverOn = (el: HTMLElement) => {
    if (!active) el.style.background = 'rgba(var(--rasp-fg-rgb),0.06)';
  };
  const hoverOff = (el: HTMLElement) => {
    if (!active) el.style.background = 'transparent';
  };

  if (!enabled) {
    return (
      <div title={`${item.label} — coming soon`} style={base}>
        <Icon size={18} color={color} />
      </div>
    );
  }

  return (
    <Link
      href={item.href!}
      title={item.label}
      style={{ ...base, textDecoration: 'none' }}
      onMouseEnter={(e) => hoverOn(e.currentTarget)}
      onMouseLeave={(e) => hoverOff(e.currentTarget)}
    >
      <Icon size={18} color={color} />
    </Link>
  );
}

// hideFirewall drops the Firewall section entirely — set in "LAN peer" mode
// (setup.mode === 'lan_peer'), where the existing router firewalls and
// Rasputin has no firewall job, so WAN/rule/port-forward tabs would only
// invite configuration for a device that can't act on it.
export function SideNav({ hideFirewall = false }: { hideFirewall?: boolean }) {
  const pathname = usePathname() ?? '/';
  const nav = hideFirewall ? NAV.filter((item) => item.label !== 'Firewall') : NAV;

  return (
    <nav
      style={{
        width: 48,
        background: 'var(--rasp-bg)',
        borderRight: '1px solid rgba(var(--rasp-fg-rgb),0.18)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        paddingTop: 8,
        paddingBottom: 8,
        flexShrink: 0,
        fontFamily: MONO,
      }}
    >
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 2, width: '100%' }}>
        {nav.map((item) => (
          <NavButton key={item.label} item={item} active={isActive(pathname, item.href)} />
        ))}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 2, width: '100%' }}>
        {BOTTOM.map((item) => (
          <NavButton key={item.label} item={item} active={isActive(pathname, item.href)} />
        ))}
      </div>
    </nav>
  );
}
