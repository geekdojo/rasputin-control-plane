'use client';

import { AlertTriangle, CheckCircle, Clock, LogOut, Server } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import type { ElementType } from 'react';
import { accentA, MONO } from './ui-theme';

interface TopBarProps {
  clusterName: string;
  nodesOnline: number;
  nodesTotal: number;
  alertsCrit: number;
  alertsWarn: number;
  tasksRunning: number;
  user?: string;
  onLogout?: () => void;
}

// Severity-aware label for the ALERTS stat. Honest: never says "WARN" when
// the underlying alert is critical.
function formatAlertsLabel(crit: number, warn: number): { value: string; color?: string } {
  if (crit === 0 && warn === 0) return { value: 'NONE' };
  if (crit > 0 && warn === 0) return { value: `${crit} CRIT`, color: '#f87171' };
  if (crit === 0 && warn > 0) return { value: `${warn} WARN`, color: '#facc15' };
  return { value: `${crit} CRIT · ${warn} WARN`, color: '#f87171' };
}

interface Stat {
  label: string;
  value: string;
  icon: ElementType;
  valueColor?: string;
  href?: string; // when set, the stat renders as a Link that routes there
}

export function TopBar({
  clusterName,
  nodesOnline,
  nodesTotal,
  alertsCrit,
  alertsWarn,
  tasksRunning,
  user,
  onLogout,
}: TopBarProps) {
  // Render the clock only after mount to avoid SSR/CSR hydration mismatch.
  const [time, setTime] = useState('');
  useEffect(() => {
    const tick = () => setTime(new Date().toUTCString().replace(' GMT', ' UTC'));
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);

  const allOnline = nodesTotal > 0 && nodesOnline === nodesTotal;
  const stats: Stat[] = [
    { label: 'CLUSTER', value: clusterName || 'RASPUTIN', icon: Server },
    {
      label: 'NODES ONLINE',
      value: `${nodesOnline} / ${nodesTotal}`,
      icon: CheckCircle,
      valueColor: allOnline ? undefined : '#facc15',
    },
    (() => {
      const a = formatAlertsLabel(alertsCrit, alertsWarn);
      return {
        label: 'ALERTS',
        value: a.value,
        icon: AlertTriangle,
        valueColor: a.color,
        // ALERTS routes to /alerts so the badge is no longer a dead end —
        // operators see what the count actually represents. TASKS RUNNING
        // links to /tasks for the same reason.
        href: '/alerts',
      };
    })(),
    { label: 'TASKS RUNNING', value: String(tasksRunning), icon: Clock, href: '/tasks' },
  ];

  return (
    <header
      style={{
        background: 'var(--rasp-bg)',
        borderBottom: '1px solid rgba(var(--rasp-fg-rgb),0.18)',
        display: 'flex',
        alignItems: 'center',
        height: 48,
        paddingLeft: 8,
        paddingRight: 16,
        flexShrink: 0,
        fontFamily: MONO,
      }}
    >
      {/* Cluster branding */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          paddingRight: 20,
          marginRight: 8,
          borderRight: '1px solid rgba(var(--rasp-fg-rgb),0.18)',
          height: '100%',
        }}
      >
        <div
          style={{
            width: 8,
            height: 8,
            borderRadius: '50%',
            background: '#4ade80',
            boxShadow: '0 0 6px #4ade80',
            flexShrink: 0,
          }}
        />
        <span
          style={{
            color: 'var(--rasp-fg)',
            letterSpacing: '0.1em',
            fontSize: 11,
            whiteSpace: 'nowrap',
          }}
        >
          RASPUTIN
        </span>
      </div>

      {/* Stats */}
      <div style={{ display: 'flex', alignItems: 'center', flex: 1, overflow: 'hidden' }}>
        {stats.map((s, i) => {
          const Icon = s.icon;
          const inner = (
            <>
              <Icon size={12} color="var(--rasp-dim)" />
              <span style={{ color: 'var(--rasp-dim)', fontSize: 10, letterSpacing: '0.08em' }}>
                {s.label}
              </span>
              <span
                style={{ color: s.valueColor ?? 'var(--rasp-fg)', fontSize: 11, letterSpacing: '0.04em' }}
              >
                {s.value}
              </span>
            </>
          );
          const baseStyle = {
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            paddingLeft: 16,
            paddingRight: 16,
            borderRight:
              i < stats.length - 1 ? '1px solid rgba(var(--rasp-fg-rgb),0.12)' : 'none',
            flexShrink: 0,
            height: '100%',
            textDecoration: 'none',
          } as const;
          if (s.href) {
            // Subtle accent-tint hover so the affordance reads as live.
            return (
              <Link
                key={s.label}
                href={s.href}
                style={{ ...baseStyle, cursor: 'pointer', transition: 'background 0.15s' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = accentA(0.06);
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = 'transparent';
                }}
              >
                {inner}
              </Link>
            );
          }
          return (
            <div key={s.label} style={baseStyle}>
              {inner}
            </div>
          );
        })}
      </div>

      {/* Timestamp */}
      <span
        style={{
          color: 'var(--rasp-dim)',
          fontSize: 10,
          letterSpacing: '0.06em',
          whiteSpace: 'nowrap',
          flexShrink: 0,
        }}
      >
        {time}
      </span>

      {/* User + sign out */}
      {user && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            marginLeft: 16,
            paddingLeft: 16,
            borderLeft: '1px solid rgba(var(--rasp-fg-rgb),0.18)',
            height: '100%',
          }}
        >
          <span
            style={{
              color: 'var(--rasp-dim)',
              fontSize: 10,
              letterSpacing: '0.04em',
              whiteSpace: 'nowrap',
            }}
          >
            {user}
          </span>
          <button
            onClick={onLogout}
            title="Sign out"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 5,
              padding: '4px 8px',
              background: 'transparent',
              border: '1px solid rgba(var(--rasp-fg-rgb),0.18)',
              color: 'var(--rasp-dim)',
              fontSize: 9,
              fontFamily: MONO,
              letterSpacing: '0.08em',
              cursor: 'pointer',
            }}
          >
            <LogOut size={11} color="var(--rasp-dim)" />
            SIGN OUT
          </button>
        </div>
      )}
    </header>
  );
}
