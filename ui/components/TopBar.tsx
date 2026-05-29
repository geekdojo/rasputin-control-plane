'use client';

import { AlertTriangle, CheckCircle, Clock, LogOut, Server } from 'lucide-react';
import { useEffect, useState } from 'react';
import type { ElementType } from 'react';
import { MONO } from './ui-theme';

interface TopBarProps {
  clusterName: string;
  nodesOnline: number;
  nodesTotal: number;
  alerts: number;
  tasksRunning: number;
  user?: string;
  onLogout?: () => void;
}

interface Stat {
  label: string;
  value: string;
  icon: ElementType;
  valueColor?: string;
}

export function TopBar({
  clusterName,
  nodesOnline,
  nodesTotal,
  alerts,
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
    {
      label: 'ALERTS',
      value: alerts > 0 ? `${alerts} WARN` : 'NONE',
      icon: AlertTriangle,
      valueColor: alerts > 0 ? '#facc15' : undefined,
    },
    { label: 'TASKS RUNNING', value: String(tasksRunning), icon: Clock },
  ];

  return (
    <header
      style={{
        background: '#07101f',
        borderBottom: '1px solid rgba(228,230,234,0.18)',
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
          borderRight: '1px solid rgba(228,230,234,0.18)',
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
            color: '#e4e6ea',
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
          return (
            <div
              key={s.label}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                paddingLeft: 16,
                paddingRight: 16,
                borderRight:
                  i < stats.length - 1 ? '1px solid rgba(228,230,234,0.12)' : 'none',
                flexShrink: 0,
              }}
            >
              <Icon size={12} color="#8a9bb5" />
              <span style={{ color: '#8a9bb5', fontSize: 10, letterSpacing: '0.08em' }}>
                {s.label}
              </span>
              <span
                style={{ color: s.valueColor ?? '#e4e6ea', fontSize: 11, letterSpacing: '0.04em' }}
              >
                {s.value}
              </span>
            </div>
          );
        })}
      </div>

      {/* Timestamp */}
      <span
        style={{
          color: '#8a9bb5',
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
            borderLeft: '1px solid rgba(228,230,234,0.18)',
            height: '100%',
          }}
        >
          <span
            style={{
              color: '#8a9bb5',
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
              border: '1px solid rgba(228,230,234,0.18)',
              color: '#8a9bb5',
              fontSize: 9,
              fontFamily: MONO,
              letterSpacing: '0.08em',
              cursor: 'pointer',
            }}
          >
            <LogOut size={11} color="#8a9bb5" />
            SIGN OUT
          </button>
        </div>
      )}
    </header>
  );
}
