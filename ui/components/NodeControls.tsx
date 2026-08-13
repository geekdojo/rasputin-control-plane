'use client';

import {
  Activity,
  AlertTriangle,
  ChevronRight,
  ExternalLink,
  FileText,
  Info,
  Layers,
  Package,
  Power,
  RefreshCw,
  RotateCcw,
  Terminal,
  Trash2,
  Upload,
  X,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import type { CSSProperties, ElementType } from 'react';
import {
  bmcPower,
  createJob,
  deleteNode,
  getBMCStatus,
  getNodeRemovalImpact,
  openBMCWS,
  type NodeRemovalImpact,
} from '../lib/api';
import type { App, BMCPowerState, DeploymentMode, Node } from '../lib/types';
import { appAccess, preferredAppUrl } from '../lib/appurl';
import { BMC_CAP_CONSOLE, BMC_CAP_POWER, BMC_CAP_RESET, type BmcCaps } from '../lib/bmc';
import { configFaults } from '../lib/configFaults';
import { ConfirmModal } from './ConfirmModal';
import { ACCENT, accentA, MONO, STATUS_COLOR } from './ui-theme';

// Compact IEC size for the STORAGE row, e.g. 110.3G / 512M. One decimal at
// G and up, whole numbers below — matches how df renders on the appliance.
function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '—';
  const units = ['B', 'K', 'M', 'G', 'T'];
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  return `${u >= 3 ? v.toFixed(1) : Math.round(v)}${units[u]}`;
}

interface NodeControlsProps {
  node: Node | null;
  cpu: number | null;
  mem: number | null;
  apps: App[];
  // Cluster id → the app-access hostname each deployed-app row links to.
  clusterId: string;
  deploymentMode?: DeploymentMode;
  // Per-node BMC gate (lib/bmc.ts): true iff some registered BMC host
  // advertises this node in its bmc-targets list.
  bmcCaps?: BmcCaps;
  onNavigate: (path: string) => void;
  onRemoved?: (id: string) => void;
}

function CtrlButton({
  icon: Icon,
  label,
  variant = 'default',
  disabled = false,
  onClick,
}: {
  icon: ElementType;
  label: string;
  variant?: 'default' | 'danger' | 'accent';
  disabled?: boolean;
  onClick?: () => void;
}) {
  const [hovered, setHovered] = useState(false);
  const colors = {
    default: { border: 'rgba(var(--rasp-fg-rgb),0.22)', bg: 'rgba(var(--rasp-fg-rgb),0.04)', hover: 'rgba(var(--rasp-fg-rgb),0.1)', text: 'var(--rasp-fg)' },
    danger: { border: 'rgba(192,57,43,0.5)', bg: 'rgba(192,57,43,0.07)', hover: 'rgba(192,57,43,0.15)', text: '#f87171' },
    accent: { border: accentA(0.4), bg: accentA(0.07), hover: accentA(0.15), text: ACCENT },
  }[variant];

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: '8px 12px',
        border: `1px solid ${colors.border}`,
        background: hovered && !disabled ? colors.hover : colors.bg,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.4 : 1,
        transition: 'background 0.15s',
        width: '100%',
      }}
    >
      <Icon size={13} color={colors.text} />
      <span style={{ color: colors.text, fontSize: 11, fontFamily: MONO, letterSpacing: '0.06em' }}>{label}</span>
      <ChevronRight size={11} color={colors.text} style={{ marginLeft: 'auto', opacity: 0.5 }} />
    </button>
  );
}

function StatBar({ label, value, color = 'var(--rasp-fg)' }: { label: string; value: number | null; color?: string }) {
  const pct = value == null ? 0 : Math.min(Math.max(value, 0), 100);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
        <span style={{ color: 'var(--rasp-dim)', fontSize: 10, fontFamily: MONO, letterSpacing: '0.06em' }}>{label}</span>
        <span style={{ color: 'var(--rasp-fg)', fontSize: 10, fontFamily: MONO }}>{value == null ? '—' : `${Math.round(value)}%`}</span>
      </div>
      <div style={{ height: 3, background: 'rgba(var(--rasp-fg-rgb),0.1)', width: '100%' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color, transition: 'width 0.3s' }} />
      </div>
    </div>
  );
}

function PowerButton({ state, disabled, onClick }: { state: BMCPowerState; disabled: boolean; onClick: () => void }) {
  const [hovered, setHovered] = useState(false);
  const on = { border: 'rgba(74,222,128,0.4)', bg: 'rgba(74,222,128,0.07)', hover: 'rgba(74,222,128,0.14)', text: '#4ade80' };
  const off = { border: 'rgba(148,163,184,0.3)', bg: 'rgba(148,163,184,0.04)', hover: 'rgba(148,163,184,0.09)', text: '#94a3b8' };
  const colors = state === 'on' ? on : off;
  const label = state === 'unknown' ? '— —' : state.toUpperCase();

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: '8px 12px',
        border: `1px solid ${colors.border}`,
        background: hovered && !disabled ? colors.hover : colors.bg,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.4 : 1,
        transition: 'background 0.15s',
        width: '100%',
      }}
    >
      <Power size={13} color={colors.text} />
      <span style={{ color: colors.text, fontSize: 11, fontFamily: MONO, letterSpacing: '0.06em' }}>BMC {label}</span>
      <ChevronRight size={11} color={colors.text} style={{ marginLeft: 'auto', opacity: 0.5 }} />
    </button>
  );
}

const sectionLabel = (text: string) => (
  <div
    style={{
      color: 'var(--rasp-dim)',
      fontSize: 9,
      fontFamily: MONO,
      letterSpacing: '0.12em',
      marginBottom: 8,
      marginTop: 4,
      paddingBottom: 4,
      borderBottom: '1px solid rgba(var(--rasp-fg-rgb),0.1)',
    }}
  >
    {text}
  </div>
);

function appStatusColor(status: App['lastStatus']): string {
  if (status === 'running') return '#4ade80';
  if (status === 'failed') return '#f87171';
  if (status === 'deploying' || status === 'stopping') return '#facc15';
  return 'rgba(148,163,184,0.5)';
}

// DeployedAppRow — one app under a node's DEPLOYED APPS list. When the app is
// running and exposes a web port, the whole row is a link that opens the app at
// its app-access URL in a new tab (network-matched, same as the Apps-page OPEN
// button — .lan from a LAN view, tailnet otherwise); otherwise it's a plain,
// non-clickable status row.
function DeployedAppRow({ app, clusterId }: { app: App; clusterId: string }) {
  const [hover, setHover] = useState(false);
  const openUrl = preferredAppUrl(appAccess(app, clusterId));
  const canOpen = app.lastStatus === 'running' && !!openUrl;

  const rowStyle: CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '5px 10px',
    background: canOpen && hover ? accentA(0.08) : 'rgba(var(--rasp-fg-rgb),0.03)',
    border: `1px solid ${canOpen && hover ? accentA(0.4) : 'rgba(var(--rasp-fg-rgb),0.1)'}`,
    transition: 'background 0.12s, border-color 0.12s',
    textDecoration: 'none',
  };

  const content = (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, minWidth: 0 }}>
        <div style={{ width: 4, height: 4, borderRadius: '50%', background: appStatusColor(app.lastStatus), flexShrink: 0 }} />
        <span style={{ color: 'var(--rasp-fg)', fontSize: 10, fontFamily: MONO, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {app.name}
        </span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
        <span style={{ color: 'var(--rasp-dim)', fontSize: 9, fontFamily: MONO }}>{app.lastStatus}</span>
        {canOpen && <ExternalLink size={10} style={{ color: hover ? ACCENT : 'var(--rasp-dim)' }} />}
      </div>
    </>
  );

  if (!canOpen) return <div style={rowStyle}>{content}</div>;
  return (
    <a
      href={openUrl!}
      target="_blank"
      rel="noopener noreferrer"
      title={`Open ${app.name} — ${openUrl}`}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{ ...rowStyle, cursor: 'pointer' }}
    >
      {content}
    </a>
  );
}

export function NodeControls({ node, cpu, mem, apps, clusterId, deploymentMode, bmcCaps, onNavigate, onRemoved }: NodeControlsProps) {
  // Each hardware control gates on the capability it needs, not on bare
  // reachability: a backend may drive power while being unable to offer a
  // console (turingpi), and rendering a button its backend can only fail
  // is exactly what bmc.md §2a forbids. See lib/bmc.ts.
  const canPower = bmcCaps?.caps.has(BMC_CAP_POWER) ?? false;
  const canReset = bmcCaps?.caps.has(BMC_CAP_RESET) ?? false;
  const canConsole = bmcCaps?.caps.has(BMC_CAP_CONSOLE) ?? false;
  const consoleLossy = bmcCaps?.console?.lossy ?? false;
  const showBmcSection = canPower || canReset || canConsole;
  const [modal, setModal] = useState<'reboot' | 'power-off' | 'power-on' | 'reset' | 'remove' | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [bmcState, setBmcState] = useState<BMCPowerState>('unknown');
  const [removeImpact, setRemoveImpact] = useState<NodeRemovalImpact | null>(null);
  const [impactErr, setImpactErr] = useState<string | null>(null);

  const nodeId = node?.id ?? null;

  // BMC power state for the selected node: seed via REST, then track live.
  // Gated per-node on the power capability — no advertised path means no
  // power state to poll and no controls to render. See lib/bmc.ts.
  useEffect(() => {
    if (!nodeId || !canPower) {
      setBmcState('unknown');
      return;
    }
    let active = true;
    setBmcState('unknown');
    getBMCStatus(nodeId)
      .then((s) => {
        if (active) setBmcState(s.powerState);
      })
      .catch(() => {});
    const close = openBMCWS((ev) => {
      if (ev.targetNodeId !== nodeId) return;
      if (ev.state) setBmcState(ev.state);
    });
    return () => {
      active = false;
      close();
    };
  }, [nodeId, canPower]);

  // Clear transient action error when selection changes.
  useEffect(() => {
    setErr(null);
    setBusy(null);
  }, [nodeId]);

  const isOnline = node?.status === 'online';
  const isControlPlane = node?.role === 'controlplane';

  // An offline node has no CURRENT utilization, only a last-known one.
  // The metrics feed doesn't emit a zero when a node dies — it simply
  // stops, leaving the final sample in `util` indefinitely, so a node
  // with its power physically cut kept rendering a live-looking CPU 6% /
  // MEM 3% (bench 2026-07-28, tp-n1 powered off via BMC). NodeGrid
  // already guards this and shows OFFL; the detail panel did not.
  // StatBar renders null as "—" with an empty bar.
  const isOffline = node?.status === 'offline';
  const liveCpu = isOffline ? null : cpu;
  const liveMem = isOffline ? null : mem;

  async function run(action: string, fn: () => Promise<unknown>) {
    setBusy(action);
    setErr(null);
    try {
      await fn();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '16px 14px', overflowY: 'auto' }}>
        {/* Header */}
        <div style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <Layers size={13} color={ACCENT} />
            <span style={{ color: 'var(--rasp-fg)', fontSize: 11, fontFamily: MONO, letterSpacing: '0.08em' }}>NODE CONTROLS</span>
            <button
              onClick={() => onNavigate('/apps')}
              disabled={!node}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 5,
                marginLeft: 'auto',
                padding: '3px 8px',
                background: accentA(0.08),
                border: `1px solid ${accentA(0.3)}`,
                color: ACCENT,
                fontSize: 9,
                fontFamily: MONO,
                letterSpacing: '0.08em',
                cursor: node ? 'pointer' : 'not-allowed',
                opacity: node ? 1 : 0.4,
                whiteSpace: 'nowrap',
              }}
            >
              <Package size={10} color={ACCENT} />
              DEPLOY APP
            </button>
          </div>
          {node ? (
            <div style={{ color: ACCENT, fontSize: 13, fontFamily: MONO, letterSpacing: '0.06em' }}>
              {node.id.toUpperCase()}
            </div>
          ) : (
            <div style={{ color: 'var(--rasp-dim)', fontSize: 10, fontFamily: MONO }}>— select a node —</div>
          )}
        </div>

        {node?.role === 'firewall' && deploymentMode === 'lan_peer' && (
          <div
            style={{
              border: `1px solid ${accentA(0.4)}`,
              background: accentA(0.06),
              padding: '10px 12px',
              marginBottom: 16,
              display: 'flex',
              gap: 8,
            }}
          >
            <Info size={13} color={ACCENT} style={{ flexShrink: 0, marginTop: 1 }} />
            <p style={{ color: 'var(--rasp-dim)', fontSize: 10, fontFamily: MONO, lineHeight: 1.6, margin: 0 }}>
              This is a firewall-capable node, but you chose to join your existing network — so it has no
              firewall job here. Its built-in address (DHCP) server is turned off so it can&apos;t clash with
              your router. It stays powered and keeps getting updates. To put it to work, re-run setup and pick
              a firewall mode, or remove it.
            </p>
          </div>
        )}

        {node && (
          <>
            {sectionLabel('STATUS')}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 16 }}>
              {[
                { label: 'HOSTNAME', value: node.hostname || '—' },
                { label: 'ROLE', value: node.role.toUpperCase() },
                { label: 'TYPE', value: node.architecture || '—' },
                { label: 'STATUS', value: node.status.toUpperCase() },
                { label: 'OS IMAGE', value: node.imageVersion || '—' },
                {
                  label: 'STORAGE',
                  value: node.storage?.persistentTotalBytes
                    ? `${fmtBytes(node.storage.persistentFreeBytes)} free / ${fmtBytes(node.storage.persistentTotalBytes)}`
                    : '—',
                },
                {
                  label: 'GROWPART',
                  value: node.storage?.growpart?.toUpperCase() || '—',
                  // failed/skipped = the historically silent stuck-partition
                  // states this field exists to surface — render as warning.
                  color:
                    node.storage?.growpart === 'failed' || node.storage?.growpart === 'skipped'
                      ? STATUS_COLOR.warning
                      : undefined,
                },
              ].map(({ label, value, color }: { label: string; value: string; color?: string }) => (
                <div key={label} style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
                  <span style={{ color: 'var(--rasp-dim)', fontSize: 10, fontFamily: MONO, letterSpacing: '0.06em' }}>{label}</span>
                  <span
                    style={{
                      color: color ?? 'var(--rasp-fg)',
                      fontSize: 10,
                      fontFamily: MONO,
                      textAlign: 'right',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {value}
                  </span>
                </div>
              ))}
            </div>

            {/* CONFIG FAULT — values this node's node.env asked for and the
                agent REFUSED. It is running, reachable and reporting; the named
                capability is simply off. Rendering it is what keeps "degrade
                instead of exit" from being a quieter lie than the crash it
                replaced (#89): before this, the fault reached nodes.metadata
                and stopped there. Absent entirely on a healthy node. */}
            {configFaults(node).length > 0 && (
              <>
                {sectionLabel('CONFIG FAULT')}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 16 }}>
                  {configFaults(node).map((f) => (
                    <div
                      key={f.variable}
                      style={{
                        border: `1px solid ${STATUS_COLOR.warning}`,
                        padding: 8,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 4,
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <AlertTriangle size={12} color={STATUS_COLOR.warning} />
                        <span
                          style={{
                            color: STATUS_COLOR.warning,
                            fontSize: 10,
                            fontFamily: MONO,
                            letterSpacing: '0.06em',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                          }}
                        >
                          {f.variable}
                        </span>
                      </div>
                      {/* The effect first: an operator acts on "updates are
                          disabled", not on "unknown backend". */}
                      {f.effect && (
                        <span style={{ color: 'var(--rasp-fg)', fontSize: 10, fontFamily: MONO, lineHeight: 1.5 }}>
                          {f.effect}
                        </span>
                      )}
                      <span style={{ color: 'var(--rasp-dim)', fontSize: 10, fontFamily: MONO, lineHeight: 1.5 }}>
                        set to <span style={{ color: STATUS_COLOR.warning }}>{f.value || '(empty)'}</span>
                        {f.expected.length > 0 && <> · expected {f.expected.join(' | ')}</>}
                      </span>
                      <span style={{ color: 'var(--rasp-dim)', fontSize: 10, fontFamily: MONO, lineHeight: 1.5 }}>
                        Fix /var/lib/rasputin/node.env on this node and restart the agent.
                      </span>
                    </div>
                  ))}
                </div>
              </>
            )}

            {sectionLabel('UTILIZATION')}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 16 }}>
              <StatBar label="CPU" value={liveCpu} />
              <StatBar label="MEMORY" value={liveMem} />
            </div>
          </>
        )}

        {sectionLabel('ACTIONS')}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 16 }}>
          <CtrlButton
            icon={RotateCcw}
            label={busy === 'reboot' ? 'REBOOTING…' : 'REBOOT (OS)'}
            variant="danger"
            disabled={!node || busy !== null || !isOnline}
            onClick={() => setModal('reboot')}
          />
          <CtrlButton icon={Upload} label="UPDATE" disabled={!node} onClick={() => onNavigate('/updates')} />
          {/* The controlplane cannot be removed — it IS the cluster; the
              api refuses server-side too. */}
          {node?.role !== 'controlplane' && (
          <CtrlButton
            icon={Trash2}
            label={busy === 'remove' ? 'REMOVING…' : 'REMOVE NODE'}
            variant="danger"
            disabled={!node || busy !== null}
            onClick={() => {
              if (!node) return;
              setImpactErr(null);
              setRemoveImpact(null);
              setModal('remove');
              void getNodeRemovalImpact(node.id)
                .then(setRemoveImpact)
                .catch((e) => setImpactErr(String(e)));
            }}
          />
          )}
        </div>

        {/* Hardware-management controls get their own section: they act
            through the BMC bus, not the node's OS, and render only for
            nodes some BMC host advertises in its bmc-targets list —
            never a control that would no-op against missing hardware.
            See lib/bmc.ts. */}
        {showBmcSection && (
          <>
            {sectionLabel('BMC')}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 16 }}>
              {/* No power control for the controlplane. The backend can
                  honour it and the hardware will do it, but the UI that
                  issues power-off is served BY this node — once it is off
                  nothing here can turn it back on. The api refuses this
                  server-side too; this only keeps the button out of reach.
                  FORCE RESTART stays: it recovers on its own. */}
              {canPower && !isControlPlane && (
              <PowerButton
                state={bmcState}
                disabled={!node || busy !== null}
                onClick={() => {
                  if (!node) return;
                  // The label shows the CURRENT state; the click's action is
                  // the opposite verb — confirm both directions with copy
                  // that names the action (bench 2026-07-23: a stale 'on'
                  // once showed the power-OFF modal on a power-ON click).
                  setModal(bmcState === 'on' ? 'power-off' : 'power-on');
                }}
              />
              )}
              {canConsole && (
                <CtrlButton
                  icon={Terminal}
                  /* A polled ring-buffer console drops output between reads,
                     so say so rather than let scrollback gaps read as a bug. */
                  label={consoleLossy ? 'CONSOLE (LOSSY)' : 'CONSOLE'}
                  disabled={!node}
                  onClick={() => node && onNavigate(`/console?node=${encodeURIComponent(node.id)}`)}
                />
              )}
              {canReset && (
                <CtrlButton
                  icon={RefreshCw}
                  /* "RESET" read as factory-reset to a homelab audience,
                     especially sitting next to REMOVE NODE — the old confirm
                     copy had to disclaim BOTH a graceful reboot and a wipe.
                     "FORCE RESTART" says forcible without implying either,
                     and pairs against REBOOT (OS) as make-it vs ask-nicely.
                     Display only: the wire verb stays proto.BMCPowerReset. */
                  label={busy === 'reset' ? 'RESTARTING…' : 'FORCE RESTART'}
                  disabled={!node || busy !== null}
                  onClick={() => setModal('reset')}
                />
              )}
            </div>
          </>
        )}

        {sectionLabel('DIAGNOSTICS')}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 16 }}>
          <CtrlButton
            icon={Activity}
            label={busy === 'ping' ? 'PINGING…' : 'PING'}
            disabled={!node || busy !== null}
            onClick={() => node && void run('ping', () => createJob('diag.ping', { nodeId: node.id }))}
          />
          <CtrlButton
            icon={FileText}
            label="VIEW LOGS"
            disabled={!node}
            onClick={() => node && onNavigate(`/metrics?node=${encodeURIComponent(node.id)}&tab=logs`)}
          />
        </div>

        {err && (
          <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12, wordBreak: 'break-word' }}>{err}</div>
        )}

        {node && (
          <>
            {sectionLabel('DEPLOYED APPS')}
            {apps.length === 0 ? (
              <span style={{ color: 'rgba(var(--rasp-fg-rgb),0.2)', fontSize: 10, fontFamily: MONO }}>— none —</span>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {apps.map((app) => (
                  <DeployedAppRow key={app.id} app={app} clusterId={clusterId} />
                ))}
              </div>
            )}
          </>
        )}
      </div>

      {modal === 'reboot' && node && (
        <ConfirmModal
          title="CONFIRM REBOOT"
          message={`Reboot ${node.id.toUpperCase()}? This asks the running OS to restart gracefully; the node will be briefly unavailable.`}
          confirmLabel="REBOOT"
          danger
          onConfirm={() => void run('reboot', () => createJob('node.reboot', { nodeId: node.id }))}
          onCancel={() => setModal(null)}
        />
      )}
      {modal === 'power-off' && node && (
        <ConfirmModal
          title="CONFIRM POWER OFF"
          message={`Power off ${node.id.toUpperCase()} via BMC? This is a hardware-level power-off — running workloads are terminated.`}
          confirmLabel="POWER OFF"
          danger
          onConfirm={() => void run('bmc-off', () => bmcPower(node.id, 'off'))}
          onCancel={() => setModal(null)}
        />
      )}
      {modal === 'power-on' && node && (
        <ConfirmModal
          title="CONFIRM POWER ON"
          message={`Power on ${node.id.toUpperCase()} via BMC? The node boots and rejoins the cluster.`}
          confirmLabel="POWER ON"
          onConfirm={() => void run('bmc-on', () => bmcPower(node.id, 'on'))}
          onCancel={() => setModal(null)}
        />
      )}
      {modal === 'reset' && node && (
        <ConfirmModal
          title="CONFIRM FORCE RESTART"
          message={`Force ${node.id.toUpperCase()} to restart via BMC? The OS is not notified and gets no chance to shut down, so anything unwritten is lost. Use REBOOT (OS) instead while the node still responds.`}
          confirmLabel="FORCE RESTART"
          danger
          onConfirm={() => void run('reset', () => bmcPower(node.id, 'reset'))}
          onCancel={() => setModal(null)}
        />
      )}
      {modal === 'remove' && node && (
        <RemoveNodeModal
          node={node}
          impact={removeImpact}
          impactErr={impactErr}
          onCancel={() => setModal(null)}
          onConfirm={() => {
            const id = node.id;
            setModal(null);
            void run('remove', async () => {
              await deleteNode(id);
              onRemoved?.(id);
            });
          }}
        />
      )}
    </>
  );
}

function RemoveNodeModal({
  node,
  impact,
  impactErr,
  onConfirm,
  onCancel,
}: {
  node: Node;
  impact: NodeRemovalImpact | null;
  impactErr: string | null;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  // Loading: impact === null && !impactErr → show a placeholder. Failure: show
  // the error and let the user retry by reopening. Loaded: show the cascade
  // counts. The remove button is enabled as soon as the preview returns; a
  // failed preview blocks the action because we don't actually know the
  // cascade scope.
  const ready = impact !== null;
  return (
    <div
      onClick={onCancel}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.6)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: 'var(--rasp-panel)',
          border: '1px solid rgba(var(--rasp-fg-rgb),0.18)',
          padding: 24,
          width: 380,
          display: 'flex',
          flexDirection: 'column',
          gap: 16,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertTriangle size={14} color="#f87171" />
            <span style={{ color: 'var(--rasp-fg)', fontSize: 11, fontFamily: MONO, letterSpacing: '0.1em' }}>
              REMOVE NODE
            </span>
          </div>
          <button onClick={onCancel} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
            <X size={14} color="var(--rasp-dim)" />
          </button>
        </div>

        <div style={{ height: 1, background: 'rgba(var(--rasp-fg-rgb),0.1)' }} />

        <p style={{ color: 'var(--rasp-dim)', fontSize: 11, fontFamily: MONO, lineHeight: 1.6, margin: 0 }}>
          Permanently remove <span style={{ color: 'var(--rasp-fg)' }}>{node.id.toUpperCase()}</span> from inventory. Use this
          when the hardware is gone or being repurposed — a re-registering agent will appear as a fresh node.
        </p>

        <div
          style={{
            border: '1px solid rgba(var(--rasp-fg-rgb),0.1)',
            padding: '10px 12px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6,
          }}
        >
          <span
            style={{
              color: 'var(--rasp-dim)',
              fontSize: 9,
              fontFamily: MONO,
              letterSpacing: '0.12em',
              paddingBottom: 4,
              borderBottom: '1px solid rgba(var(--rasp-fg-rgb),0.08)',
            }}
          >
            CASCADE
          </span>
          {!ready && !impactErr && (
            <span style={{ color: 'rgba(var(--rasp-fg-rgb),0.4)', fontSize: 10, fontFamily: MONO }}>computing…</span>
          )}
          {impactErr && <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{impactErr}</span>}
          {ready && (
            <>
              <ImpactRow label="APP DEPLOYMENTS" value={`${impact!.appIds.length} removed`} />
              <ImpactRow
                label="MESH ENROLLMENT"
                value={impact!.meshDeviceHsId ? 'removed from Headscale' : 'not enrolled'}
              />
              <ImpactRow
                label="FIREWALL STATE"
                value={impact!.hasFirewallState ? 'reconciliation row removed' : 'none'}
              />
            </>
          )}
        </div>

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button
            onClick={onCancel}
            style={{
              padding: '7px 16px',
              background: 'transparent',
              border: '1px solid rgba(var(--rasp-fg-rgb),0.18)',
              color: 'var(--rasp-dim)',
              fontSize: 10,
              fontFamily: MONO,
              letterSpacing: '0.08em',
              cursor: 'pointer',
            }}
          >
            CANCEL
          </button>
          <button
            onClick={onConfirm}
            disabled={!ready}
            style={{
              padding: '7px 16px',
              background: 'rgba(248,113,113,0.12)',
              border: '1px solid rgba(248,113,113,0.5)',
              color: '#f87171',
              fontSize: 10,
              fontFamily: MONO,
              letterSpacing: '0.08em',
              cursor: ready ? 'pointer' : 'not-allowed',
              opacity: ready ? 1 : 0.4,
            }}
          >
            REMOVE
          </button>
        </div>
      </div>
    </div>
  );
}

function ImpactRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
      <span style={{ color: 'var(--rasp-dim)', fontSize: 10, fontFamily: MONO, letterSpacing: '0.06em' }}>{label}</span>
      <span style={{ color: 'var(--rasp-fg)', fontSize: 10, fontFamily: MONO, textAlign: 'right' }}>{value}</span>
    </div>
  );
}
