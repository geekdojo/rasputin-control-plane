'use client';

import { useEffect, useState } from 'react';
import { listFirewallState } from '../../../../lib/api';
import type { FirewallNodeState } from '../../../../lib/types';
import { CopyButton, DIM, Hint, Input, SectionLabel, Tok } from '../../../../components/kit';
import { MONO } from '../../../../components/ui-theme';
import {
  LUCI_LOCAL_PORT,
  LUCI_REMOTE_PORT,
  luciLocalUrl,
  luciTunnelCommand,
} from '../../../../lib/luci-tunnel';

// The Advanced tab is the explicit escape hatch: it tells the operator how to
// reach the firewall's own native admin UI for anything Rasputin doesn't model.
// Changes made there get flagged by the next reconcile (firewall-integration.md
// §1) — users see drift in the state row and can re-Apply to overwrite or
// update intents to match.
//
// The native UI listens on the firewall's LOOPBACK interface, so this tab has
// no URL to link to and deliberately does not offer one: the operator forwards
// a local port to it over SSH and opens the local end in their own browser. The
// command is built by lib/luci-tunnel.ts, which also decides what a usable host
// is; see its header for why the host is validated before interpolation.
//
// Today the firewall ships as OpenWrt → the native UI is LuCI; when OPNsense
// lands as an alternate backend (§14 backlog), this same tab will describe the
// OPNsense web GUI. User-facing strings stay vendor-neutral so no UI churn is
// needed when the flavor field arrives on inventory. Internal nodeId / host
// derivation is the same either way.
//
// Host derivation isn't wired yet — we don't have a per-node LAN-IP field in
// inventory. For now the operator pastes their firewall host and we build the
// command client-side. When primaryLanIp lands on Node (mesh.md ships
// primaryLanCidr already; an IP follow-up is small), this becomes automatic.
export default function AdvancedPage() {
  const [states, setStates] = useState<FirewallNodeState[]>([]);
  const [firewallHost, setFirewallHost] = useState('');

  useEffect(() => {
    listFirewallState().then(setStates).catch(() => {});
  }, []);

  const nodeId = states[0]?.nodeId ?? '';
  const typed = firewallHost.trim();
  const command = luciTunnelCommand(firewallHost);

  return (
    <>
      <SectionLabel>NATIVE FIREWALL ADMIN UI</SectionLabel>
      <Hint style={{ marginBottom: 16 }}>
        The firewall&apos;s own admin interface is bound to the firewall&apos;s loopback interface,
        so it isn&apos;t served to the LAN. Reach it by forwarding a local port to it over SSH, then
        opening that local port in your browser. Use it for anything Rasputin doesn&apos;t expose.
        Changes you make there are flagged on the next reconcile as <Tok>DRIFT</Tok> — adopt or
        revert by editing the matching Rasputin intent and clicking <Tok>APPLY</Tok>.
      </Hint>

      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 12 }}>
        <span style={{ color: DIM, fontSize: 10, fontFamily: MONO }}>firewall host:</span>
        <Input
          value={firewallHost}
          onChange={(e) => setFirewallHost(e.target.value)}
          aria-label="Firewall host"
          placeholder={nodeId ? `${nodeId}.lan` : 'firewall LAN IP or hostname'}
          style={{ minWidth: 240 }}
        />
      </div>

      <div
        style={{
          display: 'flex',
          gap: 8,
          alignItems: 'center',
          flexWrap: 'wrap',
          marginBottom: 8,
        }}
      >
        <code
          style={{
            background: 'var(--rasp-field-bg)',
            border: '1px solid rgba(var(--rasp-fg-rgb),0.18)',
            color: command ? 'var(--rasp-fg)' : DIM,
            fontFamily: MONO,
            fontSize: 11,
            padding: '7px 9px',
            userSelect: 'all',
          }}
        >
          {command ?? `ssh -L ${LUCI_LOCAL_PORT}:127.0.0.1:${LUCI_REMOTE_PORT} root@<firewall host>`}
        </code>
        {command ? (
          <CopyButton value={command} ariaLabel="Copy the SSH tunnel command" />
        ) : null}
      </div>

      <Hint style={{ marginBottom: 24 }}>
        {typed && !command
          ? 'That is not a hostname or an IP address. Enter the firewall’s hostname, IPv4 address, or a bracketed IPv6 address.'
          : null}
        {!typed ? 'Enter the firewall host above to fill in the command.' : null}
        {command ? (
          <>
            Run that in a terminal, leave it running, then open <Tok>{luciLocalUrl()}</Tok> in your
            browser. <Tok>-L</Tok> forwards port <Tok>{String(LUCI_LOCAL_PORT)}</Tok> on your
            machine to the admin UI on the firewall&apos;s own <Tok>127.0.0.1</Tok>; closing the SSH
            session closes the tunnel. If port {String(LUCI_LOCAL_PORT)} is already taken on your
            machine, edit the first number in the command and open that port instead.
          </>
        ) : null}
      </Hint>

      <SectionLabel>WHAT THE NATIVE UI IS GOOD FOR</SectionLabel>
      <Hint>
        Anything Rasputin doesn&apos;t expose yet — packet captures, custom DHCP options, exotic
        routing, traffic shaping, ban lists, multi-WAN failover. The wiki doc{' '}
        <Tok>firewall-integration.md §11</Tok> lists what we plan to add to the managed surface so
        this list shrinks over time.
      </Hint>
    </>
  );
}
