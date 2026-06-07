'use client';

import { ExternalLink } from 'lucide-react';
import { useEffect, useState } from 'react';
import { listFirewallState } from '../../../../lib/api';
import type { FirewallNodeState } from '../../../../lib/types';
import { Btn, DIM, Hint, SectionLabel, Tok } from '../../../../components/kit';
import { MONO } from '../../../../components/ui-theme';

// The Advanced tab is the explicit escape hatch: link to LuCI on the firewall
// node for anything Rasputin doesn't model. Changes made there get flagged by
// the next reconcile (firewall-integration.md §1) — users see drift in the
// state row and can re-Apply to overwrite or update intents to match.
//
// LuCI URL derivation isn't wired yet — we don't have a per-node LAN-IP field
// in inventory. For now the operator pastes their firewall LAN IP and we
// build the URL client-side. When primaryLanIp lands on Node (mesh.md ships
// primaryLanCidr already; an IP follow-up is small), this becomes automatic.
export default function AdvancedPage() {
  const [states, setStates] = useState<FirewallNodeState[]>([]);
  const [luciHost, setLuciHost] = useState('');

  useEffect(() => {
    listFirewallState().then(setStates).catch(() => {});
  }, []);

  const nodeId = states[0]?.nodeId ?? '';

  return (
    <>
      <SectionLabel>LuCI — OpenWrt admin UI</SectionLabel>
      <Hint style={{ marginBottom: 16 }}>
        LuCI is the OpenWrt native admin UI on the firewall node. Use it for anything Rasputin
        doesn&apos;t expose. Changes you make there are flagged on the next reconcile as <Tok>DRIFT</Tok>{' '}
        — adopt or revert by editing the matching Rasputin intent and clicking <Tok>APPLY</Tok>.
      </Hint>

      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 24 }}>
        <span style={{ color: DIM, fontSize: 10, fontFamily: MONO }}>firewall host:</span>
        <input
          value={luciHost}
          onChange={(e) => setLuciHost(e.target.value)}
          placeholder={nodeId ? `${nodeId}.lan` : 'firewall LAN IP or hostname'}
          style={{
            background: '#111d30',
            border: '1px solid rgba(228,230,234,0.18)',
            color: '#e4e6ea',
            fontFamily: MONO,
            fontSize: 11,
            padding: '7px 9px',
            minWidth: 240,
          }}
        />
        <a
          href={luciHost ? `http://${luciHost}/` : '#'}
          target="_blank"
          rel="noopener noreferrer"
          onClick={(e) => {
            if (!luciHost) e.preventDefault();
          }}
          style={{ textDecoration: 'none' }}
        >
          <Btn variant="primary" small disabled={!luciHost}>
            OPEN LuCI <ExternalLink size={10} />
          </Btn>
        </a>
      </div>

      <SectionLabel>WHAT LuCI IS GOOD FOR</SectionLabel>
      <Hint>
        Anything Rasputin doesn&apos;t expose yet — packet captures, custom DHCP options, exotic
        routing, traffic shaping, banIP, mwan3. The wiki doc <Tok>firewall-integration.md §11</Tok>{' '}
        lists what we plan to add to the managed surface so this list shrinks over time.
      </Hint>
    </>
  );
}
