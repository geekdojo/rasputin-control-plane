'use client';

import { useEffect, useState } from 'react';
import { enrollMeshNode, getJob, listMeshDevices, listNodes } from '../../../../lib/api';
import { parseAdvertiseRoutes } from '../../../../lib/cidr';
import { useMeshStateRefresh } from '../../../../lib/mesh-state-context';
import type { MeshDevice, Node } from '../../../../lib/types';
import {
  Badge,
  Btn,
  DIM,
  FG,
  Hint,
  Input,
  SectionLabel,
  Select,
  tdStyle,
  thStyle,
} from '../../../../components/kit';
import { ACCENT, MONO } from '../../../../components/ui-theme';

const WARN = '#facc15';

export default function DevicesPage() {
  const [devices, setDevices] = useState<MeshDevice[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const refreshMeshState = useMeshStateRefresh();

  useEffect(() => {
    refresh();
  }, []);

  function refresh() {
    listMeshDevices().then(setDevices).catch((e) => setErr(String(e)));
    listNodes().then(setNodes).catch(() => {});
  }

  return (
    <>
      {err && (
        <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}>{err}</div>
      )}

      <SectionLabel>DEVICES</SectionLabel>
      {devices.length === 0 ? (
        <Hint style={{ marginBottom: 18 }}>
          no devices in the tailnet yet — enroll a Rasputin node below, or add your laptop on the KEYS tab.
        </Hint>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 18 }}>
          <thead>
            <tr>
              {['HOST', 'KIND', 'TAILNET IP', 'TAGS', 'ROUTES', 'LAST SEEN'].map((c) => (
                <th key={c} style={thStyle}>
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.hsId}>
                <td style={{ ...tdStyle, color: FG }}>
                  {d.hostname || d.hsId}
                  <TrustMarker trust={d.trust} />
                </td>
                <td style={tdStyle}>
                  <Badge color={d.kind === 'rasputin' ? ACCENT : DIM}>{d.kind.toUpperCase()}</Badge>
                </td>
                <td style={{ ...tdStyle, color: DIM }}>{d.tailnetIp || '—'}</td>
                <td style={{ ...tdStyle, color: DIM }}>{(d.tags || []).join(' · ') || '—'}</td>
                <td style={{ ...tdStyle, color: DIM }}>{(d.advertisedRoutes || []).join(', ') || '—'}</td>
                <td style={{ ...tdStyle, color: DIM }}>{new Date(d.lastSeen).toLocaleTimeString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <SectionLabel>ENROLL RASPUTIN NODE</SectionLabel>
      <EnrollNodeForm
        nodes={nodes}
        devices={devices}
        onEnrolled={() => {
          refresh();
          refreshMeshState();
        }}
      />
    </>
  );
}

// A node whose agent reports trusting a mesh CA other than the api's current
// one cannot verify anything the api serves over the mesh-CA listener (backup
// transfer, bundle downloads) until the CA is re-delivered — which the next
// mesh.reconcile does on its own. Say so on the row; an "unreported" node's
// agent has not said what it trusts (older agent), and the api leaves it alone.
function TrustMarker({ trust }: { trust?: MeshDevice['trust'] }) {
  if (!trust || trust.state === 'current') return null;
  if (trust.state === 'stale') {
    return (
      <span style={{ marginLeft: 8 }}>
        <Badge
          color={WARN}
          title={`this node trusts mesh CA ${trust.fingerprint === 'none' ? 'NONE' : (trust.fingerprint ?? '?').slice(0, 12)}, not the current one — the next mesh reconcile re-delivers it`}
        >
          TRUST STALE · re-delivering
        </Badge>
      </span>
    );
  }
  return (
    <span style={{ marginLeft: 8 }}>
      <Badge
        color={DIM}
        title={
          trust.agentPredatesField
            ? 'this node\'s agent predates trust reporting — update the node to have it report which mesh CA it trusts'
            : 'this node has not reported which mesh CA it trusts; it is left alone until it does'
        }
      >
        TRUST UNREPORTED
      </Badge>
    </span>
  );
}

function EnrollNodeForm({
  nodes,
  devices,
  onEnrolled,
}: {
  nodes: Node[];
  devices: MeshDevice[];
  onEnrolled: () => void;
}) {
  const enrolled = new Set(
    devices.filter((d) => d.kind === 'rasputin').map((d) => d.rasputinNodeId || d.hostname),
  );
  const candidates = nodes.filter((n) => n.status === 'online' && !enrolled.has(n.id));
  const [nodeId, setNodeId] = useState('');
  const [routes, setRoutes] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Default selection DERIVED rather than written from an effect — "nothing
  // chosen yet" falls back to the first candidate. Writing it was a synchronous
  // setState on effect entry (set-state-in-effect).
  const selectedNodeId = nodeId || (candidates[0]?.id ?? '');
  // Checked as typed, and the api applies the same rule: a route with host
  // bits set (192.168.1.149/24) is what `tailscale up` refuses on the node,
  // after the mesh CA is already installed (e3bench 2026-09-04). Refuse it
  // here, naming the network — never rewrite what the operator typed.
  const parsedRoutes = parseAdvertiseRoutes(routes);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedNodeId) return;
    if (parsedRoutes.error) {
      setErr(parsedRoutes.error);
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const job = await enrollMeshNode(selectedNodeId, parsedRoutes.routes);
      setRoutes('');
      // Poll the enroll job to a terminal state before refreshing. The saga
      // runs async (the agent restarts tailscaled, runs `tailscale up`, then
      // the record step writes the device) — ~10-30s on hardware. Refreshing
      // immediately shows the node still absent, so it looks like the click
      // did nothing until a manual page refresh (bench 2026-06-18). Poll up to
      // ~60s, surface a failure, then refresh either way.
      let terminal = false;
      for (let i = 0; i < 60; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        const j = await getJob(job.id);
        if (j.status === 'failed' || j.status === 'cancelled') {
          setErr(`Enrollment failed${j.error ? `: ${j.error}` : ' — see the Tasks panel for details.'}`);
          terminal = true;
          break;
        }
        if (j.status === 'succeeded') {
          terminal = true;
          break;
        }
      }
      if (!terminal) {
        setErr('Enrollment is still running — it may finish shortly. Check the Tasks panel, then refresh.');
      }
      onEnrolled();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (candidates.length === 0) {
    return <Hint>all online Rasputin nodes are already in the tailnet</Hint>;
  }

  return (
    <form onSubmit={submit} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
      <Select value={selectedNodeId} onChange={(e) => setNodeId(e.target.value)} style={{ minWidth: 180 }}>
        {candidates.map((n) => (
          <option key={n.id} value={n.id}>
            {n.id} ({n.role})
          </option>
        ))}
      </Select>
      <Input
        placeholder="advertise routes (CIDRs, comma-sep; optional)"
        value={routes}
        onChange={(e) => setRoutes(e.target.value)}
        aria-invalid={parsedRoutes.error ? true : undefined}
        style={{ flex: '1 1 240px' }}
      />
      <Btn type="submit" variant="primary" disabled={busy || !selectedNodeId || !!parsedRoutes.error}>
        {busy ? 'ENROLLING…' : 'ENROLL NODE'}
      </Btn>
      {(err || parsedRoutes.error) && (
        <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{err ?? parsedRoutes.error}</span>
      )}
    </form>
  );
}
