'use client';

import { useEffect, useState } from 'react';
import { enrollMeshNode, getJob, listMeshDevices, listNodes } from '../../../../lib/api';
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
                <td style={{ ...tdStyle, color: FG }}>{d.hostname || d.hsId}</td>
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

  useEffect(() => {
    if (!nodeId && candidates.length > 0) setNodeId(candidates[0].id);
  }, [candidates, nodeId]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!nodeId) return;
    setBusy(true);
    setErr(null);
    try {
      const cidrs = routes.split(',').map((s) => s.trim()).filter(Boolean);
      const job = await enrollMeshNode(nodeId, cidrs);
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
      <Select value={nodeId} onChange={(e) => setNodeId(e.target.value)} style={{ minWidth: 180 }}>
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
        style={{ flex: '1 1 240px' }}
      />
      <Btn type="submit" variant="primary" disabled={busy || !nodeId}>
        {busy ? 'ENROLLING…' : 'ENROLL NODE'}
      </Btn>
      {err && <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{err}</span>}
    </form>
  );
}
