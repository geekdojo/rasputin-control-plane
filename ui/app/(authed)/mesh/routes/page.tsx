'use client';

import { Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { createMeshRoute, deleteMeshRoute, listMeshRoutes, listNodes } from '../../../../lib/api';
import type { MeshIntent, Node, SubnetRouteSpec } from '../../../../lib/types';
import {
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
import { MONO } from '../../../../components/ui-theme';

export default function RoutesPage() {
  const [routes, setRoutes] = useState<MeshIntent[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    refresh();
  }, []);

  function refresh() {
    listMeshRoutes().then(setRoutes).catch((e) => setErr(String(e)));
    listNodes().then(setNodes).catch(() => {});
  }

  async function handleDeleteRoute(id: string) {
    try {
      await deleteMeshRoute(id);
      setRoutes((prev) => prev.filter((r) => r.id !== id));
    } catch (e) {
      setErr(String(e));
    }
  }

  return (
    <>
      {err && (
        <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}>{err}</div>
      )}

      <SectionLabel>SUBNET ROUTES</SectionLabel>
      {routes.length === 0 ? (
        <Hint style={{ marginBottom: 14 }}>no subnet routes yet</Hint>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 14 }}>
          <thead>
            <tr>
              {['NAME', 'NODE', 'CIDR', ''].map((c, i) => (
                <th key={c || i} style={thStyle}>
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {routes.map((r) => {
              const spec = r.spec as SubnetRouteSpec;
              return (
                <tr key={r.id}>
                  <td style={{ ...tdStyle, color: FG }}>{r.name}</td>
                  <td style={{ ...tdStyle, color: DIM }}>{spec.nodeId}</td>
                  <td style={{ ...tdStyle, color: DIM }}>{spec.cidr}</td>
                  <td style={{ ...tdStyle, paddingRight: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                      <Btn variant="danger" small onClick={() => handleDeleteRoute(r.id)}>
                        <Trash2 size={10} /> DELETE
                      </Btn>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      <SectionLabel>ADD ROUTE</SectionLabel>
      <AddRouteForm nodes={nodes} onCreated={refresh} />
    </>
  );
}

function AddRouteForm({ nodes, onCreated }: { nodes: Node[]; onCreated: () => void }) {
  const [name, setName] = useState('');
  const [nodeId, setNodeId] = useState('');
  const [cidr, setCidr] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!nodeId && nodes.length > 0) setNodeId(nodes[0].id);
  }, [nodes, nodeId]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await createMeshRoute({ name, nodeId, cidr });
      setName('');
      setCidr('');
      onCreated();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (nodes.length === 0) {
    return <Hint>no nodes registered yet</Hint>;
  }

  return (
    <form onSubmit={submit} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
      <Input
        placeholder="name (e.g. lan-vlan-10)"
        value={name}
        onChange={(e) => setName(e.target.value)}
        required
        style={{ flex: '1 1 180px' }}
      />
      <Select value={nodeId} onChange={(e) => setNodeId(e.target.value)} style={{ minWidth: 180 }}>
        {nodes.map((n) => (
          <option key={n.id} value={n.id}>
            {n.id} ({n.role})
          </option>
        ))}
      </Select>
      <Input
        placeholder="CIDR (e.g. 10.0.0.0/24)"
        value={cidr}
        onChange={(e) => setCidr(e.target.value)}
        required
        style={{ flex: '1 1 160px' }}
      />
      <Btn type="submit" variant="primary" disabled={busy || !name || !cidr}>
        {busy ? 'ADDING…' : 'ADD ROUTE'}
      </Btn>
      {err && <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{err}</span>}
    </form>
  );
}
