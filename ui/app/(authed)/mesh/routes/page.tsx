'use client';

import { Pencil, Trash2 } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import {
  createMeshRoute,
  deleteMeshRoute,
  listMeshRoutes,
  listNodes,
  updateMeshRoute,
} from '../../../../lib/api';
import { useMeshStateRefresh } from '../../../../lib/mesh-state-context';
import type { MeshIntent, Node, SubnetRouteSpec } from '../../../../lib/types';
import {
  Btn,
  DIM,
  EnabledToggle,
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
  const [editing, setEditing] = useState<MeshIntent | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const formRef = useRef<HTMLDivElement>(null);
  const refreshMeshState = useMeshStateRefresh();

  useEffect(() => {
    refresh();
  }, []);

  useEffect(() => {
    if (editing) formRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [editing]);

  function refresh() {
    listMeshRoutes().then(setRoutes).catch((e) => setErr(String(e)));
    listNodes().then(setNodes).catch(() => {});
  }

  async function handleDelete(id: string) {
    try {
      await deleteMeshRoute(id);
      setRoutes((prev) => prev.filter((r) => r.id !== id));
      if (editing?.id === id) setEditing(null);
      refreshMeshState();
    } catch (e) {
      setErr(String(e));
    }
  }

  async function handleToggle(intent: MeshIntent) {
    try {
      const updated = await updateMeshRoute(intent.id, { enabled: !intent.enabled });
      setRoutes((prev) => prev.map((p) => (p.id === updated.id ? updated : p)));
      refreshMeshState();
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
              const nameColor = r.enabled ? FG : DIM;
              const cellColor = r.enabled ? DIM : 'rgba(138, 155, 181, 0.55)';
              const isEditing = editing?.id === r.id;
              return (
                <tr
                  key={r.id}
                  style={isEditing ? { background: 'rgba(var(--rasp-fg-rgb),0.04)' } : undefined}
                >
                  <td style={{ ...tdStyle, color: nameColor }}>{r.name}</td>
                  <td style={{ ...tdStyle, color: cellColor }}>{spec.nodeId}</td>
                  <td style={{ ...tdStyle, color: cellColor }}>{spec.cidr}</td>
                  <td style={{ ...tdStyle, paddingRight: 0 }}>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6 }}>
                      <EnabledToggle enabled={r.enabled} onToggle={() => handleToggle(r)} />
                      <Btn small onClick={() => setEditing(r)} title="Edit this route">
                        <Pencil size={10} /> EDIT
                      </Btn>
                      <Btn variant="danger" small onClick={() => handleDelete(r.id)}>
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

      <div ref={formRef} style={{ scrollMarginTop: 16 }}>
        <SectionLabel>
          {editing ? `EDIT ROUTE — ${editing.name}` : 'ADD ROUTE'}
        </SectionLabel>
        <RouteForm
          nodes={nodes}
          editing={editing}
          onCreated={() => {
            refresh();
            refreshMeshState();
          }}
          onUpdated={(i) => {
            setRoutes((prev) => prev.map((p) => (p.id === i.id ? i : p)));
            setEditing(null);
            refreshMeshState();
          }}
          onCancelEdit={() => setEditing(null)}
        />
      </div>
    </>
  );
}

function RouteForm({
  nodes,
  editing,
  onCreated,
  onUpdated,
  onCancelEdit,
}: {
  nodes: Node[];
  editing: MeshIntent | null;
  onCreated: () => void;
  onUpdated: (i: MeshIntent) => void;
  onCancelEdit: () => void;
}) {
  const [name, setName] = useState('');
  const [nodeId, setNodeId] = useState('');
  const [cidr, setCidr] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!nodeId && nodes.length > 0 && !editing) setNodeId(nodes[0].id);
  }, [nodes, nodeId, editing]);

  function resetFields() {
    setName('');
    setNodeId(nodes[0]?.id ?? '');
    setCidr('');
    setErr(null);
  }

  useEffect(() => {
    if (!editing) return;
    const s = editing.spec as SubnetRouteSpec;
    setName(editing.name);
    setNodeId(s.nodeId);
    setCidr(s.cidr);
    setErr(null);
    requestAnimationFrame(() => document.getElementById('route-name')?.focus());
  }, [editing]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      if (editing) {
        const updated = await updateMeshRoute(editing.id, { name, nodeId, cidr });
        onUpdated(updated);
        resetFields();
      } else {
        await createMeshRoute({ name, nodeId, cidr });
        onCreated();
        resetFields();
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  function cancel() {
    resetFields();
    onCancelEdit();
  }

  if (nodes.length === 0 && !editing) {
    return <Hint>no nodes registered yet</Hint>;
  }

  return (
    <form onSubmit={submit} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
      <Input
        id="route-name"
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
        {busy ? (editing ? 'UPDATING…' : 'ADDING…') : editing ? 'UPDATE ROUTE' : 'ADD ROUTE'}
      </Btn>
      {editing && (
        <Btn onClick={cancel} disabled={busy}>
          CANCEL
        </Btn>
      )}
      {err && <span style={{ color: '#f87171', fontSize: 10, fontFamily: MONO }}>{err}</span>}
    </form>
  );
}
