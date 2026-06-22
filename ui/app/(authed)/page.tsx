'use client';

import { useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import { listApps, listBusTokens, listNodes, getMetrics, openInventoryWS, revokeBusToken } from '../../lib/api';
import type { App, BusTokenInfo, InventoryChangeEvent, Node, NodeRole, NodeStatus } from '../../lib/types';
import { NodeGrid, type NodeView, type PendingView } from '../../components/NodeGrid';
import { NodeControls } from '../../components/NodeControls';
import { AddNodeWizard } from '../../components/AddNodeWizard';
import { ConfirmModal } from '../../components/ConfirmModal';
import { clusterPrefixOf } from '../../lib/enroll';
import type { NodeViewStatus } from '../../components/ui-theme';

interface Util {
  cpu: number | null;
  mem: number | null;
}

const ROLE_SHORT: Record<NodeRole, string> = {
  controlplane: 'ctrl',
  firewall: 'fw',
  compute: 'work',
  storage: 'stor',
};

function viewStatus(s: NodeStatus): NodeViewStatus {
  if (s === 'online') return 'online';
  if (s === 'offline') return 'offline';
  return 'warning'; // stale → warning
}

function shortId(n: Node): string {
  const raw = n.id;
  return raw.length > 10 ? raw.slice(0, 9) + '…' : raw;
}

export default function NodesPage() {
  const router = useRouter();
  const [nodes, setNodes] = useState<Node[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [util, setUtil] = useState<Record<string, Util>>({});
  const [apps, setApps] = useState<App[]>([]);
  const [busTokens, setBusTokens] = useState<BusTokenInfo[]>([]);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [cancelTarget, setCancelTarget] = useState<PendingView | null>(null);
  const [cancelErr, setCancelErr] = useState<string | null>(null);

  // Live node inventory + 15s backstop poll (transitions arrive via WS, but a
  // steadily-online node needs the poll to refresh lastSeen-derived state).
  useEffect(() => {
    listNodes().then(setNodes).catch(() => {});
    const close = openInventoryWS((ev: InventoryChangeEvent) => {
      if (ev.change === 'removed') {
        setNodes((prev) => prev.filter((n) => n.id !== ev.node.id));
        setSelectedId((prev) => (prev === ev.node.id ? null : prev));
        return;
      }
      setNodes((prev) => {
        const exists = prev.find((n) => n.id === ev.node.id);
        return exists ? prev.map((n) => (n.id === ev.node.id ? ev.node : n)) : [...prev, ev.node];
      });
    });
    const t = setInterval(() => listNodes().then(setNodes).catch(() => {}), 15_000);
    return () => {
      close();
      clearInterval(t);
    };
  }, []);

  // Per-node CPU/MEM snapshot for the hex labels + controls panel.
  useEffect(() => {
    if (nodes.length === 0) return;
    let active = true;
    const fetchAll = async () => {
      const entries = await Promise.all(
        nodes.map(async (n): Promise<[string, Util]> => {
          try {
            const m = await getMetrics(n.id, '15m', ['cpu_percent', 'mem_used_bytes', 'mem_total_bytes']);
            const cpuArr = m.series?.cpu_percent ?? [];
            const usedArr = m.series?.mem_used_bytes ?? [];
            const totalArr = m.series?.mem_total_bytes ?? [];
            const cpu = cpuArr.length ? cpuArr[cpuArr.length - 1].value : null;
            const used = usedArr.length ? usedArr[usedArr.length - 1].value : null;
            const total = totalArr.length ? totalArr[totalArr.length - 1].value : null;
            const mem = used != null && total && total > 0 ? (used / total) * 100 : null;
            return [n.id, { cpu, mem }];
          } catch {
            return [n.id, { cpu: null, mem: null }];
          }
        }),
      );
      if (active) setUtil(Object.fromEntries(entries));
    };
    fetchAll();
    const t = setInterval(fetchAll, 30_000);
    return () => {
      active = false;
      clearInterval(t);
    };
  }, [nodes]);

  // Apps (for the selected node's "deployed apps" list).
  useEffect(() => {
    listApps().then(setApps).catch(() => {});
    const t = setInterval(() => listApps().then(setApps).catch(() => {}), 30_000);
    return () => clearInterval(t);
  }, []);

  // Bus join tokens — drives the pending-enrollment bays. A bound, unrevoked
  // token whose node hasn't registered yet is a node mid-enrollment.
  useEffect(() => {
    listBusTokens().then(setBusTokens).catch(() => {});
    const t = setInterval(() => listBusTokens().then(setBusTokens).catch(() => {}), 15_000);
    return () => clearInterval(t);
  }, []);

  const views: NodeView[] = useMemo(
    () =>
      nodes.map((n) => ({
        id: n.id,
        name: shortId(n),
        status: viewStatus(n.status),
        role: ROLE_SHORT[n.role] ?? n.role,
        cpu: util[n.id]?.cpu ?? null,
      })),
    [nodes, util],
  );

  // Pending enrollments: bound, unrevoked tokens whose node isn't in inventory
  // yet. Once the node registers it drops out of this list and becomes a live
  // hex — the come-online confirmation happens in the grid itself.
  const nodeIds = useMemo(() => new Set(nodes.map((n) => n.id)), [nodes]);
  const pending: PendingView[] = useMemo(
    () =>
      busTokens
        .filter((t) => t.nodeId && !t.revokedAt && !nodeIds.has(t.nodeId))
        .map((t) => ({
          id: t.nodeId as string,
          tokenId: t.id,
          role: ROLE_SHORT[t.label as NodeRole] ?? t.label,
        })),
    [busTokens, nodeIds],
  );

  const clusterPrefix = useMemo(() => clusterPrefixOf(nodes.map((n) => n.id)), [nodes]);
  // The OS version a new node should match — the controlplane's. Feeds the
  // wizard's "flash this image" guidance + download link.
  const clusterOsVersion = useMemo(
    () => nodes.find((n) => n.role === 'controlplane')?.imageVersion,
    [nodes],
  );
  const takenIds = useMemo(
    () => new Set<string>([...nodes.map((n) => n.id), ...pending.map((p) => p.id)]),
    [nodes, pending],
  );

  const selectedNode = nodes.find((n) => n.id === selectedId) ?? null;
  const selectedUtil = selectedId ? util[selectedId] : undefined;
  const selectedApps = selectedId ? apps.filter((a) => a.targetNode === selectedId) : [];

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
      <NodeGrid
        nodes={views}
        pending={pending}
        selectedId={selectedId}
        onSelect={(id) => setSelectedId((prev) => (prev === id ? null : id))}
        onAddNode={() => setWizardOpen(true)}
        onCancelPending={(p) => {
          setCancelErr(null);
          setCancelTarget(p);
        }}
      />
      <div style={{ flex: 1, overflowY: 'auto' }}>
        <NodeControls
          node={selectedNode}
          cpu={selectedUtil?.cpu ?? null}
          mem={selectedUtil?.mem ?? null}
          apps={selectedApps}
          onNavigate={(path) => router.push(path)}
          onRemoved={(id) => {
            setNodes((prev) => prev.filter((n) => n.id !== id));
            setSelectedId((prev) => (prev === id ? null : prev));
          }}
        />
      </div>

      {wizardOpen && (
        <AddNodeWizard
          clusterPrefix={clusterPrefix}
          clusterOsVersion={clusterOsVersion}
          taken={takenIds}
          onClose={() => setWizardOpen(false)}
          onMinted={({ id, tokenId, role }) => {
            // Optimistically show the pending bay; the 15s poll reconciles.
            setBusTokens((prev) => [
              ...prev,
              { id: tokenId, label: role, nodeId: id, createdAt: new Date().toISOString() },
            ]);
          }}
        />
      )}

      {cancelTarget && (
        <ConfirmModal
          title="CANCEL ENROLLMENT"
          message={
            cancelErr
              ? `Couldn't cancel: ${cancelErr}`
              : `Cancel the pending enrollment for ${cancelTarget.id.toUpperCase()}? Its enrollment file stops working — if you've already flashed the node, it won't be able to join.`
          }
          confirmLabel="CANCEL ENROLLMENT"
          danger
          onCancel={() => setCancelTarget(null)}
          onConfirm={() => {
            const { tokenId, id } = cancelTarget;
            revokeBusToken(tokenId)
              .then(() => {
                setBusTokens((prev) => prev.filter((t) => t.id !== tokenId));
                setCancelTarget(null);
              })
              .catch((e) => setCancelErr(String(e)));
            void id;
          }}
        />
      )}
    </div>
  );
}
