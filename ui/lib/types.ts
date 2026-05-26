export type JobStatus =
  | 'queued'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'cancelled';

export type StepStatus =
  | 'pending'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'compensated';

export interface Job {
  id: string;
  kind: string;
  spec: unknown;
  status: JobStatus;
  createdBy: string;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  parentId?: string;
  error?: string;
}

export interface JobStep {
  jobId: string;
  seq: number;
  name: string;
  status: StepStatus;
  startedAt?: string;
  finishedAt?: string;
  attempt: number;
  result?: unknown;
  error?: string;
}

export interface JobEvent {
  id?: number; // present on REST replies, absent on the wire
  type: string;
  jobId: string;
  ts: string;
  data?: unknown;
}

export type NodeRole = 'controlplane' | 'firewall' | 'compute' | 'storage';
export type NodeStatus = 'online' | 'stale' | 'offline';
export type InventoryChange =
  | 'added'
  | 'online'
  | 'stale'
  | 'offline'
  | 'updated';

export interface Node {
  id: string;
  role: NodeRole;
  hostname: string;
  agentVersion: string;
  capabilities?: string[];
  metadata?: Record<string, unknown>;
  firstSeen: string;
  lastSeen: string;
  status: NodeStatus;
}

export interface InventoryChangeEvent {
  change: InventoryChange;
  node: Node;
  ts: string;
}

export type FirewallIntentKind = 'port_forward';
export type PortForwardProto = 'tcp' | 'udp' | 'tcpudp';

export interface PortForwardSpec {
  wanPort: number;
  lanHost: string;
  lanPort: number;
  protocol: PortForwardProto;
  comment?: string;
}

export interface FirewallIntent {
  id: string;
  kind: FirewallIntentKind;
  name: string;
  enabled: boolean;
  spec: PortForwardSpec; // future: union with other spec types
  createdAt: string;
  updatedAt: string;
}

export interface FirewallNodeState {
  nodeId: string;
  intentHash: string;
  observedHash: string;
  lastApplied?: string;
  lastReconciled?: string;
  drift: boolean;
}

export type FirewallChange = 'applied' | 'drift' | 'in_sync' | 'reconciled';

export interface FirewallChangeEvent {
  nodeId: string;
  change: FirewallChange;
  intentHash?: string;
  observedHash?: string;
  ts: string;
}

export interface MetricPoint {
  ts: string;
  value: number;
}

export interface MetricSeries {
  nodeId: string;
  from: string;
  to: string;
  series: Record<string, MetricPoint[]>;
}
